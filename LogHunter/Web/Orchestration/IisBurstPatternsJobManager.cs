using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Services;
using LogHunter.Utils;

namespace LogHunter.Web.Orchestration;

internal sealed class IisBurstPatternsJobManager
{
    private readonly object _gate = new();
    private IisBurstPatternsJobSnapshot _snapshot = IisBurstPatternsJobSnapshot.CreateIdle();
    private IReadOnlyList<BurstIpCacheEntry> _ipCache = Array.Empty<BurstIpCacheEntry>();

    public IisBurstPatternsJobSnapshot GetSnapshot()
    {
        lock (_gate)
            return _snapshot;
    }

    public IReadOnlyList<BurstIpCacheEntry> GetIpCache()
    {
        lock (_gate)
            return _ipCache;
    }

    public bool TryStart(
        int bucketSeconds,
        out IisBurstPatternsJobSnapshot snapshot,
        out string? error,
        IReadOnlyList<string>? customFiles = null,
        string? customFolderPath = null)
    {
        lock (_gate)
        {
            if (string.Equals(_snapshot.State, "running", StringComparison.OrdinalIgnoreCase))
            {
                snapshot = _snapshot;
                error = "An IIS burst pattern scan is already running.";
                return false;
            }

            if (bucketSeconds is not (10 or 30 or 60 or 300))
                bucketSeconds = 60;

            List<string> files;
            if (customFiles is { Count: > 0 })
                files = customFiles.Where(File.Exists).ToList();
            else if (!string.IsNullOrWhiteSpace(customFolderPath) && Directory.Exists(customFolderPath))
                files = IisW3cReader.EnumerateLogFiles(customFolderPath);
            else
                files = IisW3cReader.EnumerateLogFiles(AppFolders.IIS);

            if (files.Count == 0)
            {
                snapshot = _snapshot;
                error = $"No .log files found in the selected source.";
                return false;
            }

            _snapshot = new IisBurstPatternsJobSnapshot(
                JobId: Guid.NewGuid().ToString("N"),
                State: "running",
                Message: "Scanning IIS logs for burst patterns.",
                BucketSeconds: bucketSeconds,
                CreatedUtc: DateTime.UtcNow,
                UpdatedUtc: DateTime.UtcNow,
                CurrentStep: 0,
                TotalSteps: files.Count,
                Phase: "scanning",
                FilesProcessed: 0,
                FilesTotal: files.Count,
                CandidateCount: 0,
                Bursts: null,
                Error: null);

            snapshot = _snapshot;
            error = null;
            _ = RunAsync(_snapshot.JobId, files, bucketSeconds);
            return true;
        }
    }

    private async Task RunAsync(string jobId, List<string> files, int bucketSeconds)
    {
        try
        {
            var thresholds = BurstThresholds.ForBucket(bucketSeconds);
            var uniqueCap = thresholds.UniqueCap;
            var uriCap = thresholds.UriCap;

            var ignoreUAPrefixes = new[] { "ELB-HealthChecker/" };
            var aggs = new Dictionary<string, BurstAgg>(StringComparer.OrdinalIgnoreCase);

            for (int f = 0; f < files.Count; f++)
            {
                var file = files[f];
                var map = await IisW3cReader.ReadFieldMapAsync(file, CancellationToken.None).ConfigureAwait(false);
                if (map is null) continue;

                if (!map.TryGetIndex("date", out var iDate)) continue;
                if (!map.TryGetIndex("time", out var iTime)) continue;
                if (!map.TryGetIndex("sc-status", out var iStatus)) continue;

                map.TryGetIndex("cs-method", out var iMethod);
                map.TryGetIndex("cs-uri-stem", out var iUriStem);
                map.TryGetIndex("time-taken", out var iTimeTaken);
                map.TryGetIndex("OriginalIP", out var iOriginalIp);
                map.TryGetIndex("c-ip", out var iCIp);
                map.TryGetIndex("cs(User-Agent)", out var iUA);

                await IisW3cReader.ForEachDataLineAsync(file, CancellationToken.None, (_, tokens) =>
                {
                    if (!TryParseDateTimeUtc(tokens.Get(iDate), tokens.Get(iTime), out var tsUtc)) return;
                    var bucketStart = FloorToBucket(tsUtc, bucketSeconds);

                    if (!TryParseInt(tokens.Get(iStatus), out var status)) return;

                    if (iUA >= 0)
                    {
                        var uaSpan = tokens.Get(iUA);
                        if (!uaSpan.IsEmpty && uaSpan[0] != '-')
                        {
                            var uaStr = uaSpan.ToString();
                            for (int k = 0; k < ignoreUAPrefixes.Length; k++)
                                if (uaStr.StartsWith(ignoreUAPrefixes[k], StringComparison.OrdinalIgnoreCase))
                                    return;
                        }
                    }

                    var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                    if (ip is null || IisClientIpResolver.IsPrivateOrLoopback(ip)) return;

                    var key = $"{ip}|{bucketStart.Ticks}";
                    if (!aggs.TryGetValue(key, out var agg))
                    {
                        agg = new BurstAgg(uniqueCap, uriCap) { Ip = ip, StartUtc = bucketStart, BucketSeconds = bucketSeconds };
                        aggs[key] = agg;
                    }

                    agg.TotalAll++;

                    if (iMethod >= 0)
                    {
                        var m = tokens.Get(iMethod);
                        if (!m.IsEmpty && m[0] != '-')
                        {
                            if (m.Equals("GET", StringComparison.OrdinalIgnoreCase)) agg.Get++;
                            else if (m.Equals("POST", StringComparison.OrdinalIgnoreCase)) agg.Post++;
                            else if (m.Equals("HEAD", StringComparison.OrdinalIgnoreCase)) agg.Head++;
                        }
                    }

                    if (status >= 200 && status <= 299) agg.C2xx++;
                    else if (status >= 300 && status <= 399) agg.C3xx++;
                    else if (status >= 400 && status <= 499) agg.C4xx++;
                    else if (status >= 500 && status <= 599) agg.C5xx++;

                    if (iTimeTaken >= 0 && TryParseInt(tokens.Get(iTimeTaken), out var ms))
                    {
                        agg.TimeTakenTotalMs += ms;
                        if (ms > agg.TimeTakenMaxMs) agg.TimeTakenMaxMs = ms;
                    }

                    if (iUA >= 0)
                    {
                        var ua = tokens.Get(iUA);
                        if (!ua.IsEmpty && ua[0] != '-')
                        {
                            var uaStr = ua.ToString();
                            if (agg.Ua is null) agg.Ua = uaStr;
                            else if (!agg.UaMixed && !string.Equals(agg.Ua, uaStr, StringComparison.OrdinalIgnoreCase))
                                agg.UaMixed = true;
                        }
                    }

                    if (iUriStem >= 0)
                    {
                        var uri = tokens.Get(iUriStem);
                        if (!uri.IsEmpty && uri[0] != '-')
                        {
                            var uriStr = uri.ToString();
                            if (IsDynamicPath(uriStr))
                            {
                                agg.TotalDynamic++;
                                if (status >= 400 && status <= 499) agg.Dynamic4xx++;
                                else if (status >= 500 && status <= 599) agg.Dynamic5xx++;
                                agg.AddDynamicUri(uriStr);
                            }
                        }
                    }
                }).ConfigureAwait(false);

                Update(jobId, snapshot => snapshot with
                {
                    UpdatedUtc = DateTime.UtcNow,
                    Message = $"Scanning IIS logs for burst patterns: {f + 1} / {files.Count} files.",
                    CurrentStep = f + 1,
                    FilesProcessed = f + 1
                });
            }

            if (aggs.Count == 0)
            {
                Update(jobId, snapshot => snapshot with
                {
                    State = "completed",
                    Phase = "completed",
                    Message = "No traffic buckets found (after filters).",
                    UpdatedUtc = DateTime.UtcNow,
                    CurrentStep = files.Count,
                    CandidateCount = 0
                });
                return;
            }

            var assessed = aggs.Values
                .Select(a => IisBurstScoring.Assess(a, thresholds))
                .Where(x => x.IsCandidate)
                .OrderByDescending(x => x.SeverityScore)
                .ThenByDescending(x => x.Agg.TotalDynamic)
                .ThenByDescending(x => x.Agg.UniqueDynamicUris)
                .ThenBy(x => x.Agg.StartUtc)
                .ToList();

            // Campaign grouping runs over the FULL candidate set (not just the top 200
            // shown) so a distributed scan whose individual bursts rank low is still
            // grouped and surfaced as one finding.
            var campaigns = BuildCampaigns(assessed);

            var candidates = assessed.Take(200).ToList();

            var burstResults = candidates.Select((c, idx) =>
            {
                var a = c.Agg;
                return new BurstResult(
                    Rank: idx + 1,
                    StartUtc: a.StartUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                    Ip: a.Ip,
                    SeverityScore: c.SeverityScore,
                    SeverityLabel: IisBurstScoring.SeverityLabel(c.SeverityScore),
                    Flags: IisBurstScoring.BuildFlags(c),
                    TotalDynamic: a.TotalDynamic,
                    UniqueDynamicUris: a.UniqueDynamicUris,
                    FourxxPct: Math.Round(a.DynamicFourxxRatio * 100.0, 1),
                    Post: a.Post,
                    Head: a.Head,
                    AvgMs: a.AvgTimeMs,
                    MaxMs: a.TimeTakenMaxMs,
                    Ua: a.UaDisplay,
                    C2xx: a.C2xx,
                    C3xx: a.C3xx,
                    C4xx: a.C4xx,
                    C5xx: a.C5xx,
                    TopUris: a.TopUris(10).Select(u => new BurstUriCount(u.Uri, u.Count)).ToList());
            }).ToList();

            // Build per-IP cache: aggregate burst count + total hits per distinct IP
            var ipAgg = new Dictionary<string, (int Bursts, int Hits, int MaxScore)>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in candidates)
            {
                if (ipAgg.TryGetValue(c.Agg.Ip, out var cur))
                    ipAgg[c.Agg.Ip] = (cur.Bursts + 1, cur.Hits + c.Agg.TotalDynamic, Math.Max(cur.MaxScore, c.SeverityScore));
                else
                    ipAgg[c.Agg.Ip] = (1, c.Agg.TotalDynamic, c.SeverityScore);
            }
            lock (_gate)
            {
                _ipCache = ipAgg
                    .OrderByDescending(kv => kv.Value.MaxScore)
                    .ThenByDescending(kv => kv.Value.Hits)
                    .Select(kv => new BurstIpCacheEntry(kv.Key, kv.Value.Bursts, kv.Value.Hits, kv.Value.MaxScore))
                    .ToList();
            }

            Update(jobId, snapshot => snapshot with
            {
                State = "completed",
                Phase = "completed",
                Message = $"Burst scan complete. {candidates.Count} candidate(s) found.",
                UpdatedUtc = DateTime.UtcNow,
                CurrentStep = files.Count,
                FilesProcessed = files.Count,
                CandidateCount = candidates.Count,
                Bursts = burstResults,
                Campaigns = campaigns
            });
        }
        catch (Exception ex)
        {
            Update(jobId, snapshot => snapshot with
            {
                State = "failed",
                Phase = "failed",
                Message = "IIS burst pattern scan failed.",
                UpdatedUtc = DateTime.UtcNow,
                Error = ex.Message
            });
        }
    }

    private void Update(string jobId, Func<IisBurstPatternsJobSnapshot, IisBurstPatternsJobSnapshot> update)
    {
        lock (_gate)
        {
            if (!string.Equals(_snapshot.JobId, jobId, StringComparison.Ordinal))
                return;
            _snapshot = update(_snapshot);
        }
    }

    // ---- Coordinated-campaign grouping (prototype) ----
    // Group candidate bursts by fingerprint = user-agent + distinct-path-set hash. Real
    // users never replay an identical path set, so the SAME fingerprint seen from several
    // source IPs is a coordinated / rotating-IP scan. Labeling uses universal scanner
    // signatures (probe paths + known scan UAs), so this generalizes across every client
    // without referencing that client's own endpoints.
    private static List<BurstCampaign> BuildCampaigns(List<BurstAssessment> assessed)
    {
        var result = new List<BurstCampaign>();

        foreach (var grp in assessed.GroupBy(c => c.Agg.FingerprintKey, StringComparer.Ordinal))
        {
            var g = grp.ToList();
            var ips = g.Select(c => c.Agg.Ip)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();

            // Coordinated = the same fingerprint (UA + identical path set) from >= 2 IPs.
            if (ips.Count < 2) continue;

            var rep = g[0].Agg;
            var totalDyn = g.Sum(c => c.Agg.TotalDynamic);
            var total4xx = g.Sum(c => c.Agg.Dynamic4xx);
            var fourxx = totalDyn == 0 ? 0.0 : (double)total4xx / totalDyn;
            var scannerUa = IisBurstScoring.IsScannerUserAgent(rep.Ua);
            var probeRatio = rep.ProbeRatio;

            // Only surface a coordinated group that actually looks hostile — probe paths,
            // mostly-errors, or a known scan tool. Two legitimate users who happen to hit
            // the same screens (all-200, no probe, real browser UA) are NOT a campaign.
            if (!(probeRatio >= 0.15 || fourxx >= 0.50 || scannerUa)) continue;

            string label =
                (probeRatio >= 0.30 || scannerUa) ? "Vuln scanner — probing known exploit/secret paths"
                : fourxx >= 0.80 ? "Distributed scan — mostly errors (paths not found)"
                : "Coordinated scan — same requests from many IPs (review)";

            result.Add(new BurstCampaign(
                Fingerprint: rep.PathSetHash.ToString("x", CultureInfo.InvariantCulture),
                Label: label,
                Ua: rep.UaDisplay,
                IpCount: ips.Count,
                BurstCount: g.Count,
                TotalDynamic: totalDyn,
                FourxxPct: Math.Round(fourxx * 100.0, 1),
                ProbePct: Math.Round(probeRatio * 100.0, 1),
                Ips: ips,
                SamplePaths: rep.TopUris(12).Select(u => u.Uri).ToList()));
        }

        return result
            .OrderByDescending(c => c.IpCount)
            .ThenByDescending(c => c.TotalDynamic)
            .Take(50)
            .ToList();
    }

    // Scoring, flags, severity labeling, thresholds and BurstAgg now live in the
    // shared IisBurstScoring module (Services/IisBurstScoring.cs), consumed by both
    // this web job manager and the console IisOption_FindBurstPatterns.

    // ---- Helpers ----

    private static bool TryParseInt(ReadOnlySpan<char> s, out int value)
    {
        value = 0;
        if (s.IsEmpty || s[0] == '-') return false;
        return int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static bool TryParseDateTimeUtc(ReadOnlySpan<char> date, ReadOnlySpan<char> time, out DateTime dtUtc)
    {
        dtUtc = default;
        if (date.Length != 10 || time.Length < 8) return false;
        if (!int.TryParse(date[..4], NumberStyles.Integer, CultureInfo.InvariantCulture, out var yyyy)) return false;
        if (!int.TryParse(date.Slice(5, 2), NumberStyles.Integer, CultureInfo.InvariantCulture, out var mm)) return false;
        if (!int.TryParse(date.Slice(8, 2), NumberStyles.Integer, CultureInfo.InvariantCulture, out var dd)) return false;
        if (!int.TryParse(time[..2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var hh)) return false;
        if (!int.TryParse(time.Slice(3, 2), NumberStyles.Integer, CultureInfo.InvariantCulture, out var mi)) return false;
        if (!int.TryParse(time.Slice(6, 2), NumberStyles.Integer, CultureInfo.InvariantCulture, out var ss)) return false;
        try { dtUtc = new DateTime(yyyy, mm, dd, hh, mi, ss, DateTimeKind.Utc); return true; } catch { return false; }
    }

    private static DateTime FloorToBucket(DateTime utc, int bucketSeconds)
    {
        var ticksPerBucket = TimeSpan.FromSeconds(bucketSeconds).Ticks;
        var floored = utc.Ticks - (utc.Ticks % ticksPerBucket);
        return new DateTime(floored, DateTimeKind.Utc);
    }

    private static bool IsDynamicPath(string uriStem)
    {
        if (uriStem.StartsWith("/ServiceCenter", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.StartsWith("/LifeTime", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("/moduleservices", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("/rest/", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("/soap/", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.EndsWith(".asmx", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.EndsWith(".aspx", StringComparison.OrdinalIgnoreCase)) return true;
        var lastSlash = uriStem.LastIndexOf('/');
        var lastDot = uriStem.LastIndexOf('.');
        if (lastDot > lastSlash && lastDot >= 0)
        {
            var ext = uriStem.Substring(lastDot).ToLowerInvariant();
            return ext switch
            {
                ".js" or ".css" or ".png" or ".jpg" or ".jpeg" or ".gif" or ".svg" or ".ico" or ".woff" or ".woff2" or ".ttf" or ".map" or ".txt" or ".xml" => false,
                _ => true
            };
        }
        return true;
    }
}

internal sealed record IisBurstPatternsJobSnapshot(
    string JobId,
    string State,
    string Message,
    int BucketSeconds,
    DateTime CreatedUtc,
    DateTime UpdatedUtc,
    int CurrentStep,
    int TotalSteps,
    string Phase,
    int FilesProcessed,
    int FilesTotal,
    int CandidateCount,
    IReadOnlyList<BurstResult>? Bursts,
    string? Error,
    IReadOnlyList<BurstCampaign>? Campaigns = null)
{
    public static IisBurstPatternsJobSnapshot CreateIdle()
        => new(
            JobId: string.Empty,
            State: "idle",
            Message: "No IIS burst pattern scan has been run yet.",
            BucketSeconds: 60,
            CreatedUtc: DateTime.UtcNow,
            UpdatedUtc: DateTime.UtcNow,
            CurrentStep: 0,
            TotalSteps: 0,
            Phase: "idle",
            FilesProcessed: 0,
            FilesTotal: 0,
            CandidateCount: 0,
            Bursts: null,
            Error: null);
}

internal sealed record BurstResult(
    int Rank,
    string StartUtc,
    string Ip,
    int SeverityScore,
    string SeverityLabel,
    string Flags,
    int TotalDynamic,
    int UniqueDynamicUris,
    double FourxxPct,
    int Post,
    int Head,
    int AvgMs,
    int MaxMs,
    string Ua,
    int C2xx,
    int C3xx,
    int C4xx,
    int C5xx,
    IReadOnlyList<BurstUriCount> TopUris);

internal sealed record BurstUriCount(string Uri, int Count);

internal sealed record BurstIpCacheEntry(string Ip, int Bursts, int TotalHits, int MaxScore);

internal sealed record BurstCampaign(
    string Fingerprint,
    string Label,
    string Ua,
    int IpCount,
    int BurstCount,
    int TotalDynamic,
    double FourxxPct,
    double ProbePct,
    IReadOnlyList<string> Ips,
    IReadOnlyList<string> SamplePaths);
