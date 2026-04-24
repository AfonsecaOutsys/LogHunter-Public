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
            var rateThreshold = (int)Math.Ceiling(2.5 * bucketSeconds);
            var strongRateThreshold = (int)Math.Ceiling(4.0 * bucketSeconds);
            var enumThreshold = Math.Max(12, (int)Math.Ceiling(0.60 * bucketSeconds));
            var strongEnumThreshold = Math.Max(enumThreshold + 8, (int)Math.Ceiling(0.90 * bucketSeconds));
            var errorThreshold = Math.Max(12, (int)Math.Ceiling((30.0 / 60.0) * bucketSeconds));
            var focusThreshold = Math.Max(12, (int)Math.Ceiling(1.2 * bucketSeconds));
            var postThreshold = Math.Max(10, (int)Math.Ceiling(0.30 * bucketSeconds));
            var headThreshold = Math.Max(8, (int)Math.Ceiling(0.25 * bucketSeconds));
            var uniqueCap = Math.Max(enumThreshold + 1, 64);
            var uriCap = 40;

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

            var candidates = aggs.Values
                .Select(a => Assess(a, rateThreshold, strongRateThreshold, enumThreshold, strongEnumThreshold, errorThreshold, focusThreshold, postThreshold, headThreshold))
                .Where(x => x.IsCandidate)
                .OrderByDescending(x => x.SeverityScore)
                .ThenByDescending(x => x.Agg.TotalDynamic)
                .ThenByDescending(x => x.Agg.UniqueDynamicUris)
                .ThenBy(x => x.Agg.StartUtc)
                .Take(200)
                .ToList();

            var burstResults = candidates.Select((c, idx) =>
            {
                var a = c.Agg;
                return new BurstResult(
                    Rank: idx + 1,
                    StartUtc: a.StartUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                    Ip: a.Ip,
                    SeverityScore: c.SeverityScore,
                    SeverityLabel: SeverityLabel(c.SeverityScore),
                    Flags: BuildFlags(c),
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
                Bursts = burstResults
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

    // ---- Scoring (mirroring console IisOption_FindBurstPatterns) ----

    private sealed record Assessment(BurstAgg Agg, int SeverityScore, bool IsCandidate, bool IsRate, bool IsStrongRate, bool IsEnum, bool IsStrongEnum, bool IsError, bool IsFocused, bool IsPostHeavy, bool IsHeadHeavy);

    private static Assessment Assess(BurstAgg a, int rateTh, int strongRateTh, int enumTh, int strongEnumTh, int errTh, int focusTh, int postTh, int headTh)
    {
        var isRate = a.TotalDynamic >= rateTh;
        var isStrongRate = a.TotalDynamic >= strongRateTh;
        var isEnum = a.TotalDynamic >= enumTh && a.UniqueDynamicUris >= enumTh && a.UniqueDynamicRatio >= 0.45;
        var isStrongEnum = a.TotalDynamic >= strongEnumTh && a.UniqueDynamicUris >= strongEnumTh && a.UniqueDynamicRatio >= 0.65;
        var isError = a.Dynamic4xx >= errTh || (a.DynamicFourxxRatio >= 0.70 && a.Dynamic4xx >= Math.Max(8, errTh / 2) && a.TotalDynamic >= Math.Max(15, rateTh / 3));
        var isFocused = a.TopDynamicUriHits >= focusTh && a.FocusedUriRatio >= 0.70;
        var isPostHeavy = a.Post >= postTh && a.PostRatio >= 0.35;
        var isHeadHeavy = a.Head >= headTh && a.HeadRatio >= 0.35;

        var isCandidate =
            isStrongEnum
            || (isFocused && isRate)
            || (isError && (isRate || isEnum || isPostHeavy || isHeadHeavy))
            || (isEnum && (isError || isPostHeavy || isHeadHeavy))
            || (isStrongRate && (isFocused || isError || isPostHeavy || isHeadHeavy));

        var score = 0;
        if (isStrongRate) score += 65 + Math.Min(50, a.TotalDynamic - strongRateTh);
        else if (isRate) score += 30 + Math.Min(35, a.TotalDynamic - rateTh);
        if (isStrongEnum) score += 70 + Math.Min(40, (a.UniqueDynamicUris - strongEnumTh) * 2);
        else if (isEnum) score += 35 + Math.Min(30, (a.UniqueDynamicUris - enumTh) * 2);
        if (isError) { score += 50 + Math.Min(35, (a.Dynamic4xx - errTh) * 2); if (a.DynamicFourxxRatio >= 0.85) score += 10; }
        if (isFocused) score += 35 + Math.Min(15, (int)Math.Round((a.FocusedUriRatio - 0.70) * 100));
        if (isPostHeavy) score += 20 + Math.Min(15, a.Post - Math.Max(10, rateTh / 4));
        if (isHeadHeavy) score += 18 + Math.Min(12, a.Head - Math.Max(8, rateTh / 5));

        return new Assessment(a, score, isCandidate, isRate, isStrongRate, isEnum, isStrongEnum, isError, isFocused, isPostHeavy, isHeadHeavy);
    }

    private static string BuildFlags(Assessment b)
    {
        var flags = new List<string>();
        if (b.IsStrongRate) flags.Add("RATE+"); else if (b.IsRate) flags.Add("RATE");
        if (b.IsStrongEnum) flags.Add("ENUM+"); else if (b.IsEnum) flags.Add("ENUM");
        if (b.IsError) flags.Add("4XX");
        if (b.IsFocused) flags.Add("FOCUS");
        if (b.IsPostHeavy) flags.Add("POST");
        if (b.IsHeadHeavy) flags.Add("HEAD");
        return flags.Count == 0 ? "-" : string.Join("+", flags);
    }

    private static string SeverityLabel(int score)
        => score >= 140 ? "CRIT" : score >= 95 ? "HIGH" : score >= 60 ? "MED" : "LOW";

    // ---- BurstAgg (mirroring console) ----

    private sealed class BurstAgg
    {
        public required string Ip { get; init; }
        public required DateTime StartUtc { get; init; }
        public int BucketSeconds { get; init; }
        public int TotalDynamic { get; set; }
        public int TotalAll { get; set; }
        public int C2xx { get; set; }
        public int C3xx { get; set; }
        public int C4xx { get; set; }
        public int C5xx { get; set; }
        public int Dynamic4xx { get; set; }
        public int Dynamic5xx { get; set; }
        public int Get { get; set; }
        public int Post { get; set; }
        public int Head { get; set; }
        public long TimeTakenTotalMs { get; set; }
        public int TimeTakenMaxMs { get; set; }
        public string? Ua { get; set; }
        public bool UaMixed { get; set; }
        public int UniqueDynamicUris { get; set; }
        private HashSet<string>? _uniqueDyn;
        private readonly int _uniqueCap;
        private Dictionary<string, int>? _uriCounts;
        private readonly int _uriCap;
        public int TopDynamicUriHits { get; private set; }

        public BurstAgg(int uniqueCap, int uriCap) { _uniqueCap = uniqueCap; _uriCap = uriCap; }

        public void AddDynamicUri(string uriStem)
        {
            int currentCount = 0;
            if (UniqueDynamicUris < _uniqueCap) { _uniqueDyn ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase); if (_uniqueDyn.Add(uriStem)) UniqueDynamicUris++; }
            else UniqueDynamicUris = _uniqueCap;

            _uriCounts ??= new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (_uriCounts.Count <= _uriCap)
            {
                if (_uriCounts.TryGetValue(uriStem, out var v)) { currentCount = v + 1; _uriCounts[uriStem] = currentCount; }
                else { currentCount = 1; _uriCounts[uriStem] = currentCount; }
            }
            if (currentCount > TopDynamicUriHits) TopDynamicUriHits = currentCount;
        }

        public List<(string Uri, int Count)> TopUris(int take)
        {
            if (_uriCounts is null || _uriCounts.Count == 0) return new();
            return _uriCounts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase).Take(take).Select(kv => (kv.Key, kv.Value)).ToList();
        }

        public string UaDisplay => UaMixed ? "(mixed)" : (Ua ?? "-");
        public int AvgTimeMs => TotalAll == 0 ? 0 : (int)(TimeTakenTotalMs / TotalAll);
        public double DynamicFourxxRatio => TotalDynamic == 0 ? 0 : (double)Dynamic4xx / TotalDynamic;
        public double UniqueDynamicRatio => TotalDynamic == 0 ? 0 : (double)UniqueDynamicUris / TotalDynamic;
        public double FocusedUriRatio => TotalDynamic == 0 ? 0 : (double)TopDynamicUriHits / TotalDynamic;
        public double PostRatio => TotalAll == 0 ? 0 : (double)Post / TotalAll;
        public double HeadRatio => TotalAll == 0 ? 0 : (double)Head / TotalAll;
    }

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
    string? Error)
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
