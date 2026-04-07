using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Services;
using LogHunter.Utils;

namespace LogHunter.Web.Orchestration;

internal sealed class IisBytesIntelJobManager
{
    private const int TopIps = 25;
    private const int TopUrisPerIp = 10;

    private readonly object _gate = new();
    private IisBytesIntelJobSnapshot _snapshot = IisBytesIntelJobSnapshot.CreateIdle();

    public IisBytesIntelJobSnapshot GetSnapshot()
    {
        lock (_gate)
            return _snapshot;
    }

    public bool TryStart(
        string mode,
        out IisBytesIntelJobSnapshot snapshot,
        out string? error)
    {
        lock (_gate)
        {
            if (string.Equals(_snapshot.State, "running", StringComparison.OrdinalIgnoreCase))
            {
                snapshot = _snapshot;
                error = "An IIS bytes intel scan is already running.";
                return false;
            }

            var isBandwidth = string.Equals(mode, "bandwidth", StringComparison.OrdinalIgnoreCase);
            var isUploads = string.Equals(mode, "uploads", StringComparison.OrdinalIgnoreCase);
            if (!isBandwidth && !isUploads)
            {
                snapshot = _snapshot;
                error = "Mode must be 'bandwidth' or 'uploads'.";
                return false;
            }

            var files = IisW3cReader.EnumerateLogFiles(AppFolders.IIS);
            if (files.Count == 0)
            {
                snapshot = _snapshot;
                error = $"No .log files found in: {AppFolders.IIS}";
                return false;
            }

            var modeLabel = isBandwidth ? "Top Bandwidth IPs" : "Uploads/Payloads";

            _snapshot = new IisBytesIntelJobSnapshot(
                JobId: Guid.NewGuid().ToString("N"),
                State: "running",
                Message: $"Scanning IIS logs for {modeLabel} (pass 1/2).",
                Mode: mode,
                CreatedUtc: DateTime.UtcNow,
                UpdatedUtc: DateTime.UtcNow,
                CurrentStep: 0,
                TotalSteps: files.Count * 2,
                Phase: "pass1",
                FilesProcessed: 0,
                FilesTotal: files.Count,
                ExportPath: null,
                TopIps: null,
                Error: null);

            snapshot = _snapshot;
            error = null;

            if (isBandwidth)
                _ = RunBandwidthAsync(_snapshot.JobId, files);
            else
                _ = RunUploadsAsync(_snapshot.JobId, files);

            return true;
        }
    }

    public bool TryOpenExport(string? jobId, out string message)
    {
        IisBytesIntelJobSnapshot snapshot;
        lock (_gate)
        {
            snapshot = _snapshot;
            if (!string.IsNullOrWhiteSpace(jobId) && !string.Equals(snapshot.JobId, jobId, StringComparison.Ordinal))
            {
                message = "Job not found.";
                return false;
            }
        }

        var path = snapshot.ExportPath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            message = "The exported CSV file is not available.";
            return false;
        }

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo { FileName = path, UseShellExecute = true });
            message = path;
            return true;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return false;
        }
    }

    // ---- Bandwidth workflow ----

    private async Task RunBandwidthAsync(string jobId, List<string> files)
    {
        try
        {
            var ignoreUAPrefixes = new[] { "ELB-HealthChecker/" };
            var ipAgg = new Dictionary<string, IpBandwidthAgg>(StringComparer.OrdinalIgnoreCase);
            var ipClassCache = new Dictionary<string, IpClass>(StringComparer.OrdinalIgnoreCase);

            // Pass 1
            for (int f = 0; f < files.Count; f++)
            {
                var file = files[f];
                var map = await IisW3cReader.ReadFieldMapAsync(file, CancellationToken.None).ConfigureAwait(false);
                if (map is null) continue;

                if (!map.TryGetIndex("sc-bytes", out var iScBytes)) continue;
                map.TryGetIndex("cs-bytes", out var iCsBytes);
                map.TryGetIndex("sc-status", out var iStatus);
                map.TryGetIndex("cs-method", out var iMethod);
                map.TryGetIndex("OriginalIP", out var iOriginalIp);
                map.TryGetIndex("c-ip", out var iCIp);
                map.TryGetIndex("cs(User-Agent)", out var iUA);

                await IisW3cReader.ForEachDataLineAsync(file, CancellationToken.None, (_, tokens) =>
                {
                    if (IsIgnoredByUa(tokens, iUA, ignoreUAPrefixes)) return;

                    var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                    if (ip is null || !IisClientIpResolver.IsPublicIp(ip, ipClassCache)) return;

                    long scBytes = TryParseLong(tokens.Get(iScBytes), out var scb) ? scb : 0L;
                    long csBytes = iCsBytes >= 0 && TryParseLong(tokens.Get(iCsBytes), out var csb) ? csb : 0L;
                    int status = iStatus >= 0 && TryParseInt(tokens.Get(iStatus), out var st) ? st : 0;

                    if (!ipAgg.TryGetValue(ip, out var a)) { a = new IpBandwidthAgg(ip); ipAgg[ip] = a; }

                    a.Hits++;
                    a.TotalScBytes += scBytes;
                    a.TotalCsBytes += csBytes;
                    if (scBytes > a.MaxScBytes) a.MaxScBytes = scBytes;

                    if (status >= 200 && status <= 299) a.C2xx++;
                    else if (status >= 300 && status <= 399) a.C3xx++;
                    else if (status >= 400 && status <= 499) a.C4xx++;
                    else if (status >= 500 && status <= 599) a.C5xx++;
                }).ConfigureAwait(false);

                Update(jobId, snapshot => snapshot with
                {
                    UpdatedUtc = DateTime.UtcNow,
                    Message = $"Scanning IIS logs for Top Bandwidth IPs (pass 1/2): {f + 1} / {files.Count} files.",
                    CurrentStep = f + 1,
                    Phase = "pass1",
                    FilesProcessed = f + 1
                });
            }

            if (ipAgg.Count == 0)
            {
                Update(jobId, snapshot => snapshot with { State = "completed", Phase = "completed", Message = "No public-client traffic found.", UpdatedUtc = DateTime.UtcNow, CurrentStep = files.Count * 2 });
                return;
            }

            var top = ipAgg.Values.OrderByDescending(x => x.TotalScBytes).ThenByDescending(x => x.Hits).Take(TopIps).ToList();
            var topSet = top.Select(x => x.Ip).ToHashSet(StringComparer.OrdinalIgnoreCase);

            var perIpUris = new Dictionary<string, Dictionary<string, UriAgg>>(StringComparer.OrdinalIgnoreCase);
            foreach (var ip in topSet) perIpUris[ip] = new Dictionary<string, UriAgg>(StringComparer.OrdinalIgnoreCase);

            // Pass 2
            for (int f = 0; f < files.Count; f++)
            {
                var file = files[f];
                var map = await IisW3cReader.ReadFieldMapAsync(file, CancellationToken.None).ConfigureAwait(false);
                if (map is null) continue;

                if (!map.TryGetIndex("sc-bytes", out var iScBytes)) continue;
                map.TryGetIndex("cs-uri-stem", out var iUriStem);
                map.TryGetIndex("OriginalIP", out var iOriginalIp);
                map.TryGetIndex("c-ip", out var iCIp);
                map.TryGetIndex("cs(User-Agent)", out var iUA);

                await IisW3cReader.ForEachDataLineAsync(file, CancellationToken.None, (_, tokens) =>
                {
                    if (IsIgnoredByUa(tokens, iUA, ignoreUAPrefixes)) return;
                    var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                    if (ip is null || !topSet.Contains(ip)) return;
                    long scBytes = TryParseLong(tokens.Get(iScBytes), out var scb) ? scb : 0L;
                    if (iUriStem < 0) return;
                    var u = tokens.Get(iUriStem);
                    if (u.IsEmpty || u[0] == '-') return;
                    var uri = u.ToString();
                    AddUriAgg(perIpUris[ip], uri, scBytes, 500);
                }).ConfigureAwait(false);

                Update(jobId, snapshot => snapshot with
                {
                    UpdatedUtc = DateTime.UtcNow,
                    Message = $"Scanning top IP URIs (pass 2/2): {f + 1} / {files.Count} files.",
                    CurrentStep = files.Count + f + 1,
                    Phase = "pass2",
                    FilesProcessed = f + 1
                });
            }

            // Export CSV
            var outDir = AppFolders.Output;
            Directory.CreateDirectory(outDir);
            var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
            var csvPath = Path.Combine(outDir, $"iis_top_bandwidth_ips_{stamp}.csv");
            WriteBandwidthCsv(csvPath, top, perIpUris);

            var topIpResults = top.Select((a, idx) =>
            {
                var topUri = perIpUris.TryGetValue(a.Ip, out var m) && m.Count > 0
                    ? m.OrderByDescending(kv => kv.Value.Bytes).First()
                    : default;

                return new BytesIntelIpResult(
                    Rank: idx + 1,
                    Ip: a.Ip,
                    Hits: a.Hits,
                    TotalScBytes: a.TotalScBytes,
                    TotalCsBytes: a.TotalCsBytes,
                    MaxScBytes: a.MaxScBytes,
                    C2xx: a.C2xx, C3xx: a.C3xx, C4xx: a.C4xx, C5xx: a.C5xx,
                    TopUri: topUri.Key ?? "-",
                    TopUriBytes: topUri.Value.Bytes,
                    TopUris: (perIpUris.TryGetValue(a.Ip, out var mu) ? mu : new Dictionary<string, UriAgg>())
                        .OrderByDescending(kv => kv.Value.Bytes).Take(TopUrisPerIp)
                        .Select(kv => new BytesIntelUriResult(kv.Key, kv.Value.Hits, kv.Value.Bytes)).ToList());
            }).ToList();

            Update(jobId, snapshot => snapshot with
            {
                State = "completed",
                Phase = "completed",
                Message = $"Top bandwidth scan complete. {top.Count} IP(s) ranked.",
                UpdatedUtc = DateTime.UtcNow,
                CurrentStep = files.Count * 2,
                FilesProcessed = files.Count,
                ExportPath = csvPath,
                TopIps = topIpResults
            });
        }
        catch (Exception ex)
        {
            Update(jobId, snapshot => snapshot with { State = "failed", Phase = "failed", Message = "IIS top bandwidth scan failed.", UpdatedUtc = DateTime.UtcNow, Error = ex.Message });
        }
    }

    // ---- Uploads workflow ----

    private async Task RunUploadsAsync(string jobId, List<string> files)
    {
        try
        {
            var ignoreUAPrefixes = new[] { "ELB-HealthChecker/" };
            var ipAgg = new Dictionary<string, UploadAgg>(StringComparer.OrdinalIgnoreCase);
            var ipClassCache = new Dictionary<string, IpClass>(StringComparer.OrdinalIgnoreCase);

            // Pass 1
            for (int f = 0; f < files.Count; f++)
            {
                var file = files[f];
                var map = await IisW3cReader.ReadFieldMapAsync(file, CancellationToken.None).ConfigureAwait(false);
                if (map is null) continue;

                if (!map.TryGetIndex("cs-method", out var iMethod)) continue;
                if (!map.TryGetIndex("cs-bytes", out var iCsBytes)) continue;
                map.TryGetIndex("sc-status", out var iStatus);
                map.TryGetIndex("sc-bytes", out var iScBytes);
                map.TryGetIndex("OriginalIP", out var iOriginalIp);
                map.TryGetIndex("c-ip", out var iCIp);
                map.TryGetIndex("cs(User-Agent)", out var iUA);

                await IisW3cReader.ForEachDataLineAsync(file, CancellationToken.None, (_, tokens) =>
                {
                    if (IsIgnoredByUa(tokens, iUA, ignoreUAPrefixes)) return;
                    var m = tokens.Get(iMethod);
                    if (m.IsEmpty || m[0] == '-') return;
                    var isPost = m.Equals("POST", StringComparison.OrdinalIgnoreCase);
                    var isPut = m.Equals("PUT", StringComparison.OrdinalIgnoreCase);
                    if (!isPost && !isPut) return;
                    if (!TryParseLong(tokens.Get(iCsBytes), out var csBytes) || csBytes <= 0) return;

                    var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                    if (ip is null || !IisClientIpResolver.IsPublicIp(ip, ipClassCache)) return;

                    long scBytes = iScBytes >= 0 && TryParseLong(tokens.Get(iScBytes), out var scb) ? scb : 0L;
                    int status = iStatus >= 0 && TryParseInt(tokens.Get(iStatus), out var st) ? st : 0;

                    if (!ipAgg.TryGetValue(ip, out var a)) { a = new UploadAgg(ip); ipAgg[ip] = a; }

                    a.PostPutCount++;
                    a.TotalCsBytes += csBytes;
                    if (csBytes > a.MaxCsBytes) a.MaxCsBytes = csBytes;
                    a.TotalScBytes += scBytes;

                    if (status >= 200 && status <= 299) a.C2xx++;
                    else if (status >= 300 && status <= 399) a.C3xx++;
                    else if (status >= 400 && status <= 499) a.C4xx++;
                    else if (status >= 500 && status <= 599) a.C5xx++;
                }).ConfigureAwait(false);

                Update(jobId, snapshot => snapshot with
                {
                    UpdatedUtc = DateTime.UtcNow,
                    Message = $"Scanning IIS logs for Uploads/Payloads (pass 1/2): {f + 1} / {files.Count} files.",
                    CurrentStep = f + 1,
                    Phase = "pass1",
                    FilesProcessed = f + 1
                });
            }

            if (ipAgg.Count == 0)
            {
                Update(jobId, snapshot => snapshot with { State = "completed", Phase = "completed", Message = "No public-client POST/PUT payload traffic found.", UpdatedUtc = DateTime.UtcNow, CurrentStep = files.Count * 2 });
                return;
            }

            var top = ipAgg.Values.OrderByDescending(x => x.MaxCsBytes).ThenByDescending(x => x.TotalCsBytes).Take(TopIps).ToList();
            var topSet = top.Select(x => x.Ip).ToHashSet(StringComparer.OrdinalIgnoreCase);

            var perIpEndpoints = new Dictionary<string, Dictionary<string, EndpointAgg>>(StringComparer.OrdinalIgnoreCase);
            foreach (var ip in topSet) perIpEndpoints[ip] = new Dictionary<string, EndpointAgg>(StringComparer.OrdinalIgnoreCase);

            // Pass 2
            for (int f = 0; f < files.Count; f++)
            {
                var file = files[f];
                var map = await IisW3cReader.ReadFieldMapAsync(file, CancellationToken.None).ConfigureAwait(false);
                if (map is null) continue;

                if (!map.TryGetIndex("cs-method", out var iMethod)) continue;
                if (!map.TryGetIndex("cs-bytes", out var iCsBytes)) continue;
                map.TryGetIndex("cs-uri-stem", out var iUriStem);
                map.TryGetIndex("OriginalIP", out var iOriginalIp);
                map.TryGetIndex("c-ip", out var iCIp);
                map.TryGetIndex("cs(User-Agent)", out var iUA);

                await IisW3cReader.ForEachDataLineAsync(file, CancellationToken.None, (_, tokens) =>
                {
                    if (IsIgnoredByUa(tokens, iUA, ignoreUAPrefixes)) return;
                    var m2 = tokens.Get(iMethod);
                    if (m2.IsEmpty || m2[0] == '-') return;
                    if (!m2.Equals("POST", StringComparison.OrdinalIgnoreCase) && !m2.Equals("PUT", StringComparison.OrdinalIgnoreCase)) return;
                    if (!TryParseLong(tokens.Get(iCsBytes), out var csBytes) || csBytes <= 0) return;

                    var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                    if (ip is null || !topSet.Contains(ip)) return;
                    if (iUriStem < 0) return;
                    var u = tokens.Get(iUriStem);
                    if (u.IsEmpty || u[0] == '-') return;
                    var endpoint = u.ToString();
                    AddEndpointAgg(perIpEndpoints[ip], endpoint, csBytes, 500);
                }).ConfigureAwait(false);

                Update(jobId, snapshot => snapshot with
                {
                    UpdatedUtc = DateTime.UtcNow,
                    Message = $"Scanning top IP endpoints (pass 2/2): {f + 1} / {files.Count} files.",
                    CurrentStep = files.Count + f + 1,
                    Phase = "pass2",
                    FilesProcessed = f + 1
                });
            }

            var outDir = AppFolders.Output;
            Directory.CreateDirectory(outDir);
            var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
            var csvPath = Path.Combine(outDir, $"iis_uploads_payload_ips_{stamp}.csv");
            WriteUploadsCsv(csvPath, top, perIpEndpoints);

            var topIpResults = top.Select((a, idx) =>
            {
                var topEp = perIpEndpoints.TryGetValue(a.Ip, out var em) && em.Count > 0
                    ? em.OrderByDescending(kv => kv.Value.CsBytes).First()
                    : default;

                return new BytesIntelIpResult(
                    Rank: idx + 1,
                    Ip: a.Ip,
                    Hits: a.PostPutCount,
                    TotalScBytes: a.TotalScBytes,
                    TotalCsBytes: a.TotalCsBytes,
                    MaxScBytes: a.MaxCsBytes,
                    C2xx: a.C2xx, C3xx: a.C3xx, C4xx: a.C4xx, C5xx: a.C5xx,
                    TopUri: topEp.Key ?? "-",
                    TopUriBytes: topEp.Value.CsBytes,
                    TopUris: (perIpEndpoints.TryGetValue(a.Ip, out var me) ? me : new Dictionary<string, EndpointAgg>())
                        .OrderByDescending(kv => kv.Value.CsBytes).Take(TopUrisPerIp)
                        .Select(kv => new BytesIntelUriResult(kv.Key, kv.Value.Hits, kv.Value.CsBytes)).ToList());
            }).ToList();

            Update(jobId, snapshot => snapshot with
            {
                State = "completed",
                Phase = "completed",
                Message = $"Uploads/payloads scan complete. {top.Count} IP(s) ranked.",
                UpdatedUtc = DateTime.UtcNow,
                CurrentStep = files.Count * 2,
                FilesProcessed = files.Count,
                ExportPath = csvPath,
                TopIps = topIpResults
            });
        }
        catch (Exception ex)
        {
            Update(jobId, snapshot => snapshot with { State = "failed", Phase = "failed", Message = "IIS uploads/payloads scan failed.", UpdatedUtc = DateTime.UtcNow, Error = ex.Message });
        }
    }

    private void Update(string jobId, Func<IisBytesIntelJobSnapshot, IisBytesIntelJobSnapshot> update)
    {
        lock (_gate)
        {
            if (!string.Equals(_snapshot.JobId, jobId, StringComparison.Ordinal))
                return;
            _snapshot = update(_snapshot);
        }
    }

    // ---- Aggregates (mirrors console) ----

    private sealed class IpBandwidthAgg
    {
        public string Ip { get; }
        public long Hits { get; set; }
        public long TotalScBytes { get; set; }
        public long TotalCsBytes { get; set; }
        public long MaxScBytes { get; set; }
        public int C2xx { get; set; }
        public int C3xx { get; set; }
        public int C4xx { get; set; }
        public int C5xx { get; set; }
        public IpBandwidthAgg(string ip) => Ip = ip;
    }

    private sealed class UploadAgg
    {
        public string Ip { get; }
        public long PostPutCount { get; set; }
        public long TotalCsBytes { get; set; }
        public long MaxCsBytes { get; set; }
        public long TotalScBytes { get; set; }
        public int C2xx { get; set; }
        public int C3xx { get; set; }
        public int C4xx { get; set; }
        public int C5xx { get; set; }
        public UploadAgg(string ip) => Ip = ip;
    }

    internal struct UriAgg { public long Hits; public long Bytes; }
    internal struct EndpointAgg { public long Hits; public long CsBytes; public long MaxCsBytes; }

    private static void AddUriAgg(Dictionary<string, UriAgg> map, string uri, long scBytes, int cap)
    {
        if (map.TryGetValue(uri, out var a)) { a.Hits++; a.Bytes += scBytes; map[uri] = a; return; }
        if (map.Count >= cap) return;
        map[uri] = new UriAgg { Hits = 1, Bytes = scBytes };
    }

    private static void AddEndpointAgg(Dictionary<string, EndpointAgg> map, string ep, long csBytes, int cap)
    {
        if (map.TryGetValue(ep, out var a)) { a.Hits++; a.CsBytes += csBytes; if (csBytes > a.MaxCsBytes) a.MaxCsBytes = csBytes; map[ep] = a; return; }
        if (map.Count >= cap) return;
        map[ep] = new EndpointAgg { Hits = 1, CsBytes = csBytes, MaxCsBytes = csBytes };
    }

    // ---- Helpers ----

    private static bool IsIgnoredByUa(IisW3cReader.TokenReader tokens, int iUA, string[] prefixes)
    {
        if (iUA < 0) return false;
        var ua = tokens.Get(iUA);
        if (ua.IsEmpty || ua[0] == '-') return false;
        for (int k = 0; k < prefixes.Length; k++)
            if (ua.StartsWith(prefixes[k], StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static bool TryParseInt(ReadOnlySpan<char> s, out int value)
        => int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);

    private static bool TryParseLong(ReadOnlySpan<char> s, out long value)
        => long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0) return "0 B";
        string[] suf = { "B", "KB", "MB", "GB", "TB" };
        double b = bytes; int i = 0;
        while (b >= 1024 && i < suf.Length - 1) { b /= 1024; i++; }
        return $"{b:0.##} {suf[i]}";
    }

    private static string CsvEsc(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        if (s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) < 0) return s;
        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }

    private static void WriteBandwidthCsv(string path, List<IpBandwidthAgg> top, Dictionary<string, Dictionary<string, UriAgg>> perIpUris)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var fs = File.Create(path);
        using var sw = new StreamWriter(fs, new UTF8Encoding(false));
        sw.WriteLine("Rank,IP,Hits,TotalScBytes,TotalCsBytes,MaxScBytes,2xx,3xx,4xx,5xx,TopUri,TopUriScBytes");
        for (int i = 0; i < top.Count; i++)
        {
            var a = top[i];
            var topUri = "";
            long topBytes = 0;
            if (perIpUris.TryGetValue(a.Ip, out var m) && m.Count > 0)
            {
                var best = m.OrderByDescending(kv => kv.Value.Bytes).First();
                topUri = best.Key;
                topBytes = best.Value.Bytes;
            }
            sw.WriteLine(string.Join(",",
                (i + 1).ToString(CultureInfo.InvariantCulture), CsvEsc(a.Ip),
                a.Hits.ToString(CultureInfo.InvariantCulture), a.TotalScBytes.ToString(CultureInfo.InvariantCulture),
                a.TotalCsBytes.ToString(CultureInfo.InvariantCulture), a.MaxScBytes.ToString(CultureInfo.InvariantCulture),
                a.C2xx.ToString(CultureInfo.InvariantCulture), a.C3xx.ToString(CultureInfo.InvariantCulture),
                a.C4xx.ToString(CultureInfo.InvariantCulture), a.C5xx.ToString(CultureInfo.InvariantCulture),
                CsvEsc(topUri), topBytes.ToString(CultureInfo.InvariantCulture)));
        }
    }

    private static void WriteUploadsCsv(string path, List<UploadAgg> top, Dictionary<string, Dictionary<string, EndpointAgg>> perIpEndpoints)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var fs = File.Create(path);
        using var sw = new StreamWriter(fs, new UTF8Encoding(false));
        sw.WriteLine("Rank,IP,PostPutCount,MaxCsBytes,TotalCsBytes,TotalScBytes,2xx,3xx,4xx,5xx,TopEndpoint,TopEndpointCsBytes");
        for (int i = 0; i < top.Count; i++)
        {
            var a = top[i];
            var topEp = "";
            long topBytes = 0;
            if (perIpEndpoints.TryGetValue(a.Ip, out var m) && m.Count > 0)
            {
                var best = m.OrderByDescending(kv => kv.Value.CsBytes).First();
                topEp = best.Key;
                topBytes = best.Value.CsBytes;
            }
            sw.WriteLine(string.Join(",",
                (i + 1).ToString(CultureInfo.InvariantCulture), CsvEsc(a.Ip),
                a.PostPutCount.ToString(CultureInfo.InvariantCulture), a.MaxCsBytes.ToString(CultureInfo.InvariantCulture),
                a.TotalCsBytes.ToString(CultureInfo.InvariantCulture), a.TotalScBytes.ToString(CultureInfo.InvariantCulture),
                a.C2xx.ToString(CultureInfo.InvariantCulture), a.C3xx.ToString(CultureInfo.InvariantCulture),
                a.C4xx.ToString(CultureInfo.InvariantCulture), a.C5xx.ToString(CultureInfo.InvariantCulture),
                CsvEsc(topEp), topBytes.ToString(CultureInfo.InvariantCulture)));
        }
    }
}

internal sealed record IisBytesIntelJobSnapshot(
    string JobId,
    string State,
    string Message,
    string Mode,
    DateTime CreatedUtc,
    DateTime UpdatedUtc,
    int CurrentStep,
    int TotalSteps,
    string Phase,
    int FilesProcessed,
    int FilesTotal,
    string? ExportPath,
    IReadOnlyList<BytesIntelIpResult>? TopIps,
    string? Error)
{
    public static IisBytesIntelJobSnapshot CreateIdle()
        => new(
            JobId: string.Empty,
            State: "idle",
            Message: "No IIS bytes intel scan has been run yet.",
            Mode: string.Empty,
            CreatedUtc: DateTime.UtcNow,
            UpdatedUtc: DateTime.UtcNow,
            CurrentStep: 0,
            TotalSteps: 0,
            Phase: "idle",
            FilesProcessed: 0,
            FilesTotal: 0,
            ExportPath: null,
            TopIps: null,
            Error: null);
}

internal sealed record BytesIntelIpResult(
    int Rank,
    string Ip,
    long Hits,
    long TotalScBytes,
    long TotalCsBytes,
    long MaxScBytes,
    int C2xx, int C3xx, int C4xx, int C5xx,
    string TopUri,
    long TopUriBytes,
    IReadOnlyList<BytesIntelUriResult> TopUris);

internal sealed record BytesIntelUriResult(string Uri, long Hits, long Bytes);
