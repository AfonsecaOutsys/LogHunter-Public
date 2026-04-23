using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ClosedXML.Excel;
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
            message = "The exported Excel file is not available.";
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

            // Export Excel
            var outDir = AppFolders.Output;
            Directory.CreateDirectory(outDir);
            var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
            var xlsxPath = Path.Combine(outDir, $"iis_top_bandwidth_ips_{stamp}.xlsx");
            WriteBandwidthExcel(xlsxPath, top, perIpUris);

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
                ExportPath = xlsxPath,
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
            var xlsxPath = Path.Combine(outDir, $"iis_uploads_payload_ips_{stamp}.xlsx");
            WriteUploadsExcel(xlsxPath, top, perIpEndpoints);

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
                ExportPath = xlsxPath,
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

    // ---- Excel styling (matches project patterns) ----

    private static readonly XLColor HeaderFill = XLColor.FromHtml("#17324D");

    private static void StyleHeaderRow(IXLRange range)
    {
        range.Style.Font.Bold = true;
        range.Style.Fill.BackgroundColor = HeaderFill;
        range.Style.Font.FontColor = XLColor.White;
        range.Style.Border.BottomBorder = XLBorderStyleValues.Thin;
    }

    private static bool LooksSensitiveOutSystems(string uriStem)
    {
        if (uriStem.StartsWith("/ServiceCenter", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.StartsWith("/LifeTime", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("PlatformServices", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("/moduleservices", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("/rest/", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("/soap/", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains(".asmx", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains(".aspx", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.StartsWith("/server.", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static string FormatRatio(long scBytes, long csBytes)
    {
        if (scBytes <= 0 && csBytes <= 0) return "0";
        if (csBytes <= 0) return "inf";
        var r = (double)scBytes / csBytes;
        if (r >= 1000) return r.ToString("0", CultureInfo.InvariantCulture);
        if (r >= 100) return r.ToString("0.0", CultureInfo.InvariantCulture);
        if (r >= 10) return r.ToString("0.00", CultureInfo.InvariantCulture);
        return r.ToString("0.000", CultureInfo.InvariantCulture);
    }

    // ---- Excel export writers ----

    private static void WriteBandwidthExcel(string path, List<IpBandwidthAgg> top, Dictionary<string, Dictionary<string, UriAgg>> perIpUris)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var wb = new XLWorkbook();

        // Sheet 1: IPs Summary
        var wsIps = wb.Worksheets.Add("IPs Summary");
        var ipHeaders = new[] { "Rank", "IP", "Hits", "TotalScBytes", "TotalCsBytes", "ScOverCs", "MaxScBytes", "2xx", "3xx", "4xx", "5xx", "TopUri", "TopUriScBytes", "TopUriHits", "TopUriSensitive" };
        for (int c = 0; c < ipHeaders.Length; c++)
            wsIps.Cell(1, c + 1).Value = ipHeaders[c];
        StyleHeaderRow(wsIps.Range(1, 1, 1, ipHeaders.Length));
        wsIps.SheetView.FreezeRows(1);

        for (int i = 0; i < top.Count; i++)
        {
            var a = top[i];
            int row = i + 2;

            string topUri = "";
            long topBytes = 0;
            long topHits = 0;
            bool topSensitive = false;
            if (perIpUris.TryGetValue(a.Ip, out var m) && m.Count > 0)
            {
                var best = m.OrderByDescending(kv => kv.Value.Bytes).First();
                topUri = best.Key;
                topBytes = best.Value.Bytes;
                topHits = best.Value.Hits;
                topSensitive = LooksSensitiveOutSystems(topUri);
            }

            wsIps.Cell(row, 1).Value = i + 1;
            wsIps.Cell(row, 2).Value = a.Ip;
            wsIps.Cell(row, 3).Value = a.Hits;
            wsIps.Cell(row, 4).Value = a.TotalScBytes;
            wsIps.Cell(row, 5).Value = a.TotalCsBytes;
            wsIps.Cell(row, 6).Value = FormatRatio(a.TotalScBytes, a.TotalCsBytes);
            wsIps.Cell(row, 7).Value = a.MaxScBytes;
            wsIps.Cell(row, 8).Value = a.C2xx;
            wsIps.Cell(row, 9).Value = a.C3xx;
            wsIps.Cell(row, 10).Value = a.C4xx;
            wsIps.Cell(row, 11).Value = a.C5xx;
            wsIps.Cell(row, 12).Value = topUri;
            wsIps.Cell(row, 13).Value = topBytes;
            wsIps.Cell(row, 14).Value = topHits;
            wsIps.Cell(row, 15).Value = topSensitive ? "true" : "false";
        }

        if (top.Count > 0)
        {
            var table = wsIps.Range(1, 1, top.Count + 1, ipHeaders.Length).CreateTable("BandwidthIPs");
            table.Theme = XLTableTheme.TableStyleMedium2;
            table.ShowAutoFilter = true;
        }
        for (int c = 3; c <= 5; c++) wsIps.Column(c).Style.NumberFormat.Format = "#,##0";
        wsIps.Column(7).Style.NumberFormat.Format = "#,##0";
        for (int c = 8; c <= 11; c++) wsIps.Column(c).Style.NumberFormat.Format = "#,##0";
        wsIps.Column(13).Style.NumberFormat.Format = "#,##0";
        wsIps.Column(14).Style.NumberFormat.Format = "#,##0";
        ExcelHelper.AutoFitColumns(wsIps, 1, ipHeaders.Length);

        // Sheet 2: URIs Detail
        var wsUris = wb.Worksheets.Add("URIs Detail");
        var uriHeaders = new[] { "IP", "UriRank", "URI", "Hits", "TotalScBytes", "Sensitive" };
        for (int c = 0; c < uriHeaders.Length; c++)
            wsUris.Cell(1, c + 1).Value = uriHeaders[c];
        StyleHeaderRow(wsUris.Range(1, 1, 1, uriHeaders.Length));
        wsUris.SheetView.FreezeRows(1);

        int uriRow = 2;
        foreach (var a in top)
        {
            if (!perIpUris.TryGetValue(a.Ip, out var map) || map.Count == 0)
                continue;

            var ordered = map.OrderByDescending(kv => kv.Value.Bytes)
                .ThenByDescending(kv => kv.Value.Hits)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(TopUrisPerIp)
                .ToList();

            for (int i = 0; i < ordered.Count; i++)
            {
                var uri = ordered[i].Key;
                var agg = ordered[i].Value;
                wsUris.Cell(uriRow, 1).Value = a.Ip;
                wsUris.Cell(uriRow, 2).Value = i + 1;
                wsUris.Cell(uriRow, 3).Value = uri;
                wsUris.Cell(uriRow, 4).Value = agg.Hits;
                wsUris.Cell(uriRow, 5).Value = agg.Bytes;
                wsUris.Cell(uriRow, 6).Value = LooksSensitiveOutSystems(uri) ? "true" : "false";
                uriRow++;
            }
        }

        if (uriRow > 2)
        {
            var table = wsUris.Range(1, 1, uriRow - 1, uriHeaders.Length).CreateTable("BandwidthURIs");
            table.Theme = XLTableTheme.TableStyleMedium9;
            table.ShowAutoFilter = true;
        }
        wsUris.Column(4).Style.NumberFormat.Format = "#,##0";
        wsUris.Column(5).Style.NumberFormat.Format = "#,##0";
        ExcelHelper.AutoFitColumns(wsUris, 1, uriHeaders.Length);

        wb.SaveAs(path);
    }

    private static void WriteUploadsExcel(string path, List<UploadAgg> top, Dictionary<string, Dictionary<string, EndpointAgg>> perIpEndpoints)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var wb = new XLWorkbook();

        // Sheet 1: IPs Summary
        var wsIps = wb.Worksheets.Add("IPs Summary");
        var ipHeaders = new[] { "Rank", "IP", "PostPutCount", "MaxCsBytes", "TotalCsBytes", "TotalScBytes", "2xx", "3xx", "4xx", "5xx", "TopEndpoint", "TopEndpointCsBytes", "TopEndpointHits", "TopEndpointSensitive" };
        for (int c = 0; c < ipHeaders.Length; c++)
            wsIps.Cell(1, c + 1).Value = ipHeaders[c];
        StyleHeaderRow(wsIps.Range(1, 1, 1, ipHeaders.Length));
        wsIps.SheetView.FreezeRows(1);

        for (int i = 0; i < top.Count; i++)
        {
            var a = top[i];
            int row = i + 2;

            string topEp = "";
            long topBytes = 0;
            long topHits = 0;
            bool topSensitive = false;
            if (perIpEndpoints.TryGetValue(a.Ip, out var m) && m.Count > 0)
            {
                var best = m.OrderByDescending(kv => kv.Value.CsBytes).First();
                topEp = best.Key;
                topBytes = best.Value.CsBytes;
                topHits = best.Value.Hits;
                topSensitive = LooksSensitiveOutSystems(topEp);
            }

            wsIps.Cell(row, 1).Value = i + 1;
            wsIps.Cell(row, 2).Value = a.Ip;
            wsIps.Cell(row, 3).Value = a.PostPutCount;
            wsIps.Cell(row, 4).Value = a.MaxCsBytes;
            wsIps.Cell(row, 5).Value = a.TotalCsBytes;
            wsIps.Cell(row, 6).Value = a.TotalScBytes;
            wsIps.Cell(row, 7).Value = a.C2xx;
            wsIps.Cell(row, 8).Value = a.C3xx;
            wsIps.Cell(row, 9).Value = a.C4xx;
            wsIps.Cell(row, 10).Value = a.C5xx;
            wsIps.Cell(row, 11).Value = topEp;
            wsIps.Cell(row, 12).Value = topBytes;
            wsIps.Cell(row, 13).Value = topHits;
            wsIps.Cell(row, 14).Value = topSensitive ? "true" : "false";
        }

        if (top.Count > 0)
        {
            var table = wsIps.Range(1, 1, top.Count + 1, ipHeaders.Length).CreateTable("UploadsIPs");
            table.Theme = XLTableTheme.TableStyleMedium2;
            table.ShowAutoFilter = true;
        }
        for (int c = 3; c <= 6; c++) wsIps.Column(c).Style.NumberFormat.Format = "#,##0";
        for (int c = 7; c <= 10; c++) wsIps.Column(c).Style.NumberFormat.Format = "#,##0";
        wsIps.Column(12).Style.NumberFormat.Format = "#,##0";
        wsIps.Column(13).Style.NumberFormat.Format = "#,##0";
        ExcelHelper.AutoFitColumns(wsIps, 1, ipHeaders.Length);

        // Sheet 2: Endpoints Detail
        var wsEps = wb.Worksheets.Add("Endpoints Detail");
        var epHeaders = new[] { "IP", "EndpointRank", "Endpoint", "Hits", "TotalCsBytes", "MaxCsBytes", "Sensitive" };
        for (int c = 0; c < epHeaders.Length; c++)
            wsEps.Cell(1, c + 1).Value = epHeaders[c];
        StyleHeaderRow(wsEps.Range(1, 1, 1, epHeaders.Length));
        wsEps.SheetView.FreezeRows(1);

        int epRow = 2;
        foreach (var a in top)
        {
            if (!perIpEndpoints.TryGetValue(a.Ip, out var map) || map.Count == 0)
                continue;

            var ordered = map.OrderByDescending(kv => kv.Value.CsBytes)
                .ThenByDescending(kv => kv.Value.Hits)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(TopUrisPerIp)
                .ToList();

            for (int i = 0; i < ordered.Count; i++)
            {
                var ep = ordered[i].Key;
                var agg = ordered[i].Value;
                wsEps.Cell(epRow, 1).Value = a.Ip;
                wsEps.Cell(epRow, 2).Value = i + 1;
                wsEps.Cell(epRow, 3).Value = ep;
                wsEps.Cell(epRow, 4).Value = agg.Hits;
                wsEps.Cell(epRow, 5).Value = agg.CsBytes;
                wsEps.Cell(epRow, 6).Value = agg.MaxCsBytes;
                wsEps.Cell(epRow, 7).Value = LooksSensitiveOutSystems(ep) ? "true" : "false";
                epRow++;
            }
        }

        if (epRow > 2)
        {
            var table = wsEps.Range(1, 1, epRow - 1, epHeaders.Length).CreateTable("UploadsEndpoints");
            table.Theme = XLTableTheme.TableStyleMedium9;
            table.ShowAutoFilter = true;
        }
        wsEps.Column(4).Style.NumberFormat.Format = "#,##0";
        wsEps.Column(5).Style.NumberFormat.Format = "#,##0";
        wsEps.Column(6).Style.NumberFormat.Format = "#,##0";
        ExcelHelper.AutoFitColumns(wsEps, 1, epHeaders.Length);

        wb.SaveAs(path);
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
