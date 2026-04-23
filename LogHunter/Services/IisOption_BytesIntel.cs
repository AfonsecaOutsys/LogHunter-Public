using ClosedXML.Excel;
using LogHunter.Utils;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Services;

/// <summary>
/// IIS bytes-based intel:
/// 1) Top bandwidth IPs / URIs (sc-bytes)
/// 2) Uploads / payload attempts (cs-bytes) for POST/PUT
///
/// PERF NOTES:
/// - Uses a 2-pass scan:
///   Pass 1: per-IP totals only (fast, low allocations)
///   Pass 2: only for Top N IPs, build per-IP top URIs/endpoints (controlled allocations)
/// - Relies on IisW3cReader fast tokenization (offset cache).
/// </summary>
public static class IisOption_BytesIntel
{
    // -------- Tunables --------
    private const int TopIps = 25;
    private const int TopUrisPerIp = 10;
    private const int TopEndpointsPerIp = 10;

    private const int PerIpUriCap = 500;        // cap unique URIs tracked per IP in pass 2
    private const int PerIpEndpointCap = 500;   // cap unique endpoints tracked per IP in pass 2
    private const int GlobalUriCap = 5000;      // cap unique URIs tracked in global table (pass 2)
    private const int GlobalEndpointCap = 5000; // cap unique endpoints tracked in global table (pass 2)

    private static readonly string[] IgnoreUaPrefixes =
    {
        "ELB-HealthChecker/",
    };

    // -------- Public entrypoints --------

    public static async Task RunTopBandwidthAsync(string root, CancellationToken ct = default)
    {
        ConsoleEx.Header("IIS: Top bandwidth IPs and URIs (sc-bytes)");

        var (_, files) = EnsureIisFiles(root);
        if (files is null) return;

        // Pass 1: per-IP totals only
        var ipAgg = new Dictionary<string, IpBandwidthAgg>(StringComparer.OrdinalIgnoreCase);
        var ipClassCache = new Dictionary<string, IpClass>(StringComparer.OrdinalIgnoreCase);

        await ScanBandwidthPass1Async(files, ipAgg, ipClassCache, ct).ConfigureAwait(false);

        if (ipAgg.Count == 0)
        {
            ConsoleEx.Info("No public-client traffic found (after filters).");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var top = ipAgg.Values
            .OrderByDescending(x => x.TotalScBytes)
            .ThenByDescending(x => x.Hits)
            .ThenBy(x => x.Ip, StringComparer.OrdinalIgnoreCase)
            .Take(TopIps)
            .ToList();

        // Pass 2: only for Top N, compute per-IP top URIs and global URI totals
        var topSet = top.Select(x => x.Ip).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var perIpUris = new Dictionary<string, Dictionary<string, UriAgg>>(StringComparer.OrdinalIgnoreCase);
        foreach (var ip in topSet)
            perIpUris[ip] = new Dictionary<string, UriAgg>(StringComparer.OrdinalIgnoreCase);

        var globalUris = new Dictionary<string, UriAgg>(StringComparer.OrdinalIgnoreCase);

        await ScanBandwidthPass2Async(files, topSet, perIpUris, globalUris, ipClassCache, ct).ConfigureAwait(false);

        // -------- Render --------
        ConsoleEx.Header("IIS: Top bandwidth IPs", $"Workspace: {root}");
        RenderBandwidthTable(top, perIpUris);

        // -------- Export Excel --------
        var outDir = Path.Combine(root, "output");
        Directory.CreateDirectory(outDir);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);

        var xlsxPath = Path.Combine(outDir, $"iis_top_bandwidth_ips_{stamp}.xlsx");
        WriteBandwidthExcel(xlsxPath, top, perIpUris, TopUrisPerIp);
        ConsoleEx.Success($"Exported: {xlsxPath}");

        // Optional global table + CSV
        var showGlobal = ConsoleEx.ReadYesNo("Show top URIs by total sc-bytes (global)?", defaultYes: false);
        if (showGlobal)
        {
            ConsoleEx.Header("IIS: Top URIs by sc-bytes (global)");

            var ordered = globalUris
                .OrderByDescending(kv => kv.Value.Bytes)
                .ThenByDescending(kv => kv.Value.Hits)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(50)
                .ToList();

            var t = new Table().RoundedBorder();
            t.AddColumn("#");
            t.AddColumn("URI");
            t.AddColumn("Hits");
            t.AddColumn("sc-bytes");

            for (int i = 0; i < ordered.Count; i++)
            {
                var (uri, a) = (ordered[i].Key, ordered[i].Value);
                t.AddRow(
                    (i + 1).ToString(CultureInfo.InvariantCulture),
                    TrimMiddle(uri, 90),
                    a.Hits.ToString("n0", CultureInfo.InvariantCulture),
                    FormatBytes(a.Bytes)
                );
            }

            AnsiConsole.Write(t);
            AnsiConsole.WriteLine();

            var globalCsv = Path.Combine(outDir, $"iis_top_bandwidth_uris_global_{stamp}.csv");
            WriteCsv(globalCsv, BuildGlobalUriCsv(ordered));
            ConsoleEx.Success($"Exported: {globalCsv}");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    public static async Task RunUploadsPayloadsAsync(string root, CancellationToken ct = default)
    {
        ConsoleEx.Header("IIS: Uploads and payload attempts (cs-bytes)");

        var (_, files) = EnsureIisFiles(root);
        if (files is null) return;

        // Pass 1: per-IP totals for POST/PUT payloads only (fast)
        var ipAgg = new Dictionary<string, UploadAgg>(StringComparer.OrdinalIgnoreCase);
        var ipClassCache = new Dictionary<string, IpClass>(StringComparer.OrdinalIgnoreCase);

        await ScanUploadsPass1Async(files, ipAgg, ipClassCache, ct).ConfigureAwait(false);

        if (ipAgg.Count == 0)
        {
            ConsoleEx.Info("No public-client POST/PUT payload traffic found (after filters).");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var top = ipAgg.Values
            .OrderByDescending(x => x.MaxCsBytes)
            .ThenByDescending(x => x.TotalCsBytes)
            .ThenByDescending(x => x.PostPutCount)
            .ThenBy(x => x.Ip, StringComparer.OrdinalIgnoreCase)
            .Take(TopIps)
            .ToList();

        // Pass 2: only for Top N, compute per-IP top endpoints and global endpoint totals
        var topSet = top.Select(x => x.Ip).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var perIpEndpoints = new Dictionary<string, Dictionary<string, EndpointAgg>>(StringComparer.OrdinalIgnoreCase);
        foreach (var ip in topSet)
            perIpEndpoints[ip] = new Dictionary<string, EndpointAgg>(StringComparer.OrdinalIgnoreCase);

        var globalEndpoints = new Dictionary<string, EndpointAgg>(StringComparer.OrdinalIgnoreCase);

        await ScanUploadsPass2Async(files, topSet, perIpEndpoints, globalEndpoints, ipClassCache, ct).ConfigureAwait(false);

        // -------- Render --------
        ConsoleEx.Header("IIS: Payload-heavy IPs (POST/PUT)", $"Workspace: {root}");
        RenderUploadsTable(top, perIpEndpoints);

        // -------- Export Excel --------
        var outDir = Path.Combine(root, "output");
        Directory.CreateDirectory(outDir);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);

        var xlsxPath = Path.Combine(outDir, $"iis_uploads_payload_ips_{stamp}.xlsx");
        WriteUploadsExcel(xlsxPath, top, perIpEndpoints, TopEndpointsPerIp);
        ConsoleEx.Success($"Exported: {xlsxPath}");

        var showGlobal = ConsoleEx.ReadYesNo("Show top endpoints by total cs-bytes (global)?", defaultYes: true);
        if (showGlobal)
        {
            ConsoleEx.Header("IIS: Top endpoints by cs-bytes (global)");

            var ordered = globalEndpoints
                .OrderByDescending(kv => kv.Value.CsBytes)
                .ThenByDescending(kv => kv.Value.MaxCsBytes)
                .ThenByDescending(kv => kv.Value.Hits)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(50)
                .ToList();

            var t = new Table().RoundedBorder();
            t.AddColumn("#");
            t.AddColumn("Endpoint");
            t.AddColumn("Hits");
            t.AddColumn("max cs-bytes");
            t.AddColumn("total cs-bytes");
            t.AddColumn("sensitive");

            for (int i = 0; i < ordered.Count; i++)
            {
                var (ep, a) = (ordered[i].Key, ordered[i].Value);

                t.AddRow(
                    (i + 1).ToString(CultureInfo.InvariantCulture),
                    TrimMiddle(ep, 90),
                    a.Hits.ToString("n0", CultureInfo.InvariantCulture),
                    FormatBytes(a.MaxCsBytes),
                    FormatBytes(a.CsBytes),
                    a.SensitiveHits.ToString("n0", CultureInfo.InvariantCulture)
                );
            }

            AnsiConsole.Write(t);
            AnsiConsole.WriteLine();

            var globalCsv = Path.Combine(outDir, $"iis_uploads_payload_endpoints_global_{stamp}.csv");
            WriteCsv(globalCsv, BuildGlobalEndpointCsv(ordered));
            ConsoleEx.Success($"Exported: {globalCsv}");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    // -------- Pass 1 scanners (fast, per-IP totals only) --------

    private static async Task ScanBandwidthPass1Async(
        List<string> files,
        Dictionary<string, IpBandwidthAgg> ipAgg,
        Dictionary<string, IpClass> ipClassCache,
        CancellationToken ct)
    {
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Pass 1/2: scanning totals (bandwidth)...", async ctx =>
            {
                for (int f = 0; f < files.Count; f++)
                {
                    ct.ThrowIfCancellationRequested();

                    var file = files[f];
                    ctx.Status($"Pass 1/2: totals... ({f + 1}/{files.Count}) {Path.GetFileName(file)}");

                    var map = await IisW3cReader.ReadFieldMapAsync(file, ct).ConfigureAwait(false);
                    if (map is null) continue;

                    if (!map.TryGetIndex("sc-bytes", out var iScBytes)) continue;

                    map.TryGetIndex("cs-bytes", out var iCsBytes);
                    map.TryGetIndex("sc-status", out var iStatus);
                    map.TryGetIndex("cs-method", out var iMethod);

                    map.TryGetIndex("OriginalIP", out var iOriginalIp);
                    map.TryGetIndex("c-ip", out var iCIp);
                    map.TryGetIndex("cs(User-Agent)", out var iUA);

                    await IisW3cReader.ForEachDataLineAsync(file, ct, (_, tokens) =>
                    {
                        if (IsIgnoredByUa(tokens, iUA)) return;

                        var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                        if (ip is null) return;

                        if (!IisClientIpResolver.IsPublicIp(ip, ipClassCache)) return;

                        long scBytes = TryParseLong(tokens.Get(iScBytes), out var scb) ? scb : 0L;
                        long csBytes = (iCsBytes >= 0 && TryParseLong(tokens.Get(iCsBytes), out var csb)) ? csb : 0L;

                        int status = (iStatus >= 0 && TryParseInt(tokens.Get(iStatus), out var st)) ? st : 0;

                        if (!ipAgg.TryGetValue(ip, out var a))
                        {
                            a = new IpBandwidthAgg(ip);
                            ipAgg[ip] = a;
                        }

                        a.Hits++;
                        a.TotalScBytes += scBytes;
                        a.TotalCsBytes += csBytes;
                        if (scBytes > a.MaxScBytes) a.MaxScBytes = scBytes;

                        if (status >= 200 && status <= 299) a.C2xx++;
                        else if (status >= 300 && status <= 399) a.C3xx++;
                        else if (status >= 400 && status <= 499) a.C4xx++;
                        else if (status >= 500 && status <= 599) a.C5xx++;

                        if (iMethod >= 0)
                        {
                            var m = tokens.Get(iMethod);
                            if (!m.IsEmpty && m[0] != '-')
                            {
                                if (m.Equals("GET", StringComparison.OrdinalIgnoreCase)) a.Get++;
                                else if (m.Equals("POST", StringComparison.OrdinalIgnoreCase)) a.Post++;
                                else if (m.Equals("HEAD", StringComparison.OrdinalIgnoreCase)) a.Head++;
                                else if (m.Equals("PUT", StringComparison.OrdinalIgnoreCase)) a.Put++;
                            }
                        }
                    }).ConfigureAwait(false);
                }
            });
    }

    private static async Task ScanUploadsPass1Async(
        List<string> files,
        Dictionary<string, UploadAgg> ipAgg,
        Dictionary<string, IpClass> ipClassCache,
        CancellationToken ct)
    {
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Pass 1/2: scanning totals (uploads)...", async ctx =>
            {
                for (int f = 0; f < files.Count; f++)
                {
                    ct.ThrowIfCancellationRequested();

                    var file = files[f];
                    ctx.Status($"Pass 1/2: totals... ({f + 1}/{files.Count}) {Path.GetFileName(file)}");

                    var map = await IisW3cReader.ReadFieldMapAsync(file, ct).ConfigureAwait(false);
                    if (map is null) continue;

                    if (!map.TryGetIndex("cs-method", out var iMethod)) continue;
                    if (!map.TryGetIndex("cs-bytes", out var iCsBytes)) continue;

                    map.TryGetIndex("sc-status", out var iStatus);
                    map.TryGetIndex("sc-bytes", out var iScBytes);

                    map.TryGetIndex("OriginalIP", out var iOriginalIp);
                    map.TryGetIndex("c-ip", out var iCIp);
                    map.TryGetIndex("cs(User-Agent)", out var iUA);

                    await IisW3cReader.ForEachDataLineAsync(file, ct, (_, tokens) =>
                    {
                        if (IsIgnoredByUa(tokens, iUA)) return;

                        var m = tokens.Get(iMethod);
                        if (m.IsEmpty || m[0] == '-') return;

                        // payload-carrying methods only
                        var isPost = m.Equals("POST", StringComparison.OrdinalIgnoreCase);
                        var isPut = m.Equals("PUT", StringComparison.OrdinalIgnoreCase);
                        if (!isPost && !isPut) return;

                        if (!TryParseLong(tokens.Get(iCsBytes), out var csBytes)) return;
                        if (csBytes <= 0) return;

                        var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                        if (ip is null) return;

                        if (!IisClientIpResolver.IsPublicIp(ip, ipClassCache)) return;

                        long scBytes = (iScBytes >= 0 && TryParseLong(tokens.Get(iScBytes), out var scb)) ? scb : 0L;
                        int status = (iStatus >= 0 && TryParseInt(tokens.Get(iStatus), out var st)) ? st : 0;

                        if (!ipAgg.TryGetValue(ip, out var a))
                        {
                            a = new UploadAgg(ip);
                            ipAgg[ip] = a;
                        }

                        a.PostPutCount++;
                        a.TotalCsBytes += csBytes;
                        if (csBytes > a.MaxCsBytes) a.MaxCsBytes = csBytes;

                        a.TotalScBytes += scBytes;

                        if (status >= 200 && status <= 299) a.C2xx++;
                        else if (status >= 300 && status <= 399) a.C3xx++;
                        else if (status >= 400 && status <= 499) a.C4xx++;
                        else if (status >= 500 && status <= 599) a.C5xx++;
                    }).ConfigureAwait(false);
                }
            });
    }

    // -------- Pass 2 scanners (only for Top N IPs, build URI/endpoint detail) --------

    private static async Task ScanBandwidthPass2Async(
        List<string> files,
        HashSet<string> topIps,
        Dictionary<string, Dictionary<string, UriAgg>> perIpUris,
        Dictionary<string, UriAgg> globalUris,
        Dictionary<string, IpClass> ipClassCache,
        CancellationToken ct)
    {
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Pass 2/2: scanning top IP URIs...", async ctx =>
            {
                for (int f = 0; f < files.Count; f++)
                {
                    ct.ThrowIfCancellationRequested();

                    var file = files[f];
                    ctx.Status($"Pass 2/2: URIs... ({f + 1}/{files.Count}) {Path.GetFileName(file)}");

                    var map = await IisW3cReader.ReadFieldMapAsync(file, ct).ConfigureAwait(false);
                    if (map is null) continue;

                    if (!map.TryGetIndex("sc-bytes", out var iScBytes)) continue;

                    map.TryGetIndex("cs-uri-stem", out var iUriStem);

                    map.TryGetIndex("OriginalIP", out var iOriginalIp);
                    map.TryGetIndex("c-ip", out var iCIp);
                    map.TryGetIndex("cs(User-Agent)", out var iUA);

                    await IisW3cReader.ForEachDataLineAsync(file, ct, (_, tokens) =>
                    {
                        if (IsIgnoredByUa(tokens, iUA)) return;

                        var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                        if (ip is null) return;

                        if (!IisClientIpResolver.IsPublicIp(ip, ipClassCache)) return;
                        if (!topIps.Contains(ip)) return;

                        long scBytes = TryParseLong(tokens.Get(iScBytes), out var scb) ? scb : 0L;

                        if (iUriStem < 0) return;

                        var u = tokens.Get(iUriStem);
                        if (u.IsEmpty || u[0] == '-') return;

                        // Create URI string only here (Pass 2, top IPs only)
                        var uri = u.ToString();

                        var ipMap = perIpUris[ip];
                        AddUriAgg(ipMap, uri, scBytes, PerIpUriCap);

                        AddUriAgg(globalUris, uri, scBytes, GlobalUriCap);
                    }).ConfigureAwait(false);
                }
            });
    }

    private static async Task ScanUploadsPass2Async(
        List<string> files,
        HashSet<string> topIps,
        Dictionary<string, Dictionary<string, EndpointAgg>> perIpEndpoints,
        Dictionary<string, EndpointAgg> globalEndpoints,
        Dictionary<string, IpClass> ipClassCache,
        CancellationToken ct)
    {
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Pass 2/2: scanning top IP endpoints...", async ctx =>
            {
                for (int f = 0; f < files.Count; f++)
                {
                    ct.ThrowIfCancellationRequested();

                    var file = files[f];
                    ctx.Status($"Pass 2/2: endpoints... ({f + 1}/{files.Count}) {Path.GetFileName(file)}");

                    var map = await IisW3cReader.ReadFieldMapAsync(file, ct).ConfigureAwait(false);
                    if (map is null) continue;

                    if (!map.TryGetIndex("cs-method", out var iMethod)) continue;
                    if (!map.TryGetIndex("cs-bytes", out var iCsBytes)) continue;

                    map.TryGetIndex("cs-uri-stem", out var iUriStem);

                    map.TryGetIndex("OriginalIP", out var iOriginalIp);
                    map.TryGetIndex("c-ip", out var iCIp);
                    map.TryGetIndex("cs(User-Agent)", out var iUA);

                    await IisW3cReader.ForEachDataLineAsync(file, ct, (_, tokens) =>
                    {
                        if (IsIgnoredByUa(tokens, iUA)) return;

                        var m = tokens.Get(iMethod);
                        if (m.IsEmpty || m[0] == '-') return;

                        var isPost = m.Equals("POST", StringComparison.OrdinalIgnoreCase);
                        var isPut = m.Equals("PUT", StringComparison.OrdinalIgnoreCase);
                        if (!isPost && !isPut) return;

                        if (!TryParseLong(tokens.Get(iCsBytes), out var csBytes)) return;
                        if (csBytes <= 0) return;

                        var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                        if (ip is null) return;

                        if (!IisClientIpResolver.IsPublicIp(ip, ipClassCache)) return;
                        if (!topIps.Contains(ip)) return;

                        if (iUriStem < 0) return;

                        var u = tokens.Get(iUriStem);
                        if (u.IsEmpty || u[0] == '-') return;

                        var endpoint = u.ToString();
                        var sensitive = LooksSensitiveOutSystems(endpoint);

                        var ipMap = perIpEndpoints[ip];
                        AddEndpointAgg(ipMap, endpoint, csBytes, sensitive, PerIpEndpointCap);

                        AddEndpointAgg(globalEndpoints, endpoint, csBytes, sensitive, GlobalEndpointCap);
                    }).ConfigureAwait(false);
                }
            });
    }

    // -------- Aggregates --------

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

        public int Get { get; set; }
        public int Post { get; set; }
        public int Head { get; set; }
        public int Put { get; set; }

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

    private struct UriAgg
    {
        public long Hits;
        public long Bytes;
    }

    private struct EndpointAgg
    {
        public long Hits;
        public long CsBytes;
        public long MaxCsBytes;
        public long SensitiveHits;
    }

    // -------- Rendering --------

    private static void RenderBandwidthTable(List<IpBandwidthAgg> top, Dictionary<string, Dictionary<string, UriAgg>> perIpUris)
    {
        var t = new Table().RoundedBorder();
        t.AddColumn("#");
        t.AddColumn("IP");
        t.AddColumn("Hits");
        t.AddColumn("sc-bytes");
        t.AddColumn("cs-bytes");
        t.AddColumn("sc/cs");
        t.AddColumn("4xx%");
        t.AddColumn("Top URI (bytes)");

        for (int i = 0; i < top.Count; i++)
        {
            var a = top[i];

            var fourxxPct = a.Hits == 0
                ? "0.0"
                : ((double)a.C4xx / a.Hits * 100.0).ToString("0.0", CultureInfo.InvariantCulture);

            string topUriCell = "-";
            if (perIpUris.TryGetValue(a.Ip, out var map) && map.Count > 0)
            {
                var best = map.OrderByDescending(kv => kv.Value.Bytes).First();
                var prefix = LooksSensitiveOutSystems(best.Key) ? "(!) " : "";
                topUriCell = prefix + TrimMiddle(best.Key, 70) + $" ({FormatBytes(best.Value.Bytes)})";
            }

            t.AddRow(
                (i + 1).ToString(CultureInfo.InvariantCulture),
                a.Ip,
                a.Hits.ToString("n0", CultureInfo.InvariantCulture),
                FormatBytes(a.TotalScBytes),
                FormatBytes(a.TotalCsBytes),
                FormatRatio(a.TotalScBytes, a.TotalCsBytes),
                fourxxPct,
                topUriCell
            );
        }

        AnsiConsole.Write(t);
        AnsiConsole.WriteLine();

        // Per IP details (with red highlighting for sensitive OutSystems surfaces)
        foreach (var a in top)
        {
            AnsiConsole.MarkupLine(
                $"[bold]{Markup.Escape(a.Ip)}[/]  [dim]sc-bytes:[/] {FormatBytes(a.TotalScBytes)}  [dim]hits:[/] {a.Hits:n0}  [dim]2xx/3xx/4xx/5xx:[/] {a.C2xx}/{a.C3xx}/{a.C4xx}/{a.C5xx}");

            if (!perIpUris.TryGetValue(a.Ip, out var map) || map.Count == 0)
            {
                AnsiConsole.MarkupLine("  [grey](no URI detail)[/]");
                AnsiConsole.WriteLine();
                continue;
            }

            var ordered = map
                .OrderByDescending(kv => kv.Value.Bytes)
                .ThenByDescending(kv => kv.Value.Hits)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(TopUrisPerIp)
                .ToList();

            foreach (var kv in ordered)
            {
                var uri = kv.Key;
                var agg = kv.Value;

                var uriMarkup = LooksSensitiveOutSystems(uri)
                    ? $"[red]{Markup.Escape(uri)}[/]"
                    : Markup.Escape(uri);

                AnsiConsole.MarkupLine($"  {uriMarkup}  [dim]{FormatBytes(agg.Bytes)}[/]  [grey]({agg.Hits:n0} hits)[/]");
            }

            AnsiConsole.WriteLine();
        }
    }

    private static void RenderUploadsTable(List<UploadAgg> top, Dictionary<string, Dictionary<string, EndpointAgg>> perIpEndpoints)
    {
        var t = new Table().RoundedBorder();
        t.AddColumn("#");
        t.AddColumn("IP");
        t.AddColumn("POST/PUT");
        t.AddColumn("max cs-bytes");
        t.AddColumn("total cs-bytes");
        t.AddColumn("total sc-bytes");
        t.AddColumn("2xx/3xx/4xx/5xx");
        t.AddColumn("Top endpoint (cs)");

        for (int i = 0; i < top.Count; i++)
        {
            var a = top[i];

            string topEpCell = "-";
            if (perIpEndpoints.TryGetValue(a.Ip, out var map) && map.Count > 0)
            {
                var best = map.OrderByDescending(kv => kv.Value.CsBytes).First();
                var prefix = LooksSensitiveOutSystems(best.Key) ? "(!) " : "";
                topEpCell = prefix + TrimMiddle(best.Key, 70) + $" ({FormatBytes(best.Value.CsBytes)})";
            }

            t.AddRow(
                (i + 1).ToString(CultureInfo.InvariantCulture),
                a.Ip,
                a.PostPutCount.ToString("n0", CultureInfo.InvariantCulture),
                FormatBytes(a.MaxCsBytes),
                FormatBytes(a.TotalCsBytes),
                FormatBytes(a.TotalScBytes),
                $"{a.C2xx}/{a.C3xx}/{a.C4xx}/{a.C5xx}",
                topEpCell
            );
        }

        AnsiConsole.Write(t);
        AnsiConsole.WriteLine();

        foreach (var a in top)
        {
            AnsiConsole.MarkupLine(
                $"[bold]{Markup.Escape(a.Ip)}[/]  [dim]POST/PUT:[/] {a.PostPutCount:n0}  [dim]max cs-bytes:[/] {FormatBytes(a.MaxCsBytes)}  [dim]total cs-bytes:[/] {FormatBytes(a.TotalCsBytes)}");

            if (!perIpEndpoints.TryGetValue(a.Ip, out var map) || map.Count == 0)
            {
                AnsiConsole.MarkupLine("  [grey](no endpoint detail)[/]");
                AnsiConsole.WriteLine();
                continue;
            }

            var ordered = map
                .OrderByDescending(kv => kv.Value.CsBytes)
                .ThenByDescending(kv => kv.Value.Hits)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(TopEndpointsPerIp)
                .ToList();

            foreach (var kv in ordered)
            {
                var ep = kv.Key;
                var agg = kv.Value;

                var epMarkup = LooksSensitiveOutSystems(ep)
                    ? $"[red]{Markup.Escape(ep)}[/]"
                    : Markup.Escape(ep);

                AnsiConsole.MarkupLine($"  {epMarkup}  [dim]{FormatBytes(agg.CsBytes)}[/]  [grey]({agg.Hits:n0} hits)[/]");
            }

            AnsiConsole.WriteLine();
        }
    }

    // -------- Excel export writers --------

    private static readonly XLColor HeaderFillColor = XLColor.FromHtml("#17324D");

    private static void StyleExcelHeaderRow(IXLRange range)
    {
        range.Style.Font.Bold = true;
        range.Style.Fill.BackgroundColor = HeaderFillColor;
        range.Style.Font.FontColor = XLColor.White;
        range.Style.Border.BottomBorder = XLBorderStyleValues.Thin;
    }

    private static void WriteBandwidthExcel(
        string path,
        List<IpBandwidthAgg> top,
        Dictionary<string, Dictionary<string, UriAgg>> perIpUris,
        int topUrisPerIp)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var wb = new XLWorkbook();

        // Sheet 1: IPs Summary
        var wsIps = wb.Worksheets.Add("IPs Summary");
        var ipHeaders = new[] { "Rank", "IP", "Hits", "TotalScBytes", "TotalCsBytes", "ScOverCs", "MaxScBytes", "2xx", "3xx", "4xx", "5xx", "TopUri", "TopUriScBytes", "TopUriHits", "TopUriSensitive" };
        for (int c = 0; c < ipHeaders.Length; c++)
            wsIps.Cell(1, c + 1).Value = ipHeaders[c];
        StyleExcelHeaderRow(wsIps.Range(1, 1, 1, ipHeaders.Length));
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
        StyleExcelHeaderRow(wsUris.Range(1, 1, 1, uriHeaders.Length));
        wsUris.SheetView.FreezeRows(1);

        int uriRow = 2;
        foreach (var a in top)
        {
            if (!perIpUris.TryGetValue(a.Ip, out var map) || map.Count == 0)
                continue;

            var ordered = map
                .OrderByDescending(kv => kv.Value.Bytes)
                .ThenByDescending(kv => kv.Value.Hits)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(topUrisPerIp)
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

    private static void WriteUploadsExcel(
        string path,
        List<UploadAgg> top,
        Dictionary<string, Dictionary<string, EndpointAgg>> perIpEndpoints,
        int topEndpointsPerIp)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var wb = new XLWorkbook();

        // Sheet 1: IPs Summary
        var wsIps = wb.Worksheets.Add("IPs Summary");
        var ipHeaders = new[] { "Rank", "IP", "PostPutCount", "MaxCsBytes", "TotalCsBytes", "TotalScBytes", "2xx", "3xx", "4xx", "5xx", "TopEndpoint", "TopEndpointCsBytes", "TopEndpointHits", "TopEndpointSensitive" };
        for (int c = 0; c < ipHeaders.Length; c++)
            wsIps.Cell(1, c + 1).Value = ipHeaders[c];
        StyleExcelHeaderRow(wsIps.Range(1, 1, 1, ipHeaders.Length));
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
        StyleExcelHeaderRow(wsEps.Range(1, 1, 1, epHeaders.Length));
        wsEps.SheetView.FreezeRows(1);

        int epRow = 2;
        foreach (var a in top)
        {
            if (!perIpEndpoints.TryGetValue(a.Ip, out var map) || map.Count == 0)
                continue;

            var ordered = map
                .OrderByDescending(kv => kv.Value.CsBytes)
                .ThenByDescending(kv => kv.Value.Hits)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(topEndpointsPerIp)
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

    private static IEnumerable<string[]> BuildGlobalUriCsv(List<KeyValuePair<string, UriAgg>> ordered)
    {
        yield return new[] { "Rank", "URI", "Hits", "TotalScBytes", "Sensitive" };

        for (int i = 0; i < ordered.Count; i++)
        {
            var uri = ordered[i].Key;
            var agg = ordered[i].Value;

            yield return new[]
            {
                (i+1).ToString(CultureInfo.InvariantCulture),
                uri,
                agg.Hits.ToString(CultureInfo.InvariantCulture),
                agg.Bytes.ToString(CultureInfo.InvariantCulture),
                LooksSensitiveOutSystems(uri) ? "true" : "false"
            };
        }
    }

    private static IEnumerable<string[]> BuildGlobalEndpointCsv(List<KeyValuePair<string, EndpointAgg>> ordered)
    {
        yield return new[] { "Rank", "Endpoint", "Hits", "MaxCsBytes", "TotalCsBytes", "SensitiveHits", "Sensitive" };

        for (int i = 0; i < ordered.Count; i++)
        {
            var ep = ordered[i].Key;
            var agg = ordered[i].Value;

            yield return new[]
            {
                (i+1).ToString(CultureInfo.InvariantCulture),
                ep,
                agg.Hits.ToString(CultureInfo.InvariantCulture),
                agg.MaxCsBytes.ToString(CultureInfo.InvariantCulture),
                agg.CsBytes.ToString(CultureInfo.InvariantCulture),
                agg.SensitiveHits.ToString(CultureInfo.InvariantCulture),
                LooksSensitiveOutSystems(ep) ? "true" : "false"
            };
        }
    }

    // -------- Dictionary update helpers (caps) --------

    private static void AddUriAgg(Dictionary<string, UriAgg> map, string uri, long scBytes, int cap)
    {
        if (map.TryGetValue(uri, out var a))
        {
            a.Hits++;
            a.Bytes += scBytes;
            map[uri] = a;
            return;
        }

        if (map.Count >= cap) return;

        map[uri] = new UriAgg { Hits = 1, Bytes = scBytes };
    }

    private static void AddEndpointAgg(Dictionary<string, EndpointAgg> map, string ep, long csBytes, bool sensitive, int cap)
    {
        if (map.TryGetValue(ep, out var a))
        {
            a.Hits++;
            a.CsBytes += csBytes;
            if (csBytes > a.MaxCsBytes) a.MaxCsBytes = csBytes;
            if (sensitive) a.SensitiveHits++;
            map[ep] = a;
            return;
        }

        if (map.Count >= cap) return;

        map[ep] = new EndpointAgg
        {
            Hits = 1,
            CsBytes = csBytes,
            MaxCsBytes = csBytes,
            SensitiveHits = sensitive ? 1 : 0
        };
    }

    // -------- Common helpers --------

    private static (string iisDir, List<string>? files) EnsureIisFiles(string root)
    {
        var iisDir = Path.Combine(root, "IIS");
        if (!Directory.Exists(iisDir))
        {
            ConsoleEx.Error($"Missing IIS folder: {iisDir}");
            ConsoleEx.Pause("Press Enter to return...");
            return (iisDir, null);
        }

        var files = IisW3cReader.EnumerateLogFiles(iisDir);
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No IIS logs found under: {iisDir}");
            ConsoleEx.Pause("Press Enter to return...");
            return (iisDir, null);
        }

        return (iisDir, files);
    }

    private static bool IsIgnoredByUa(IisW3cReader.TokenReader tokens, int iUA)
    {
        if (iUA < 0) return false;

        var ua = tokens.Get(iUA);
        if (ua.IsEmpty || ua[0] == '-') return false;

        for (int k = 0; k < IgnoreUaPrefixes.Length; k++)
        {
            if (ua.StartsWith(IgnoreUaPrefixes[k], StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static bool TryParseInt(ReadOnlySpan<char> s, out int value)
        => int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);

    private static bool TryParseLong(ReadOnlySpan<char> s, out long value)
        => long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);

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

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0) return "0 B";

        string[] suf = { "B", "KB", "MB", "GB", "TB" };
        double b = bytes;
        int i = 0;

        while (b >= 1024 && i < suf.Length - 1)
        {
            b /= 1024;
            i++;
        }

        return $"{b:0.##} {suf[i]}";
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

    private static string TrimMiddle(string s, int max)
    {
        if (string.IsNullOrEmpty(s) || s.Length <= max) return s;
        if (max <= 3) return s[..max];

        // Use ASCII "..." to avoid font/console issues.
        var cut = max - 3;
        var head = cut / 2;
        var tail = cut - head;

        return s[..head] + "..." + s[^tail..];
    }

    // -------- CSV helpers --------

    private static string CsvEsc(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        if (s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) < 0) return s;
        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }

    private static void WriteCsv(string path, IEnumerable<string[]> rows)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        using var fs = File.Create(path);
        using var sw = new StreamWriter(fs, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        foreach (var r in rows)
            sw.WriteLine(string.Join(",", r.Select(CsvEsc)));
    }
}
