using LogHunter.Utils;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Services;

public static class IisOption_FindBurstPatterns
{
    private const string SelectAllSentinel = "__ALL__";

    // how many rows to show in Spectre (fast triage)
    private const int SpectreTop = 20;

    // safety cap for HTML report (avoid absurdly huge JSON on massive log sets)
    private const int HtmlMaxRows = 5000;

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

        public BurstAgg(int uniqueCap, int uriCap)
        {
            _uniqueCap = uniqueCap;
            _uriCap = uriCap;
        }

        public void AddDynamicUri(string uriStem)
        {
            if (UniqueDynamicUris < _uniqueCap)
            {
                _uniqueDyn ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (_uniqueDyn.Add(uriStem))
                    UniqueDynamicUris++;
            }
            else
            {
                UniqueDynamicUris = _uniqueCap;
            }

            _uriCounts ??= new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (_uriCounts.Count <= _uriCap)
            {
                if (_uriCounts.TryGetValue(uriStem, out var v)) _uriCounts[uriStem] = v + 1;
                else _uriCounts[uriStem] = 1;
            }
        }

        public List<(string Uri, int Count)> TopUris(int take)
        {
            if (_uriCounts is null || _uriCounts.Count == 0) return new();
            return _uriCounts
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(take)
                .Select(kv => (kv.Key, kv.Value))
                .ToList();
        }

        public string UaDisplay => UaMixed ? "(mixed)" : (Ua ?? "-");
        public int AvgTimeMs => TotalAll == 0 ? 0 : (int)(TimeTakenTotalMs / TotalAll);
        public double FourxxRatio => TotalAll == 0 ? 0 : (double)C4xx / TotalAll;
    }

    private sealed record BurstPick(string Id, string Display);

    private sealed class BurstWindow
    {
        public required string Id { get; init; }
        public required string Ip { get; init; }
        public required DateTime StartUtc { get; init; }
        public required DateTime EndUtc { get; init; }
        public required string OutPath { get; init; }
    }

    // HTML rows for Tabulator
    private sealed record BurstUri(string Uri, int Count);

    private sealed record BurstRow(
        int Rank,
        string Id,
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
        List<BurstUri> TopUris,
        string RawLog
    );

    public static async Task RunAsync(SessionState session, CancellationToken ct = default)
    {
        var root = session.Root;

        ConsoleEx.Header("IIS: Burst patterns");

        var iisDir = Path.Combine(root, "IIS");
        if (!Directory.Exists(iisDir))
        {
            ConsoleEx.Error($"Missing IIS folder: {iisDir}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = IisW3cReader.EnumerateLogFiles(iisDir);
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No IIS logs found under: {iisDir}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        // Ensure tabulator assets under the selected workspace root.
        EmbeddedAssets.EnsureTabulatorAssets(root);

        // Tabulator assets (you placed them here)
        var assetsDir = Path.Combine(root, "ALB", "configs", "_assets");
        var tabJs = Path.Combine(assetsDir, "tabulator.min.js");
        var tabCss = Path.Combine(assetsDir, "tabulator.min.css");
        var tabulatorOk = File.Exists(tabJs) && File.Exists(tabCss);

        if (!tabulatorOk)
        {
            ConsoleEx.Warn("Tabulator assets not found. HTML report will be skipped.");
            AnsiConsole.MarkupLine($"[dim]Expected:[/]\n  {Markup.Escape(tabJs)}\n  {Markup.Escape(tabCss)}");
            AnsiConsole.WriteLine();
        }

        var bucketChoice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Bucket size for burst detection")
                .PageSize(10)
                .AddChoices(new[]
                {
                    "10 seconds (microbursts)",
                    "30 seconds",
                    "60 seconds (default)",
                    "300 seconds (5 minutes)"
                })
        );

        var bucketSeconds = bucketChoice.StartsWith("10", StringComparison.Ordinal) ? 10
                         : bucketChoice.StartsWith("30", StringComparison.Ordinal) ? 30
                         : bucketChoice.StartsWith("300", StringComparison.Ordinal) ? 300
                         : 60;

        var rateThreshold = (int)Math.Ceiling(2.0 * bucketSeconds);
        var enumThreshold = Math.Max(10, (int)Math.Ceiling(0.5 * bucketSeconds));
        var errorThreshold = Math.Max(10, (int)Math.Ceiling((25.0 / 60.0) * bucketSeconds));

        var uniqueCap = Math.Max(enumThreshold + 1, 64);
        var uriCap = 40;

        var ignoreUAPrefixes = new[] { "ELB-HealthChecker/" };

        var aggs = new Dictionary<string, BurstAgg>(StringComparer.OrdinalIgnoreCase);
        IisW3cReader.FieldMap? firstMap = null;

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Scanning IIS logs for bursts...", async ctx =>
            {
                for (int f = 0; f < files.Count; f++)
                {
                    ct.ThrowIfCancellationRequested();

                    var file = files[f];
                    ctx.Status($"Scanning... ({f + 1}/{files.Count}) {Path.GetFileName(file)}");

                    var map = await IisW3cReader.ReadFieldMapAsync(file, ct).ConfigureAwait(false);
                    if (map is null)
                        continue;

                    firstMap ??= map;

                    if (!map.TryGetIndex("date", out var iDate)) continue;
                    if (!map.TryGetIndex("time", out var iTime)) continue;
                    if (!map.TryGetIndex("sc-status", out var iStatus)) continue;

                    map.TryGetIndex("cs-method", out var iMethod);
                    map.TryGetIndex("cs-uri-stem", out var iUriStem);
                    map.TryGetIndex("time-taken", out var iTimeTaken);
                    map.TryGetIndex("OriginalIP", out var iOriginalIp);
                    map.TryGetIndex("c-ip", out var iCIp);
                    map.TryGetIndex("cs(User-Agent)", out var iUA);

                    await IisW3cReader.ForEachDataLineAsync(file, ct, (rawLine, tokens) =>
                    {
                        if (!TryParseDateTimeUtc(tokens.Get(iDate), tokens.Get(iTime), out var tsUtc))
                            return;

                        var bucketStart = FloorToBucket(tsUtc, bucketSeconds);

                        if (!TryParseInt(tokens.Get(iStatus), out var status))
                            return;

                        if (iUA >= 0)
                        {
                            var uaSpan = tokens.Get(iUA);
                            if (!uaSpan.IsEmpty && uaSpan[0] != '-')
                            {
                                var uaStr = uaSpan.ToString();
                                for (int k = 0; k < ignoreUAPrefixes.Length; k++)
                                {
                                    if (uaStr.StartsWith(ignoreUAPrefixes[k], StringComparison.OrdinalIgnoreCase))
                                        return;
                                }
                            }
                        }

                        var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                        if (ip is null) return;
                        if (IisClientIpResolver.IsPrivateOrLoopback(ip)) return;

                        var key = $"{ip}|{bucketStart.Ticks}";
                        if (!aggs.TryGetValue(key, out var agg))
                        {
                            agg = new BurstAgg(uniqueCap, uriCap)
                            {
                                Ip = ip,
                                StartUtc = bucketStart,
                                BucketSeconds = bucketSeconds
                            };
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
                                    agg.AddDynamicUri(uriStr);
                                }
                            }
                        }
                    }).ConfigureAwait(false);
                }
            });

        if (aggs.Count == 0)
        {
            ConsoleEx.Info("No traffic buckets found (after filters).");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        // Build candidates once, then:
        // - Spectre shows top 20
        // - HTML contains "all bursts" (capped)
        var burstCandidates = aggs.Values
            .Select(a => new
            {
                Agg = a,
                IsRate = a.TotalDynamic >= rateThreshold,
                IsEnum = a.UniqueDynamicUris >= enumThreshold,
                IsError = a.C4xx >= errorThreshold || (a.FourxxRatio >= 0.80 && a.TotalAll >= Math.Max(20, rateThreshold / 2)),
                SeverityScore = Score(a, rateThreshold, enumThreshold, errorThreshold)
            })
            .Where(x => x.IsRate || x.IsEnum || x.IsError)
            .OrderByDescending(x => x.SeverityScore)
            .ThenByDescending(x => x.Agg.TotalDynamic)
            .ThenByDescending(x => x.Agg.UniqueDynamicUris)
            .ThenByDescending(x => x.Agg.C4xx)
            .ThenBy(x => x.Agg.StartUtc)
            .ToList();

        if (burstCandidates.Count == 0)
        {
            ConsoleEx.Info("No bursts matched the current heuristics.");
            ConsoleEx.Info("Try a smaller bucket size or a wider time range.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var burstsForSpectre = burstCandidates.Take(SpectreTop).ToList();
        var burstsForHtml = burstCandidates.Take(HtmlMaxRows).ToList();

        ConsoleEx.Header(
            $"IIS: Burst buckets (Top {Math.Min(SpectreTop, burstsForSpectre.Count)})",
            $"Bucket: {bucketSeconds}s | Rate>={rateThreshold} dyn | Unique>={enumThreshold} | 4xx>={errorThreshold} | HTML rows: {Math.Min(HtmlMaxRows, burstCandidates.Count)}");

        var table = new Table()
            .RoundedBorder()
            .AddColumn(new TableColumn("[bold]#[/]").RightAligned())
            .AddColumn("[bold]Start (UTC)[/]")
            .AddColumn("[bold]IP[/]")
            .AddColumn(new TableColumn("[bold]Req/min[/]").RightAligned())
            .AddColumn(new TableColumn("[bold]4xx%[/]").RightAligned())
            .AddColumn("[bold]Flags[/]")
            .AddColumn(new TableColumn("[bold]Avg ms[/]").RightAligned())
            .AddColumn("[bold]UA[/]");

        for (int i = 0; i < burstsForSpectre.Count; i++)
        {
            var a = burstsForSpectre[i].Agg;
            var flags = BurstFlags(a, rateThreshold, enumThreshold, errorThreshold);

            table.AddRow(
                (i + 1).ToString(CultureInfo.InvariantCulture),
                a.StartUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                Markup.Escape(a.Ip),
                a.TotalDynamic.ToString("n0", CultureInfo.InvariantCulture),
                (a.FourxxRatio * 100).ToString("0.0", CultureInfo.InvariantCulture),
                $"[dim]{Markup.Escape(flags)}[/]",
                a.AvgTimeMs.ToString("n0", CultureInfo.InvariantCulture),
                Markup.Escape(Truncate(UaSummary(a), 40))
            );
        }

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();

        // Save distinct burst IPs to session: from ALL candidates (not only top 20)
        if (ConsoleEx.ReadYesNo("Save burst IPs (distinct) to session? This replaces the previous burst-IP list.", defaultYes: true))
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var ipHits = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var b in burstCandidates)
            {
                set.Add(b.Agg.Ip);
                ipHits[b.Agg.Ip] = ipHits.TryGetValue(b.Agg.Ip, out var existing)
                    ? existing + b.Agg.TotalDynamic
                    : b.Agg.TotalDynamic;
            }

            session.ReplaceIisBurstIps(set, ipHits);

            AnsiConsole.MarkupLine($"[green]Saved[/] {set.Count} IP(s) to session (updated {session.IisBurstIpsUpdatedUtc:yyyy-MM-dd HH:mm:ss}Z).");
            AnsiConsole.WriteLine();
        }

        // Selection (export): keep selecting from top 20 (what user just saw)
        var pick = new MultiSelectionPrompt<BurstPick>()
            .Title("Select burst bucket(s) to export raw lines")
            .NotRequired()
            .PageSize(20)
            .InstructionsText("[grey](Space: toggle, Enter: confirm)[/]")
            .UseConverter(p => p.Display);

        pick.AddChoice(new BurstPick(SelectAllSentinel, "[bold][[Select ALL]][/] Export all bursts shown (Top 20)"));

        for (int i = 0; i < burstsForSpectre.Count; i++)
        {
            var a = burstsForSpectre[i].Agg;
            var id = $"{a.Ip}|{a.StartUtc.Ticks}";
            var flags = BurstFlags(a, rateThreshold, enumThreshold, errorThreshold);

            pick.AddChoice(new BurstPick(
                id,
                $"{i + 1}. {a.StartUtc:yyyy-MM-dd HH:mm:ss}Z | {a.Ip} | dyn:{a.TotalDynamic} unique:{a.UniqueDynamicUris} 4xx:{a.C4xx} | {flags}"
            ));
        }

        var selected = AnsiConsole.Prompt(pick);
        if (selected.Count == 0)
        {
            ConsoleEx.Info("No bursts selected.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        HashSet<string> selectedIds;
        if (selected.Any(x => x.Id == SelectAllSentinel))
            selectedIds = burstsForSpectre.Select(b => $"{b.Agg.Ip}|{b.Agg.StartUtc.Ticks}").ToHashSet(StringComparer.OrdinalIgnoreCase);
        else
            selectedIds = selected.Select(x => x.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var outDir = Path.Combine(root, "output");
        Directory.CreateDirectory(outDir);

        var batchDir = Path.Combine(outDir, $"iis_bursts_{DateTime.UtcNow:yyyyMMdd_HHmmss}");
        Directory.CreateDirectory(batchDir);

        var windows = new List<BurstWindow>();
        int outRank = 1;

        foreach (var b in burstsForSpectre)
        {
            var id = $"{b.Agg.Ip}|{b.Agg.StartUtc.Ticks}";
            if (!selectedIds.Contains(id))
                continue;

            var safeIp = b.Agg.Ip.Replace(":", "_", StringComparison.Ordinal);
            var fileName = $"burst_{outRank:00}_{safeIp}_{b.Agg.StartUtc:yyyyMMdd_HHmmss}Z_{bucketSeconds}s.log";

            windows.Add(new BurstWindow
            {
                Id = id,
                Ip = b.Agg.Ip,
                StartUtc = b.Agg.StartUtc,
                EndUtc = b.Agg.StartUtc.AddSeconds(bucketSeconds),
                OutPath = Path.Combine(batchDir, fileName)
            });

            outRank++;
        }

        var writers = new Dictionary<string, StreamWriter>(StringComparer.OrdinalIgnoreCase);

        foreach (var w in windows)
        {
            var sw = new StreamWriter(File.Create(w.OutPath), Encoding.UTF8);

            if (firstMap is not null)
            {
                foreach (var h in firstMap.HeaderLines)
                    sw.WriteLine(h);
                sw.WriteLine(firstMap.FieldsLine);
            }
            else
            {
                sw.WriteLine("#Software: Microsoft Internet Information Services 10.0");
                sw.WriteLine("#Version: 1.0");
                sw.WriteLine($"#Date: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
            }

            writers[w.Id] = sw;
        }

        var windowsByIp = windows
            .GroupBy(w => w.Ip, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderBy(w => w.StartUtc).ToList(), StringComparer.OrdinalIgnoreCase);

        long exported = 0;

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Exporting selected bursts...", async ctx =>
            {
                for (int f = 0; f < files.Count; f++)
                {
                    ct.ThrowIfCancellationRequested();

                    var file = files[f];
                    ctx.Status($"Exporting... ({f + 1}/{files.Count}) {Path.GetFileName(file)}");

                    var map = await IisW3cReader.ReadFieldMapAsync(file, ct).ConfigureAwait(false);
                    if (map is null)
                        continue;

                    if (!map.TryGetIndex("date", out var iDate)) continue;
                    if (!map.TryGetIndex("time", out var iTime)) continue;

                    map.TryGetIndex("OriginalIP", out var iOriginalIp);
                    map.TryGetIndex("c-ip", out var iCIp);

                    await IisW3cReader.ForEachDataLineAsync(file, ct, (rawLine, tokens) =>
                    {
                        if (!TryParseDateTimeUtc(tokens.Get(iDate), tokens.Get(iTime), out var tsUtc))
                            return;

                        var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                        if (ip is null) return;

                        if (!windowsByIp.TryGetValue(ip, out var list))
                            return;

                        for (int i = 0; i < list.Count; i++)
                        {
                            var w = list[i];
                            if (tsUtc < w.StartUtc) continue;
                            if (tsUtc >= w.EndUtc) continue;

                            writers[w.Id].WriteLine(rawLine);
                            exported++;
                        }
                    }).ConfigureAwait(false);
                }
            });

        foreach (var sw in writers.Values)
            sw.Dispose();

        // HTML report
        string? htmlPath = null;
        if (tabulatorOk)
        {
            // Map bucket ID -> local log link (only for exported top-20 selections)
            var idToRelLog = windows.ToDictionary(
                w => w.Id,
                w => "./" + Path.GetFileName(w.OutPath),
                StringComparer.OrdinalIgnoreCase
            );

            var rows = new List<BurstRow>(burstsForHtml.Count);

            for (int i = 0; i < burstsForHtml.Count; i++)
            {
                var a = burstsForHtml[i].Agg;
                var id = $"{a.Ip}|{a.StartUtc.Ticks}";
                var score = burstsForHtml[i].SeverityScore;
                var flags = BurstFlags(a, rateThreshold, enumThreshold, errorThreshold);

                idToRelLog.TryGetValue(id, out var rawLog);

                rows.Add(new BurstRow(
                    Rank: i + 1,
                    Id: id,
                    StartUtc: a.StartUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                    Ip: a.Ip,
                    SeverityScore: score,
                    SeverityLabel: SeverityLabel(score),
                    Flags: flags,
                    TotalDynamic: a.TotalDynamic,
                    UniqueDynamicUris: a.UniqueDynamicUris,
                    FourxxPct: Math.Round(a.FourxxRatio * 100.0, 1),
                    Post: a.Post,
                    Head: a.Head,
                    AvgMs: a.AvgTimeMs,
                    MaxMs: a.TimeTakenMaxMs,
                    Ua: a.UaDisplay,
                    C2xx: a.C2xx,
                    C3xx: a.C3xx,
                    C4xx: a.C4xx,
                    C5xx: a.C5xx,
                    TopUris: a.TopUris(10).Select(x => new BurstUri(x.Uri, x.Count)).ToList(),
                    RawLog: rawLog ?? ""
                ));
            }

            htmlPath = Path.Combine(batchDir, "burst_report.html");
            WriteTabulatorReportHtml(
                outHtmlPath: htmlPath,
                batchDir: batchDir,
                tabJsPath: tabJs,
                tabCssPath: tabCss,
                bucketSeconds: bucketSeconds,
                rateThreshold: rateThreshold,
                enumThreshold: enumThreshold,
                errorThreshold: errorThreshold,
                rows: rows
            );
        }

        ConsoleEx.Header("IIS: Burst export complete");
        AnsiConsole.MarkupLine($"[dim]Bucket:[/] {bucketSeconds}s");
        AnsiConsole.MarkupLine($"[dim]Exported lines:[/] {exported:n0}");
        AnsiConsole.MarkupLine($"[dim]Output folder:[/] {Markup.Escape(batchDir)}");

        if (htmlPath is not null)
        {
            AnsiConsole.MarkupLine($"[dim]HTML report:[/] {Markup.Escape(htmlPath)}");
            if (ConsoleEx.ReadYesNo("Open HTML report now?", defaultYes: true))
                TryOpenFile(htmlPath);
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    // ---------------- HTML (Tabulator) ----------------

    private static void WriteTabulatorReportHtml(
        string outHtmlPath,
        string batchDir,
        string tabJsPath,
        string tabCssPath,
        int bucketSeconds,
        int rateThreshold,
        int enumThreshold,
        int errorThreshold,
        List<BurstRow> rows
    )
    {
        var relJs = MakeRelativePath(batchDir, tabJsPath).Replace('\\', '/');
        var relCss = MakeRelativePath(batchDir, tabCssPath).Replace('\\', '/');

        var json = JsonSerializer.Serialize(rows, new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = false
        });

        var sb = new StringBuilder(96_000);

        sb.AppendLine("<!doctype html>");
        sb.AppendLine("<html><head><meta charset=\"utf-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.AppendLine("<title>IIS Burst Report</title>");
        sb.AppendLine("<link rel=\"stylesheet\" href=\"" + HtmlEsc(relCss) + "\">");
        sb.AppendLine("<style>");
        sb.AppendLine(@"
:root{--bg:#0b0f14;--fg:#e6edf3;--muted:#9aa4b2;--card:#111827;--line:#1f2937;--chip:#0f172a}
*{box-sizing:border-box} body{margin:0;font:14px/1.35 system-ui,-apple-system,Segoe UI,Roboto,Arial;background:var(--bg);color:var(--fg)}
.wrap{max-width:1300px;margin:22px auto;padding:0 16px}
h1{font-size:18px;margin:0 0 8px}
.sub{color:var(--muted);margin-bottom:14px}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;background:var(--card);border:1px solid var(--line);padding:10px;border-radius:12px;margin-bottom:12px}
input[type=search]{flex:1;min-width:240px;background:#0b1220;color:var(--fg);border:1px solid var(--line);padding:8px 10px;border-radius:10px;outline:none}
.chk{display:flex;gap:6px;align-items:center;color:var(--muted);user-select:none}
.small{font-size:12px;color:var(--muted)}
.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-weight:700;font-size:12px}
.sev-low{background:#111827;border:1px solid #334155;color:#cbd5e1}
.sev-med{background:#3b2f0b;border:1px solid #a16207;color:#fde68a}
.sev-high{background:#3b1d0b;border:1px solid #c2410c;color:#fed7aa}
.sev-crit{background:#3b0b0b;border:1px solid #b91c1c;color:#fecaca}
.flag{display:inline-block;padding:2px 6px;border-radius:8px;background:var(--chip);border:1px solid var(--line);color:var(--muted);margin-right:6px;font-size:12px}
.btn{background:#0b1220;border:1px solid var(--line);color:var(--fg);padding:6px 8px;border-radius:10px;cursor:pointer;font-size:12px;text-decoration:none;display:inline-block}
.btn:hover{border-color:#334155}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-variant-numeric:tabular-nums}
.detail{padding:10px 12px;border-top:1px solid var(--line);background:#0b1220}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
pre{margin:0;background:#0b0f14;border:1px solid var(--line);padding:10px;border-radius:10px;overflow:auto;max-height:220px}
");
        sb.AppendLine("</style>");
        sb.AppendLine("</head><body><div class=\"wrap\">");

        sb.AppendLine("<h1>IIS Burst buckets</h1>");
        sb.AppendLine("<div class=\"sub\">Bucket: <span class=\"mono\">" + bucketSeconds.ToString(CultureInfo.InvariantCulture) +
                      "s</span> · Trigger: dyn ≥ <span class=\"mono\">" + rateThreshold.ToString(CultureInfo.InvariantCulture) +
                      "</span>, unique ≥ <span class=\"mono\">" + enumThreshold.ToString(CultureInfo.InvariantCulture) +
                      "</span>, 4xx ≥ <span class=\"mono\">" + errorThreshold.ToString(CultureInfo.InvariantCulture) + "</span></div>");

        sb.AppendLine("<div class=\"toolbar\">");
        sb.AppendLine("<input id=\"q\" type=\"search\" placeholder=\"Search IP, UA, flags, time...\">");
        sb.AppendLine("<label class=\"chk\"><input type=\"checkbox\" class=\"f\" value=\"RATE\" checked> RATE</label>");
        sb.AppendLine("<label class=\"chk\"><input type=\"checkbox\" class=\"f\" value=\"ENUM\" checked> ENUM</label>");
        sb.AppendLine("<label class=\"chk\"><input type=\"checkbox\" class=\"f\" value=\"4XX\" checked> 4XX</label>");
        sb.AppendLine("<label class=\"chk\"><input type=\"checkbox\" class=\"f\" value=\"POST\" checked> POST</label>");
        sb.AppendLine("<label class=\"chk\"><input type=\"checkbox\" class=\"f\" value=\"HEAD\" checked> HEAD</label>");
        sb.AppendLine("<span class=\"small\">(click a row for details; click headers to sort)</span>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div id=\"tbl\"></div>");

        sb.AppendLine("<script src=\"" + HtmlEsc(relJs) + "\"></script>");
        sb.AppendLine("<script>");
        sb.AppendLine("var DATA = " + json + ";");

        // Keep JS free of template literals/backticks to avoid escaping hell.
        sb.AppendLine(@"
function sevClass(score){
  if(score>=140) return 'sev-crit';
  if(score>=95)  return 'sev-high';
  if(score>=60)  return 'sev-med';
  return 'sev-low';
}

function escHtml(s){
  if(s===null || s===undefined) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/""/g,'&quot;').replace(/'/g,'&#39;');
}

function flagsHtml(flags){
  if(!flags || flags==='-') return '';
  var parts = String(flags).split('+');
  var out = '';
  for(var i=0;i<parts.length;i++){
    var f = parts[i];
    if(!f) continue;
    out += '<span class=""flag"">' + escHtml(f) + '</span> ';
  }
  return out.trim();
}

function methodsText(r){
  return 'POST ' + Number(r.Post||0).toLocaleString() + ' | HEAD ' + Number(r.Head||0).toLocaleString();
}

function hasAnyFlag(row, want){
  var flags = String(row.Flags||'').split('+').filter(Boolean);
  if(flags.length===0) return true;
  for(var i=0;i<flags.length;i++){
    if(want[flags[i]]) return true;
  }
  return false;
}

function buildDetailHtml(r){
  var top = '(none)';
  if(r.TopUris && r.TopUris.length){
    var lines = [];
    for(var i=0;i<r.TopUris.length;i++){
      var it = r.TopUris[i];
      var c = String(it.Count).padStart(6,' ');
      lines.push(c + '  ' + it.Uri);
    }
    top = lines.join('\n');
  }

  var html = '';
  html += '<div class=""detail""><div class=""grid"">';
  html += '<div>';
  html += '<div class=""small"">User-Agent</div><div class=""mono"" style=""margin-bottom:8px"">' + escHtml(r.Ua||'-') + '</div>';
  html += '<div class=""small"">Status counts</div>';
  html += '<div class=""mono"" style=""margin-bottom:8px"">2xx ' + Number(r.C2xx||0).toLocaleString() +
          ' · 3xx ' + Number(r.C3xx||0).toLocaleString() +
          ' · 4xx ' + Number(r.C4xx||0).toLocaleString() +
          ' · 5xx ' + Number(r.C5xx||0).toLocaleString() + '</div>';
  html += '<div class=""small"">Latency</div>';
  html += '<div class=""mono"">avg ' + Number(r.AvgMs||0).toLocaleString() + ' ms · max ' + Number(r.MaxMs||0).toLocaleString() + ' ms</div>';
  html += '</div>';
  html += '<div>';
  html += '<div class=""small"">Top dynamic URIs</div>';
  html += '<pre class=""mono"">' + escHtml(top) + '</pre>';
  html += '</div>';
  html += '</div></div>';
  return html;
}

var table = new Tabulator('#tbl', {
  data: DATA,
  layout: 'fitDataStretch',
  pagination: 'local',
  paginationSize: 20,
  initialSort: [{column:'SeverityScore', dir:'desc'}],
  columns: [
    {title:'#', field:'Rank', width:60, hozAlign:'right'},
    {title:'Start (UTC)', field:'StartUtc', width:170, cssClass:'mono'},
    {title:'IP', field:'Ip', width:170, cssClass:'mono'},
    {title:'Req/min', field:'TotalDynamic', sorter:'number', hozAlign:'right', cssClass:'mono'},
    {title:'4xx%', field:'FourxxPct', sorter:'number', hozAlign:'right', cssClass:'mono'},
    {title:'Methods', field:'Post', width:170, formatter:function(cell){
      var r = cell.getRow().getData();
      return '<span class=""mono"">' + escHtml(methodsText(r)) + '</span>';
    }},
    {title:'Avg ms', field:'AvgMs', sorter:'number', hozAlign:'right', cssClass:'mono'},
    {title:'Flags', field:'Flags', width:230, formatter:function(cell){ return flagsHtml(cell.getValue()); }},
    {title:'Actions', field:'Ip', width:230, formatter:function(cell){
      var r = cell.getRow().getData();
      var btn = '<button class=""btn"" data-copy=""' + escHtml(r.Ip) + '"">Copy IP</button>';
      var raw = '';
      if(r.RawLog) raw = ' <a class=""btn"" href=""' + escHtml(r.RawLog) + '"" download>Raw log</a>';
      return btn + raw;
    }, cellClick: async function(e, cell){
      var el = e.target;
      if(!el) return;
      var ip = el.getAttribute && el.getAttribute('data-copy');
      if(!ip) return;
      try{ await navigator.clipboard.writeText(ip); el.textContent='Copied'; setTimeout(function(){el.textContent='Copy IP';}, 800); }catch{}
    }}
  ],
  rowClick: function(e, row){
    var el = row.getElement();
    var next = el.nextElementSibling;
    if(next && next.classList.contains('detail-row')){
      next.remove();
      return;
    }
    var d = document.createElement('div');
    d.className = 'detail-row';
    d.innerHTML = buildDetailHtml(row.getData());
    el.parentNode.insertBefore(d, el.nextSibling);
  }
});

function getWantFlags(){
  var want = {};
  var boxes = document.querySelectorAll('.f');
  for(var i=0;i<boxes.length;i++){
    if(boxes[i].checked) want[boxes[i].value] = true;
  }
  return want;
}

function applyFilters(){
  var term = (document.getElementById('q').value || '').toLowerCase().trim();
  var want = getWantFlags();
  table.setFilter(function(data){
    if(!hasAnyFlag(data, want)) return false;
    if(!term) return true;
    // cheap global match
    return JSON.stringify(data).toLowerCase().indexOf(term) >= 0;
  });
}

document.getElementById('q').addEventListener('input', applyFilters);
var f = document.querySelectorAll('.f');
for(var i=0;i<f.length;i++){
  f[i].addEventListener('change', applyFilters);
}
applyFilters();
");
        sb.AppendLine("</script>");

        sb.AppendLine("</div></body></html>");

        File.WriteAllText(outHtmlPath, sb.ToString(), Encoding.UTF8);
    }

    private static string HtmlEsc(string s)
        => s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
            .Replace("\"", "&quot;").Replace("'", "&#39;");

    private static string MakeRelativePath(string fromDir, string toPath)
    {
        var from = new Uri(AppendSlash(Path.GetFullPath(fromDir)));
        var to = new Uri(Path.GetFullPath(toPath));
        var rel = from.MakeRelativeUri(to).ToString();
        return Uri.UnescapeDataString(rel);

        static string AppendSlash(string p) => p.EndsWith(Path.DirectorySeparatorChar) ? p : p + Path.DirectorySeparatorChar;
    }

    private static void TryOpenFile(string path)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true
            });
        }
        catch { }
    }

    // ---------------- Scoring / flags ----------------

    private static int Score(BurstAgg a, int rateTh, int enumTh, int errTh)
    {
        int score = 0;

        if (a.TotalDynamic >= rateTh) score += 50 + (a.TotalDynamic - rateTh);
        if (a.UniqueDynamicUris >= enumTh) score += 40 + (a.UniqueDynamicUris - enumTh) * 2;

        if (a.C4xx >= errTh) score += 35 + (a.C4xx - errTh) * 2;
        else if (a.FourxxRatio >= 0.80 && a.TotalAll >= Math.Max(20, rateTh / 2)) score += 30;

        if (a.Post > 0) score += Math.Min(20, a.Post);
        if (a.Head > 0) score += Math.Min(10, a.Head);

        if (a.TimeTakenMaxMs >= 5000) score += 15;
        else if (a.TimeTakenMaxMs >= 2000) score += 8;

        return score;
    }

    private static string BurstFlags(BurstAgg a, int rateTh, int enumTh, int errTh)
    {
        var flags = new List<string>();

        if (a.TotalDynamic >= rateTh) flags.Add("RATE");
        if (a.UniqueDynamicUris >= enumTh) flags.Add("ENUM");
        if (a.C4xx >= errTh || (a.FourxxRatio >= 0.80 && a.TotalAll >= Math.Max(20, rateTh / 2))) flags.Add("4XX");

        if (a.Post > 0) flags.Add("POST");
        if (a.Head > 0) flags.Add("HEAD");

        return flags.Count == 0 ? "-" : string.Join("+", flags);
    }

    private static string SeverityLabel(int score)
        => score >= 140 ? "CRIT" : score >= 95 ? "HIGH" : score >= 60 ? "MED" : "LOW";

    private static string SeverityColor(int score)
        => score >= 140 ? "red" : score >= 95 ? "darkorange" : score >= 60 ? "yellow" : "grey";

    private static string UaSummary(BurstAgg a)
    {
        if (a.UaMixed) return "mixed";
        if (string.IsNullOrWhiteSpace(a.Ua) || a.Ua == "-") return "-";

        var ua = a.Ua!;
        var first = ua.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return string.IsNullOrWhiteSpace(first) ? ua : first;
    }

    // ---------------- Parsing / IP / bucketing ----------------

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

        if (!TryParse2(date.Slice(0, 4), out var yyyy)) return false;
        if (!TryParse2(date.Slice(5, 2), out var mm)) return false;
        if (!TryParse2(date.Slice(8, 2), out var dd)) return false;

        if (!TryParse2(time.Slice(0, 2), out var hh)) return false;
        if (!TryParse2(time.Slice(3, 2), out var mi)) return false;
        if (!TryParse2(time.Slice(6, 2), out var ss)) return false;

        try
        {
            dtUtc = new DateTime(yyyy, mm, dd, hh, mi, ss, DateTimeKind.Utc);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryParse2(ReadOnlySpan<char> s, out int value)
    {
        value = 0;
        return int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
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

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s.Substring(0, Math.Max(0, max - 3)) + "...";
}
