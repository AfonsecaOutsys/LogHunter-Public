using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ClosedXML.Excel;
using LogHunter.Models;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static class AlbOptions
{
    private static long SumFileSizesSafe(List<string> files)
    {
        long total = 0;
        foreach (var f in files)
        {
            try { total += new FileInfo(f).Length; }
            catch { /* ignore */ }
        }
        return total;
    }

    private struct UriAgg
    {
        public long Count;
        public double SumSeconds;
        public double MaxSeconds;
    }

    private sealed record TopIpRow(int Rank, string IP, int Hits);
    private sealed record TopUriRow(string URI, int Hits);
    private sealed record TopUrisByIpGroup(TopIpRow Ip, List<TopUriRow> TopUris);
    private sealed record OutputFileChoice(string FullPath, string Display);
    private sealed record IpChoice(string Ip, int Hits);
    private sealed record Option6SelectionResult(List<string> Ips, string SourceLabel);
    private const string SelectAllSentinel = "__ALL__";

    private static DateTime FloorTo5MinUtc(DateTime dtUtc)
    {
        dtUtc = dtUtc.Kind == DateTimeKind.Utc ? dtUtc : dtUtc.ToUniversalTime();
        int flooredMinute = (dtUtc.Minute / 5) * 5;
        return new DateTime(dtUtc.Year, dtUtc.Month, dtUtc.Day, dtUtc.Hour, flooredMinute, 0, DateTimeKind.Utc);
    }

    // ---------- Shared UX helpers (Spectre) ----------

    private static void InfoPanel(string title, params (string Key, string Value)[] rows)
    {
        var t = new Table().RoundedBorder().AddColumn("Field").AddColumn("Value");
        foreach (var (k, v) in rows)
            t.AddRow(Markup.Escape(k), Markup.Escape(v));

        AnsiConsole.Write(new Panel(t)
        {
            Header = new PanelHeader(Markup.Escape(title)),
            Border = BoxBorder.Rounded
        });

        AnsiConsole.WriteLine();
    }

    private static Table TopTable(params string[] columns)
    {
        var t = new Table().RoundedBorder();
        foreach (var c in columns)
            t.AddColumn(new TableColumn(Markup.Escape(c)));
        return t;
    }

    private static async Task RunScanWithProgressAsync(
        string title,
        List<string> files,
        Func<string, Action<long>, Task> scanFileAsync)
    {
        var totalBytes = SumFileSizesSafe(files);

        await AnsiConsole.Progress()
            .AutoClear(false)
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new RemainingTimeColumn(),
                new SpinnerColumn()
            })
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask(title, maxValue: Math.Max(1, totalBytes));

                foreach (var file in files)
                {
                    await scanFileAsync(file, delta =>
                    {
                        if (delta <= 0) return;
                        task.Increment(delta);
                    }).ConfigureAwait(false);
                }

                // Ensure 100% even if deltas don't perfectly match file sizes.
                if (task.Value < task.MaxValue)
                    task.Value = task.MaxValue;

                task.StopTask();
            });

        AnsiConsole.WriteLine();
    }

    // ---------- OPTION 6 ----------

    public static async Task TrackRequestsPerIpPer5MinAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Requests per IP (5-minute buckets)",
            $"Reading logs from: {albFolder}");
        ConsoleEx.Info("This option scans ALB logs and builds a per-IP request timeline in 5-minute buckets.");
        ConsoleEx.Info("Choose IPs from ALB-generated outputs (or manual fallback), then run the ALB timeline scan.");
        AnsiConsole.WriteLine();

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var selection = SelectOption6Ips();
        if (selection is null)
            return;

        var ips = selection.Ips;

        if (ips.Count == 0)
        {
            ConsoleEx.Warn("No IPs selected.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        InfoPanel("Scan plan",
            ("Mode", "Requests per IP per 5 minutes"),
            ("Selected from", selection.SourceLabel),
            ("IPs", string.Join(", ", ips)),
            ("Files", files.Count.ToString("N0")),
            ("Input", albFolder),
            ("Output", outputFolder));

        // IP -> bucket -> count
        var bucketsByIp = new Dictionary<string, SortedDictionary<DateTime, long>>(StringComparer.Ordinal);
        foreach (var ip in ips)
            bucketsByIp[ip] = new SortedDictionary<DateTime, long>();

        var totalBytes = SumFileSizesSafe(files);

        await AnsiConsole.Progress()
            .AutoClear(false)
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new RemainingTimeColumn(),
                new SpinnerColumn()
            })
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask("Scanning ALB logs", maxValue: Math.Max(1, totalBytes));

                foreach (var file in files)
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
                    using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

                    long lastReportedPos = 0;
                    const long chunk = 64L * 1024 * 1024;

                    while (true)
                    {
                        var line = await sr.ReadLineAsync().ConfigureAwait(false);
                        if (line is null) break;
                        if (line.Length == 0) continue;

                        var ip = AlbScanner.ExtractAlbClientIp(line);
                        if (ip is null) continue;

                        if (!bucketsByIp.TryGetValue(ip, out var map))
                            continue;

                        var tsUtc = AlbScanner.ExtractAlbTimestampUtc(line);
                        if (tsUtc is null) continue;

                        var bucket = FloorTo5MinUtc(tsUtc.Value);

                        if (map.TryGetValue(bucket, out var cur))
                            map[bucket] = cur + 1;
                        else
                            map[bucket] = 1;

                        var pos = fs.Position;
                        if (pos - lastReportedPos >= chunk)
                        {
                            task.Increment(pos - lastReportedPos);
                            lastReportedPos = pos;
                        }
                    }

                    var remaining = fs.Length - lastReportedPos;
                    if (remaining > 0)
                        task.Increment(remaining);
                }

                if (task.Value < task.MaxValue)
                    task.Value = task.MaxValue;

                task.StopTask();
            });

        AnsiConsole.WriteLine();

        // Build unified timeline
        var allBuckets = new SortedSet<DateTime>();
        foreach (var ip in ips)
            foreach (var b in bucketsByIp[ip].Keys)
                allBuckets.Add(b);

        if (allBuckets.Count == 0)
        {
            ConsoleEx.Warn("No matches found for those IPs.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        // Export CSV
        Directory.CreateDirectory(outputFolder);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var csvFile = Path.Combine(outputFolder, $"ALB_RequestsPer5Min_{stamp}.csv");

        using (var w = new StreamWriter(csvFile, false, Encoding.UTF8))
        {
            w.Write("BucketStartUtc");
            foreach (var ip in ips) w.Write($",{ip}");
            w.WriteLine();

            foreach (var b in allBuckets)
            {
                w.Write(b.ToString("yyyy-MM-dd HH:mm:ss 'UTC'"));
                foreach (var ip in ips)
                {
                    bucketsByIp[ip].TryGetValue(b, out var c);
                    w.Write($",{c}");
                }
                w.WriteLine();
            }
        }

        ConsoleEx.Success($"Exported CSV: {csvFile}");

        // Build series for chart (shared timeline)
        var times = allBuckets.ToArray();
        var series = new List<(string SeriesName, DateTime[] TimesUtc, double[] Values)>(ips.Count);

        foreach (var ip in ips)
        {
            var ys = new double[times.Length];
            var map = bucketsByIp[ip];

            for (int i = 0; i < times.Length; i++)
            {
                map.TryGetValue(times[i], out var c);
                ys[i] = c;
            }

            series.Add((ip, times, ys));
        }

        var html = Charts.SaveTimeSeriesHtmlAndOpen(
            outputFolder: outputFolder,
            title: "ALB Requests per IP per 5 minutes",
            yLabel: "Requests",
            series: series,
            filePrefix: "ALB_RequestsPer5Min");

        ConsoleEx.Success($"Chart (offline HTML): {html}");
        ConsoleEx.Pause("Press Enter to return...");
    }

    // ---------- OPTION 2 ----------

    public static async Task TopIpsForEndpointAsync(string root, List<SavedSelection> _savedSelections)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Top full paths by IP for endpoint/path fragment",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var endpoint = ConsoleEx.ReadLineWithEsc("Endpoint/path fragment (e.g., login or /login/):");
        if (endpoint is null)
            return;

        if (string.IsNullOrWhiteSpace(endpoint))
        {
            ConsoleEx.Warn("No endpoint provided.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        const int topIpCount = 20;
        const int topUriPerIpCount = 10;

        InfoPanel("Scan plan",
            ("Mode", "Top IPs for endpoint fragment + top full paths per IP (no query)"),
            ("Endpoint fragment", endpoint),
            ("Passes", "2"),
            ("Top IPs", topIpCount.ToString(CultureInfo.InvariantCulture)),
            ("Top URIs per IP", topUriPerIpCount.ToString(CultureInfo.InvariantCulture)),
            ("Files", files.Count.ToString("N0")),
            ("Input", albFolder));

        var endpointIpCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        await RunScanWithProgressAsync(
            title: "Scanning ALB logs (pass 1/2: top IPs for fragment)",
            files: files,
            scanFileAsync: (file, reportDelta) =>
                AlbScanner.ScanFileForEndpointIpCountsAsync(
                    filePath: file,
                    endpointFragment: endpoint,
                    ipCounts: endpointIpCounts,
                    reportBytesDelta: reportDelta)
        );

        if (endpointIpCounts.Count == 0)
        {
            ConsoleEx.Warn($"No hits found for: {endpoint}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var topIps = endpointIpCounts
            .OrderByDescending(kvp => kvp.Value)
            .ThenBy(kvp => kvp.Key, StringComparer.Ordinal)
            .Take(topIpCount)
            .Select((kvp, idx) => new TopIpRow(idx + 1, kvp.Key, kvp.Value))
            .ToList();

        var selectedIps = new HashSet<string>(topIps.Select(x => x.IP), StringComparer.Ordinal);

        // Pass 2: only for top IPs, count URI hits by IP.
        var uriCountsByIp = new Dictionary<string, Dictionary<string, int>>(StringComparer.Ordinal);

        await RunScanWithProgressAsync(
            title: "Scanning ALB logs (pass 2/2: top full paths per top IP)",
            files: files,
            scanFileAsync: (file, reportDelta) =>
                AlbScanner.ScanFileForEndpointUriCountsBySelectedIpsAsync(
                    filePath: file,
                    endpointFragment: endpoint,
                    selectedIps: selectedIps,
                    uriCountsByIp: uriCountsByIp,
                    reportBytesDelta: reportDelta)
        );

        var topIpsTable = TopTable("IP Rank", "Hits", "IP");
        foreach (var row in topIps)
            topIpsTable.AddRow(
                row.Rank.ToString(CultureInfo.InvariantCulture),
                row.Hits.ToString("N0", CultureInfo.InvariantCulture),
                Markup.Escape(row.IP));

        AnsiConsole.Write(new Panel(topIpsTable)
        {
            Header = new PanelHeader($"Top IPs matching fragment: {Markup.Escape(endpoint)} (max {topIpCount})"),
            Border = BoxBorder.Rounded
        });
        AnsiConsole.WriteLine();

        var topUrisByIp = topIps
            .Select(ipRow =>
            {
                var topUris = uriCountsByIp.TryGetValue(ipRow.IP, out var uriCounts)
                    ? uriCounts
                        .OrderByDescending(x => x.Value)
                        .ThenBy(x => x.Key, StringComparer.Ordinal)
                        .Take(topUriPerIpCount)
                        .Select(x => new TopUriRow(x.Key, x.Value))
                        .ToList()
                    : new List<TopUriRow>();

                return new TopUrisByIpGroup(ipRow, topUris);
            })
            .ToList();

        foreach (var group in topUrisByIp)
        {
            var urisTable = TopTable("URI Rank", "Hits", "URI (no query)");
            if (group.TopUris.Count == 0)
            {
                urisTable.AddRow("-", "0", "(no URI matches)");
            }
            else
            {
                for (int i = 0; i < group.TopUris.Count; i++)
                {
                    var row = group.TopUris[i];
                    urisTable.AddRow(
                        (i + 1).ToString(CultureInfo.InvariantCulture),
                        row.Hits.ToString("N0", CultureInfo.InvariantCulture),
                        Markup.Escape(row.URI));
                }
            }

            AnsiConsole.Write(new Panel(urisTable)
            {
                Header = new PanelHeader(
                    $"IP #{group.Ip.Rank}: {Markup.Escape(group.Ip.IP)} ({group.Ip.Hits:N0} hits)"),
                Border = BoxBorder.Rounded
            });
            AnsiConsole.WriteLine();
        }

        var doExport = ConsoleEx.ReadYesNo("Export these results now?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_TopIps_TopUris_ForFragment_{stamp}.xlsx");
            ExportTopIpsTopUrisGroupedXlsx(outFile, endpoint, topIps, topUrisByIp);

            ConsoleEx.Success($"Exported: {outFile}");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    private static void ExportTopIpsTopUrisGroupedXlsx(
        string outFile,
        string endpoint,
        List<TopIpRow> topIps,
        List<TopUrisByIpGroup> topUrisByIp)
    {
        using var wb = new XLWorkbook();
        var ws = wb.Worksheets.Add("Top IPs + URIs");

        int row = 1;

        ws.Cell(row, 1).Value = "ALB - Top IPs + Top Full Paths for Endpoint Fragment";
        ws.Range(row, 1, row, 6).Merge();
        ws.Cell(row, 1).Style.Font.Bold = true;
        ws.Cell(row, 1).Style.Font.FontSize = 14;
        row += 1;

        ws.Cell(row, 1).Value = "Endpoint fragment";
        ws.Cell(row, 2).Value = endpoint;
        row += 1;

        ws.Cell(row, 1).Value = "Generated";
        ws.Cell(row, 2).Value = DateTime.Now;
        ws.Cell(row, 2).Style.DateFormat.Format = "yyyy-mm-dd hh:mm:ss";
        row += 2;

        ws.Cell(row, 1).Value = "Top IP Summary";
        ws.Range(row, 1, row, 3).Merge();
        ws.Cell(row, 1).Style.Font.Bold = true;
        ws.Cell(row, 1).Style.Fill.BackgroundColor = XLColor.LightGray;
        row += 1;

        ws.Cell(row, 1).Value = "IP Rank";
        ws.Cell(row, 2).Value = "Hits";
        ws.Cell(row, 3).Value = "IP";
        ws.Range(row, 1, row, 3).Style.Font.Bold = true;
        ws.Range(row, 1, row, 3).Style.Fill.BackgroundColor = XLColor.AliceBlue;
        row += 1;

        foreach (var ip in topIps)
        {
            ws.Cell(row, 1).Value = ip.Rank;
            ws.Cell(row, 2).Value = ip.Hits;
            ws.Cell(row, 3).Value = ip.IP;
            row++;
        }

        ws.Range(row - topIps.Count, 1, row - 1, 3).Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
        ws.Range(row - topIps.Count, 1, row - 1, 3).Style.Border.InsideBorder = XLBorderStyleValues.Thin;

        row += 2;

        foreach (var group in topUrisByIp)
        {
            ws.Cell(row, 1).Value = $"IP #{group.Ip.Rank}: {group.Ip.IP} ({group.Ip.Hits:N0} hits)";
            ws.Range(row, 1, row, 6).Merge();
            ws.Cell(row, 1).Style.Font.Bold = true;
            ws.Cell(row, 1).Style.Fill.BackgroundColor = XLColor.LightGray;
            row += 1;

            ws.Cell(row, 1).Value = "URI Rank";
            ws.Cell(row, 2).Value = "Hits";
            ws.Cell(row, 3).Value = "URI (no query)";
            ws.Range(row, 1, row, 3).Style.Font.Bold = true;
            ws.Range(row, 1, row, 3).Style.Fill.BackgroundColor = XLColor.AliceBlue;
            row += 1;

            int start = row;
            if (group.TopUris.Count == 0)
            {
                ws.Cell(row, 1).Value = "-";
                ws.Cell(row, 2).Value = 0;
                ws.Cell(row, 3).Value = "(no URI matches)";
                row++;
            }
            else
            {
                for (int i = 0; i < group.TopUris.Count; i++)
                {
                    var uri = group.TopUris[i];
                    ws.Cell(row, 1).Value = i + 1;
                    ws.Cell(row, 2).Value = uri.Hits;
                    ws.Cell(row, 3).Value = uri.URI;
                    row++;
                }
            }

            ws.Range(start, 1, row - 1, 3).Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
            ws.Range(start, 1, row - 1, 3).Style.Border.InsideBorder = XLBorderStyleValues.Thin;
            row += 1;
        }

        ws.SheetView.FreezeRows(6);
        ws.Columns(1, 3).AdjustToContents(10, 110);

        wb.SaveAs(outFile);
    }

    // ---------- OPTION 3 ----------

    public static async Task Top50IpsOverallAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Top 50 IPs overall",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        InfoPanel("Scan plan",
            ("Mode", "Top 50 IPs overall"),
            ("Files", files.Count.ToString("N0")),
            ("Input", albFolder));

        var ipCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        await RunScanWithProgressAsync(
            title: "Scanning ALB logs",
            files: files,
            scanFileAsync: (file, reportDelta) =>
                AlbScanner.ScanFileForOverallIpCountsAsync(
                    filePath: file,
                    ipCounts: ipCounts,
                    reportBytesDelta: reportDelta)
        );

        if (ipCounts.Count == 0)
        {
            ConsoleEx.Warn("No IPs found.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var top = ipCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(50)
            .Select((kvp, idx) => new { Rank = idx + 1, IP = kvp.Key, Hits = kvp.Value })
            .ToList();

        var table = TopTable("Rank", "Hits", "IP");
        foreach (var row in top)
            table.AddRow(row.Rank.ToString(), row.Hits.ToString("N0"), Markup.Escape(row.IP));

        AnsiConsole.Write(new Panel(table)
        {
            Header = new PanelHeader("Top 50 IPs overall"),
            Border = BoxBorder.Rounded
        });
        AnsiConsole.WriteLine();

        var doExport = ConsoleEx.ReadYesNo("Export these results now?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_Top50_IPs_{stamp}.csv");

            using var swCsv = new StreamWriter(outFile, false, Encoding.UTF8);
            swCsv.WriteLine("Rank,IP,Hits");
            foreach (var row in top)
                swCsv.WriteLine($"{row.Rank},{row.IP},{row.Hits}");

            ConsoleEx.Success($"Exported: {outFile}");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    // ---------- OPTION 4 ----------

    public static async Task Top50IpUriNoQueryAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Top 50 IPs by URI (no query)",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        InfoPanel("Scan plan",
            ("Mode", "Top 50 IP + URI (no query)"),
            ("Files", files.Count.ToString("N0")),
            ("Input", albFolder));

        var pairCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        await RunScanWithProgressAsync(
            title: "Scanning ALB logs",
            files: files,
            scanFileAsync: (file, reportDelta) =>
                AlbScanner.ScanFileForIpUriCountsAsync(
                    filePath: file,
                    pairCounts: pairCounts,
                    reportBytesDelta: reportDelta)
        );

        if (pairCounts.Count == 0)
        {
            ConsoleEx.Warn("No results found.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var top = pairCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(50)
            .Select((kvp, idx) =>
            {
                var key = kvp.Key;
                var tab = key.IndexOf('\t');
                var ip = tab > 0 ? key[..tab] : key;
                var uri = (tab > 0 && tab + 1 < key.Length) ? key[(tab + 1)..] : "";
                return new { Rank = idx + 1, IP = ip, URI = uri, Hits = kvp.Value };
            })
            .ToList();

        var table = TopTable("Rank", "Hits", "IP", "URI");
        foreach (var row in top)
            table.AddRow(row.Rank.ToString(), row.Hits.ToString("N0"), Markup.Escape(row.IP), Markup.Escape(row.URI));

        AnsiConsole.Write(new Panel(table)
        {
            Header = new PanelHeader("Top 50 IP + URI (no query)"),
            Border = BoxBorder.Rounded
        });
        AnsiConsole.WriteLine();

        var doExport = ConsoleEx.ReadYesNo("Export these results now?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_Top50_IPs_NoQuery_URIs_{stamp}.csv");

            using var swCsv = new StreamWriter(outFile, false, Encoding.UTF8);
            swCsv.WriteLine("Rank,Hits,IP,URI");

            foreach (var row in top)
            {
                var uri = row.URI.Replace("\"", "\"\"");
                swCsv.WriteLine($"{row.Rank},{row.Hits},{row.IP},\"{uri}\"");
            }

            ConsoleEx.Success($"Exported: {outFile}");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    // ---------- OPTION 5 ----------

    public static async Task Top50RequestsByAvgDurationNoQueryAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Top 50 requests by AVG duration",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        InfoPanel("Scan plan",
            ("Mode", "Top 50 requests by AVG duration (URI without query)"),
            ("Files", files.Count.ToString("N0")),
            ("Input", albFolder));

        var stats = new Dictionary<string, UriAgg>(StringComparer.Ordinal);
        var totalBytes = SumFileSizesSafe(files);

        // ✅ Ctrl+C cancels scanning and returns (doesn't kill the app)
        var cancelled = false;
        ConsoleCancelEventHandler? cancelHandler = (_, e) =>
        {
            e.Cancel = true;
            cancelled = true;
        };

        Console.CancelKeyPress += cancelHandler;

        try
        {
            await AnsiConsole.Progress()
                .AutoClear(false)
                .Columns(new ProgressColumn[]
                {
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new RemainingTimeColumn(),
                new SpinnerColumn()
                })
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask("Scanning ALB logs (Ctrl+C to cancel)", maxValue: Math.Max(1, totalBytes));

                    foreach (var file in files)
                    {
                        if (cancelled) break;

                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
                        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

                        long lastReportedPos = 0;
                        const long chunk = 64L * 1024 * 1024;

                        while (!cancelled)
                        {
                            var line = await sr.ReadLineAsync().ConfigureAwait(false);
                            if (line is null) break;
                            if (line.Length == 0) continue;

                            var dur = AlbScanner.ExtractAlbTargetProcessingTimeSeconds(line);
                            if (dur is null || dur.Value < 0) continue;

                            var uri = AlbScanner.ExtractAlbUriNoQuery(line);
                            if (string.IsNullOrEmpty(uri)) continue;

                            if (!stats.TryGetValue(uri, out var agg))
                                agg = default;

                            agg.Count++;
                            agg.SumSeconds += dur.Value;
                            if (dur.Value > agg.MaxSeconds) agg.MaxSeconds = dur.Value;

                            stats[uri] = agg;

                            var pos = fs.Position;
                            if (pos - lastReportedPos >= chunk)
                            {
                                task.Increment(pos - lastReportedPos);
                                lastReportedPos = pos;
                            }
                        }

                        var remaining = fs.Length - lastReportedPos;
                        if (remaining > 0)
                            task.Increment(remaining);
                    }

                    if (task.Value < task.MaxValue)
                        task.Value = task.MaxValue;

                    task.StopTask();
                });

            AnsiConsole.WriteLine();
        }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
        }

        if (cancelled)
        {
            ConsoleEx.Warn("Cancelled.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        if (stats.Count == 0)
        {
            ConsoleEx.Warn("No request duration data found in parsed logs.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var results = stats
            .Select(kvp =>
            {
                var uri = kvp.Key;
                var agg = kvp.Value;
                var avg = agg.Count > 0 ? agg.SumSeconds / agg.Count : 0.0;
                return new
                {
                    AvgSeconds = avg,
                    Count = agg.Count,
                    MaxSeconds = agg.MaxSeconds,
                    URI = uri
                };
            })
            .OrderByDescending(x => x.AvgSeconds)
            .Take(50)
            .Select((x, idx) => new { Rank = idx + 1, x.AvgSeconds, x.Count, x.MaxSeconds, x.URI })
            .ToList();

        var table = TopTable("Rank", "AVG (s)", "COUNT", "MAX (s)", "URI");
        foreach (var r in results)
            table.AddRow(
                r.Rank.ToString(),
                r.AvgSeconds.ToString("0.000"),
                r.Count.ToString("N0"),
                r.MaxSeconds.ToString("0.000"),
                Markup.Escape(r.URI));

        AnsiConsole.Write(new Panel(table)
        {
            Header = new PanelHeader("Top 50 requests (URI no query) by AVG duration"),
            Border = BoxBorder.Rounded
        });
        AnsiConsole.WriteLine();

        var doExport = ConsoleEx.ReadYesNo("Export these results now?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_Top50_Requests_AvgDuration_{stamp}.csv");

            using var swCsv = new StreamWriter(outFile, false, Encoding.UTF8);
            swCsv.WriteLine("AvgSeconds,Count,MaxSeconds,URI");

            foreach (var r in results)
            {
                var uriEsc = r.URI.Replace("\"", "\"\"");
                swCsv.WriteLine($"{r.AvgSeconds:0.000},{r.Count},{r.MaxSeconds:0.000},\"{uriEsc}\"");
            }

            ConsoleEx.Success($"Exported: {outFile}");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    // ---------- OPTION 7 ----------

    public static async Task WafBlockedSummaryAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: WAF blocked summary",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        InfoPanel("Scan plan",
            ("Mode", "WAF blocked summary"),
            ("Files", files.Count.ToString("N0")),
            ("Input", albFolder));

        var totalBytes = SumFileSizesSafe(files);

        long total = 0;
        long blocked = 0;

        var blockedCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        await AnsiConsole.Progress()
            .AutoClear(false)
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new RemainingTimeColumn(),
                new SpinnerColumn()
            })
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask("Scanning ALB logs", maxValue: Math.Max(1, totalBytes));

                foreach (var file in files)
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
                    using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

                    long lastReportedPos = 0;
                    const long chunk = 64L * 1024 * 1024;

                    while (true)
                    {
                        var line = await sr.ReadLineAsync().ConfigureAwait(false);
                        if (line is null) break;
                        if (line.Length == 0) continue;

                        total++;

                        // Current definition: blocked == NOT "waf,forward"
                        if (!line.Contains("waf,forward", StringComparison.OrdinalIgnoreCase))
                        {
                            blocked++;

                            var ip = AlbScanner.ExtractAlbClientIp(line);
                            if (ip is not null)
                            {
                                var uri = AlbScanner.ExtractAlbUriNoQuery(line) ?? "";
                                var key = $"{ip}\t{uri}";

                                if (blockedCounts.TryGetValue(key, out var cur))
                                    blockedCounts[key] = cur + 1;
                                else
                                    blockedCounts[key] = 1;
                            }
                        }

                        var pos = fs.Position;
                        if (pos - lastReportedPos >= chunk)
                        {
                            task.Increment(pos - lastReportedPos);
                            lastReportedPos = pos;
                        }
                    }

                    var remaining = fs.Length - lastReportedPos;
                    if (remaining > 0)
                        task.Increment(remaining);
                }

                if (task.Value < task.MaxValue)
                    task.Value = task.MaxValue;

                task.StopTask();
            });

        AnsiConsole.WriteLine();

        InfoPanel("Summary",
            ("Total entries parsed", total.ToString("N0")),
            ("Blocked entries", $"{blocked:N0} (entries without 'waf,forward')"));

        if (blockedCounts.Count == 0)
        {
            ConsoleEx.Warn("No blocked requests found (or blocked entries had no parseable IP/URI).");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var top = blockedCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(50)
            .Select((kvp, idx) =>
            {
                var key = kvp.Key;
                var tab = key.IndexOf('\t');
                var ip = tab > 0 ? key[..tab] : key;
                var uri = (tab > 0 && tab + 1 < key.Length) ? key[(tab + 1)..] : "";
                return new { Rank = idx + 1, IP = ip, URI = uri, Hits = kvp.Value };
            })
            .ToList();

        var table = TopTable("Rank", "Hits", "IP", "URI");
        foreach (var row in top)
            table.AddRow(row.Rank.ToString(), row.Hits.ToString("N0"), Markup.Escape(row.IP), Markup.Escape(row.URI));

        AnsiConsole.Write(new Panel(table)
        {
            Header = new PanelHeader("Top 50 blocked (IP + URI)"),
            Border = BoxBorder.Rounded
        });
        AnsiConsole.WriteLine();

        var doExport = ConsoleEx.ReadYesNo("Export these results now?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_WAF_Blocked_Top50_{stamp}.csv");

            using var swCsv = new StreamWriter(outFile, false, Encoding.UTF8);
            swCsv.WriteLine("Rank,Hits,IP,URI");
            foreach (var row in top)
            {
                var uri = row.URI.Replace("\"", "\"\"");
                swCsv.WriteLine($"{row.Rank},{row.Hits},{row.IP},\"{uri}\"");
            }

            ConsoleEx.Success($"Exported: {outFile}");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    // ---------- OPTION 8 ----------

    public static async Task WafBlockedPerMinuteChartAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: WAF blocks over time (per minute)",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        // Minute bucket -> blocked count
        var buckets = new SortedDictionary<DateTime, long>();
        var totalBytes = SumFileSizesSafe(files);

        await AnsiConsole.Progress()
            .AutoClear(false)
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new RemainingTimeColumn(),
                new SpinnerColumn()
            })
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask("Scanning ALB logs", maxValue: Math.Max(1, totalBytes));

                foreach (var file in files)
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
                    using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

                    long lastReportedPos = 0;
                    const long chunk = 64L * 1024 * 1024;

                    while (true)
                    {
                        var line = await sr.ReadLineAsync().ConfigureAwait(false);
                        if (line is null) break;
                        if (line.Length == 0) continue;

                        // Same blocked definition as the summary view.
                        if (!line.Contains("waf,forward", StringComparison.OrdinalIgnoreCase))
                        {
                            var tsUtc = AlbScanner.ExtractAlbTimestampUtc(line);
                            if (tsUtc is not null)
                            {
                                var t = tsUtc.Value.Kind == DateTimeKind.Utc ? tsUtc.Value : tsUtc.Value.ToUniversalTime();
                                var minute = new DateTime(t.Year, t.Month, t.Day, t.Hour, t.Minute, 0, DateTimeKind.Utc);

                                if (buckets.TryGetValue(minute, out var cur))
                                    buckets[minute] = cur + 1;
                                else
                                    buckets[minute] = 1;
                            }
                        }

                        var pos = fs.Position;
                        if (pos - lastReportedPos >= chunk)
                        {
                            task.Increment(pos - lastReportedPos);
                            lastReportedPos = pos;
                        }
                    }

                    var remaining = fs.Length - lastReportedPos;
                    if (remaining > 0)
                        task.Increment(remaining);
                }

                if (task.Value < task.MaxValue)
                    task.Value = task.MaxValue;

                task.StopTask();
            });

        AnsiConsole.WriteLine();

        if (buckets.Count == 0)
        {
            ConsoleEx.Warn("No blocked entries found (per current definition).");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        Directory.CreateDirectory(outputFolder);

        var times = buckets.Keys.ToArray();
        var ys = new double[times.Length];
        for (int i = 0; i < times.Length; i++)
            ys[i] = buckets[times[i]];

        var series = new List<(string SeriesName, DateTime[] TimesUtc, double[] Values)>(1)
        {
            ("Blocked/min", times, ys)
        };

        var html = Charts.SaveTimeSeriesHtmlAndOpen(
            outputFolder: outputFolder,
            title: "ALB WAF blocks over time (per minute)",
            yLabel: "Blocked requests",
            series: series,
            filePrefix: "ALB_WAF_BlockedPerMin");

        ConsoleEx.Success($"Chart (offline HTML): {html}");
        ConsoleEx.Pause("Press Enter to return...");
    }

    private static Option6SelectionResult? SelectOption6Ips()
    {
        var modeItems = new[]
        {
            new ConsoleEx.MenuItem(
                "Select IPs from ALB Top 50 IPs export",
                "Use files named ALB_Top50_IPs_*.csv generated by ALB option 3."),
            new ConsoleEx.MenuItem(
                "Select IPs from ALB Top IP + URI exports",
                "Use ALB_Top50_IPs_NoQuery_URIs_*.csv (option 4) or ALB_TopIps_TopUris_ForFragment_*.xlsx (option 2)."),
            new ConsoleEx.MenuItem(
                "Manually enter IPs",
                "Fallback path: type IPs directly (Esc cancels)."),
            new ConsoleEx.MenuItem("Back", "Return to ALB menu.")
        };

        var mode = ConsoleEx.Menu("Option 6 source: ALB request timeline per selected IP", modeItems, pageSize: 10);
        if (mode is null || mode.Value == 3)
            return null;

        if (mode.Value == 2)
            return SelectOption6ManualIps();

        var allowedPrefixes = mode.Value == 0
            ? new[] { "ALB_Top50_IPs_" }
            : new[] { "ALB_Top50_IPs_NoQuery_URIs_", "ALB_TopIps_TopUris_ForFragment_" };

        var outputFile = PickAlbOutputAnalysisFile(allowedPrefixes);
        if (outputFile is null)
            return null;

        if (!TryExtractIpCountsFromFile(outputFile.FullPath, out var ipColumn, out var counts, out var orderedChoices, out var error))
        {
            ConsoleEx.Error($"Invalid ALB source file: {error}");
            ConsoleEx.Pause("Press Enter to return...");
            return null;
        }

        AnsiConsole.MarkupLine($"[dim]Source file:[/] {Markup.Escape(Path.GetFileName(outputFile.FullPath))}");
        AnsiConsole.MarkupLine($"[dim]Detected IP column:[/] [bold]{Markup.Escape(ipColumn)}[/]");
        AnsiConsole.MarkupLine($"[dim]Unique IPs found:[/] {counts.Count}");
        AnsiConsole.WriteLine();

        RenderTopIpPreview(orderedChoices, top: 20);

        var visibleChoices = orderedChoices.Take(400).ToList();
        var selectedChoices = AnsiConsole.Prompt(
            new MultiSelectionPrompt<IpChoice>()
                .Title("Select IPs for ALB request timeline (5-minute buckets):")
                .PageSize(18)
                .WrapAround()
                .NotRequired()
                .InstructionsText("[grey](Space: toggle, Enter: run, Esc: back. List is capped to top 400; Select ALL uses the full valid ALB IP set.)[/]")
                .AddChoices(new[] { new IpChoice(SelectAllSentinel, -1) }.Concat(visibleChoices))
                .UseConverter(x => x.Ip == SelectAllSentinel
                    ? $"[bold]Select ALL[/] [grey]({orderedChoices.Count} IPs)[/]"
                    : $"{x.Ip} [grey]({x.Hits})[/]"));

        var ips = selectedChoices.Any(x => x.Ip == SelectAllSentinel)
            ? orderedChoices.Select(x => x.Ip).Distinct(StringComparer.Ordinal).ToList()
            : selectedChoices.Select(x => x.Ip).Distinct(StringComparer.Ordinal).ToList();

        if (ips.Count == 0)
        {
            ConsoleEx.Warn("No IPs selected.");
            ConsoleEx.Pause("Press Enter to return...");
            return null;
        }

        return new Option6SelectionResult(ips, Path.GetFileName(outputFile.FullPath));
    }

    private static Option6SelectionResult? SelectOption6ManualIps()
    {
        var ips = new List<string>(capacity: 20);
        while (ips.Count < 20)
        {
            var input = ConsoleEx.ReadLineWithEsc($"Add IP #{ips.Count + 1} (blank to finish):");
            if (input is null)
                return null;

            if (string.IsNullOrWhiteSpace(input))
                break;

            var ip = NormalizeIp(input);
            if (ip is null)
            {
                ConsoleEx.Warn("That does not look like a valid IP. Try again.");
                continue;
            }

            if (ips.Contains(ip, StringComparer.OrdinalIgnoreCase))
            {
                ConsoleEx.Warn("Already added.");
                continue;
            }

            ips.Add(ip);
        }

        if (ips.Count == 0)
        {
            ConsoleEx.Warn("No IPs selected.");
            ConsoleEx.Pause("Press Enter to return...");
            return null;
        }

        return new Option6SelectionResult(ips, "Manual entry");
    }

    private static OutputFileChoice? PickAlbOutputAnalysisFile(IReadOnlyCollection<string> allowedPrefixes)
    {
        var outDir = AppFolders.Output;
        if (!Directory.Exists(outDir))
        {
            ConsoleEx.Warn($"Output folder not found: {outDir}");
            ConsoleEx.Pause("Press Enter to return...");
            return null;
        }

        var files = Directory.EnumerateFiles(outDir, "*", SearchOption.TopDirectoryOnly)
            .Where(p => p.EndsWith(".csv", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".xlsx", StringComparison.OrdinalIgnoreCase))
            .Select(p => new FileInfo(p))
            .Where(f => allowedPrefixes.Any(prefix => f.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .Take(200)
            .ToList();

        if (files.Count == 0)
        {
            ConsoleEx.Warn("No matching ALB output files found for this source.");
            ConsoleEx.Info("Run ALB option 2, 3, or 4 first to generate valid source files.");
            ConsoleEx.Pause("Press Enter to return...");
            return null;
        }

        var items = files
            .Select(f => new ConsoleEx.MenuItem(
                f.Name,
                $"Modified: {f.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss}Z | Size: {FormatBytes(f.Length)} | Path: {f.FullName}"))
            .ToList();
        items.Add(new ConsoleEx.MenuItem("Back", "Return without selecting a file."));

        var selected = ConsoleEx.Menu("Pick ALB output source file (Esc = back)", items, pageSize: 12);
        if (selected is null || selected.Value == items.Count - 1)
            return null;

        var file = files[selected.Value];
        return new OutputFileChoice(file.FullName, file.Name);
    }

    private static void RenderTopIpPreview(List<IpChoice> orderedChoices, int top)
    {
        var table = new Table().RoundedBorder();
        table.AddColumn("#");
        table.AddColumn("IP");
        table.AddColumn("Hits");

        var topRows = orderedChoices
            .OrderByDescending(x => x.Hits)
            .ThenBy(x => x.Ip, StringComparer.OrdinalIgnoreCase)
            .Take(top)
            .ToList();

        for (var i = 0; i < topRows.Count; i++)
        {
            var x = topRows[i];
            table.AddRow((i + 1).ToString(CultureInfo.InvariantCulture), Markup.Escape(x.Ip), x.Hits.ToString("N0", CultureInfo.InvariantCulture));
        }

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();
    }

    private static bool TryExtractIpCountsFromFile(
        string filePath,
        out string ipColumnName,
        out Dictionary<string, int> counts,
        out List<IpChoice> orderedChoices,
        out string error)
    {
        if (filePath.EndsWith(".csv", StringComparison.OrdinalIgnoreCase))
            return TryExtractIpCountsFromCsv(filePath, out ipColumnName, out counts, out orderedChoices, out error);

        if (filePath.EndsWith(".xlsx", StringComparison.OrdinalIgnoreCase))
            return TryExtractIpCountsFromXlsx(filePath, out ipColumnName, out counts, out orderedChoices, out error);

        ipColumnName = "";
        counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        orderedChoices = new List<IpChoice>();
        error = "Only CSV and XLSX are supported.";
        return false;
    }

    private static bool TryExtractIpCountsFromCsv(
        string filePath,
        out string ipColumnName,
        out Dictionary<string, int> counts,
        out List<IpChoice> orderedChoices,
        out string error)
    {
        ipColumnName = "";
        counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        orderedChoices = new List<IpChoice>();
        error = "";

        try
        {
            using var sr = new StreamReader(filePath, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            var header = sr.ReadLine();
            if (string.IsNullOrWhiteSpace(header))
            {
                error = "CSV appears empty.";
                return false;
            }

            var delim = CsvLite.DetectDelimiter(header);
            var headers = CsvLite.Split(header, delim).Select(h => h.Trim()).ToList();

            var ipCol = FindIpColumnIndex(headers);
            if (ipCol < 0)
            {
                error = "No IP-like column found in CSV header.";
                return false;
            }

            ipColumnName = headers[ipCol];
            var hitsCol = FindHitsColumnIndex(headers);

            string? line;
            while ((line = sr.ReadLine()) is not null)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                var cols = CsvLite.Split(line, delim);
                if (ipCol >= cols.Count) continue;

                var ip = NormalizeIp(cols[ipCol]);
                if (ip is null) continue;

                var hits = 1;
                if (hitsCol >= 0 && hitsCol < cols.Count)
                {
                    var text = cols[hitsCol].Trim();
                    if (int.TryParse(text.Replace(",", "", StringComparison.Ordinal), out var parsed) && parsed > 0)
                        hits = parsed;
                }

                counts[ip] = counts.TryGetValue(ip, out var cur) ? cur + hits : hits;
            }

            orderedChoices = counts
                .OrderByDescending(kvp => kvp.Value)
                .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
                .Select(kvp => new IpChoice(kvp.Key, kvp.Value))
                .ToList();

            if (orderedChoices.Count == 0)
            {
                error = $"Detected IP column '{ipColumnName}', but no valid IPs were found.";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool TryExtractIpCountsFromXlsx(
        string filePath,
        out string ipColumnName,
        out Dictionary<string, int> counts,
        out List<IpChoice> orderedChoices,
        out string error)
    {
        ipColumnName = "";
        counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        orderedChoices = new List<IpChoice>();
        error = "";

        try
        {
            using var wb = new XLWorkbook(filePath);
            var ws = wb.Worksheets.FirstOrDefault();
            if (ws is null)
            {
                error = "Workbook has no worksheets.";
                return false;
            }

            var used = ws.RangeUsed();
            if (used is null)
            {
                error = "Worksheet is empty.";
                return false;
            }

            var firstRow = used.RangeAddress.FirstAddress.RowNumber;
            var lastRow = used.RangeAddress.LastAddress.RowNumber;
            var firstCol = used.RangeAddress.FirstAddress.ColumnNumber;
            var lastCol = used.RangeAddress.LastAddress.ColumnNumber;

            var headers = new List<string>();
            for (var c = firstCol; c <= lastCol; c++)
                headers.Add(ws.Cell(firstRow, c).GetString().Trim());

            var ipIdx = FindIpColumnIndex(headers);
            if (ipIdx < 0)
            {
                error = "No IP-like column found in XLSX header.";
                return false;
            }

            ipColumnName = headers[ipIdx];
            var ipCol = firstCol + ipIdx;
            var hitsIdx = FindHitsColumnIndex(headers);
            var hitsCol = hitsIdx >= 0 ? firstCol + hitsIdx : -1;

            for (var r = firstRow + 1; r <= lastRow; r++)
            {
                var ip = NormalizeIp(ws.Cell(r, ipCol).GetString());
                if (ip is null) continue;

                var hits = 1;
                if (hitsCol > 0)
                {
                    var text = ws.Cell(r, hitsCol).GetString().Trim();
                    if (int.TryParse(text.Replace(",", "", StringComparison.Ordinal), out var parsed) && parsed > 0)
                        hits = parsed;
                }

                counts[ip] = counts.TryGetValue(ip, out var cur) ? cur + hits : hits;
            }

            orderedChoices = counts
                .OrderByDescending(kvp => kvp.Value)
                .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
                .Select(kvp => new IpChoice(kvp.Key, kvp.Value))
                .ToList();

            if (orderedChoices.Count == 0)
            {
                error = $"Detected IP column '{ipColumnName}', but no valid IPs were found.";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static int FindIpColumnIndex(IReadOnlyList<string> headers)
    {
        var preferred = new[] { "ip", "ipaddress", "ip_address", "clientip", "client_ip", "sourceip", "source_ip" };

        for (var i = 0; i < headers.Count; i++)
        {
            var h = headers[i].Trim().ToLowerInvariant();
            if (preferred.Contains(h))
                return i;
        }

        for (var i = 0; i < headers.Count; i++)
        {
            var h = headers[i].Trim().ToLowerInvariant();
            if (h.Contains("ip") && !h.Contains("zip") && !h.Contains("ship"))
                return i;
        }

        return -1;
    }

    private static int FindHitsColumnIndex(IReadOnlyList<string> headers)
    {
        var preferred = new[] { "hits", "count", "requests", "total", "occurrences" };

        for (var i = 0; i < headers.Count; i++)
        {
            var h = headers[i].Trim().ToLowerInvariant();
            if (preferred.Contains(h))
                return i;
        }

        return -1;
    }

    private static string? NormalizeIp(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var s = raw.Trim().Trim('"').Trim();
        if (s.Contains('.') && s.Count(c => c == ':') == 1)
            s = s.Split(':', 2)[0];
        if (s.StartsWith('[') && s.EndsWith(']') && s.Length > 2)
            s = s[1..^1];

        return System.Net.IPAddress.TryParse(s, out _) ? s : null;
    }

    private static string FormatBytes(long bytes)
    {
        var suf = new[] { "B", "KB", "MB", "GB", "TB" };
        double b = bytes;
        var i = 0;
        while (b >= 1024 && i < suf.Length - 1)
        {
            b /= 1024;
            i++;
        }

        return $"{b:0.##} {suf[i]}";
    }
}
