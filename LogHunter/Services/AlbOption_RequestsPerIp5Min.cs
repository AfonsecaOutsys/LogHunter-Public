using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ClosedXML.Excel;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static partial class AlbOptions
{
    private sealed record TopIpRow(int Rank, string IP, int Hits);
    private sealed record TopUriRow(string URI, int Hits);
    private sealed record TopUrisByIpGroup(TopIpRow Ip, List<TopUriRow> TopUris);
    private sealed record OutputFileChoice(string FullPath, string Display);
    private sealed record IpChoice(string Ip, int Hits);
    private sealed record Option7SelectionResult(List<string> Ips, string SourceLabel, Dictionary<string, int>? SourceHitsByIp = null);
    private const string SelectAllSentinel = "__ALL__";

    private static DateTime FloorTo5MinUtc(DateTime dtUtc)
    {
        dtUtc = dtUtc.Kind == DateTimeKind.Utc ? dtUtc : dtUtc.ToUniversalTime();
        int flooredMinute = (dtUtc.Minute / 5) * 5;
        return new DateTime(dtUtc.Year, dtUtc.Month, dtUtc.Day, dtUtc.Hour, flooredMinute, 0, DateTimeKind.Utc);
    }

    // ---------- OPTION 7 ----------

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

        var selection = SelectOption7Ips();
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
        var series = new List<Charts.TimeSeriesSeries>(ips.Count);

        foreach (var ip in ips)
        {
            var ys = new double[times.Length];
            var map = bucketsByIp[ip];

            for (int i = 0; i < times.Length; i++)
            {
                map.TryGetValue(times[i], out var c);
                ys[i] = c;
            }

            long? sourceHits = null;
            if (selection.SourceHitsByIp is not null && selection.SourceHitsByIp.TryGetValue(ip, out var srcHits) && srcHits > 0)
                sourceHits = srcHits;

            series.Add(new Charts.TimeSeriesSeries(
                SeriesName: ip,
                TimesUtc: times,
                Values: ys,
                SourceHits: sourceHits));
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

    private static Option7SelectionResult? SelectOption7Ips()
    {
        var modeItems = new[]
        {
            new ConsoleEx.MenuItem(
                "Select IPs from ALB Top 50 IPs export",
                "Use files named ALB_Top50_IPs_*.csv generated by ALB option 4."),
            new ConsoleEx.MenuItem(
                "Select IPs from ALB Top IP + URI exports",
                "Use ALB_Top50_IPs_NoQuery_URIs_*.csv (option 5) or ALB_TopIps_TopUris_ForFragment_*.xlsx (option 2)."),
            new ConsoleEx.MenuItem(
                "Manually enter IPs",
                "Fallback path: type IPs directly (Esc cancels)."),
            new ConsoleEx.MenuItem("Back", "Return to ALB menu.")
        };

        var mode = ConsoleEx.Menu("Option 7 source: ALB request timeline per selected IP", modeItems, pageSize: 10);
        if (mode is null || mode.Value == 3)
            return null;

        if (mode.Value == 2)
            return SelectOption7ManualIps();

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

        var sourceHitsByIp = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var ip in ips)
        {
            if (counts.TryGetValue(ip, out var hits) && hits > 0)
                sourceHitsByIp[ip] = hits;
        }

        return new Option7SelectionResult(ips, Path.GetFileName(outputFile.FullPath), sourceHitsByIp);
    }

    private static Option7SelectionResult? SelectOption7ManualIps()
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

        return new Option7SelectionResult(ips, "Manual entry", null);
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
            ConsoleEx.Info("Run ALB option 2, 4, or 5 first to generate valid source files.");
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
