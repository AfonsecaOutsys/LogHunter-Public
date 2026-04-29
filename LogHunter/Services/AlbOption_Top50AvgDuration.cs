using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ClosedXML.Excel;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static partial class AlbOptions
{
    internal struct UriAgg
    {
        public long Count;
        public double SumSeconds;
        public double MaxSeconds;
    }

    // ---------- OPTION 6 ----------

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

        using var cts = new CancellationTokenSource();
        var cancelled = false;
        ConsoleCancelEventHandler? cancelHandler = (_, e) =>
        {
            e.Cancel = true;
            cancelled = true;
            cts.Cancel();
        };

        Console.CancelKeyPress += cancelHandler;

        try
        {
            await RunScanWithProgressParallelAsync(
                title: "Scanning ALB logs (Ctrl+C to cancel)",
                files: files,
                createLocal: () => new Dictionary<string, UriAgg>(StringComparer.Ordinal),
                scanFileAsync: ScanFileForUriDurationAsync,
                mergeLocal: local =>
                {
                    foreach (var kvp in local)
                    {
                        if (stats.TryGetValue(kvp.Key, out var agg))
                        {
                            agg.Count += kvp.Value.Count;
                            agg.SumSeconds += kvp.Value.SumSeconds;
                            if (kvp.Value.MaxSeconds > agg.MaxSeconds) agg.MaxSeconds = kvp.Value.MaxSeconds;
                            stats[kvp.Key] = agg;
                        }
                        else
                        {
                            stats[kvp.Key] = kvp.Value;
                        }
                    }
                },
                cancellationToken: cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancelled)
        {
            // user pressed Ctrl+C; fall through to cancelled-path below
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
            var outFile = Path.Combine(outputFolder, $"ALB_Top50_Requests_AvgDuration_{stamp}.xlsx");

            using var wb = new XLWorkbook();
            var ws = wb.Worksheets.Add("Top 50 AVG Duration");
            ExcelHelper.WriteHeaderRow(ws, 1, new[] { "AvgSeconds", "Count", "MaxSeconds", "URI" });
            ws.SheetView.FreezeRows(1);

            var dataRow = 2;
            foreach (var r in results) {
                ws.Cell(dataRow, 1).Value = r.AvgSeconds;
                ws.Cell(dataRow, 2).Value = r.Count;
                ws.Cell(dataRow, 3).Value = r.MaxSeconds;
                ws.Cell(dataRow, 4).Value = r.URI;
                dataRow++;
            }

            ws.Column(1).Style.NumberFormat.Format = "0.000";
            ws.Column(3).Style.NumberFormat.Format = "0.000";

            if (dataRow > 2) {
                var xlTable = ws.Range(1, 1, dataRow - 1, 4).CreateTable("AlbTop50AvgDuration");
                xlTable.Theme = XLTableTheme.TableStyleMedium2;
                xlTable.ShowAutoFilter = true;
            }

            ExcelHelper.AutoFitColumns(ws);
            wb.SaveAs(outFile);

            ConsoleEx.Success($"Exported: {outFile}");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    private static async Task ScanFileForUriDurationAsync(
        string filePath,
        Dictionary<string, UriAgg> local,
        Action<long> reportBytesDelta,
        CancellationToken ct)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

        long lastReportedPos = 0;
        const long chunk = 64L * 1024 * 1024;
        int lineCount = 0;

        while (true)
        {
            if ((++lineCount & 0xFFFF) == 0)
                ct.ThrowIfCancellationRequested();

            var line = await sr.ReadLineAsync().ConfigureAwait(false);
            if (line is null) break;
            if (line.Length == 0) continue;

            var dur = AlbScanner.ExtractAlbTargetProcessingTimeSeconds(line);
            if (dur is null || dur.Value < 0) continue;

            var uri = AlbScanner.ExtractAlbUriNoQuery(line);
            if (string.IsNullOrEmpty(uri)) continue;

            if (!local.TryGetValue(uri, out var agg))
                agg = default;

            agg.Count++;
            agg.SumSeconds += dur.Value;
            if (dur.Value > agg.MaxSeconds) agg.MaxSeconds = dur.Value;

            local[uri] = agg;

            var pos = fs.Position;
            if (pos - lastReportedPos >= chunk)
            {
                reportBytesDelta(pos - lastReportedPos);
                lastReportedPos = pos;
            }
        }

        var remaining = fs.Length - lastReportedPos;
        if (remaining > 0)
            reportBytesDelta(remaining);
    }
}
