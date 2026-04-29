using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static partial class AlbOptions
{
    // ---------- OPTION 8 ----------

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
}
