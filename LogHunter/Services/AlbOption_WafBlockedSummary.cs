using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static partial class AlbOptions
{
    // ---------- OPTION 8 ----------

    private sealed class WafBlockedLocal
    {
        public long Total;
        public long Blocked;
        public Dictionary<string, Dictionary<string, int>> Pairs = new(StringComparer.Ordinal);
    }

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

        long total = 0;
        long blocked = 0;
        var pairs = new Dictionary<string, Dictionary<string, int>>(StringComparer.Ordinal);

        await RunScanWithProgressParallelAsync(
            title: "Scanning ALB logs",
            files: files,
            createLocal: () => new WafBlockedLocal(),
            scanFileAsync: ScanFileForWafBlockedSummaryAsync,
            mergeLocal: local =>
            {
                total += local.Total;
                blocked += local.Blocked;
                foreach (var ipKvp in local.Pairs)
                {
                    if (!pairs.TryGetValue(ipKvp.Key, out var uriMap))
                    {
                        uriMap = new Dictionary<string, int>(StringComparer.Ordinal);
                        pairs[ipKvp.Key] = uriMap;
                    }
                    foreach (var uriKvp in ipKvp.Value)
                    {
                        if (uriMap.TryGetValue(uriKvp.Key, out var cur))
                            uriMap[uriKvp.Key] = cur + uriKvp.Value;
                        else
                            uriMap[uriKvp.Key] = uriKvp.Value;
                    }
                }
            }).ConfigureAwait(false);

        InfoPanel("Summary",
            ("Total entries parsed", total.ToString("N0")),
            ("Blocked entries", $"{blocked:N0} (entries without 'waf,forward')"));

        var totalPairs = pairs.Sum(p => (long)p.Value.Count);
        if (totalPairs == 0)
        {
            ConsoleEx.Warn("No blocked requests found (or blocked entries had no parseable IP/URI).");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var top = pairs
            .SelectMany(ipKvp => ipKvp.Value.Select(uriKvp => new { IP = ipKvp.Key, URI = uriKvp.Key, Hits = uriKvp.Value }))
            .OrderByDescending(x => x.Hits)
            .Take(50)
            .Select((x, idx) => new { Rank = idx + 1, x.IP, x.URI, x.Hits })
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

    private static async Task ScanFileForWafBlockedSummaryAsync(
        string filePath,
        WafBlockedLocal local,
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

            local.Total++;

            // Current definition: blocked == NOT "waf,forward"
            if (!line.Contains("waf,forward", StringComparison.OrdinalIgnoreCase))
            {
                local.Blocked++;

                var ip = AlbScanner.ExtractAlbClientIp(line);
                if (ip is not null)
                {
                    var uri = AlbScanner.ExtractAlbUriNoQuery(line) ?? "";

                    if (!local.Pairs.TryGetValue(ip, out var uriMap))
                    {
                        uriMap = new Dictionary<string, int>(StringComparer.Ordinal);
                        local.Pairs[ip] = uriMap;
                    }

                    if (uriMap.TryGetValue(uri, out var cur))
                        uriMap[uri] = cur + 1;
                    else
                        uriMap[uri] = 1;
                }
            }

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
