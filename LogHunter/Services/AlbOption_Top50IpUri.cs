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
    // ---------- OPTION 5 ----------

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
}
