using System;
using System.Collections.Generic;
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
    // ---------- OPTION 4 ----------

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
            var outFile = Path.Combine(outputFolder, $"ALB_Top50_IPs_{stamp}.xlsx");

            using var wb = new XLWorkbook();
            var ws = wb.Worksheets.Add("Top 50 IPs");
            ExcelHelper.WriteHeaderRow(ws, 1, new[] { "Rank", "IP", "Hits" });
            ws.SheetView.FreezeRows(1);

            var dataRow = 2;
            foreach (var row in top) {
                ws.Cell(dataRow, 1).Value = row.Rank;
                ws.Cell(dataRow, 2).Value = row.IP;
                ws.Cell(dataRow, 3).Value = row.Hits;
                dataRow++;
            }

            if (dataRow > 2) {
                var xlTable = ws.Range(1, 1, dataRow - 1, 3).CreateTable("AlbTop50IpsOverall");
                xlTable.Theme = XLTableTheme.TableStyleMedium2;
                xlTable.ShowAutoFilter = true;
            }

            ExcelHelper.AutoFitColumns(ws);
            wb.SaveAs(outFile);

            ConsoleEx.Success($"Exported: {outFile}");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }
}
