using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static partial class AlbOptions
{
    public static async Task Alb5xxWhileBackendSucceededAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: 5xx while backend succeeded", $"Reading logs from: {albFolder}");
        ConsoleEx.Info("Find requests where the customer-facing ALB response was 5xx, but the backend/target returned 2xx or 3xx.");
        AnsiConsole.WriteLine();

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
            ("Mode", "ELB 5xx while target/backend is 2xx/3xx"),
            ("Files", files.Count.ToString("N0", CultureInfo.InvariantCulture)),
            ("Input", albFolder),
            ("Output", outputFolder));

        var result = new AlbStatusMismatchScanner.ScanResult();

        await RunScanWithProgressParallelAsync(
            title: "Scanning ALB logs (5xx while backend succeeded)",
            files: files,
            createLocal: () => new AlbStatusMismatchScanner.ScanResult(),
            scanFileAsync: (file, local, reportDelta, _) =>
                AlbStatusMismatchScanner.ScanFileAsync(file, local, reportDelta),
            mergeLocal: local =>
            {
                // Merge by replaying rows in their per-file scan order.
                // ScanResult.AddRow already handles all derived state (counters,
                // FirstHit/LastHit, SourceFiles, TotalRows). Locals are merged
                // in input file order, so the master Rows list ends up identical
                // to the original sequential scan.
                foreach (var row in local.Rows)
                    result.AddRow(row, row.SourceFile);
            }
        );

        if (result.TotalRows == 0)
        {
            ConsoleEx.Warn("No matches found where ALB returned 5xx and the target/backend returned 2xx/3xx.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        RenderSummary(result);

        Directory.CreateDirectory(outputFolder);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var excelPath = Path.Combine(outputFolder, $"alb_5xx_while_backend_succeeded_{stamp}.xlsx");
        AlbStatusMismatchExportExcel.Export(excelPath, result);
        ConsoleEx.Success($"Excel export created: {excelPath}");

        ConsoleEx.Pause("Press Enter to return...");
    }

    private static void RenderSummary(AlbStatusMismatchScanner.ScanResult result)
    {
        InfoPanel("Summary",
            ("Matches", result.TotalRows.ToString("N0", CultureInfo.InvariantCulture)),
            ("Files with hits", result.SourceFiles.Count.ToString("N0", CultureInfo.InvariantCulture)),
            ("First hit UTC", result.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-"),
            ("Last hit UTC", result.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-"));

        RenderTopTable("Top status pairs", "Status pair", result.TopStatusPairs(10));
        RenderTopTable("Top URIs", "URI", result.TopUris(15));
        RenderTopTable("Top target endpoints", "Target endpoint", result.TopTargetEndpoints(15));
        RenderTopTable("Top client IPs", "Client IP", result.TopClientIps(15));
    }

    private static void RenderTopTable(string title, string valueLabel, System.Collections.Generic.IReadOnlyList<System.Collections.Generic.KeyValuePair<string, int>> rows)
    {
        var table = TopTable("Rank", "Hits", valueLabel);
        if (rows.Count == 0)
        {
            table.AddRow("-", "0", "(none)");
        }
        else
        {
            for (int i = 0; i < rows.Count; i++)
            {
                table.AddRow(
                    (i + 1).ToString(CultureInfo.InvariantCulture),
                    rows[i].Value.ToString("N0", CultureInfo.InvariantCulture),
                    Markup.Escape(rows[i].Key));
            }
        }

        AnsiConsole.Write(new Panel(table)
        {
            Header = new PanelHeader(title),
            Border = BoxBorder.Rounded
        });
        AnsiConsole.WriteLine();
    }
}
