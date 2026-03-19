using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ClosedXML.Excel;
using LogHunter.Models;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static partial class AlbOptions
{
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
}
