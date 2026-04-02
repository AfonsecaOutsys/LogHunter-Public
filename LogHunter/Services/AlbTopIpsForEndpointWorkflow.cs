using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ClosedXML.Excel;

namespace LogHunter.Services;

internal static class AlbTopIpsForEndpointWorkflow
{
    public const int DefaultTopIpCount = 20;
    public const int DefaultTopUriPerIpCount = 10;

    public static async Task ScanEndpointIpCountsAsync(
        List<string> files,
        string endpointFragment,
        Dictionary<string, int> endpointIpCounts,
        Action<long>? reportBytesDelta = null)
    {
        foreach (var file in files)
        {
            await AlbScanner.ScanFileForEndpointIpCountsAsync(
                filePath: file,
                endpointFragment: endpointFragment,
                ipCounts: endpointIpCounts,
                reportBytesDelta: reportBytesDelta ?? IgnoreProgress).ConfigureAwait(false);
        }
    }

    public static async Task ScanEndpointUriCountsBySelectedIpsAsync(
        List<string> files,
        string endpointFragment,
        HashSet<string> selectedIps,
        Dictionary<string, Dictionary<string, int>> uriCountsByIp,
        Action<long>? reportBytesDelta = null)
    {
        foreach (var file in files)
        {
            await AlbScanner.ScanFileForEndpointUriCountsBySelectedIpsAsync(
                filePath: file,
                endpointFragment: endpointFragment,
                selectedIps: selectedIps,
                uriCountsByIp: uriCountsByIp,
                reportBytesDelta: reportBytesDelta ?? IgnoreProgress).ConfigureAwait(false);
        }
    }

    public static AlbTopIpsForEndpointResult BuildResult(
        string endpointFragment,
        int filesScanned,
        Dictionary<string, int> endpointIpCounts,
        Dictionary<string, Dictionary<string, int>> uriCountsByIp,
        int topIpCount = DefaultTopIpCount,
        int topUriPerIpCount = DefaultTopUriPerIpCount)
    {
        var topIps = endpointIpCounts
            .OrderByDescending(kvp => kvp.Value)
            .ThenBy(kvp => kvp.Key, StringComparer.Ordinal)
            .Take(topIpCount)
            .Select((kvp, idx) =>
            {
                var topUris = uriCountsByIp.TryGetValue(kvp.Key, out var uriCounts)
                    ? uriCounts
                        .OrderByDescending(x => x.Value)
                        .ThenBy(x => x.Key, StringComparer.Ordinal)
                        .Take(topUriPerIpCount)
                        .Select((x, uriIdx) => new AlbTopUriResult(uriIdx + 1, x.Key, x.Value))
                        .ToList()
                    : new List<AlbTopUriResult>();

                return new AlbTopIpResult(idx + 1, kvp.Key, kvp.Value, topUris);
            })
            .ToList();

        return new AlbTopIpsForEndpointResult(
            EndpointFragment: endpointFragment,
            FilesScanned: filesScanned,
            TotalMatchingIps: endpointIpCounts.Count,
            TopIps: topIps);
    }

    public static string ExportXlsx(string outputFolder, AlbTopIpsForEndpointResult result)
    {
        Directory.CreateDirectory(outputFolder);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var outFile = Path.Combine(outputFolder, $"ALB_TopIps_TopUris_ForFragment_{stamp}.xlsx");

        using var wb = new XLWorkbook();
        var ws = wb.Worksheets.Add("Top IPs + URIs");

        int row = 1;

        // Title
        ws.Cell(row, 1).Value = "ALB - Top IPs + Top Full Paths for Endpoint Fragment";
        ws.Range(row, 1, row, 6).Merge();
        ws.Cell(row, 1).Style.Font.Bold = true;
        ws.Cell(row, 1).Style.Font.FontSize = 14;
        row += 1;

        // Metadata
        ws.Cell(row, 1).Value = "Endpoint fragment";
        ws.Cell(row, 1).Style.Font.Bold = true;
        ws.Cell(row, 2).Value = result.EndpointFragment;
        ws.Range(row, 2, row, 4).Merge();
        row += 1;

        ws.Cell(row, 1).Value = "Generated";
        ws.Cell(row, 1).Style.Font.Bold = true;
        ws.Cell(row, 2).Value = DateTime.Now;
        ws.Cell(row, 2).Style.DateFormat.Format = "yyyy-mm-dd hh:mm:ss";
        ws.Range(row, 2, row, 4).Merge();
        row += 2;

        // Top IP Summary header
        ws.Cell(row, 1).Value = "Top IP Summary";
        ws.Range(row, 1, row, 3).Merge();
        ws.Cell(row, 1).Style.Font.Bold = true;
        ws.Cell(row, 1).Style.Font.FontSize = 12;
        ws.Cell(row, 1).Style.Fill.BackgroundColor = XLColor.LightGray;
        row += 1;

        // Column headers
        ws.Cell(row, 1).Value = "IP Rank";
        ws.Cell(row, 2).Value = "Hits";
        ws.Cell(row, 3).Value = "IP";
        ws.Range(row, 1, row, 3).Style.Font.Bold = true;
        ws.Range(row, 1, row, 3).Style.Fill.BackgroundColor = XLColor.AliceBlue;
        ws.Range(row, 1, row, 2).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
        row += 1;

        // IP data rows
        foreach (var ip in result.TopIps)
        {
            ws.Cell(row, 1).Value = ip.Rank;
            ws.Cell(row, 1).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
            ws.Cell(row, 2).Value = ip.Hits;
            ws.Cell(row, 2).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Right;
            ws.Cell(row, 2).Style.NumberFormat.Format = "#,##0";
            ws.Cell(row, 3).Value = ip.IP;
            row++;
        }

        if (result.TopIps.Count > 0)
        {
            ws.Range(row - result.TopIps.Count, 1, row - 1, 3).Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
            ws.Range(row - result.TopIps.Count, 1, row - 1, 3).Style.Border.InsideBorder = XLBorderStyleValues.Thin;
        }

        row += 2;

        // Per-IP URI detail sections
        foreach (var group in result.TopIps)
        {
            ws.Cell(row, 1).Value = $"IP #{group.Rank}: {group.IP} ({group.Hits:N0} hits)";
            ws.Range(row, 1, row, 6).Merge();
            ws.Cell(row, 1).Style.Font.Bold = true;
            ws.Cell(row, 1).Style.Font.FontSize = 11;
            ws.Cell(row, 1).Style.Fill.BackgroundColor = XLColor.LightGray;
            row += 1;

            ws.Cell(row, 1).Value = "URI Rank";
            ws.Cell(row, 2).Value = "Hits";
            ws.Cell(row, 3).Value = "URI (no query)";
            ws.Range(row, 1, row, 3).Style.Font.Bold = true;
            ws.Range(row, 1, row, 3).Style.Fill.BackgroundColor = XLColor.AliceBlue;
            ws.Range(row, 1, row, 2).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
            row += 1;

            int start = row;
            if (group.TopUris.Count == 0)
            {
                ws.Cell(row, 1).Value = "-";
                ws.Cell(row, 1).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
                ws.Cell(row, 2).Value = 0;
                ws.Cell(row, 2).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Right;
                ws.Cell(row, 3).Value = "(no URI matches)";
                row++;
            }
            else
            {
                foreach (var uri in group.TopUris)
                {
                    ws.Cell(row, 1).Value = uri.Rank;
                    ws.Cell(row, 1).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
                    ws.Cell(row, 2).Value = uri.Hits;
                    ws.Cell(row, 2).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Right;
                    ws.Cell(row, 2).Style.NumberFormat.Format = "#,##0";
                    ws.Cell(row, 3).Value = uri.URI;
                    row++;
                }
            }

            ws.Range(start, 1, row - 1, 3).Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
            ws.Range(start, 1, row - 1, 3).Style.Border.InsideBorder = XLBorderStyleValues.Thin;
            row += 1;
        }

        ws.SheetView.FreezeRows(6);
        ws.Column(1).Width = 12;
        ws.Column(2).Width = 12;
        ws.Column(3).AdjustToContents(20, 80);

        wb.SaveAs(outFile);
        return outFile;
    }

    private static void IgnoreProgress(long _)
    {
    }
}

internal sealed record AlbTopIpsForEndpointResult(
    string EndpointFragment,
    int FilesScanned,
    int TotalMatchingIps,
    IReadOnlyList<AlbTopIpResult> TopIps);

internal sealed record AlbTopIpResult(
    int Rank,
    string IP,
    int Hits,
    IReadOnlyList<AlbTopUriResult> TopUris);

internal sealed record AlbTopUriResult(
    int Rank,
    string URI,
    int Hits);
