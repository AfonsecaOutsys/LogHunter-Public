using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using ClosedXML.Excel;

namespace LogHunter.Services;

public static class AlbIpSummaryExportExcel
{
    private static readonly XLColor HeaderFill = XLColor.FromHtml("#17324D");
    private static readonly XLColor SectionFill = XLColor.FromHtml("#DCEAF7");
    private static readonly XLColor CardFill = XLColor.FromHtml("#F7FAFC");

    public static void Export(string outFile, IReadOnlyList<AlbIpSummaryScanner.ScanResult> results)
    {
        using var wb = new XLWorkbook();

        WriteOverviewSheet(wb.Worksheets.Add("Summary"), results);

        foreach (var result in results.Where(r => r.HasRetainedRows))
            WriteIpSheet(wb.Worksheets.Add(BuildSheetName(result.RequestedIp)), result);

        WriteHitsSheet(wb.Worksheets.Add("Hits"), results);
        wb.SaveAs(outFile);
    }

    private static void WriteOverviewSheet(IXLWorksheet ws, IReadOnlyList<AlbIpSummaryScanner.ScanResult> results)
    {
        ws.Cell(1, 1).Value = "ALB Multi-IP Summary";
        ws.Cell(1, 1).Style.Font.Bold = true;
        ws.Cell(1, 1).Style.Font.FontSize = 14;
        ws.Cell(1, 1).Style.Fill.BackgroundColor = HeaderFill;
        ws.Cell(1, 1).Style.Font.FontColor = XLColor.White;
        ws.Range(1, 1, 1, 8).Merge();

        var headers = new[]
        {
            "IP", "TotalRequests", "FilesWithHits", "FirstHitUtc", "LastHitUtc", "ELB 2xx/3xx", "ELB 4xx/5xx", "FE 4xx/5xx"
        };

        for (int i = 0; i < headers.Length; i++)
            ws.Cell(3, i + 1).Value = headers[i];

        var headerRange = ws.Range(3, 1, 3, headers.Length);
        headerRange.Style.Font.Bold = true;
        headerRange.Style.Fill.BackgroundColor = HeaderFill;
        headerRange.Style.Font.FontColor = XLColor.White;
        ws.SheetView.FreezeRows(3);

        var row = 4;
        foreach (var result in results.OrderByDescending(r => r.TotalRows).ThenBy(r => r.RequestedIp, StringComparer.OrdinalIgnoreCase))
        {
            ws.Cell(row, 1).Value = result.RequestedIp;
            ws.Cell(row, 2).Value = result.TotalRows;
            ws.Cell(row, 3).Value = result.SourceFiles.Count;
            ws.Cell(row, 4).Value = result.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-";
            ws.Cell(row, 5).Value = result.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-";
            ws.Cell(row, 6).Value = result.ElbResponseTotals.S2xx + result.ElbResponseTotals.S3xx;
            ws.Cell(row, 7).Value = result.ElbResponseTotals.S4xx + result.ElbResponseTotals.S5xx;
            ws.Cell(row, 8).Value = result.FeResponseTotals.S4xx + result.FeResponseTotals.S5xx;
            row++;
        }

        if (row > 4)
        {
            var table = ws.Range(3, 1, row - 1, headers.Length).CreateTable("AlbIpSummaryOverview");
            table.Theme = XLTableTheme.TableStyleMedium2;
            table.ShowAutoFilter = true;
        }

        ws.Columns().AdjustToContents();
    }

    private static void WriteIpSheet(IXLWorksheet ws, AlbIpSummaryScanner.ScanResult result)
    {
        int row = 1;

        ws.Cell(row, 1).Value = $"ALB IP Summary - {result.RequestedIp}";
        ws.Cell(row, 1).Style.Font.Bold = true;
        ws.Cell(row, 1).Style.Font.FontSize = 14;
        ws.Cell(row, 1).Style.Fill.BackgroundColor = HeaderFill;
        ws.Cell(row, 1).Style.Font.FontColor = XLColor.White;
        ws.Range(row, 1, row, 4).Merge();
        row += 2;

        var summaryStartRow = row;
        WriteMetricRow(ws, row++, "Requested IP", result.RequestedIp);
        WriteMetricRow(ws, row++, "Total matching requests", result.TotalRows);
        WriteMetricRow(ws, row++, "Files with hits", result.SourceFiles.Count);
        WriteMetricRow(ws, row++, "First hit UTC", result.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-");
        WriteMetricRow(ws, row++, "Last hit UTC", result.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-");
        StyleMetricBlock(ws.Range(summaryStartRow, 1, row - 1, 2));
        row += 1;

        WriteStatusTable(ws, row, 1, "ELB Response totals", result.ElbResponseTotals);
        WriteStatusTable(ws, row, 5, "FE Response totals", result.FeResponseTotals);
        row += 7;

        WriteMismatchTable(ws, row, 1, result);
        row += 7;

        _ = WriteTopCounts(ws, row, 1, "Top 10 target endpoints", result.TopTargetEndpoints(10));

        ws.Columns().AdjustToContents(10, 80);
    }

    private static void WriteHitsSheet(IXLWorksheet ws, IReadOnlyList<AlbIpSummaryScanner.ScanResult> results)
    {
        var headers = new[]
        {
            "RequestedIp",
            "TimestampUtc",
            "ClientIp",
            "Method",
            "RawRequest",
            "ELB Response Code",
            "FE Response Code",
            "TargetEndpoint",
            "TargetProcessingTimeSeconds",
            "RequestProcessingTimeSeconds",
            "ResponseProcessingTimeSeconds",
            "ActionsExecuted",
            "UserAgent"
        };

        for (int i = 0; i < headers.Length; i++)
            ws.Cell(1, i + 1).Value = headers[i];

        var headerRange = ws.Range(1, 1, 1, headers.Length);
        headerRange.Style.Font.Bold = true;
        headerRange.Style.Fill.BackgroundColor = HeaderFill;
        headerRange.Style.Font.FontColor = XLColor.White;
        ws.SheetView.FreezeRows(1);

        int row = 2;
        foreach (var result in results.Where(r => r.HasRetainedRows).OrderBy(r => r.RequestedIp, StringComparer.OrdinalIgnoreCase))
        {
            foreach (var hit in result.Rows.OrderBy(h => h.TimestampUtc))
            {
                ws.Cell(row, 1).Value = result.RequestedIp;
                ws.Cell(row, 2).Value = hit.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
                ws.Cell(row, 3).Value = hit.ClientIp;
                ws.Cell(row, 4).Value = hit.Method;
                ws.Cell(row, 5).Value = hit.RawRequest;
                ws.Cell(row, 6).Value = hit.ElbStatusCode;
                ws.Cell(row, 7).Value = hit.FeStatusCode;
                ws.Cell(row, 8).Value = hit.TargetEndpoint;
                ws.Cell(row, 9).Value = hit.TargetProcessingTimeSeconds;
                ws.Cell(row, 10).Value = hit.RequestProcessingTimeSeconds;
                ws.Cell(row, 11).Value = hit.ResponseProcessingTimeSeconds;
                ws.Cell(row, 12).Value = hit.ActionsExecuted;
                ws.Cell(row, 13).Value = hit.UserAgent;
                row++;
            }
        }

        if (row > 2)
        {
            var table = ws.Range(1, 1, row - 1, headers.Length).CreateTable("AlbIpSummaryHits");
            table.Theme = XLTableTheme.TableStyleMedium9;
            table.ShowAutoFilter = true;
        }

        ws.Columns(1, headers.Length).AdjustToContents(10, 80);
    }

    private static void WriteStatusTable(IXLWorksheet ws, int row, int col, string title, AlbIpSummaryScanner.StatusGroupCounts counts)
    {
        ws.Cell(row, col).Value = title;
        ws.Cell(row, col).Style.Font.Bold = true;
        ws.Range(row, col, row, col + 1).Style.Fill.BackgroundColor = SectionFill;
        row++;

        ws.Cell(row, col).Value = "2xx/3xx";
        ws.Cell(row, col + 1).Value = counts.S2xx + counts.S3xx;
        row++;
        ws.Cell(row, col).Value = "4xx";
        ws.Cell(row, col + 1).Value = counts.S4xx;
        row++;
        ws.Cell(row, col).Value = "5xx";
        ws.Cell(row, col + 1).Value = counts.S5xx;
    }

    private static void WriteMismatchTable(IXLWorksheet ws, int row, int col, AlbIpSummaryScanner.ScanResult result)
    {
        ws.Cell(row, col).Value = "Interesting Mismatches";
        ws.Cell(row, col).Style.Font.Bold = true;
        row++;

        ws.Cell(row, col).Value = "Signal";
        ws.Cell(row, col + 1).Value = "Hits";
        ws.Range(row, col, row, col + 1).Style.Font.Bold = true;
        row++;

        ws.Cell(row, col).Value = "FE Response 5xx while ELB Response is 2xx/3xx";
        ws.Cell(row, col + 1).Value = result.Fe5xxWhileElb2xx3xx;
        row++;
        ws.Cell(row, col).Value = "FE Response 4xx while ELB Response is 2xx/3xx";
        ws.Cell(row, col + 1).Value = result.Fe4xxWhileElb2xx3xx;
        row++;
        ws.Cell(row, col).Value = "ELB Response 5xx while FE Response is 2xx/3xx";
        ws.Cell(row, col + 1).Value = result.Elb5xxWhileFe2xx3xx;
        row++;
        ws.Cell(row, col).Value = "ELB Response 4xx while FE Response is 2xx/3xx";
        ws.Cell(row, col + 1).Value = result.Elb4xxWhileFe2xx3xx;
    }

    private static int WriteTopCounts(IXLWorksheet ws, int row, int col, string title, IReadOnlyList<KeyValuePair<string, int>> items)
    {
        ws.Cell(row, col).Value = title;
        ws.Cell(row, col).Style.Font.Bold = true;
        row++;

        ws.Cell(row, col).Value = "Value";
        ws.Cell(row, col + 1).Value = "Hits";
        ws.Range(row, col, row, col + 1).Style.Font.Bold = true;
        row++;

        if (items.Count == 0)
        {
            ws.Cell(row, col).Value = "(none)";
            ws.Cell(row, col + 1).Value = 0;
            return row + 1;
        }

        foreach (var item in items)
        {
            ws.Cell(row, col).Value = item.Key;
            ws.Cell(row, col + 1).Value = item.Value;
            row++;
        }

        return row + 1;
    }

    private static void WriteMetricRow(IXLWorksheet ws, int row, string label, object value)
    {
        ws.Cell(row, 1).Value = label;
        ws.Cell(row, 2).Value = XLCellValue.FromObject(value);
    }

    private static void StyleMetricBlock(IXLRange range)
    {
        range.Style.Fill.BackgroundColor = CardFill;
        range.Column(1).Style.Font.Bold = true;
        range.Column(1).Style.Fill.BackgroundColor = SectionFill;
    }

    private static string BuildSheetName(string ip)
    {
        var invalid = new HashSet<char>(['[', ']', '*', '?', '/', '\\', ':']);
        var cleaned = new string(ip.Select(c => invalid.Contains(c) ? '_' : c).ToArray());
        if (string.IsNullOrWhiteSpace(cleaned))
            cleaned = "IP";
        if (cleaned.Length > 31)
            cleaned = cleaned[..31];
        return cleaned;
    }
}
