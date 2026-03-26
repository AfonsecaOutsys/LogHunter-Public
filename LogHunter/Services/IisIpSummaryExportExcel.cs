using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using ClosedXML.Excel;

namespace LogHunter.Services;

public static class IisIpSummaryExportExcel
{
    private const int ExcelMaxRows = 1_048_576;
    private const int HitsHeaderRow = 1;
    private const int HitsFirstDataRow = 2;
    private const int HitsRowsPerSheet = ExcelMaxRows - HitsFirstDataRow + 1;

    private static readonly XLColor HeaderFill = XLColor.FromHtml("#17324D");
    private static readonly XLColor SectionFill = XLColor.FromHtml("#DCEAF7");
    private static readonly XLColor CardFill = XLColor.FromHtml("#F7FAFC");
    private static readonly XLColor StatusOkFill = XLColor.FromHtml("#DFF3E4");
    private static readonly XLColor StatusWarnFill = XLColor.FromHtml("#FFF1CC");
    private static readonly XLColor StatusErrorFill = XLColor.FromHtml("#FAD7D7");

    public static void Export(string outFile, IReadOnlyList<IisIpSummaryScanner.ScanResult> results)
    {
        using var wb = new XLWorkbook();

        WriteOverviewSheet(wb.Worksheets.Add("Summary"), results);

        foreach (var result in results.Where(r => r.HasRetainedRows))
            WriteIpSheet(wb.Worksheets.Add(BuildSheetName(result.RequestedIp)), result);

        WriteHitsSheets(wb, results);
        wb.SaveAs(outFile);
    }

    private static void WriteOverviewSheet(IXLWorksheet ws, IReadOnlyList<IisIpSummaryScanner.ScanResult> results)
    {
        var orderedResults = results
            .OrderByDescending(r => r.TotalRows)
            .ThenBy(r => r.RequestedIp, StringComparer.OrdinalIgnoreCase)
            .ToList();

        ws.Cell(1, 1).Value = "IIS Multi-IP Summary";
        StyleTitle(ws.Range(1, 1, 1, 12));

        var metaStartRow = 3;
        WriteMetricRow(ws, metaStartRow++, "Requested IPs", orderedResults.Count);
        WriteMetricRow(ws, metaStartRow++, "IPs with retained detail rows", orderedResults.Count(r => r.HasRetainedRows));
        WriteMetricRow(ws, metaStartRow++, "Total matching requests", orderedResults.Sum(r => r.TotalRows));
        WriteMetricRow(ws, metaStartRow++, "Generated UTC", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
        StyleMetricBlock(ws.Range(3, 1, metaStartRow - 1, 2));

        var headers = new[]
        {
            "IP","TotalRequests","FilesWithHits","FirstHitUtc","LastHitUtc","AvgTimeTakenMs","MaxTimeTakenMs","TotalCsBytes","TotalScBytes","Status2xx3xx","Status4xx","Status5xx"
        };

        var headerRow = metaStartRow + 1;

        for (int i = 0; i < headers.Length; i++)
            ws.Cell(headerRow, i + 1).Value = headers[i];

        StyleHeaderRow(ws.Range(headerRow, 1, headerRow, headers.Length));
        ws.SheetView.FreezeRows(headerRow);

        var row = headerRow + 1;
        foreach (var result in orderedResults)
        {
            ws.Cell(row, 1).Value = result.RequestedIp;
            ws.Cell(row, 2).Value = result.TotalRows;
            ws.Cell(row, 3).Value = result.SourceFiles.Count;
            ws.Cell(row, 4).Value = result.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-";
            ws.Cell(row, 5).Value = result.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-";
            ws.Cell(row, 6).Value = result.AverageTimeTakenMs;
            ws.Cell(row, 7).Value = result.MaxTimeTakenMs;
            ws.Cell(row, 8).Value = result.TotalCsBytes;
            ws.Cell(row, 9).Value = result.TotalScBytes;
            ws.Cell(row, 10).Value = result.StatusTotals.S2xx + result.StatusTotals.S3xx;
            ws.Cell(row, 11).Value = result.StatusTotals.S4xx;
            ws.Cell(row, 12).Value = result.StatusTotals.S5xx;
            row++;
        }

        if (row > headerRow + 1)
        {
            var dataRange = ws.Range(headerRow, 1, row - 1, headers.Length);
            var table = dataRange.CreateTable("IisIpSummaryOverview");
            table.Theme = XLTableTheme.TableStyleMedium2;
            table.ShowAutoFilter = true;
        }

        var usedRange = ws.RangeUsed();
        if (usedRange is not null)
            usedRange.Style.Alignment.Vertical = XLAlignmentVerticalValues.Top;
        ws.Column(2).Style.NumberFormat.Format = "#,##0";
        ws.Column(3).Style.NumberFormat.Format = "#,##0";
        ws.Column(6).Style.NumberFormat.Format = "#,##0.0";
        ws.Column(7).Style.NumberFormat.Format = "#,##0";
        ws.Column(8).Style.NumberFormat.Format = "#,##0";
        ws.Column(9).Style.NumberFormat.Format = "#,##0";
        ws.Column(10).Style.NumberFormat.Format = "#,##0";
        ws.Column(11).Style.NumberFormat.Format = "#,##0";
        ws.Column(12).Style.NumberFormat.Format = "#,##0";
        ws.Columns(1, headers.Length).AdjustToContents(10, 80);
    }

    private static void WriteIpSheet(IXLWorksheet ws, IisIpSummaryScanner.ScanResult result)
    {
        int row = 1;

        ws.Cell(row, 1).Value = $"IIS IP Summary - {result.RequestedIp}";
        StyleTitle(ws.Range(row, 1, row, 6));
        row += 2;

        var summaryStartRow = row;
        WriteMetricRow(ws, row++, "Requested IP", result.RequestedIp);
        WriteMetricRow(ws, row++, "Total matching requests", result.TotalRows);
        WriteMetricRow(ws, row++, "Files with hits", result.SourceFiles.Count);
        WriteMetricRow(ws, row++, "First hit UTC", result.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-");
        WriteMetricRow(ws, row++, "Last hit UTC", result.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-");
        WriteMetricRow(ws, row++, "Average time-taken (ms)", result.AverageTimeTakenMs, "#,##0.0");
        WriteMetricRow(ws, row++, "Max time-taken (ms)", result.MaxTimeTakenMs);
        WriteMetricRow(ws, row++, "Total cs-bytes", result.TotalCsBytes);
        WriteMetricRow(ws, row++, "Total sc-bytes", result.TotalScBytes);
        StyleMetricBlock(ws.Range(summaryStartRow, 1, row - 1, 2));
        row += 1;

        WriteStatusTable(ws, row, 1, "HTTP status totals", result.StatusTotals);
        row += 6;

        var nextUriRow = WriteTopCounts(ws, row, 1, "Top 10 URIs", "URI", result.TopUris(10));
        var nextMethodRow = WriteTopCounts(ws, row, 5, "Top 10 methods", "Method", result.TopMethods(10));
        row = Math.Max(nextUriRow, nextMethodRow) + 1;

        _ = WriteTopCounts(ws, row, 1, "Top exact status codes", "Status", result.TopExactStatuses(10));
        var usedRange = ws.RangeUsed();
        if (usedRange is not null)
            usedRange.Style.Alignment.Vertical = XLAlignmentVerticalValues.Top;
        ws.Columns().AdjustToContents(10, 80);
    }

    private static void WriteHitsSheets(XLWorkbook wb, IReadOnlyList<IisIpSummaryScanner.ScanResult> results)
    {
        var headers = new[]
        {
            "RequestedIp",
            "TimestampUtc",
            "ClientIp",
            "Method",
            "UriStem",
            "UriQuery",
            "Host",
            "StatusCode",
            "SubStatusCode",
            "Win32StatusCode",
            "TimeTakenMs",
            "CsBytes",
            "ScBytes",
            "UserAgent",
            "Referer"
        };

        IXLWorksheet ws = CreateHitsWorksheet(wb, 1, headers);
        var sheetIndex = 1;
        var row = HitsFirstDataRow;

        foreach (var result in results.Where(r => r.HasRetainedRows).OrderBy(r => r.RequestedIp, StringComparer.OrdinalIgnoreCase))
        {
            foreach (var hit in result.Rows.OrderBy(h => h.TimestampUtc))
            {
                if (row > ExcelMaxRows)
                {
                    FinalizeHitsWorksheet(ws, headers.Length, row);
                    ws = CreateHitsWorksheet(wb, ++sheetIndex, headers);
                    row = HitsFirstDataRow;
                }

                ws.Cell(row, 1).Value = result.RequestedIp;
                ws.Cell(row, 2).Value = hit.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
                ws.Cell(row, 3).Value = hit.ClientIp;
                ws.Cell(row, 4).Value = hit.Method;
                ws.Cell(row, 5).Value = hit.UriStem;
                ws.Cell(row, 6).Value = hit.UriQuery;
                ws.Cell(row, 7).Value = hit.Host;
                ws.Cell(row, 8).Value = hit.StatusCode;
                ws.Cell(row, 9).Value = hit.SubStatusCode;
                ws.Cell(row, 10).Value = hit.Win32StatusCode;
                ws.Cell(row, 11).Value = hit.TimeTakenMs;
                ws.Cell(row, 12).Value = hit.CsBytes;
                ws.Cell(row, 13).Value = hit.ScBytes;
                ws.Cell(row, 14).Value = hit.UserAgent;
                ws.Cell(row, 15).Value = hit.Referer;
                row++;
            }
        }

        FinalizeHitsWorksheet(ws, headers.Length, row);
    }

    private static IXLWorksheet CreateHitsWorksheet(XLWorkbook wb, int sheetIndex, IReadOnlyList<string> headers)
    {
        var ws = wb.Worksheets.Add(sheetIndex == 1 ? "Hits" : $"Hits {sheetIndex}");

        for (int i = 0; i < headers.Count; i++)
            ws.Cell(HitsHeaderRow, i + 1).Value = headers[i];

        StyleHeaderRow(ws.Range(HitsHeaderRow, 1, HitsHeaderRow, headers.Count));
        ws.SheetView.FreezeRows(HitsHeaderRow);

        return ws;
    }

    private static void FinalizeHitsWorksheet(IXLWorksheet ws, int headerCount, int nextRow)
    {
        if (nextRow > HitsFirstDataRow)
        {
            var tableRange = ws.Range(HitsHeaderRow, 1, nextRow - 1, headerCount);
            var tableName = BuildHitsTableName(ws.Name);
            var table = tableRange.CreateTable(tableName);
            table.Theme = XLTableTheme.TableStyleMedium9;
            table.ShowAutoFilter = true;
        }

        var usedRange = ws.RangeUsed();
        if (usedRange is not null)
            usedRange.Style.Alignment.Vertical = XLAlignmentVerticalValues.Top;
        ws.Column(8).Style.NumberFormat.Format = "#,##0";
        ws.Column(9).Style.NumberFormat.Format = "#,##0";
        ws.Column(10).Style.NumberFormat.Format = "#,##0";
        ws.Column(11).Style.NumberFormat.Format = "#,##0";
        ws.Column(12).Style.NumberFormat.Format = "#,##0";
        ws.Column(13).Style.NumberFormat.Format = "#,##0";
        ws.Columns(1, headerCount).AdjustToContents();
    }

    private static string BuildHitsTableName(string worksheetName)
    {
        var cleaned = new string(worksheetName.Where(char.IsLetterOrDigit).ToArray());
        if (string.IsNullOrWhiteSpace(cleaned))
            cleaned = "Hits";
        return $"IisIpSummary{cleaned}";
    }

    private static void WriteStatusTable(IXLWorksheet ws, int row, int col, string title, IisIpSummaryScanner.StatusGroupCounts counts)
    {
        ws.Cell(row, col).Value = title;
        ws.Cell(row, col).Style.Font.Bold = true;
        ws.Range(row, col, row, col + 1).Style.Fill.BackgroundColor = SectionFill;
        row++;

        ws.Cell(row, col).Value = "2xx/3xx";
        ws.Cell(row, col + 1).Value = counts.S2xx + counts.S3xx;
        ws.Range(row, col, row, col + 1).Style.Fill.BackgroundColor = StatusOkFill;
        row++;
        ws.Cell(row, col).Value = "4xx";
        ws.Cell(row, col + 1).Value = counts.S4xx;
        ws.Range(row, col, row, col + 1).Style.Fill.BackgroundColor = StatusWarnFill;
        row++;
        ws.Cell(row, col).Value = "5xx";
        ws.Cell(row, col + 1).Value = counts.S5xx;
        ws.Range(row, col, row, col + 1).Style.Fill.BackgroundColor = StatusErrorFill;
        ws.Range(row - 3, col, row, col + 1).Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
        ws.Range(row - 3, col, row, col + 1).Style.Border.InsideBorder = XLBorderStyleValues.Thin;
    }

    private static int WriteTopCounts(IXLWorksheet ws, int row, int col, string title, string label, IReadOnlyList<KeyValuePair<string, int>> items)
    {
        var titleRow = row;
        ws.Cell(row, col).Value = title;
        ws.Cell(row, col).Style.Font.Bold = true;
        ws.Range(row, col, row, col + 1).Style.Fill.BackgroundColor = SectionFill;
        row++;

        ws.Cell(row, col).Value = label;
        ws.Cell(row, col + 1).Value = "Hits";
        ws.Range(row, col, row, col + 1).Style.Font.Bold = true;
        ws.Range(row, col, row, col + 1).Style.Fill.BackgroundColor = HeaderFill;
        ws.Range(row, col, row, col + 1).Style.Font.FontColor = XLColor.White;
        row++;

        if (items.Count == 0)
        {
            ws.Cell(row, col).Value = "(none)";
            ws.Cell(row, col + 1).Value = 0;
            var emptyRange = ws.Range(titleRow, col, row, col + 1);
            emptyRange.Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
            emptyRange.Style.Border.InsideBorder = XLBorderStyleValues.Thin;
            return row + 1;
        }

        foreach (var item in items)
        {
            ws.Cell(row, col).Value = item.Key;
            ws.Cell(row, col + 1).Value = item.Value;
            ws.Range(row, col, row, col + 1).Style.Fill.BackgroundColor = (row % 2 == 0) ? CardFill : XLColor.White;
            row++;
        }

        var dataRange = ws.Range(titleRow + 1, col, row - 1, col + 1);
        dataRange.Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
        dataRange.Style.Border.InsideBorder = XLBorderStyleValues.Thin;
        dataRange.Column(2).Style.NumberFormat.Format = "#,##0";
        return row + 1;
    }

    private static void WriteMetricRow(IXLWorksheet ws, int row, string label, object value, string? numberFormat = null)
    {
        ws.Cell(row, 1).Value = label;
        ws.Cell(row, 2).Value = XLCellValue.FromObject(value);
        if (!string.IsNullOrWhiteSpace(numberFormat))
            ws.Cell(row, 2).Style.NumberFormat.Format = numberFormat;
    }

    private static void StyleTitle(IXLRange range)
    {
        range.Merge();
        range.Style.Font.Bold = true;
        range.Style.Font.FontSize = 14;
        range.Style.Fill.BackgroundColor = HeaderFill;
        range.Style.Font.FontColor = XLColor.White;
        range.Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
    }

    private static void StyleHeaderRow(IXLRange range)
    {
        range.Style.Font.Bold = true;
        range.Style.Fill.BackgroundColor = HeaderFill;
        range.Style.Font.FontColor = XLColor.White;
        range.Style.Border.BottomBorder = XLBorderStyleValues.Thin;
    }

    private static void StyleMetricBlock(IXLRange range)
    {
        range.Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
        range.Style.Border.InsideBorder = XLBorderStyleValues.Thin;
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
