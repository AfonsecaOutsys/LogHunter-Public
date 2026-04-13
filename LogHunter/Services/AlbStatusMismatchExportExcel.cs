using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using ClosedXML.Excel;

namespace LogHunter.Services;

public static class AlbStatusMismatchExportExcel
{
    private static readonly XLColor HeaderFill = XLColor.FromHtml("#17324D");
    private static readonly XLColor SectionFill = XLColor.FromHtml("#DCEAF7");
    private static readonly XLColor CardFill = XLColor.FromHtml("#F7FAFC");
    private static readonly XLColor BorderColor = XLColor.FromHtml("#C7D6E5");

    public static void Export(string outFile, AlbStatusMismatchScanner.ScanResult result)
    {
        using var wb = new XLWorkbook();
        WriteSummarySheet(wb.Worksheets.Add("Summary"), result);
        WriteHitsSheet(wb.Worksheets.Add("Hits"), result);
        wb.SaveAs(outFile);
    }

    private static void WriteSummarySheet(IXLWorksheet ws, AlbStatusMismatchScanner.ScanResult result)
    {
        int row = 1;

        ws.Cell(row, 1).Value = "ALB 5xx While Backend Succeeded";
        ws.Cell(row, 1).Style.Font.Bold = true;
        ws.Cell(row, 1).Style.Font.FontSize = 14;
        var titleRange = ws.Range(row, 1, row, 2);
        titleRange.Merge();
        titleRange.Style.Fill.BackgroundColor = SectionFill;
        titleRange.Style.Font.FontColor = XLColor.Black;
        row += 2;

        var summaryStartRow = row;
        WriteMetricRow(ws, row++, "Filter", "ELB 5xx while target/backend is 2xx/3xx");
        WriteMetricRow(ws, row++, "Matching requests", result.TotalRows);
        WriteMetricRow(ws, row++, "Files with hits", result.SourceFiles.Count);
        WriteMetricRow(ws, row++, "First hit UTC", result.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-");
        WriteMetricRow(ws, row++, "Last hit UTC", result.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-");
        StyleMetricBlock(ws.Range(summaryStartRow, 1, row - 1, 2));
        row += 1;

        row = WriteStatusBreakdownTable(ws, row, 1, result) + 2;
        row = WriteCountTable(ws, row, 1, "Top status pairs", "StatusPair", "AlbStatusMismatchTopStatusPairs", result.TopStatusPairs(15)) + 2;
        row = WriteCountTable(ws, row, 1, "Top URIs", "URI", "AlbStatusMismatchTopUris", result.TopUris(25)) + 2;
        row = WriteCountTable(ws, row, 1, "Top target endpoints", "TargetEndpoint", "AlbStatusMismatchTopTargetEndpoints", result.TopTargetEndpoints(25)) + 2;
        _ = WriteCountTable(ws, row, 1, "Top client IPs", "ClientIp", "AlbStatusMismatchTopClientIps", result.TopClientIps(25));

        ws.SheetView.FreezeRows(1);
        ApplyOuterBorder(ws.RangeUsed());
        ws.Columns().AdjustToContents(10, 80);
    }

    private static void WriteHitsSheet(IXLWorksheet ws, AlbStatusMismatchScanner.ScanResult result)
    {
        var headers = new[]
        {
            "TimestampUtc",
            "ClientIp",
            "Method",
            "UriNoQuery",
            "RawRequest",
            "ELB Response Code",
            "Target Response Code",
            "TargetEndpoint",
            "TargetProcessingTimeSeconds",
            "RequestProcessingTimeSeconds",
            "ResponseProcessingTimeSeconds",
            "ActionsExecuted",
            "UserAgent",
            "SourceFile"
        };

        for (int i = 0; i < headers.Length; i++)
            ws.Cell(1, i + 1).Value = headers[i];

        var headerRange = ws.Range(1, 1, 1, headers.Length);
        headerRange.Style.Font.Bold = true;
        headerRange.Style.Fill.BackgroundColor = HeaderFill;
        headerRange.Style.Font.FontColor = XLColor.White;
        ws.SheetView.FreezeRows(1);

        int row = 2;
        foreach (var hit in result.Rows.OrderBy(h => h.TimestampUtc))
        {
            ws.Cell(row, 1).Value = hit.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
            ws.Cell(row, 2).Value = hit.ClientIp;
            ws.Cell(row, 3).Value = hit.Method;
            ws.Cell(row, 4).Value = hit.UriNoQuery;
            ws.Cell(row, 5).Value = hit.RawRequest;
            ws.Cell(row, 6).Value = hit.ElbStatusCode;
            ws.Cell(row, 7).Value = hit.TargetStatusCode;
            ws.Cell(row, 8).Value = hit.TargetEndpoint;
            ws.Cell(row, 9).Value = hit.TargetProcessingTimeSeconds;
            ws.Cell(row, 10).Value = hit.RequestProcessingTimeSeconds;
            ws.Cell(row, 11).Value = hit.ResponseProcessingTimeSeconds;
            ws.Cell(row, 12).Value = hit.ActionsExecuted;
            ws.Cell(row, 13).Value = hit.UserAgent;
            ws.Cell(row, 14).Value = hit.SourceFile;
            row++;
        }

        if (row > 2)
        {
            var table = ws.Range(1, 1, row - 1, headers.Length).CreateTable("AlbStatusMismatchHits");
            table.Theme = XLTableTheme.TableStyleMedium9;
            table.ShowAutoFilter = true;
        }

        ws.Column(1).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Left;
        ws.Column(6).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
        ws.Column(7).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
        ws.Columns(9, 11).Style.NumberFormat.Format = "0.000";
        ApplyOuterBorder(ws.RangeUsed());
        ws.Columns(1, headers.Length).AdjustToContents(10, 80);
    }

    private static int WriteStatusBreakdownTable(IXLWorksheet ws, int row, int col, AlbStatusMismatchScanner.ScanResult result)
    {
        ws.Cell(row, col).Value = "Status breakdown";
        var titleRange = ws.Range(row, col, row, col + 1);
        titleRange.Merge();
        titleRange.Style.Font.Bold = true;
        titleRange.Style.Fill.BackgroundColor = SectionFill;
        row++;

        ws.Cell(row, col).Value = "Status";
        ws.Cell(row, col + 1).Value = "Hits";
        var headerRange = ws.Range(row, col, row, col + 1);
        headerRange.Style.Font.Bold = true;
        headerRange.Style.Fill.BackgroundColor = HeaderFill;
        headerRange.Style.Font.FontColor = XLColor.White;
        row++;

        foreach (var pair in result.TopElbStatuses())
        {
            ws.Cell(row, col).Value = $"ELB {pair.Key}";
            ws.Cell(row, col + 1).Value = pair.Value;
            row++;
        }

        foreach (var pair in result.TopTargetStatuses())
        {
            ws.Cell(row, col).Value = $"Target {pair.Key}";
            ws.Cell(row, col + 1).Value = pair.Value;
            row++;
        }

        ApplySectionBorder(ws.Range(row - (result.TopElbStatuses().Count + result.TopTargetStatuses().Count) - 1, col, row - 1, col + 1));
        return row - 1;
    }

    private static int WriteCountTable(IXLWorksheet ws, int row, int col, string title, string keyHeader, string tableName, IReadOnlyList<KeyValuePair<string, int>> items)
    {
        ws.Cell(row, col).Value = title;
        var titleRange = ws.Range(row, col, row, col + 1);
        titleRange.Merge();
        titleRange.Style.Font.Bold = true;
        titleRange.Style.Fill.BackgroundColor = SectionFill;
        row++;

        ws.Cell(row, col).Value = keyHeader;
        ws.Cell(row, col + 1).Value = "Hits";
        var headerRange = ws.Range(row, col, row, col + 1);
        headerRange.Style.Font.Bold = true;
        headerRange.Style.Fill.BackgroundColor = HeaderFill;
        headerRange.Style.Font.FontColor = XLColor.White;
        row++;

        if (items.Count == 0)
        {
            ws.Cell(row, col).Value = "(none)";
            ws.Cell(row, col + 1).Value = 0;
            ApplySectionBorder(ws.Range(row - 1, col, row, col + 1));
            return row;
        }

        foreach (var item in items)
        {
            ws.Cell(row, col).Value = item.Key;
            ws.Cell(row, col + 1).Value = item.Value;
            row++;
        }

        ApplySectionBorder(ws.Range(row - items.Count - 1, col, row - 1, col + 1));
        return row - 1;
    }

    private static void WriteMetricRow(IXLWorksheet ws, int row, string label, object value)
    {
        ws.Cell(row, 1).Value = label;
        ws.Cell(row, 1).Style.Font.Bold = true;
        ws.Cell(row, 1).Style.Fill.BackgroundColor = CardFill;
        ws.Cell(row, 2).Value = XLCellValue.FromObject(value);
    }

    private static void StyleMetricBlock(IXLRange range)
    {
        ApplySectionBorder(range);
        range.Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
    }

    private static void ApplySectionBorder(IXLRange range)
    {
        range.Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
        range.Style.Border.InsideBorder = XLBorderStyleValues.Thin;
        range.Style.Border.OutsideBorderColor = BorderColor;
        range.Style.Border.InsideBorderColor = BorderColor;
    }

    private static void ApplyOuterBorder(IXLRange? range)
    {
        if (range is null)
            return;

        range.Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
        range.Style.Border.OutsideBorderColor = BorderColor;
    }
}
