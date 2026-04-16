using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using ClosedXML.Excel;

namespace LogHunter.Services;

public static class AlbIpSummaryExportExcel
{
    private static readonly XLColor HeaderFill = XLColor.FromHtml("#17324D");
    private static readonly XLColor TitleFill = XLColor.FromHtml("#DCEAF7");
    private static readonly XLColor LabelFill = XLColor.FromHtml("#F7FAFC");
    private static readonly XLColor BorderColor = XLColor.FromHtml("#C7D2E2");

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
        var titleRange = ws.Range(1, 1, 1, 8);
        titleRange.Merge();
        titleRange.Style.Fill.BackgroundColor = TitleFill;
        titleRange.Style.Font.FontColor = XLColor.Black;

        var headers = new[]
        {
            "IP", "TotalRequests", "FilesWithHits", "FirstHitUtc", "LastHitUtc", "ELB 2xx/3xx", "ELB 4xx/5xx", "FE 4xx/5xx"
        };

        WriteHeaderRow(ws, 3, headers);
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

        var usedRange = ws.RangeUsed();
        if (usedRange is not null)
            usedRange.Style.Alignment.WrapText = false;
        ApplyOuterBorder(usedRange);
        ExcelHelper.AutoFitColumns(ws);
    }

    private static void WriteIpSheet(IXLWorksheet ws, AlbIpSummaryScanner.ScanResult result)
    {
        int row = 1;

        ws.Cell(row, 1).Value = $"ALB IP Summary - {result.RequestedIp}";
        ws.Cell(row, 1).Style.Font.Bold = true;
        ws.Cell(row, 1).Style.Font.FontSize = 14;
        var titleRange = ws.Range(row, 1, row, 4);
        titleRange.Merge();
        titleRange.Style.Fill.BackgroundColor = TitleFill;
        titleRange.Style.Font.FontColor = XLColor.Black;
        row += 2;

        var summaryStartRow = row;
        WriteMetricRow(ws, row++, "Requested IP", result.RequestedIp);
        WriteMetricRow(ws, row++, "Total matching requests", result.TotalRows);
        WriteMetricRow(ws, row++, "Files with hits", result.SourceFiles.Count);
        WriteMetricRow(ws, row++, "First hit UTC", result.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-");
        WriteMetricRow(ws, row++, "Last hit UTC", result.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-");
        StyleMetricBlock(ws.Range(summaryStartRow, 1, row - 1, 4));
        row += 1;

        WriteStatusTable(ws, row, 1, "ELB Response totals", result.ElbResponseTotals);
        WriteStatusTable(ws, row, 5, "FE Response totals", result.FeResponseTotals);
        row += 7;

        WriteMismatchTable(ws, row, 1, result);
        row += 7;

        _ = WriteTopCounts(ws, row, 1, "Top 10 target endpoints", result.TopTargetEndpoints(10));

        var usedRange = ws.RangeUsed();
        if (usedRange is not null)
            usedRange.Style.Alignment.WrapText = false;
        ws.SheetView.FreezeRows(1);
        ExcelHelper.AutoFitColumns(ws);
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

        WriteHeaderRow(ws, 1, headers);
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

        var usedRange = ws.RangeUsed();
        if (usedRange is not null)
            usedRange.Style.Alignment.WrapText = false;
        ApplyOuterBorder(usedRange);
        ExcelHelper.AutoFitColumns(ws, 1, headers.Length);
    }

    private static void WriteStatusTable(IXLWorksheet ws, int row, int col, string title, AlbIpSummaryScanner.StatusGroupCounts counts)
    {
        ws.Cell(row, col).Value = title;
        var titleRange = ws.Range(row, col, row, col + 1);
        titleRange.Merge();
        titleRange.Style.Font.Bold = true;
        titleRange.Style.Fill.BackgroundColor = TitleFill;
        row++;

        ws.Cell(row, col).Value = "Class";
        ws.Cell(row, col + 1).Value = "Hits";
        var headerRange = ws.Range(row, col, row, col + 1);
        headerRange.Style.Font.Bold = true;
        headerRange.Style.Fill.BackgroundColor = HeaderFill;
        headerRange.Style.Font.FontColor = XLColor.White;
        row++;

        ws.Cell(row, col).Value = "2xx/3xx";
        ws.Cell(row, col + 1).Value = counts.S2xx + counts.S3xx;
        row++;
        ws.Cell(row, col).Value = "4xx";
        ws.Cell(row, col + 1).Value = counts.S4xx;
        row++;
        ws.Cell(row, col).Value = "5xx";
        ws.Cell(row, col + 1).Value = counts.S5xx;

        ApplySectionBorder(ws.Range(row - 4, col, row, col + 1));
    }

    private static void WriteMismatchTable(IXLWorksheet ws, int row, int col, AlbIpSummaryScanner.ScanResult result)
    {
        ws.Cell(row, col).Value = "Interesting Mismatches";
        var titleRange = ws.Range(row, col, row, col + 1);
        titleRange.Merge();
        titleRange.Style.Font.Bold = true;
        titleRange.Style.Fill.BackgroundColor = TitleFill;
        row++;

        ws.Cell(row, col).Value = "Signal";
        ws.Cell(row, col + 1).Value = "Hits";
        var headerRange = ws.Range(row, col, row, col + 1);
        headerRange.Style.Font.Bold = true;
        headerRange.Style.Fill.BackgroundColor = HeaderFill;
        headerRange.Style.Font.FontColor = XLColor.White;
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

        ApplySectionBorder(ws.Range(row - 5, col, row, col + 1));
    }

    private static int WriteTopCounts(IXLWorksheet ws, int row, int col, string title, IReadOnlyList<KeyValuePair<string, int>> items)
    {
        ws.Cell(row, col).Value = title;
        var titleRange = ws.Range(row, col, row, col + 1);
        titleRange.Merge();
        titleRange.Style.Font.Bold = true;
        titleRange.Style.Fill.BackgroundColor = TitleFill;
        row++;

        ws.Cell(row, col).Value = "Value";
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
            return row + 1;
        }

        foreach (var item in items)
        {
            ws.Cell(row, col).Value = item.Key;
            ws.Cell(row, col + 1).Value = item.Value;
            row++;
        }

        ApplySectionBorder(ws.Range(row - items.Count - 1, col, row - 1, col + 1));
        return row + 1;
    }

    private static void WriteMetricRow(IXLWorksheet ws, int row, string label, object value)
    {
        ws.Cell(row, 1).Value = label;
        ws.Cell(row, 1).Style.Font.Bold = true;
        ws.Cell(row, 1).Style.Fill.BackgroundColor = LabelFill;
        ws.Range(row, 2, row, 4).Merge();
        ws.Cell(row, 2).Value = XLCellValue.FromObject(value);
        ws.Cell(row, 2).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Left;
    }

    private static void StyleMetricBlock(IXLRange range)
    {
        ApplySectionBorder(range);
        range.Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
    }

    private static void WriteHeaderRow(IXLWorksheet ws, int row, IReadOnlyList<string> headers)
    {
        for (var i = 0; i < headers.Count; i++)
            ws.Cell(row, i + 1).Value = headers[i];

        var headerRange = ws.Range(row, 1, row, headers.Count);
        headerRange.Style.Font.Bold = true;
        headerRange.Style.Fill.BackgroundColor = HeaderFill;
        headerRange.Style.Font.FontColor = XLColor.White;
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
