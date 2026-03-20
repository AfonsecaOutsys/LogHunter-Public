using System;
using System.Globalization;
using ClosedXML.Excel;

namespace LogHunter.Services;

public static class AlbIpSummaryExportExcel
{
    public static void Export(string outFile, AlbIpSummaryScanner.ScanResult result)
    {
        using var wb = new XLWorkbook();

        WriteSummarySheet(wb.Worksheets.Add("Summary"), result);
        WriteHitsSheet(wb.Worksheets.Add("Hits"), result);

        wb.SaveAs(outFile);
    }

    private static void WriteSummarySheet(IXLWorksheet ws, AlbIpSummaryScanner.ScanResult result)
    {
        int row = 1;

        ws.Cell(row, 1).Value = "ALB IP Summary";
        ws.Cell(row, 1).Style.Font.Bold = true;
        ws.Cell(row, 1).Style.Font.FontSize = 14;
        row += 2;

        ws.Cell(row, 1).Value = "Requested IP";
        ws.Cell(row, 2).Value = result.RequestedIp;
        row++;
        ws.Cell(row, 1).Value = "Total matching requests";
        ws.Cell(row, 2).Value = result.TotalRows;
        row++;
        ws.Cell(row, 1).Value = "Files with hits";
        ws.Cell(row, 2).Value = result.SourceFiles.Count;
        row++;
        ws.Cell(row, 1).Value = "First hit UTC";
        ws.Cell(row, 2).Value = result.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-";
        row++;
        ws.Cell(row, 1).Value = "Last hit UTC";
        ws.Cell(row, 2).Value = result.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-";
        row += 2;

        WriteStatusTable(ws, row, 1, "ELB Response totals", result.ElbResponseTotals);
        WriteStatusTable(ws, row, 5, "FE Response totals", result.FeResponseTotals);
        row += 7;

        WriteMismatchTable(ws, row, 1, result);
        row += 7;

        _ = WriteTopCounts(ws, row, 1, "Top 10 target endpoints", result.TopTargetEndpoints(10));

        ws.Columns().AdjustToContents(10, 80);
    }

    private static void WriteHitsSheet(IXLWorksheet ws, AlbIpSummaryScanner.ScanResult result)
    {
        var headers = new[]
        {
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
        headerRange.Style.Fill.BackgroundColor = XLColor.AliceBlue;
        ws.SheetView.FreezeRows(1);
        ws.RangeUsed()?.SetAutoFilter();

        int row = 2;
        foreach (var hit in result.Rows)
        {
            ws.Cell(row, 1).Value = hit.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
            ws.Cell(row, 2).Value = hit.ClientIp;
            ws.Cell(row, 3).Value = hit.Method;
            ws.Cell(row, 4).Value = hit.RawRequest;
            ws.Cell(row, 5).Value = hit.ElbStatusCode;
            ws.Cell(row, 6).Value = hit.FeStatusCode;
            ws.Cell(row, 7).Value = hit.TargetEndpoint;
            ws.Cell(row, 8).Value = hit.TargetProcessingTimeSeconds;
            ws.Cell(row, 9).Value = hit.RequestProcessingTimeSeconds;
            ws.Cell(row, 10).Value = hit.ResponseProcessingTimeSeconds;
            ws.Cell(row, 11).Value = hit.ActionsExecuted;
            ws.Cell(row, 12).Value = hit.UserAgent;
            row++;
        }

        ws.RangeUsed()?.SetAutoFilter();
        ws.Columns(1, headers.Length).AdjustToContents(10, 80);
    }

    private static void WriteStatusTable(IXLWorksheet ws, int row, int col, string title, AlbIpSummaryScanner.StatusGroupCounts counts)
    {
        ws.Cell(row, col).Value = title;
        ws.Cell(row, col).Style.Font.Bold = true;
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

    private static int WriteTopCounts(IXLWorksheet ws, int row, int col, string title, System.Collections.Generic.IReadOnlyList<System.Collections.Generic.KeyValuePair<string, int>> items)
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
}
