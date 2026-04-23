using System;
using System.Collections.Generic;
using ClosedXML.Excel;

namespace LogHunter.Services;

/// <summary>
/// Shared Excel formatting helpers used by console export commands.
/// </summary>
internal static class ExcelHelper
{
    private static readonly XLColor HeaderFill = XLColor.FromHtml("#17324D");

    public static void WriteHeaderRow(IXLWorksheet ws, int row, IReadOnlyList<string> headers)
    {
        for (var i = 0; i < headers.Count; i++)
            ws.Cell(row, i + 1).Value = headers[i];

        var headerRange = ws.Range(row, 1, row, headers.Count);
        headerRange.Style.Font.Bold = true;
        headerRange.Style.Fill.BackgroundColor = HeaderFill;
        headerRange.Style.Font.FontColor = XLColor.White;
    }

    /// <summary>
    /// Auto-fits all columns and adds padding to compensate for ClosedXML's
    /// approximate width calculation (bold text, number formatting, filter arrows).
    /// </summary>
    public static void AutoFitColumns(IXLWorksheet ws, double minWidth = 10, double maxWidth = 80, double padding = 3)
    {
        ws.Columns().AdjustToContents(minWidth, maxWidth);
        foreach (var col in ws.ColumnsUsed())
            col.Width = Math.Min(col.Width + padding, maxWidth);
    }

    /// <summary>
    /// Auto-fits a specific column range and adds padding.
    /// </summary>
    public static void AutoFitColumns(IXLWorksheet ws, int firstColumn, int lastColumn, double minWidth = 10, double maxWidth = 80, double padding = 3)
    {
        ws.Columns(firstColumn, lastColumn).AdjustToContents(minWidth, maxWidth);
        for (int c = firstColumn; c <= lastColumn; c++)
            ws.Column(c).Width = Math.Min(ws.Column(c).Width + padding, maxWidth);
    }
}
