using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using ClosedXML.Excel;
using LogHunter.Utils;

namespace LogHunter.Services;

/// <summary>
/// Writes the IP sweep evidence: a customer-safe HTML report (source labels only, no file paths)
/// and an Excel workbook for the investigation.
/// </summary>
internal static class IocSweepReport
{
    public static readonly string[] Caveats =
    {
        "Only the files listed under Scope were searched. Traffic outside the observed time range is not covered.",
        "ALB logs record the connecting IP. If a CDN, WAF or proxy sits in front of the application, the ALB sees that service, not the original client.",
        "IIS results use the client IP from X-Forwarded-For (OriginalIP), falling back to c-ip. X-Forwarded-For values set by the client can be forged.",
        "Access logs do not contain request or response bodies.",
        "No hits means the targets did not connect within the scope above; it does not prove they never targeted the environment through other paths.",
    };

    public static string TargetKind(IpTarget target) =>
        target.IsSingle ? "IP" : target.Text.Contains('/') ? "CIDR" : "Range";

    public static IEnumerable<KeyValuePair<string, long>> Top(Dictionary<string, long> map, int n) =>
        map.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.Ordinal).Take(n);

    public static string FormatTop(Dictionary<string, long> map, int n) =>
        string.Join(", ", Top(map, n).Select(kv => $"{kv.Key} ({kv.Value:N0})"));

    public static string FormatUtc(DateTime? value) =>
        value?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + (value is null ? "" : " UTC");

    public static void WriteHtml(IocSweepResult result, string path)
    {
        var sb = new StringBuilder();
        var hits = result.Targets.Where(t => t.Hits > 0).OrderByDescending(t => t.Hits).ToList();
        var misses = result.Targets.Where(t => t.Hits == 0).ToList();

        sb.Append("<!doctype html><html><head><meta charset=\"utf-8\"><title>IP sweep report</title><style>")
          .Append("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2933}table{border-collapse:collapse;margin:8px 0 20px}")
          .Append("th,td{border:1px solid #cbd2d9;padding:4px 8px;text-align:left;font-size:13px;vertical-align:top}th{background:#f0f4f8}")
          .Append(".num{text-align:right}.hit{color:#b42318;font-weight:600}.muted{color:#616e7c}</style></head><body>");
        sb.Append("<h1>IP sweep report</h1>");
        sb.Append($"<p class=\"muted\">Generated {E(FormatUtc(result.FinishedUtc))} · {result.Targets.Count:N0} targets · ")
          .Append($"<span class=\"hit\">{hits.Count:N0} with hits</span> · {misses.Count:N0} without hits</p>");

        AppendScope(sb, result.Scopes);
        AppendHits(sb, hits);
        AppendMisses(sb, misses);

        if (result.InvalidTokens.Count > 0)
            sb.Append($"<h2>Ignored input</h2><p>{E(string.Join(", ", result.InvalidTokens))}</p>");

        sb.Append("<h2>Notes</h2><ul>");
        foreach (var c in Caveats) sb.Append($"<li>{E(c)}</li>");
        sb.Append("</ul></body></html>");

        File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
    }

    private static void AppendScope(StringBuilder sb, IReadOnlyList<IocSweepSourceScope> scopes)
    {
        sb.Append("<h2>Scope</h2><table><tr><th>Source</th><th>Files</th><th class=\"num\">Lines</th><th class=\"num\">Records</th>")
          .Append("<th class=\"num\">Unparsed</th><th>Observed range</th><th class=\"num\">Unreadable files</th></tr>");
        foreach (var s in scopes)
        {
            var kinds = string.Join(" + ", new[] { s.AlbFiles > 0 ? $"{s.AlbFiles:N0} ALB" : null, s.IisFiles > 0 ? $"{s.IisFiles:N0} IIS" : null }.Where(x => x != null));
            sb.Append($"<tr><td>{E(s.Label)}</td><td>{E(kinds.Length == 0 ? "0" : kinds)}</td><td class=\"num\">{s.LinesRead:N0}</td>")
              .Append($"<td class=\"num\">{s.RecordsParsed:N0}</td><td class=\"num\">{s.ParseFailures:N0}</td>")
              .Append($"<td>{E(FormatUtc(s.MinUtc))} → {E(FormatUtc(s.MaxUtc))}</td><td class=\"num\">{s.UnreadableFiles.Count:N0}</td></tr>");
        }

        sb.Append("</table>");
    }

    private static void AppendHits(StringBuilder sb, List<IocSweepTargetResult> hits)
    {
        sb.Append("<h2>Targets with hits</h2>");
        if (hits.Count == 0)
        {
            sb.Append("<p>None of the targets appear in the scope above.</p>");
            return;
        }

        sb.Append("<table><tr><th>Target</th><th>Type</th><th class=\"num\">Hits</th><th>First seen</th><th>Last seen</th>")
          .Append("<th>Matched IPs</th><th>Top paths</th><th>Status codes</th><th>Sources</th></tr>");
        foreach (var t in hits)
        {
            sb.Append($"<tr><td>{E(t.Target.Text)}</td><td>{TargetKind(t.Target)}</td><td class=\"num hit\">{t.Hits:N0}</td>")
              .Append($"<td>{E(FormatUtc(t.FirstSeenUtc))}</td><td>{E(FormatUtc(t.LastSeenUtc))}</td>")
              .Append($"<td>{E(FormatTop(t.MatchedIps, 5))}</td><td>{E(FormatTop(t.Uris, 5))}</td>")
              .Append($"<td>{E(FormatTop(t.Statuses, 5))}</td><td>{E(FormatTop(t.HitsBySource, 10))}</td></tr>");
        }

        sb.Append("</table>");
    }

    private static void AppendMisses(StringBuilder sb, List<IocSweepTargetResult> misses)
    {
        sb.Append("<h2>Targets without hits</h2>");
        sb.Append(misses.Count == 0
            ? "<p>Every target has at least one hit.</p>"
            : $"<p>{E(string.Join(", ", misses.Select(m => m.Target.Text)))}</p>");
    }

    public static void WriteExcel(IocSweepResult result, string path)
    {
        using var wb = new XLWorkbook();

        var summary = wb.Worksheets.Add("Targets");
        WriteRow(summary, 1, "Target", "Type", "Hits", "First seen (UTC)", "Last seen (UTC)", "Distinct IPs", "Top paths", "Status codes", "Sources");
        var row = 2;
        foreach (var t in result.Targets.OrderByDescending(t => t.Hits).ThenBy(t => t.Target.Text, StringComparer.Ordinal))
        {
            WriteRow(summary, row++, t.Target.Text, TargetKind(t.Target), t.Hits, FormatUtc(t.FirstSeenUtc), FormatUtc(t.LastSeenUtc),
                t.MatchedIps.Count, FormatTop(t.Uris, 10), FormatTop(t.Statuses, 10), FormatTop(t.HitsBySource, 20));
        }

        var ips = wb.Worksheets.Add("Matched IPs");
        WriteRow(ips, 1, "Target", "Matched IP", "Hits");
        row = 2;
        foreach (var t in result.Targets.Where(t => t.Hits > 0))
            foreach (var kv in Top(t.MatchedIps, IocSweepTargetResult.MaxDistinctKeys))
                WriteRow(ips, row++, t.Target.Text, kv.Key, kv.Value);

        var uris = wb.Worksheets.Add("Paths");
        WriteRow(uris, 1, "Target", "Path", "Hits");
        row = 2;
        foreach (var t in result.Targets.Where(t => t.Hits > 0))
            foreach (var kv in Top(t.Uris, 200))
                WriteRow(uris, row++, t.Target.Text, kv.Key, kv.Value);

        var scope = wb.Worksheets.Add("Scope");
        WriteRow(scope, 1, "Source", "ALB files", "IIS files", "Lines", "Records", "Unparsed", "First record (UTC)", "Last record (UTC)", "Unreadable files");
        row = 2;
        foreach (var s in result.Scopes)
        {
            var unreadable = string.Join("; ", s.UnreadableFiles.Select(Path.GetFileName));
            WriteRow(scope, row++, s.Label, s.AlbFiles, s.IisFiles, s.LinesRead, s.RecordsParsed, s.ParseFailures,
                FormatUtc(s.MinUtc), FormatUtc(s.MaxUtc), unreadable);
        }

        var notes = wb.Worksheets.Add("Notes");
        row = 1;
        foreach (var c in Caveats) WriteRow(notes, row++, c);
        if (result.InvalidTokens.Count > 0) WriteRow(notes, row + 1, $"Ignored input: {string.Join(", ", result.InvalidTokens)}");

        foreach (var ws in wb.Worksheets)
        {
            ws.Row(1).Style.Font.Bold = true;
            ws.SheetView.FreezeRows(1);
            ws.Columns().AdjustToContents(1, Math.Min(ws.LastRowUsed()?.RowNumber() ?? 1, 500), 10, 80);
        }

        wb.SaveAs(path);
    }

    // Strings are stored as text cells (ClosedXML never evaluates Value as a formula), so log
    // content such as "=cmd|..." in a URI cannot become a formula.
    private static void WriteRow(IXLWorksheet ws, int row, params object?[] values)
    {
        for (var i = 0; i < values.Length; i++)
        {
            var cell = ws.Cell(row, i + 1);
            switch (values[i])
            {
                case long l: cell.Value = l; break;
                case int n: cell.Value = n; break;
                case null: break;
                default: cell.Value = values[i]!.ToString() ?? ""; break;
            }
        }
    }

    private static string E(string? value) => WebUtility.HtmlEncode(value ?? "");
}
