using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static class IisOption_IpSummary
{
    private const string IpSummaryThresholdPrompt =
        "1M rows have been processed so far, continuing means there will be no Excel export only the Charts View and summary, proceed with SQLite for deep analysis?";

    public static async Task RunAsync(string root, CancellationToken ct = default)
    {
        var iisFolder = AppFolders.IIS;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("IIS: IP Summary", $"Reading logs from: {iisFolder}");

        if (!Directory.Exists(iisFolder))
        {
            ConsoleEx.Error($"IIS folder not found: {iisFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var input = ConsoleEx.ReadLineWithEsc("Client IP to summarize:");
        if (input is null)
            return;

        input = input.Trim();
        if (!IPAddress.TryParse(input, out var requestedIp))
        {
            ConsoleEx.Error($"Invalid IP address: {input}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = IisW3cReader.EnumerateLogFiles(iisFolder);
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No IIS logs found in: {iisFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        Directory.CreateDirectory(outputFolder);
        var sanitizedIp = SanitizeFileComponent(requestedIp.ToString());
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var excelPath = Path.Combine(outputFolder, $"iis_ip_summary_{sanitizedIp}_{stamp}.xlsx");
        var sqlitePath = Path.Combine(outputFolder, $"iis_ip_summary_{sanitizedIp}_{stamp}.db");

        InfoPanel("Scan plan",
            ("Mode", "IP summary with 1-minute status chart + external detail export"),
            ("Client IP", requestedIp.ToString()),
            ("Files", files.Count.ToString("N0", CultureInfo.InvariantCulture)),
            ("Input", iisFolder),
            ("Excel threshold", "Rows < 1,000,000"),
            ("1M-row behavior", "Prompt once for optional SQLite deep analysis"),
            ("Output", outputFolder));

        using var result = new IisIpSummaryScanner.ScanResult(requestedIp.ToString(), sqlitePath);
        await ScanWithPhasedProgressAsync(files, requestedIp, result, ct).ConfigureAwait(false);
        result.CompleteStreamingExports();

        if (result.TotalRows == 0)
        {
            ConsoleEx.Warn($"No IIS hits found for IP: {requestedIp}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        string? detailExportPath = null;
        string? detailExportKind = null;
        if (result.TotalRows < IisIpSummaryScanner.ExcelRowThreshold)
        {
            result.Rows.Sort((a, b) => a.TimestampUtc.CompareTo(b.TimestampUtc));
            IisIpSummaryExportExcel.Export(excelPath, result);
            detailExportPath = excelPath;
            detailExportKind = "Excel";
        }
        else if (result.DetailMode == IisIpSummaryScanner.DetailRetentionMode.SqliteApproved)
        {
            detailExportPath = sqlitePath;
            detailExportKind = "SQLite";
        }

        var htmlPath = BuildReport(outputFolder, result, detailExportKind, detailExportPath, sanitizedIp);

        if (TryOpenFile(htmlPath))
            ConsoleEx.Success($"HTML report opened: {htmlPath}");
        else
            ConsoleEx.Success($"HTML report generated: {htmlPath}");

        if (detailExportKind == "SQLite")
        {
            ConsoleEx.Success($"SQLite deep analysis database created: {detailExportPath}");
            ConsoleEx.Success("Launching local viewer...");
            if (IisIpSummarySqliteViewerLauncher.Launch(detailExportPath!, result.RequestedIp))
                ConsoleEx.Success("Local SQLite viewer launched in a separate LogHunter process.");
            else
                ConsoleEx.Warn("SQLite viewer could not be launched automatically. Open it manually with --viewer-sqlite <path>.");

            ConsoleEx.Success($"Charts View and summary generated from the full scan, and SQLite deep-analysis output was generated: {detailExportPath}");
        }
        else if (detailExportKind == "Excel")
        {
            ConsoleEx.Success($"Detailed export generated as Excel: {detailExportPath}");
        }
        else
        {
            ConsoleEx.Success("Charts View and summary were generated from the full scan.");
            ConsoleEx.Success("Detailed export was intentionally skipped by user choice after the 1M-row prompt.");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    private static IisIpSummaryScanner.DetailRetentionMode PromptForDetailMode()
        => ConsoleEx.ReadYesNo(IpSummaryThresholdPrompt, defaultYes: true)
            ? IisIpSummaryScanner.DetailRetentionMode.SqliteApproved
            : IisIpSummaryScanner.DetailRetentionMode.SummaryOnly;

    private static async Task ScanWithPhasedProgressAsync(List<string> files, IPAddress requestedIp, IisIpSummaryScanner.ScanResult result, CancellationToken ct)
    {
        int nextFileIndex = 0;
        while (nextFileIndex < files.Count)
        {
            nextFileIndex = await RunScanPhaseAsync(files, nextFileIndex, requestedIp, result, ct).ConfigureAwait(false);
            if (result.ThresholdPromptPending)
                result.ApplyThresholdDecision(PromptForDetailMode());
        }
    }

    private static async Task<int> RunScanPhaseAsync(List<string> files, int startIndex, IPAddress requestedIp, IisIpSummaryScanner.ScanResult result, CancellationToken ct)
    {
        int nextFileIndex = startIndex;

        await AnsiConsole.Status().AutoRefresh(true).Spinner(Spinner.Known.Dots).StartAsync(BuildStatusText(startIndex + 1, files.Count, files[startIndex], result.DetailMode), async ctx =>
        {
            for (int i = startIndex; i < files.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                ctx.Status(BuildStatusText(i + 1, files.Count, files[i], result.DetailMode));
                await IisIpSummaryScanner.ScanFileAsync(files[i], requestedIp, result, ct).ConfigureAwait(false);
                nextFileIndex = i + 1;
                if (result.ThresholdPromptPending)
                    break;
            }
        }).ConfigureAwait(false);

        AnsiConsole.WriteLine();
        return nextFileIndex;
    }

    private static string BuildStatusText(int currentFileIndex, int totalFiles, string filePath, IisIpSummaryScanner.DetailRetentionMode mode)
    {
        var modeLabel = mode switch
        {
            IisIpSummaryScanner.DetailRetentionMode.SummaryOnly => "summary-only",
            IisIpSummaryScanner.DetailRetentionMode.SqliteApproved => "detail+summary (SQLite)",
            _ => "detail+summary"
        };

        var fileName = Path.GetFileName(filePath);
        if (string.IsNullOrWhiteSpace(fileName))
            fileName = filePath;

        fileName = TruncateProgressText(fileName, 48);
        return $"Scanning IIS logs (IP summary): file {currentFileIndex.ToString(CultureInfo.InvariantCulture)} of {totalFiles.ToString(CultureInfo.InvariantCulture)} | {modeLabel} | {Markup.Escape(fileName)}";
    }

    private static string BuildReport(string outputFolder, IisIpSummaryScanner.ScanResult result, string? detailExportKind, string? detailExportPath, string sanitizedIp)
    {
        var htmlPath = Charts.SaveTimeSeriesHtml(outputFolder, $"IIS IP Summary: {result.RequestedIp}", "Requests per minute", BuildSeries(result), $"iis_ip_summary_{sanitizedIp}");

        var html = File.ReadAllText(htmlPath);
        html = html.Replace("\r\n", "\n", StringComparison.Ordinal);
        html = html.Replace("Filter IP...", "Filter series...", StringComparison.Ordinal);
        html = html.Replace("<th>IP</th><th>Source hits</th><th>Total requests</th><th>Peak (5 min)</th><th>Visible</th>", "<th>Series</th><th>Total requests</th><th>Peak bucket</th><th>Peak time (UTC)</th><th>Visible</th>", StringComparison.Ordinal);
        html = html.Replace("function buildSummary(){", @"function getPeakTimeUtc(s){let peakIndex=-1;let peakValue=Number.NEGATIVE_INFINITY;for(let idx=0;idx<s.y.length;idx++){const value=s.y[idx];if(value>peakValue){peakValue=value;peakIndex=idx;}}if(peakIndex<0||!Number.isFinite(peakValue)) return '-';return fmtUtc(T[peakIndex]);} function buildSummary(){", StringComparison.Ordinal);
        html = html.Replace("      `<td>${s.sourceHits == null ? '—' : Number(s.sourceHits).toLocaleString('en-US')}</td>` +\n      `<td>${fmtNum(s.total)}</td>` +\n      `<td>${fmtNum(s.peak)}</td>` +\n      `<td>${s.visible ? 'Shown' : 'Hidden'}</td>`;", "      `<td>${fmtNum(s.total)}</td>` +\n      `<td>${fmtNum(s.peak)}</td>` +\n      `<td>${getPeakTimeUtc(s)}</td>` +\n      `<td>${s.visible ? 'Shown' : 'Hidden'}</td>`;", StringComparison.Ordinal);
        html = html.Replace("</body>", BuildSummarySectionHtml(result, detailExportKind, detailExportPath) + Environment.NewLine + "</body>", StringComparison.OrdinalIgnoreCase);
        File.WriteAllText(htmlPath, html, Encoding.UTF8);
        return htmlPath;
    }

    private static List<Charts.TimeSeriesSeries> BuildSeries(IisIpSummaryScanner.ScanResult result)
    {
        var start = result.FirstHitUtc!.Value;
        var end = result.LastHitUtc!.Value;
        start = new DateTime(start.Year, start.Month, start.Day, start.Hour, start.Minute, 0, DateTimeKind.Utc);
        end = new DateTime(end.Year, end.Month, end.Day, end.Hour, end.Minute, 0, DateTimeKind.Utc);

        var points = (int)Math.Max(1, (end - start).TotalMinutes + 1);
        var times = new DateTime[points];
        var s2xx3xx = new double[points];
        var s4xx = new double[points];
        var s5xx = new double[points];

        for (int i = 0; i < points; i++)
        {
            var bucketUtc = start.AddMinutes(i);
            times[i] = bucketUtc;
            if (!result.BucketsByMinuteUtc.TryGetValue(bucketUtc, out var bucket))
                continue;

            s2xx3xx[i] = bucket.S2xx + bucket.S3xx;
            s4xx[i] = bucket.S4xx;
            s5xx[i] = bucket.S5xx;
        }

        return
        [
            BuildSeries("HTTP 2xx/3xx", times, s2xx3xx),
            BuildSeries("HTTP 4xx", times, s4xx),
            BuildSeries("HTTP 5xx", times, s5xx)
        ];
    }

    private static Charts.TimeSeriesSeries BuildSeries(string name, DateTime[] timesUtc, double[] values)
    {
        double total = 0;
        double peak = 0;
        for (int i = 0; i < values.Length; i++)
        {
            total += values[i];
            if (values[i] > peak)
                peak = values[i];
        }

        return new Charts.TimeSeriesSeries(name, timesUtc, values, (long)total, total, peak);
    }

    private static string BuildSummarySectionHtml(IisIpSummaryScanner.ScanResult result, string? detailExportKind, string? detailExportPath)
    {
        var firstHit = result.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
        var lastHit = result.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
        var sb = new StringBuilder(24 * 1024);
        sb.AppendLine("<style>.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}.summary-card{margin-top:12px;background:#0f1620;border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:12px;box-shadow:0 12px 28px rgba(0,0,0,.35)}.summary-title{font-size:16px;font-weight:600;margin:0 0 8px 0}.summary-subtitle{font-size:13px;font-weight:600;margin:0 0 8px 0}.summary-table{width:100%;border-collapse:collapse;font-size:12px}.summary-table th,.summary-table td{padding:6px 8px;border-bottom:1px solid rgba(255,255,255,.07);text-align:left;vertical-align:top}.summary-table th:last-child,.summary-table td:last-child{text-align:right}.summary-note{font-size:12px;opacity:.8;line-height:1.45}.summary-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-word}</style>");
        sb.AppendLine("<div class=\"wrap\"><div class=\"summary-card\"><div class=\"summary-title\">IIS IP summary</div><div class=\"row\">");
        sb.AppendLine($"<div class=\"pill\">Requested IP: {Html(result.RequestedIp)}</div><div class=\"pill\">Total matching requests: {result.TotalRows.ToString("N0", CultureInfo.InvariantCulture)}</div><div class=\"pill\">Files with hits: {result.SourceFiles.Count.ToString("N0", CultureInfo.InvariantCulture)}</div><div class=\"pill\">Time range: {Html(firstHit ?? "-")} -> {Html(lastHit ?? "-")}</div>");
        sb.AppendLine("</div><div class=\"summary-grid\">");
        sb.AppendLine(BuildStatusTableHtml(result.StatusTotals));
        sb.AppendLine(BuildLatencyCardHtml(result));
        sb.AppendLine(BuildExportCardHtml(result, detailExportKind, detailExportPath));
        sb.AppendLine(BuildTopTableHtml("Top 10 URIs", "URI", result.TopUris(10)));
        sb.AppendLine(BuildTopTableHtml("Top 10 methods", "Method", result.TopMethods(10)));
        sb.AppendLine(BuildTopTableHtml("Top exact status codes", "Status", result.TopExactStatuses(10)));
        sb.AppendLine("</div></div></div>");
        return sb.ToString();
    }

    private static string BuildStatusTableHtml(IisIpSummaryScanner.StatusGroupCounts counts)
        => $"<div class=\"summary-card\"><div class=\"summary-subtitle\">HTTP status totals</div><table class=\"summary-table\"><tr><th>Class</th><th>Hits</th></tr><tr><td>2xx/3xx</td><td>{(counts.S2xx + counts.S3xx).ToString("N0", CultureInfo.InvariantCulture)}</td></tr><tr><td>4xx</td><td>{counts.S4xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr><tr><td>5xx</td><td>{counts.S5xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr></table></div>";

    private static string BuildLatencyCardHtml(IisIpSummaryScanner.ScanResult result)
        => $"<div class=\"summary-card\"><div class=\"summary-subtitle\">Latency and bytes</div><table class=\"summary-table\"><tr><td>Average time-taken</td><td>{result.AverageTimeTakenMs.ToString("N1", CultureInfo.InvariantCulture)} ms</td></tr><tr><td>Max time-taken</td><td>{result.MaxTimeTakenMs.ToString("N0", CultureInfo.InvariantCulture)} ms</td></tr><tr><td>Total cs-bytes</td><td>{result.TotalCsBytes.ToString("N0", CultureInfo.InvariantCulture)}</td></tr><tr><td>Total sc-bytes</td><td>{result.TotalScBytes.ToString("N0", CultureInfo.InvariantCulture)}</td></tr></table></div>";

    private static string BuildTopTableHtml(string title, string label, IReadOnlyList<KeyValuePair<string, int>> items)
    {
        var sb = new StringBuilder();
        sb.Append($"<div class=\"summary-card\"><div class=\"summary-subtitle\">{Html(title)}</div><table class=\"summary-table\"><tr><th>{Html(label)}</th><th>Hits</th></tr>");
        if (items.Count == 0)
            sb.Append("<tr><td>(none)</td><td>0</td></tr>");
        else
            foreach (var item in items)
                sb.Append($"<tr><td class=\"summary-mono\">{Html(item.Key)}</td><td>{item.Value.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>");
        sb.Append("</table></div>");
        return sb.ToString();
    }

    private static string BuildExportCardHtml(IisIpSummaryScanner.ScanResult result, string? detailExportKind, string? detailExportPath)
    {
        if (string.IsNullOrWhiteSpace(detailExportKind) || string.IsNullOrWhiteSpace(detailExportPath))
        {
            var note = result.DetailMode == IisIpSummaryScanner.DetailRetentionMode.SummaryOnly
                ? "Charts View and summary were completed for the full scan. Detailed export was intentionally skipped after the 1M-row prompt."
                : "No detailed export was generated.";
            return $"<div class=\"summary-card\"><div class=\"summary-subtitle\">Detailed export</div><div class=\"summary-note\">{Html(note)}</div></div>";
        }

        return $"<div class=\"summary-card\"><div class=\"summary-subtitle\">Detailed export</div><div class=\"summary-note\">Full request detail was written to <strong>{Html(detailExportKind)}</strong> using the option threshold rule.</div><div class=\"summary-note summary-mono\" style=\"margin-top:8px\">{Html(detailExportPath)}</div></div>";
    }

    private static void InfoPanel(string title, params (string Key, string Value)[] rows)
    {
        var t = new Table().RoundedBorder().AddColumn("Field").AddColumn("Value");
        foreach (var (k, v) in rows)
            t.AddRow(Markup.Escape(k), Markup.Escape(v));
        AnsiConsole.Write(new Panel(t) { Header = new PanelHeader(Markup.Escape(title)), Border = BoxBorder.Rounded });
        AnsiConsole.WriteLine();
    }

    private static string TruncateProgressText(string value, int maxLength)
        => string.IsNullOrEmpty(value) || value.Length <= maxLength ? value : maxLength <= 3 ? value[..maxLength] : value[..(maxLength - 3)] + "...";

    private static bool TryOpenFile(string filePath)
    {
        try
        {
            Process.Start(new ProcessStartInfo { FileName = filePath, UseShellExecute = true });
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string SanitizeFileComponent(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
            sb.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
        return sb.ToString();
    }

    private static string Html(string value)
        => (value ?? string.Empty).Replace("&", "&amp;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal).Replace(">", "&gt;", StringComparison.Ordinal).Replace("\"", "&quot;", StringComparison.Ordinal);
}
