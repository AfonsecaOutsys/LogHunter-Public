using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static partial class AlbOptions
{
    // ---------- OPTION 3 ----------
    private const string IpSummaryThresholdPrompt =
        "1M rows have been processed so far, continuing means there will be no Excel export only the Charts View and summary, proceed with SQLite for deep analysis?";

    public static async Task IpSummaryAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: IP Summary",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
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

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        Directory.CreateDirectory(outputFolder);
        var sanitizedIp = SanitizeFileComponent(requestedIp.ToString());
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var excelPath = Path.Combine(outputFolder, $"alb_ip_summary_{sanitizedIp}_{stamp}.xlsx");
        var sqlitePath = Path.Combine(outputFolder, $"alb_ip_summary_{sanitizedIp}_{stamp}.db");

        InfoPanel("Scan plan",
            ("Mode", "IP summary with 1-minute ELB/FE response chart + external detail export"),
            ("Client IP", requestedIp.ToString()),
            ("Files", files.Count.ToString("N0", CultureInfo.InvariantCulture)),
            ("Input", albFolder),
            ("Excel threshold", "Rows < 1,000,000"),
            ("1M-row behavior", "Prompt once for optional SQLite deep analysis"),
            ("Output", outputFolder));

        using var result = new AlbIpSummaryScanner.ScanResult(requestedIp.ToString(), sqlitePath);
        await ScanIpSummaryWithPhasedProgressAsync(files, requestedIp, result);

        result.CompleteStreamingExports();

        if (result.TotalRows == 0)
        {
            ConsoleEx.Warn($"No ALB hits found for IP: {requestedIp}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        string? detailExportPath = null;
        string? detailExportKind = null;
        if (result.TotalRows < AlbIpSummaryScanner.ExcelRowThreshold)
        {
            result.Rows.Sort((a, b) => a.TimestampUtc.CompareTo(b.TimestampUtc));
            AlbIpSummaryExportExcel.Export(excelPath, result);
            detailExportPath = excelPath;
            detailExportKind = "Excel";
        }
        else if (result.DetailMode == AlbIpSummaryScanner.DetailRetentionMode.SqliteApproved)
        {
            detailExportPath = sqlitePath;
            detailExportKind = "SQLite";
        }

        var htmlPath = BuildIpSummaryReport(outputFolder, result, detailExportKind, detailExportPath, sanitizedIp);

        if (TryOpenFile(htmlPath))
            ConsoleEx.Success($"HTML report opened: {htmlPath}");
        else
            ConsoleEx.Success($"HTML report generated: {htmlPath}");

        if (detailExportKind == "SQLite")
        {
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

    private static AlbIpSummaryScanner.DetailRetentionMode PromptForIpSummaryDetailMode()
        => ConsoleEx.ReadYesNo(IpSummaryThresholdPrompt, defaultYes: true)
            ? AlbIpSummaryScanner.DetailRetentionMode.SqliteApproved
            : AlbIpSummaryScanner.DetailRetentionMode.SummaryOnly;

    private static async Task ScanIpSummaryWithPhasedProgressAsync(
        List<string> files,
        IPAddress requestedIp,
        AlbIpSummaryScanner.ScanResult result)
    {
        int nextFileIndex = 0;
        while (nextFileIndex < files.Count)
        {
            nextFileIndex = await RunIpSummaryScanPhaseAsync(files, nextFileIndex, requestedIp, result);

            if (!result.ThresholdPromptPending)
                continue;

            result.ApplyThresholdDecision(PromptForIpSummaryDetailMode());
        }
    }

    private static async Task<int> RunIpSummaryScanPhaseAsync(
        List<string> files,
        int startIndex,
        IPAddress requestedIp,
        AlbIpSummaryScanner.ScanResult result)
    {
        int nextFileIndex = startIndex;

        await AnsiConsole.Status()
            .AutoRefresh(true)
            .Spinner(Spinner.Known.Dots)
            .StartAsync(
                BuildIpSummaryStatusText(startIndex + 1, files.Count, files[startIndex], result.DetailMode),
                async ctx =>
            {
                for (int i = startIndex; i < files.Count; i++)
                {
                    ctx.Status(BuildIpSummaryStatusText(i + 1, files.Count, files[i], result.DetailMode));

                    await AlbIpSummaryScanner.ScanFileAsync(
                        filePath: files[i],
                        requestedIp: requestedIp,
                        result: result,
                        reportBytesDelta: _ => { }).ConfigureAwait(false);

                    nextFileIndex = i + 1;
                    if (result.ThresholdPromptPending)
                        break;
                }
            });

        AnsiConsole.WriteLine();
        return nextFileIndex;
    }

    private static string BuildIpSummaryStatusText(
        int currentFileIndex,
        int totalFiles,
        string filePath,
        AlbIpSummaryScanner.DetailRetentionMode mode)
    {
        var modeLabel = mode switch
        {
            AlbIpSummaryScanner.DetailRetentionMode.SummaryOnly => "summary-only",
            AlbIpSummaryScanner.DetailRetentionMode.SqliteApproved => "detail+summary (SQLite)",
            _ => "detail+summary"
        };

        var fileName = Path.GetFileName(filePath);
        if (string.IsNullOrWhiteSpace(fileName))
            fileName = filePath;

        fileName = TruncateProgressText(fileName, 48);

        return $"Scanning ALB logs (IP summary): file {currentFileIndex.ToString(CultureInfo.InvariantCulture)} of {totalFiles.ToString(CultureInfo.InvariantCulture)} | {modeLabel} | {Markup.Escape(fileName)}";
    }

    private static string TruncateProgressText(string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            return value;

        if (maxLength <= 3)
            return value[..maxLength];

        return value[..(maxLength - 3)] + "...";
    }

    private static string BuildIpSummaryReport(
        string outputFolder,
        AlbIpSummaryScanner.ScanResult result,
        string? detailExportKind,
        string? detailExportPath,
        string sanitizedIp)
    {
        var series = BuildIpSummarySeries(result);
        var htmlPath = Charts.SaveTimeSeriesHtml(
            outputFolder: outputFolder,
            title: $"ALB IP Summary: {result.RequestedIp}",
            yLabel: "Requests per minute",
            series: series,
            filePrefix: $"alb_ip_summary_{sanitizedIp}");

        var html = File.ReadAllText(htmlPath);
        html = html.Replace("\r\n", "\n", StringComparison.Ordinal);
        html = html.Replace("Filter IP...", "Filter series...", StringComparison.Ordinal);
        html = html.Replace(
            "<th>IP</th><th>Source hits</th><th>Total requests</th><th>Peak (5 min)</th><th>Visible</th>",
            $"<th>{TitleTooltipHtml("Series", "The chart line or metric represented in this report.")}</th><th>{TitleTooltipHtml("Total requests", "Total number of matching requests counted for this series across the full scan.")}</th><th>{TitleTooltipHtml("Peak bucket", "Highest number of requests seen for this series in a single time bucket on the chart.")}</th><th>{TitleTooltipHtml("Peak time (UTC)", "UTC timestamp of the highest bucket value for this series.")}</th><th>{TitleTooltipHtml("Visible", "Whether this series is currently shown or hidden on the chart.")}</th>",
            StringComparison.Ordinal);
        html = html.Replace(
            "function buildSummary(){",
            @"function getPeakTimeUtc(s){
  let peakIndex = -1;
  let peakValue = Number.NEGATIVE_INFINITY;
  for (let idx = 0; idx < s.y.length; idx++) {
    const value = s.y[idx];
    if (value > peakValue) {
      peakValue = value;
      peakIndex = idx;
    }
  }
  if (peakIndex < 0 || !Number.isFinite(peakValue)) return '—';
  return fmtUtc(T[peakIndex]);
}

function buildSummary(){",
            StringComparison.Ordinal);
        html = html.Replace(
            "      `<td>${s.sourceHits == null ? '—' : Number(s.sourceHits).toLocaleString('en-US')}</td>` +\n      `<td>${fmtNum(s.total)}</td>` +\n      `<td>${fmtNum(s.peak)}</td>` +\n      `<td>${s.visible ? 'Shown' : 'Hidden'}</td>`;",
            "      `<td>${fmtNum(s.total)}</td>` +\n      `<td>${fmtNum(s.peak)}</td>` +\n      `<td>${getPeakTimeUtc(s)}</td>` +\n      `<td>${s.visible ? 'Shown' : 'Hidden'}</td>`;",
            StringComparison.Ordinal);

        var summaryHtml = BuildSummarySectionHtml(result, detailExportKind, detailExportPath);
        html = html.Replace("</body>", summaryHtml + Environment.NewLine + "</body>", StringComparison.OrdinalIgnoreCase);
        File.WriteAllText(htmlPath, html, Encoding.UTF8);

        return htmlPath;
    }

    private static List<Charts.TimeSeriesSeries> BuildIpSummarySeries(AlbIpSummaryScanner.ScanResult result)
    {
        var start = result.FirstHitUtc!.Value;
        var end = result.LastHitUtc!.Value;
        start = new DateTime(start.Year, start.Month, start.Day, start.Hour, start.Minute, 0, DateTimeKind.Utc);
        end = new DateTime(end.Year, end.Month, end.Day, end.Hour, end.Minute, 0, DateTimeKind.Utc);

        var points = (int)Math.Max(1, (end - start).TotalMinutes + 1);
        var times = new DateTime[points];
        var elb2xx3xx = new double[points];
        var elb4xx = new double[points];
        var elb5xx = new double[points];
        var fe2xx3xx = new double[points];
        var fe4xx = new double[points];
        var fe5xx = new double[points];

        for (int i = 0; i < points; i++)
        {
            var bucketUtc = start.AddMinutes(i);
            times[i] = bucketUtc;

            if (!result.BucketsByMinuteUtc.TryGetValue(bucketUtc, out var bucket))
                continue;

            elb2xx3xx[i] = bucket.Elb.S2xx + bucket.Elb.S3xx;
            elb4xx[i] = bucket.Elb.S4xx;
            elb5xx[i] = bucket.Elb.S5xx;
            fe2xx3xx[i] = bucket.Fe.S2xx + bucket.Fe.S3xx;
            fe4xx[i] = bucket.Fe.S4xx;
            fe5xx[i] = bucket.Fe.S5xx;
        }

        return new List<Charts.TimeSeriesSeries>
        {
            BuildSeries("ELB Response 2xx/3xx", times, elb2xx3xx),
            BuildSeries("ELB Response 4xx", times, elb4xx),
            BuildSeries("ELB Response 5xx", times, elb5xx),
            BuildSeries("FE Response 2xx/3xx", times, fe2xx3xx),
            BuildSeries("FE Response 4xx", times, fe4xx),
            BuildSeries("FE Response 5xx", times, fe5xx)
        };
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

        return new Charts.TimeSeriesSeries(
            SeriesName: name,
            TimesUtc: timesUtc,
            Values: values,
            SourceHits: (long)total,
            TotalRequests: total,
            PeakBucket: peak);
    }

    private static string BuildSummarySectionHtml(
        AlbIpSummaryScanner.ScanResult result,
        string? detailExportKind,
        string? detailExportPath)
    {
        var firstHit = result.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
        var lastHit = result.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";

        var sb = new StringBuilder(32 * 1024);
        sb.AppendLine("<style>");
        sb.AppendLine(@"
.summary-grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:12px; }
.summary-card { margin-top:12px; background:#0f1620; border:1px solid rgba(255,255,255,.08); border-radius:14px; padding:12px; box-shadow: 0 12px 28px rgba(0,0,0,.35); }
.summary-title { font-size:16px; font-weight:600; margin:0 0 8px 0; }
.summary-subtitle { font-size:13px; font-weight:600; margin:0 0 8px 0; }
.summary-table { width:100%; border-collapse: collapse; font-size:12px; }
.summary-table th, .summary-table td { padding:6px 8px; border-bottom:1px solid rgba(255,255,255,.07); text-align:left; vertical-align:top; }
.summary-table th:last-child, .summary-table td:last-child { text-align:right; }
.summary-note { font-size:12px; opacity:.8; line-height:1.45; }
.summary-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break:break-word; }
.lh-tip, .lh-tip-inline { display:inline-flex; align-items:center; gap:6px; cursor:help; border-bottom:1px dotted rgba(255,255,255,.28); text-decoration:none; }
.lh-tip { position:relative; }
.lh-tip:focus-visible, .lh-tip-inline:focus-visible { outline:none; border-bottom-color:rgba(125,211,252,.5); }
.lh-tip::after { content:attr(data-tip); position:absolute; left:0; bottom:calc(100% + 8px); min-width:180px; max-width:280px; padding:6px 8px; border-radius:8px; border:1px solid rgba(255,255,255,.12); background:#111926; color:#e6edf3; box-shadow:0 12px 28px rgba(0,0,0,.35); font-size:11px; font-weight:400; line-height:1.35; white-space:normal; opacity:0; pointer-events:none; transform:translateY(4px); transition:opacity .12s ease, transform .12s ease; z-index:30; }
.lh-tip::before { content:''; position:absolute; left:14px; bottom:calc(100% + 2px); border:6px solid transparent; border-top-color:#111926; opacity:0; pointer-events:none; transform:translateY(4px); transition:opacity .12s ease, transform .12s ease; z-index:30; }
.lh-tip:hover::after, .lh-tip:hover::before, .lh-tip:focus-visible::after, .lh-tip:focus-visible::before { opacity:1; transform:translateY(0); }
.lh-tip-icon { font-size:11px; line-height:1; color:rgba(230,237,243,.58); transition:color .12s ease, transform .12s ease; }
.lh-tip:hover .lh-tip-icon, .lh-tip:focus-visible .lh-tip-icon, .lh-tip-inline:hover .lh-tip-icon, .lh-tip-inline:focus-visible .lh-tip-icon { color:#cbd5e1; transform:translateY(-1px); }
");
        sb.AppendLine("</style>");
        sb.AppendLine("<div class=\"wrap\">");
        sb.AppendLine("  <div class=\"summary-card\">");
        sb.AppendLine($"    <div class=\"summary-title\">{TooltipHtml("IP summary", "High-level context for this IP across the scanned ALB logs.")}</div>");
        sb.AppendLine("    <div class=\"row\">");
        sb.AppendLine($"      <div class=\"pill\">Requested IP: {Html(result.RequestedIp)}</div>");
        sb.AppendLine($"      <div class=\"pill\">Total matching requests: {result.TotalRows.ToString("N0", CultureInfo.InvariantCulture)}</div>");
        sb.AppendLine($"      <div class=\"pill\">Files with hits: {result.SourceFiles.Count.ToString("N0", CultureInfo.InvariantCulture)}</div>");
        sb.AppendLine($"      <div class=\"pill\">Time range: {Html(firstHit ?? "-")} → {Html(lastHit ?? "-")}</div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("    <div class=\"summary-grid\">");
        sb.AppendLine(BuildStatusTableHtml("ELB Response totals", result.ElbResponseTotals));
        sb.AppendLine(BuildStatusTableHtml("FE Response totals", result.FeResponseTotals));
        sb.AppendLine(BuildMismatchCardHtml(result));
        sb.AppendLine(BuildExportCardHtml(result, detailExportKind, detailExportPath));
        sb.AppendLine(BuildTopTableHtml(
            "Top 10 FE endpoints",
            "FE endpoint",
            result.TopTargetEndpoints(10),
            "The backend endpoints most frequently reached by requests from this IP."));
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");
        return sb.ToString();
    }

    private static string BuildStatusTableHtml(string title, AlbIpSummaryScanner.StatusGroupCounts counts)
    {
        var tooltip = title.StartsWith("ELB Response", StringComparison.Ordinal)
            ? "ELB Response status classes returned to the end user for this IP."
            : "Front-End Response status classes returned by the backend or server for this IP.";

        var sb = new StringBuilder();
        sb.AppendLine("<div class=\"summary-card\">");
        sb.AppendLine($"  <div class=\"summary-subtitle\">{TooltipHtml(title, tooltip)}</div>");
        sb.AppendLine("  <table class=\"summary-table\">");
        sb.AppendLine("    <tr><th>Class</th><th>Hits</th></tr>");
        sb.AppendLine($"    <tr><td>2xx/3xx</td><td>{(counts.S2xx + counts.S3xx).ToString("N0", CultureInfo.InvariantCulture)}</td></tr>");
        sb.AppendLine($"    <tr><td>4xx</td><td>{counts.S4xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>");
        sb.AppendLine($"    <tr><td>5xx</td><td>{counts.S5xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>");
        sb.AppendLine("  </table>");
        sb.AppendLine("</div>");
        return sb.ToString();
    }

    private static string BuildMismatchCardHtml(AlbIpSummaryScanner.ScanResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<div class=\"summary-card\" style=\"border-color: rgba(245, 158, 11, .45);\">");
        sb.AppendLine($"  <div class=\"summary-subtitle\">{TooltipHtml("⭐ Interesting Mismatches", "Counts of cases where ELB Response and Front-End Response differ in a meaningful way for investigation.")}</div>");
        sb.AppendLine("  <table class=\"summary-table\">");
        sb.AppendLine("    <tr><th>Signal</th><th>Hits</th></tr>");
        sb.AppendLine($"    <tr><td>FE Response 5xx while ELB Response is 2xx/3xx</td><td>{result.Fe5xxWhileElb2xx3xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>");
        sb.AppendLine($"    <tr><td>FE Response 4xx while ELB Response is 2xx/3xx</td><td>{result.Fe4xxWhileElb2xx3xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>");
        sb.AppendLine($"    <tr><td>ELB Response 5xx while FE Response is 2xx/3xx</td><td>{result.Elb5xxWhileFe2xx3xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>");
        sb.AppendLine($"    <tr><td>ELB Response 4xx while FE Response is 2xx/3xx</td><td>{result.Elb4xxWhileFe2xx3xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>");
        sb.AppendLine("  </table>");
        sb.AppendLine("</div>");
        return sb.ToString();
    }

    private static string BuildTopTableHtml(
        string title,
        string label,
        IReadOnlyList<KeyValuePair<string, int>> items,
        string? titleTooltip = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<div class=\"summary-card\">");
        sb.AppendLine($"  <div class=\"summary-subtitle\">{(string.IsNullOrWhiteSpace(titleTooltip) ? Html(title) : TooltipHtml(title, titleTooltip))}</div>");
        sb.AppendLine("  <table class=\"summary-table\">");
        sb.AppendLine($"    <tr><th>{Html(label)}</th><th>Hits</th></tr>");

        if (items.Count == 0)
        {
            sb.AppendLine("    <tr><td>(none)</td><td>0</td></tr>");
        }
        else
        {
            foreach (var item in items)
                sb.AppendLine($"    <tr><td class=\"summary-mono\">{Html(item.Key)}</td><td>{item.Value.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>");
        }

        sb.AppendLine("  </table>");
        sb.AppendLine("</div>");
        return sb.ToString();
    }

    private static string BuildExportCardHtml(
        AlbIpSummaryScanner.ScanResult result,
        string? detailExportKind,
        string? detailExportPath)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<div class=\"summary-card\">");
        sb.AppendLine($"  <div class=\"summary-subtitle\">{TooltipHtml("Detailed export", "Where the full request-level export was written, if a detailed export was generated.")}</div>");

        if (string.IsNullOrWhiteSpace(detailExportKind) || string.IsNullOrWhiteSpace(detailExportPath))
        {
            if (result.DetailMode == AlbIpSummaryScanner.DetailRetentionMode.SummaryOnly)
            {
                sb.AppendLine("  <div class=\"summary-note\">Charts View and summary were completed for the full scan. Detailed export was intentionally skipped after the 1M-row prompt.</div>");
            }
            else
            {
                sb.AppendLine("  <div class=\"summary-note\">No detailed export was generated.</div>");
            }
        }
        else
        {
            sb.AppendLine($"  <div class=\"summary-note\">Full request detail was written to <strong>{Html(detailExportKind)}</strong> using the option 3 threshold rule.</div>");
            sb.AppendLine($"  <div class=\"summary-note summary-mono\" style=\"margin-top:8px\">{Html(detailExportPath)}</div>");
        }

        sb.AppendLine("</div>");
        return sb.ToString();
    }

    private static string TooltipHtml(string text, string tooltip)
        => $"<span class=\"lh-tip\" data-tip=\"{Html(tooltip)}\" tabindex=\"0\"><span class=\"lh-tip-label\">{Html(text)}</span><span class=\"lh-tip-icon\" aria-hidden=\"true\">ⓘ</span></span>";

    private static string TitleTooltipHtml(string text, string tooltip)
        => $"<span class=\"lh-tip-inline\" title=\"{Html(tooltip)}\" tabindex=\"0\"><span class=\"lh-tip-label\">{Html(text)}</span><span class=\"lh-tip-icon\" aria-hidden=\"true\">ⓘ</span></span>";

    private static bool TryOpenFile(string filePath)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = filePath,
                UseShellExecute = true
            });
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
        => (value ?? string.Empty)
            .Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal)
            .Replace("\"", "&quot;", StringComparison.Ordinal);
}
