using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static partial class AlbOptions
{
    // ---------- OPTION 3 ----------

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
            ("Mode", "IP summary with 1-minute ALB status chart + external detail export"),
            ("Client IP", requestedIp.ToString()),
            ("Files", files.Count.ToString("N0", CultureInfo.InvariantCulture)),
            ("Input", albFolder),
            ("Excel threshold", "Rows < 1,000,000"),
            ("SQLite threshold", "Rows >= 1,000,000"),
            ("Output", outputFolder));

        using var result = new AlbIpSummaryScanner.ScanResult(requestedIp.ToString(), sqlitePath);

        await RunScanWithProgressAsync(
            title: "Scanning ALB logs (IP summary)",
            files: files,
            scanFileAsync: (file, reportDelta) =>
                AlbIpSummaryScanner.ScanFileAsync(
                    filePath: file,
                    requestedIp: requestedIp,
                    result: result,
                    reportBytesDelta: reportDelta)
        );

        result.CompleteStreamingExports();

        if (result.TotalRows == 0)
        {
            ConsoleEx.Warn($"No ALB hits found for IP: {requestedIp}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        string detailExportPath;
        string detailExportKind;
        if (result.TotalRows < AlbIpSummaryScanner.ExcelRowThreshold)
        {
            result.Rows.Sort((a, b) => a.TimestampUtc.CompareTo(b.TimestampUtc));
            AlbIpSummaryExportExcel.Export(excelPath, result);
            detailExportPath = excelPath;
            detailExportKind = "Excel";
        }
        else
        {
            detailExportPath = sqlitePath;
            detailExportKind = "SQLite";
        }

        var htmlPath = BuildIpSummaryReport(outputFolder, result, detailExportKind, detailExportPath, sanitizedIp);

        if (TryOpenFile(htmlPath))
            ConsoleEx.Success($"HTML report opened: {htmlPath}");
        else
            ConsoleEx.Success($"HTML report generated: {htmlPath}");

        ConsoleEx.Success($"Detailed export generated as {detailExportKind}: {detailExportPath}");
        ConsoleEx.Pause("Press Enter to return...");
    }

    private static string BuildIpSummaryReport(
        string outputFolder,
        AlbIpSummaryScanner.ScanResult result,
        string detailExportKind,
        string detailExportPath,
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
        html = html.Replace("Filter IP...", "Filter series...", StringComparison.Ordinal);
        html = html.Replace(
            "<th>IP</th><th>Source hits</th><th>Total requests</th><th>Peak (5 min)</th><th>Visible</th>",
            "<th>Series</th><th>Source hits</th><th>Total requests</th><th>Peak (bucket)</th><th>Visible</th>",
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
        var elb2xx = new double[points];
        var elb3xx = new double[points];
        var elb4xx = new double[points];
        var elb5xx = new double[points];
        var target2xx = new double[points];
        var target3xx = new double[points];
        var target4xx = new double[points];
        var target5xx = new double[points];

        for (int i = 0; i < points; i++)
        {
            var bucketUtc = start.AddMinutes(i);
            times[i] = bucketUtc;

            if (!result.BucketsByMinuteUtc.TryGetValue(bucketUtc, out var bucket))
                continue;

            elb2xx[i] = bucket.Elb.S2xx;
            elb3xx[i] = bucket.Elb.S3xx;
            elb4xx[i] = bucket.Elb.S4xx;
            elb5xx[i] = bucket.Elb.S5xx;
            target2xx[i] = bucket.Target.S2xx;
            target3xx[i] = bucket.Target.S3xx;
            target4xx[i] = bucket.Target.S4xx;
            target5xx[i] = bucket.Target.S5xx;
        }

        return new List<Charts.TimeSeriesSeries>
        {
            BuildSeries("ELB 2xx", times, elb2xx),
            BuildSeries("ELB 3xx", times, elb3xx),
            BuildSeries("ELB 4xx", times, elb4xx),
            BuildSeries("ELB 5xx", times, elb5xx),
            BuildSeries("Target 2xx", times, target2xx),
            BuildSeries("Target 3xx", times, target3xx),
            BuildSeries("Target 4xx", times, target4xx),
            BuildSeries("Target 5xx", times, target5xx)
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
        string detailExportKind,
        string detailExportPath)
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
");
        sb.AppendLine("</style>");
        sb.AppendLine("<div class=\"wrap\">");
        sb.AppendLine("  <div class=\"summary-card\">");
        sb.AppendLine("    <div class=\"summary-title\">IP summary</div>");
        sb.AppendLine("    <div class=\"row\">");
        sb.AppendLine($"      <div class=\"pill\">Requested IP: {Html(result.RequestedIp)}</div>");
        sb.AppendLine($"      <div class=\"pill\">Total matching requests: {result.TotalRows.ToString("N0", CultureInfo.InvariantCulture)}</div>");
        sb.AppendLine($"      <div class=\"pill\">Files with hits: {result.SourceFiles.Count.ToString("N0", CultureInfo.InvariantCulture)}</div>");
        sb.AppendLine($"      <div class=\"pill\">Time range: {Html(firstHit ?? "-")} → {Html(lastHit ?? "-")}</div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("    <div class=\"summary-grid\">");
        sb.AppendLine(BuildStatusTableHtml("ELB status totals", result.ElbTotals));
        sb.AppendLine(BuildStatusTableHtml("Target status totals", result.TargetTotals));
        sb.AppendLine(BuildExportCardHtml(detailExportKind, detailExportPath));
        sb.AppendLine(BuildTopTableHtml("Top 10 paths", "Path", result.TopPaths(10)));
        sb.AppendLine(BuildTopTableHtml("Top 10 hosts", "Host", result.TopHosts(10)));
        sb.AppendLine(BuildTopTableHtml("Top 10 target endpoints", "Target endpoint", result.TopTargetEndpoints(10)));
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");
        return sb.ToString();
    }

    private static string BuildStatusTableHtml(string title, AlbIpSummaryScanner.StatusGroupCounts counts)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<div class=\"summary-card\">");
        sb.AppendLine($"  <div class=\"summary-subtitle\">{Html(title)}</div>");
        sb.AppendLine("  <table class=\"summary-table\">");
        sb.AppendLine("    <tr><th>Class</th><th>Hits</th></tr>");
        sb.AppendLine($"    <tr><td>2xx</td><td>{counts.S2xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>");
        sb.AppendLine($"    <tr><td>3xx</td><td>{counts.S3xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>");
        sb.AppendLine($"    <tr><td>4xx</td><td>{counts.S4xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>");
        sb.AppendLine($"    <tr><td>5xx</td><td>{counts.S5xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>");
        sb.AppendLine("  </table>");
        sb.AppendLine("</div>");
        return sb.ToString();
    }

    private static string BuildTopTableHtml(string title, string label, IReadOnlyList<KeyValuePair<string, int>> items)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<div class=\"summary-card\">");
        sb.AppendLine($"  <div class=\"summary-subtitle\">{Html(title)}</div>");
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

    private static string BuildExportCardHtml(string detailExportKind, string detailExportPath)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<div class=\"summary-card\">");
        sb.AppendLine("  <div class=\"summary-subtitle\">Detailed export</div>");
        sb.AppendLine($"  <div class=\"summary-note\">Full request detail was written to <strong>{Html(detailExportKind)}</strong> using the option 3 threshold rule.</div>");
        sb.AppendLine($"  <div class=\"summary-note summary-mono\" style=\"margin-top:8px\">{Html(detailExportPath)}</div>");
        sb.AppendLine("</div>");
        return sb.ToString();
    }

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
