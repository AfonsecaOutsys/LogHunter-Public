using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
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

        EmbeddedAssets.EnsureTabulatorAssets(root);
        var assetsDir = Path.Combine(root, "ALB", "configs", "_assets");
        var tabJs = Path.Combine(assetsDir, "tabulator.min.js");
        var tabCss = Path.Combine(assetsDir, "tabulator.min.css");

        if (!File.Exists(tabJs) || !File.Exists(tabCss))
        {
            ConsoleEx.Error("Tabulator assets are missing; cannot build the HTML report.");
            AnsiConsole.MarkupLine($"[dim]Expected:[/]\n  {Markup.Escape(tabJs)}\n  {Markup.Escape(tabCss)}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        InfoPanel("Scan plan",
            ("Mode", "IP summary with 1-minute ALB status chart + detailed request table"),
            ("Client IP", requestedIp.ToString()),
            ("Files", files.Count.ToString("N0", CultureInfo.InvariantCulture)),
            ("Input", albFolder),
            ("Output", outputFolder));

        var result = new AlbIpSummaryScanner.ScanResult(requestedIp.ToString());

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

        if (result.Rows.Count == 0)
        {
            ConsoleEx.Warn($"No ALB hits found for IP: {requestedIp}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        result.Rows.Sort((a, b) => a.TimestampUtc.CompareTo(b.TimestampUtc));

        Directory.CreateDirectory(outputFolder);
        var htmlPath = BuildIpSummaryReport(outputFolder, result, tabCss, tabJs);

        if (TryOpenFile(htmlPath))
            ConsoleEx.Success($"Report opened: {htmlPath}");
        else
            ConsoleEx.Success($"Report generated: {htmlPath}");

        ConsoleEx.Pause("Press Enter to return...");
    }

    private static string BuildIpSummaryReport(
        string outputFolder,
        AlbIpSummaryScanner.ScanResult result,
        string tabCssPath,
        string tabJsPath)
    {
        var series = BuildIpSummarySeries(result);
        var prefix = $"alb_ip_summary_{SanitizeFileComponent(result.RequestedIp)}";
        var htmlPath = Charts.SaveTimeSeriesHtml(
            outputFolder: outputFolder,
            title: $"ALB IP Summary: {result.RequestedIp}",
            yLabel: "Requests per minute",
            series: series,
            filePrefix: prefix);

        var injected = BuildTabulatorSectionHtml(htmlPath, result, tabCssPath, tabJsPath);
        var html = File.ReadAllText(htmlPath);
        html = html.Replace("Filter IP...", "Filter series...", StringComparison.Ordinal);
        html = html.Replace(
            "<th>IP</th><th>Source hits</th><th>Total requests</th><th>Peak (5 min)</th><th>Visible</th>",
            "<th>Series</th><th>Source hits</th><th>Total requests</th><th>Peak (bucket)</th><th>Visible</th>",
            StringComparison.Ordinal);
        html = html.Replace("</body>", injected + Environment.NewLine + "</body>", StringComparison.OrdinalIgnoreCase);
        File.WriteAllText(htmlPath, html, Encoding.UTF8);

        return htmlPath;
    }

    private static List<Charts.TimeSeriesSeries> BuildIpSummarySeries(AlbIpSummaryScanner.ScanResult result)
    {
        var start = result.Rows[0].TimestampUtc;
        var end = result.Rows[^1].TimestampUtc;
        start = new DateTime(start.Year, start.Month, start.Day, start.Hour, start.Minute, 0, DateTimeKind.Utc);
        end = new DateTime(end.Year, end.Month, end.Day, end.Hour, end.Minute, 0, DateTimeKind.Utc);

        var points = (int)Math.Max(1, ((end - start).TotalMinutes + 1));
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

    private static string BuildTabulatorSectionHtml(
        string htmlPath,
        AlbIpSummaryScanner.ScanResult result,
        string tabCssPath,
        string tabJsPath)
    {
        var data = result.Rows.Select(r => new
        {
            TimestampUtc = r.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC",
            TimestampUnixMs = new DateTimeOffset(r.TimestampUtc).ToUnixTimeMilliseconds(),
            r.ClientIp,
            r.ClientPort,
            r.Method,
            r.Host,
            PathNoQuery = r.PathNoQuery,
            r.RawRequest,
            ElbStatusCode = r.ElbStatusCode,
            TargetStatusCode = r.TargetStatusCode,
            TargetEndpoint = r.TargetEndpoint,
            TargetProcessingTimeSeconds = r.TargetProcessingTimeSeconds,
            RequestProcessingTimeSeconds = r.RequestProcessingTimeSeconds,
            ResponseProcessingTimeSeconds = r.ResponseProcessingTimeSeconds,
            r.ActionsExecuted,
            r.TraceId,
            r.UserAgent,
            r.SourceFile,
            r.RawLine
        }).ToList();

        var json = JsonSerializer.Serialize(data, new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });

        var cssHref = ToHtmlPath(Path.GetRelativePath(Path.GetDirectoryName(htmlPath)!, tabCssPath));
        var jsSrc = ToHtmlPath(Path.GetRelativePath(Path.GetDirectoryName(htmlPath)!, tabJsPath));

        var sb = new StringBuilder(128 * 1024);
        sb.AppendLine($"<link rel=\"stylesheet\" href=\"{HtmlAttr(cssHref)}\" />");
        sb.AppendLine("<style>");
        sb.AppendLine(@"
.lh-report { padding:0 16px 16px 16px; }
.lh-card { margin-top:12px; background:#0f1620; border:1px solid rgba(255,255,255,.08); border-radius:14px; padding:12px; box-shadow:0 12px 28px rgba(0,0,0,.35); }
.lh-title { font-size:16px; font-weight:600; margin:0 0 8px 0; }
.lh-row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:8px; }
.lh-search { background:#0b0f14; color:#e6edf3; border:1px solid rgba(255,255,255,.14); border-radius:8px; padding:6px 8px; min-width:280px; }
.lh-pill { font-size:12px; padding:6px 10px; border:1px solid rgba(255,255,255,.10); border-radius:999px; background:rgba(255,255,255,.03); }
.lh-small { font-size:12px; opacity:.75; }
#ip-summary-table { margin-top:8px; }
.tabulator { background:#0b0f14; border:1px solid rgba(255,255,255,.10); color:#e6edf3; }
.tabulator .tabulator-header { background:#111a25; color:#e6edf3; border-bottom:1px solid rgba(255,255,255,.12); }
.tabulator .tabulator-col { background:#111a25; }
.tabulator .tabulator-tableholder .tabulator-table { background:#0b0f14; color:#e6edf3; }
.tabulator-row, .tabulator-row.tabulator-row-even { background:#0b0f14; }
.tabulator-row:hover { background:#132031 !important; }
.tabulator-row .tabulator-cell { border-right:1px solid rgba(255,255,255,.08); }
.lh-detail { padding:12px; background:#0b0f14; border:1px solid rgba(255,255,255,.08); border-radius:10px; margin:6px 0 10px 0; }
.lh-detail-grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap:12px; }
.lh-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; white-space:pre-wrap; word-break:break-word; }
");
        sb.AppendLine("</style>");
        sb.AppendLine("<div class=\"lh-report\">\n  <div class=\"lh-card\">\n    <div class=\"lh-title\">Matching requests</div>");
        sb.AppendLine("    <div class=\"lh-row\">");
        sb.AppendLine($"      <div class=\"lh-pill\">IP: {Html(result.RequestedIp)}</div>");
        sb.AppendLine($"      <div class=\"lh-pill\">Rows: {result.Rows.Count.ToString("N0", CultureInfo.InvariantCulture)}</div>");
        sb.AppendLine($"      <div class=\"lh-pill\">Files with hits: {result.SourceFiles.Count.ToString("N0", CultureInfo.InvariantCulture)}</div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("    <div class=\"lh-row\">");
        sb.AppendLine("      <input id=\"ipSummarySearch\" class=\"lh-search\" type=\"text\" placeholder=\"Filter rows...\" />");
        sb.AppendLine("      <div class=\"lh-small\">Default sort: chronological ascending. Click a row to inspect the raw ALB line.</div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("    <div id=\"ip-summary-table\"></div>");
        sb.AppendLine("  </div>\n</div>");
        sb.AppendLine($"<script src=\"{HtmlAttr(jsSrc)}\"></script>");
        sb.AppendLine("<script>");
        sb.Append("const IP_SUMMARY_DATA = ");
        sb.Append(json);
        sb.AppendLine(";");
        sb.AppendLine("""
function escHtml(v){
  return String(v ?? '')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}
function fmtMaybe(v){
  return v == null || v === '' ? '—' : String(v);
}
function fmtSeconds(v){
  if(v == null || Number.isNaN(Number(v))) return '—';
  return Number(v).toFixed(6);
}
function buildDetail(row){
  return '' +
    '<div class="lh-detail">' +
      '<div class="lh-detail-grid">' +
        '<div>' +
          '<div class="lh-small">Raw request</div>' +
          '<div class="lh-mono">' + escHtml(fmtMaybe(row.RawRequest)) + '</div>' +
        '</div>' +
        '<div>' +
          '<div class="lh-small">Actions executed</div>' +
          '<div class="lh-mono">' + escHtml(fmtMaybe(row.ActionsExecuted)) + '</div>' +
        '</div>' +
        '<div>' +
          '<div class="lh-small">Trace ID</div>' +
          '<div class="lh-mono">' + escHtml(fmtMaybe(row.TraceId)) + '</div>' +
        '</div>' +
        '<div>' +
          '<div class="lh-small">User-Agent</div>' +
          '<div class="lh-mono">' + escHtml(fmtMaybe(row.UserAgent)) + '</div>' +
        '</div>' +
        '<div style="grid-column:1 / -1">' +
          '<div class="lh-small">Raw ALB line</div>' +
          '<div class="lh-mono">' + escHtml(fmtMaybe(row.RawLine)) + '</div>' +
        '</div>' +
      '</div>' +
    '</div>';
}
const table = new Tabulator('#ip-summary-table', {
  data: IP_SUMMARY_DATA,
  layout: 'fitDataStretch',
  pagination: 'local',
  paginationSize: 50,
  movableColumns: true,
  initialSort: [{ column: 'TimestampUnixMs', dir: 'asc' }],
  columns: [
    { title: 'Timestamp UTC', field: 'TimestampUtc', sorter: 'datetime', width: 185, cssClass: 'lh-mono' },
    { title: 'Client IP', field: 'ClientIp', width: 150, cssClass: 'lh-mono' },
    { title: 'Port', field: 'ClientPort', width: 90, cssClass: 'lh-mono' },
    { title: 'Method', field: 'Method', width: 95 },
    { title: 'Host', field: 'Host', width: 180, formatter: function(cell){ return '<span class="lh-mono">' + escHtml(fmtMaybe(cell.getValue())) + '</span>'; } },
    { title: 'Path', field: 'PathNoQuery', width: 260, formatter: function(cell){ return '<span class="lh-mono">' + escHtml(fmtMaybe(cell.getValue())) + '</span>'; } },
    { title: 'Raw request', field: 'RawRequest', width: 320, formatter: function(cell){ return '<span class="lh-mono">' + escHtml(fmtMaybe(cell.getValue())) + '</span>'; } },
    { title: 'ELB status', field: 'ElbStatusCode', sorter: 'number', hozAlign: 'right', width: 110 },
    { title: 'Target status', field: 'TargetStatusCode', sorter: 'number', hozAlign: 'right', width: 120 },
    { title: 'Target endpoint', field: 'TargetEndpoint', width: 180, formatter: function(cell){ return '<span class="lh-mono">' + escHtml(fmtMaybe(cell.getValue())) + '</span>'; } },
    { title: 'Target proc (s)', field: 'TargetProcessingTimeSeconds', sorter: 'number', hozAlign: 'right', width: 130, formatter: function(cell){ return '<span class="lh-mono">' + escHtml(fmtSeconds(cell.getValue())) + '</span>'; } },
    { title: 'Request proc (s)', field: 'RequestProcessingTimeSeconds', sorter: 'number', hozAlign: 'right', width: 135, formatter: function(cell){ return '<span class="lh-mono">' + escHtml(fmtSeconds(cell.getValue())) + '</span>'; } },
    { title: 'Response proc (s)', field: 'ResponseProcessingTimeSeconds', sorter: 'number', hozAlign: 'right', width: 140, formatter: function(cell){ return '<span class="lh-mono">' + escHtml(fmtSeconds(cell.getValue())) + '</span>'; } },
    { title: 'Actions', field: 'ActionsExecuted', width: 180, formatter: function(cell){ return '<span class="lh-mono">' + escHtml(fmtMaybe(cell.getValue())) + '</span>'; } },
    { title: 'Trace ID', field: 'TraceId', width: 220, formatter: function(cell){ return '<span class="lh-mono">' + escHtml(fmtMaybe(cell.getValue())) + '</span>'; } },
    { title: 'User-Agent', field: 'UserAgent', width: 260, formatter: function(cell){ return '<span class="lh-mono">' + escHtml(fmtMaybe(cell.getValue())) + '</span>'; } },
    { title: 'Source file', field: 'SourceFile', width: 220, formatter: function(cell){ return '<span class="lh-mono">' + escHtml(fmtMaybe(cell.getValue())) + '</span>'; } },
    { title: 'Timestamp sort', field: 'TimestampUnixMs', visible: false }
  ],
  rowClick: function(e, row){
    const el = row.getElement();
    const next = el.nextElementSibling;
    if(next && next.classList.contains('detail-row')){
      next.remove();
      return;
    }
    const detail = document.createElement('div');
    detail.className = 'detail-row';
    detail.innerHTML = buildDetail(row.getData());
    el.parentNode.insertBefore(detail, el.nextSibling);
  }
});
const search = document.getElementById('ipSummarySearch');
search.addEventListener('input', function(){
  const term = (search.value || '').toLowerCase().trim();
  table.setFilter(function(data){
    if(!term) return true;
    return JSON.stringify(data).toLowerCase().indexOf(term) >= 0;
  });
});
""");
        sb.AppendLine("</script>");
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

    private static string ToHtmlPath(string path)
        => path.Replace(Path.DirectorySeparatorChar, '/');

    private static string Html(string value)
        => (value ?? string.Empty)
            .Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal)
            .Replace("\"", "&quot;", StringComparison.Ordinal);

    private static string HtmlAttr(string value) => Html(value);
}
