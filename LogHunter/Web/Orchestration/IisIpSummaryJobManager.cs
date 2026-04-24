using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Services;
using LogHunter.Utils;

namespace LogHunter.Web.Orchestration;

internal sealed class IisIpSummaryJobManager
{
    private readonly object _gate = new();
    private IisIpSummaryJobSnapshot _snapshot = IisIpSummaryJobSnapshot.CreateIdle();

    public IisIpSummaryJobSnapshot GetSnapshot()
    {
        lock (_gate)
            return _snapshot;
    }

    public bool TryStart(
        IReadOnlyList<string> requestedIps,
        bool exportXlsx,
        bool chartOnly,
        out IisIpSummaryJobSnapshot snapshot,
        out string? error,
        IReadOnlyList<string>? customFiles = null,
        string? customFolderPath = null)
    {
        lock (_gate)
        {
            if (string.Equals(_snapshot.State, "running", StringComparison.OrdinalIgnoreCase))
            {
                snapshot = _snapshot;
                error = "An IIS IP summary scan is already running.";
                return false;
            }

            if (requestedIps.Count == 0)
            {
                snapshot = _snapshot;
                error = "At least one IP is required.";
                return false;
            }

            if (requestedIps.Count > 10)
            {
                snapshot = _snapshot;
                error = "A maximum of 10 IPs is supported per scan.";
                return false;
            }

            List<string> files;
            if (customFiles is { Count: > 0 })
            {
                files = customFiles.ToList();
            }
            else
            {
                var folder = !string.IsNullOrWhiteSpace(customFolderPath) ? customFolderPath : AppFolders.IIS;
                files = IisW3cReader.EnumerateLogFiles(folder);
            }

            if (files.Count == 0)
            {
                snapshot = _snapshot;
                error = customFiles is { Count: > 0 }
                    ? "No .log files found in the selected files."
                    : $"No .log files found in: {(!string.IsNullOrWhiteSpace(customFolderPath) ? customFolderPath : AppFolders.IIS)}";
                return false;
            }

            _snapshot = new IisIpSummaryJobSnapshot(
                JobId: Guid.NewGuid().ToString("N"),
                State: "running",
                Message: "Scanning IIS logs for IP summary.",
                RequestedIps: requestedIps.ToList(),
                CreatedUtc: DateTime.UtcNow,
                UpdatedUtc: DateTime.UtcNow,
                CurrentStep: 0,
                TotalSteps: files.Count,
                Phase: "scanning",
                FilesProcessed: 0,
                FilesTotal: files.Count,
                IpRowCounts: requestedIps.ToDictionary(ip => ip, _ => 0L, StringComparer.OrdinalIgnoreCase),
                HtmlReportPath: null,
                ExcelPath: null,
                SqlitePath: null,
                DetailMode: null,
                PerIpSummaries: null,
                Error: null);

            snapshot = _snapshot;
            error = null;
            _ = RunAsync(_snapshot.JobId, files, requestedIps, exportXlsx, chartOnly);
            return true;
        }
    }

    public bool TryOpenReport(string? jobId, out string message)
        => TryOpenArtifact(jobId, s => s.HtmlReportPath, "HTML report", out message);

    public bool TryOpenExport(string? jobId, out string message)
    {
        IisIpSummaryJobSnapshot snapshot;
        lock (_gate)
        {
            snapshot = _snapshot;
            if (!string.IsNullOrWhiteSpace(jobId) && !string.Equals(snapshot.JobId, jobId, StringComparison.Ordinal))
            {
                message = "Job not found.";
                return false;
            }
        }

        var path = snapshot.ExcelPath ?? snapshot.SqlitePath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            message = "No export artifact is available.";
            return false;
        }

        return TryShellOpen(path, out message);
    }

    private bool TryOpenArtifact(string? jobId, Func<IisIpSummaryJobSnapshot, string?> pathSelector, string label, out string message)
    {
        IisIpSummaryJobSnapshot snapshot;
        lock (_gate)
        {
            snapshot = _snapshot;
            if (!string.IsNullOrWhiteSpace(jobId) && !string.Equals(snapshot.JobId, jobId, StringComparison.Ordinal))
            {
                message = "Job not found.";
                return false;
            }
        }

        var path = pathSelector(snapshot);
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            message = $"The {label} is not available.";
            return false;
        }

        return TryShellOpen(path, out message);
    }

    private static bool TryShellOpen(string path, out string message)
    {
        var ext = Path.GetExtension(path);
        if (string.Equals(ext, ".db", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(ext, ".sqlite", StringComparison.OrdinalIgnoreCase))
        {
            if (IisIpSummarySqliteViewerLauncher.Launch(path, null))
            {
                message = path;
                return true;
            }

            return TryRevealInExplorer(path, out message);
        }

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true
            });
            message = path;
            return true;
        }
        catch
        {
            return TryRevealInExplorer(path, out message);
        }
    }

    private static bool TryRevealInExplorer(string path, out string message)
    {
        try
        {
            System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{path}\"");
            message = path;
            return true;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return false;
        }
    }

    private async Task RunAsync(string jobId, List<string> files, IReadOnlyList<string> requestedIps, bool exportXlsx, bool chartOnly)
    {
        var outputFolder = AppFolders.Output;
        Directory.CreateDirectory(outputFolder);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var htmlPath = Path.Combine(outputFolder, $"iis_ip_summary_multi_{stamp}.html");
        var excelPath = Path.Combine(outputFolder, $"iis_ip_summary_multi_{stamp}.xlsx");
        var sqlitePath = Path.Combine(outputFolder, $"iis_ip_summary_multi_{stamp}.db");

        var resultsByIp = requestedIps.ToDictionary(
            ip => ip,
            ip => new IisIpSummaryScanner.ScanResult(ip, Path.Combine(outputFolder, $"iis_ip_summary_{SanitizeFileComponent(ip)}_{stamp}.db")),
            StringComparer.OrdinalIgnoreCase);

        IisIpSummaryExportSqlite.Writer? sharedSqliteWriter = null;
        bool sqliteAutoApproved = false;

        if (chartOnly)
        {
            foreach (var result in resultsByIp.Values)
                result.ApplyGlobalDetailMode(IisIpSummaryScanner.DetailRetentionMode.SummaryOnly);
        }

        try
        {
            for (var i = 0; i < files.Count; i++)
            {
                await IisIpSummaryScanner.ScanFileAsync(
                    filePath: files[i],
                    resultsByIp: resultsByIp,
                    ct: CancellationToken.None).ConfigureAwait(false);

                var ipRowCounts = resultsByIp.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.TotalRows,
                    StringComparer.OrdinalIgnoreCase);

                Update(jobId, snapshot => snapshot with
                {
                    UpdatedUtc = DateTime.UtcNow,
                    Message = $"Scanning IIS logs: {i + 1} / {files.Count} files.",
                    CurrentStep = i + 1,
                    FilesProcessed = i + 1,
                    IpRowCounts = ipRowCounts
                });

                if (!chartOnly && !sqliteAutoApproved)
                {
                    var aggregateRows = resultsByIp.Values
                        .Where(r => r.DetailMode == IisIpSummaryScanner.DetailRetentionMode.BelowThreshold)
                        .Sum(r => r.TotalRows);

                    var anyPending = resultsByIp.Values.Any(r => r.ThresholdPromptPending);

                    if (anyPending || aggregateRows >= IisIpSummaryScanner.ExcelRowThreshold)
                    {
                        sqliteAutoApproved = true;
                        sharedSqliteWriter ??= IisIpSummaryExportSqlite.Open(sqlitePath);

                        foreach (var result in resultsByIp.Values)
                        {
                            if (result.ThresholdPromptPending)
                                result.ApplyThresholdDecision(IisIpSummaryScanner.DetailRetentionMode.SqliteApproved, sharedSqliteWriter, sqlitePath);
                            else if (result.DetailMode == IisIpSummaryScanner.DetailRetentionMode.BelowThreshold)
                                result.ApplyGlobalDetailMode(IisIpSummaryScanner.DetailRetentionMode.SqliteApproved, sharedSqliteWriter, sqlitePath);
                        }

                        Update(jobId, snapshot => snapshot with
                        {
                            DetailMode = "sqlite",
                            Message = $"Scanning IIS logs: {i + 1} / {files.Count} files. Switched to SQLite (>1M rows)."
                        });
                    }
                }
            }

            foreach (var result in resultsByIp.Values)
                result.CompleteStreamingExports();
            sharedSqliteWriter?.Complete();

            var anyHits = resultsByIp.Values.Any(r => r.TotalRows > 0);
            if (!anyHits)
            {
                Update(jobId, snapshot => snapshot with
                {
                    State = "completed",
                    Phase = "completed",
                    Message = "No IIS hits found for any of the requested IPs.",
                    UpdatedUtc = DateTime.UtcNow,
                    CurrentStep = files.Count
                });
                return;
            }

            var anySqlite = resultsByIp.Values.Any(r => r.DetailMode == IisIpSummaryScanner.DetailRetentionMode.SqliteApproved);
            string? finalExcelPath = null;
            string? finalSqlitePath = anySqlite ? sqlitePath : null;

            if (anySqlite)
            {
                Update(jobId, snapshot => snapshot with
                {
                    Phase = "building-sqlite",
                    Message = "Scan complete. Finalizing SQLite database...",
                    UpdatedUtc = DateTime.UtcNow,
                    CurrentStep = files.Count
                });
            }
            else if (exportXlsx)
            {
                Update(jobId, snapshot => snapshot with
                {
                    Phase = "building-excel",
                    Message = "Scan complete. Building Excel workbook...",
                    UpdatedUtc = DateTime.UtcNow,
                    CurrentStep = files.Count
                });
            }
            else
            {
                Update(jobId, snapshot => snapshot with
                {
                    Phase = "building-report",
                    Message = "Scan complete. Building chart report...",
                    UpdatedUtc = DateTime.UtcNow,
                    CurrentStep = files.Count
                });
            }

            if (!anySqlite && exportXlsx)
            {
                var excelEligible = resultsByIp.Values
                    .Where(r => r.TotalRows > 0 && r.HasRetainedRows)
                    .OrderBy(r => r.RequestedIp, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                foreach (var result in excelEligible)
                    result.Rows.Sort((a, b) => a.TimestampUtc.CompareTo(b.TimestampUtc));

                if (excelEligible.Count > 0)
                {
                    IisIpSummaryExportExcel.Export(excelPath, excelEligible);
                    finalExcelPath = excelPath;
                }
            }

            Update(jobId, snapshot => snapshot with
            {
                Phase = "building-report",
                Message = "Building chart report...",
                UpdatedUtc = DateTime.UtcNow
            });

            var orderedResults = resultsByIp.Values
                .OrderBy(r => r.RequestedIp, StringComparer.OrdinalIgnoreCase)
                .ToList();

            BuildMultiIpHtmlReport(htmlPath, orderedResults, finalExcelPath, finalSqlitePath);

            var perIpSummaries = orderedResults.Select(r => new IisIpSummaryPerIpResult(
                Ip: r.RequestedIp,
                TotalRows: r.TotalRows,
                FilesWithHits: r.SourceFiles.Count,
                FirstHitUtc: r.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                LastHitUtc: r.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                S2xx: r.StatusTotals.S2xx,
                S3xx: r.StatusTotals.S3xx,
                S4xx: r.StatusTotals.S4xx,
                S5xx: r.StatusTotals.S5xx,
                AvgTimeTakenMs: (long)r.AverageTimeTakenMs,
                MaxTimeTakenMs: r.MaxTimeTakenMs,
                TotalCsBytes: r.TotalCsBytes,
                TotalScBytes: r.TotalScBytes,
                TopUris: r.TopUris(10).Select(kvp => new IisIpSummaryUriHit(kvp.Key, kvp.Value)).ToList(),
                TopMethods: r.TopMethods(5).Select(kvp => new IisIpSummaryUriHit(kvp.Key, kvp.Value)).ToList(),
                TopStatuses: r.TopExactStatuses(10).Select(kvp => new IisIpSummaryUriHit(kvp.Key, kvp.Value)).ToList()))
            .ToList();

            var finalIpRowCounts = resultsByIp.ToDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value.TotalRows,
                StringComparer.OrdinalIgnoreCase);

            Update(jobId, snapshot => snapshot with
            {
                State = "completed",
                Phase = "completed",
                Message = $"IP summary complete. {orderedResults.Count(r => r.TotalRows > 0)} IP(s) had hits.",
                UpdatedUtc = DateTime.UtcNow,
                CurrentStep = files.Count,
                FilesProcessed = files.Count,
                IpRowCounts = finalIpRowCounts,
                HtmlReportPath = htmlPath,
                ExcelPath = finalExcelPath,
                SqlitePath = finalSqlitePath,
                DetailMode = anySqlite ? "sqlite" : "excel",
                PerIpSummaries = perIpSummaries
            });
        }
        catch (Exception ex)
        {
            Update(jobId, snapshot => snapshot with
            {
                State = "failed",
                Phase = "failed",
                Message = "IIS IP summary scan failed.",
                UpdatedUtc = DateTime.UtcNow,
                Error = ex.Message
            });
        }
        finally
        {
            sharedSqliteWriter?.Dispose();
            foreach (var result in resultsByIp.Values)
                result.Dispose();
        }
    }

    private void Update(string jobId, Func<IisIpSummaryJobSnapshot, IisIpSummaryJobSnapshot> update)
    {
        lock (_gate)
        {
            if (!string.Equals(_snapshot.JobId, jobId, StringComparison.Ordinal))
                return;
            _snapshot = update(_snapshot);
        }
    }

    private static void BuildMultiIpHtmlReport(
        string htmlPath,
        IReadOnlyList<IisIpSummaryScanner.ScanResult> results,
        string? excelPath,
        string? sqlitePath)
    {
        var payload = results.Select(r => new
        {
            ip = r.RequestedIp,
            totalRows = r.TotalRows,
            summaryHtml = BuildPerIpSummaryHtml(r),
            chart = BuildChartPayload(r)
        }).ToList();

        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        var html = BuildReportHtml(json);
        File.WriteAllText(htmlPath, html, Encoding.UTF8);
    }

    private static string BuildPerIpSummaryHtml(IisIpSummaryScanner.ScanResult result)
    {
        if (result.TotalRows == 0)
            return "<div class=\"card\"><div class=\"empty\">No IIS hits found for this IP.</div></div>";

        var sb = new StringBuilder(8192);
        sb.AppendLine("<div class=\"wrap\">");
        sb.AppendLine("  <div class=\"summary-card\">");
        sb.AppendLine("    <div class=\"row\">");
        sb.AppendLine($"      <div class=\"pill\">IP: {Esc(result.RequestedIp)}</div>");
        sb.AppendLine($"      <div class=\"pill\">Total: {result.TotalRows.ToString("N0", CultureInfo.InvariantCulture)}</div>");
        sb.AppendLine($"      <div class=\"pill\">Files: {result.SourceFiles.Count.ToString("N0", CultureInfo.InvariantCulture)}</div>");

        var first = result.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
        var last = result.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
        sb.AppendLine($"      <div class=\"pill\">{Esc(first)} &rarr; {Esc(last)}</div>");
        sb.AppendLine("    </div>");

        sb.AppendLine("    <div class=\"summary-grid\">");
        sb.AppendLine(BuildStatusTableHtml(result.StatusTotals));
        sb.AppendLine(BuildLatencyHtml(result));
        sb.AppendLine(BuildTopUrisHtml(result));
        sb.AppendLine(BuildTopMethodsHtml(result));
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");
        return sb.ToString();
    }

    private static string BuildStatusTableHtml(IisIpSummaryScanner.StatusGroupCounts counts)
    {
        return $"""
<div class="summary-card">
  <div class="summary-subtitle">Status totals</div>
  <table class="summary-table">
    <tr><th>Class</th><th>Hits</th></tr>
    <tr><td>2xx</td><td>{counts.S2xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>
    <tr><td>3xx</td><td>{counts.S3xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>
    <tr><td>4xx</td><td>{counts.S4xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>
    <tr><td>5xx</td><td>{counts.S5xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>
  </table>
</div>
""";
    }

    private static string BuildLatencyHtml(IisIpSummaryScanner.ScanResult r)
    {
        return $"""
<div class="summary-card">
  <div class="summary-subtitle">Latency and bytes</div>
  <table class="summary-table">
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Avg time-taken</td><td>{r.AverageTimeTakenMs.ToString("N0", CultureInfo.InvariantCulture)} ms</td></tr>
    <tr><td>Max time-taken</td><td>{r.MaxTimeTakenMs.ToString("N0", CultureInfo.InvariantCulture)} ms</td></tr>
    <tr><td>Total cs-bytes</td><td>{FormatBytes(r.TotalCsBytes)}</td></tr>
    <tr><td>Total sc-bytes</td><td>{FormatBytes(r.TotalScBytes)}</td></tr>
  </table>
</div>
""";
    }

    private static string BuildTopUrisHtml(IisIpSummaryScanner.ScanResult r)
    {
        var items = r.TopUris(10);
        var rows = items.Count == 0
            ? "    <tr><td>(none)</td><td>0</td></tr>"
            : string.Join("\n", items.Select(kvp =>
                $"    <tr><td style=\"font-family:monospace;word-break:break-all\">{Esc(kvp.Key)}</td><td>{kvp.Value.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>"));

        return $"""
<div class="summary-card">
  <div class="summary-subtitle">Top 10 URIs</div>
  <table class="summary-table">
    <tr><th>URI</th><th>Hits</th></tr>
{rows}
  </table>
</div>
""";
    }

    private static string BuildTopMethodsHtml(IisIpSummaryScanner.ScanResult r)
    {
        var items = r.TopMethods(5);
        var rows = items.Count == 0
            ? "    <tr><td>(none)</td><td>0</td></tr>"
            : string.Join("\n", items.Select(kvp =>
                $"    <tr><td>{Esc(kvp.Key)}</td><td>{kvp.Value.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>"));

        return $"""
<div class="summary-card">
  <div class="summary-subtitle">Methods</div>
  <table class="summary-table">
    <tr><th>Method</th><th>Hits</th></tr>
{rows}
  </table>
</div>
""";
    }

    private static object BuildChartPayload(IisIpSummaryScanner.ScanResult result)
    {
        if (result.TotalRows == 0 || !result.FirstHitUtc.HasValue || !result.LastHitUtc.HasValue)
            return new { timesUtc = Array.Empty<long>(), series = Array.Empty<object>() };

        var start = result.FirstHitUtc.Value;
        var end = result.LastHitUtc.Value;
        start = new DateTime(start.Year, start.Month, start.Day, start.Hour, start.Minute, 0, DateTimeKind.Utc);
        end = new DateTime(end.Year, end.Month, end.Day, end.Hour, end.Minute, 0, DateTimeKind.Utc);

        var minuteCount = (int)Math.Max(1, (end - start).TotalMinutes + 1);
        var bucketSize = Math.Max(1, (int)Math.Ceiling(minuteCount / 2400.0));
        var points = (int)Math.Ceiling(minuteCount / (double)bucketSize);

        var times = new long[points];
        var s2xx = new double[points];
        var s3xx = new double[points];
        var s4xx = new double[points];
        var s5xx = new double[points];

        for (int i = 0; i < points; i++)
        {
            var bucketStart = start.AddMinutes(i * bucketSize);
            times[i] = new DateTimeOffset(bucketStart).ToUnixTimeMilliseconds();

            for (int offset = 0; offset < bucketSize; offset++)
            {
                var minute = bucketStart.AddMinutes(offset);
                if (minute > end) break;
                if (!result.BucketsByMinuteUtc.TryGetValue(minute, out var bucket)) continue;

                s2xx[i] += bucket.S2xx;
                s3xx[i] += bucket.S3xx;
                s4xx[i] += bucket.S4xx;
                s5xx[i] += bucket.S5xx;
            }
        }

        return new
        {
            timesUtc = times,
            series = new[]
            {
                new { name = "2xx", values = s2xx },
                new { name = "3xx", values = s3xx },
                new { name = "4xx", values = s4xx },
                new { name = "5xx", values = s5xx }
            }
        };
    }

    private static string BuildReportHtml(string dataJson)
    {
        return $$$"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>IIS Multi-IP Summary</title>
<style>
:root { color-scheme: dark; }
body { margin:0; background:#0b0f14; color:#e6edf3; font-family: ui-sans-serif, system-ui, Segoe UI, Roboto, Arial; }
.wrap { padding:16px; max-width:1600px; margin:0 auto; }
.card { margin-top:12px; background:#0f1620; border:1px solid rgba(255,255,255,.08); border-radius:14px; padding:12px; box-shadow:0 12px 28px rgba(0,0,0,.35); }
.toolbar { display:grid; grid-template-columns:minmax(260px,420px) 1fr; gap:12px; align-items:end; }
.field { display:flex; flex-direction:column; gap:6px; }
.field label { font-size:13px; opacity:.8; }
select { background:#0b0f14; color:#e6edf3; border:1px solid rgba(255,255,255,.14); border-radius:8px; padding:10px 12px; }
.row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:8px; }
.pill { display:inline-block; font-size:12px; padding:6px 10px; border:1px solid rgba(255,255,255,.10); border-radius:999px; background:rgba(255,255,255,.03); margin:0 6px 6px 0; }
.summary-card { margin-top:12px; background:#0f1620; border:1px solid rgba(255,255,255,.08); border-radius:14px; padding:12px; }
.summary-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(280px,1fr)); gap:12px; }
.summary-subtitle { font-size:13px; font-weight:600; margin:0 0 8px 0; }
.summary-table { width:100%; border-collapse:collapse; font-size:12px; }
.summary-table th, .summary-table td { padding:6px 8px; border-bottom:1px solid rgba(255,255,255,.07); text-align:left; vertical-align:top; }
.summary-table th:last-child, .summary-table td:last-child { text-align:right; }
.note { font-size:12px; opacity:.8; line-height:1.45; }
.empty { opacity:.7; font-size:13px; }
canvas { width:100%; height:520px; display:block; background:#0b0f14; border-radius:12px; }
.btn { border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.03); color:#e6edf3; padding:5px 9px; border-radius:8px; cursor:pointer; font-size:12px; }
.btn:hover { background:rgba(255,255,255,.08); }
.toggleRow { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:8px; }
.seriesToggle { display:inline-flex; align-items:center; gap:8px; padding:5px 9px; border-radius:999px; border:1px solid rgba(255,255,255,.12); background:rgba(255,255,255,.03); cursor:pointer; font-size:12px; user-select:none; }
.seriesToggle.off { opacity:.45; }
.sw { width:10px; height:10px; border-radius:3px; display:inline-block; }
kbd { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:11px; padding:2px 6px; border-radius:6px; border:1px solid rgba(255,255,255,.15); background:rgba(255,255,255,.04); }
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="toolbar">
      <div class="field">
        <label for="ipSelect">Selected IP</label>
        <select id="ipSelect"></select>
      </div>
      <div class="note">Multi-IP summary report generated by LogHunter web UI (IIS).</div>
    </div>
  </div>
  <div class="card">
    <div class="row">
      <div class="pill">Pan: <kbd>drag</kbd></div>
      <div class="pill">Zoom X: <kbd>wheel</kbd></div>
      <div class="pill">Reset: <kbd>double click</kbd></div>
      <button class="btn" id="btnResetZoom" type="button">Reset zoom</button>
      <button class="btn" id="btnShowAllSeries" type="button">Show all series</button>
    </div>
    <div class="toggleRow" id="seriesToggles"></div>
    <canvas id="chart"></canvas>
  </div>
  <div id="summaryHost"></div>
</div>
<script>
const DATA = {{{dataJson}}};
const select = document.getElementById('ipSelect');
const summaryHost = document.getElementById('summaryHost');
const canvas = document.getElementById('chart');
const toggleHost = document.getElementById('seriesToggles');
const ctx = canvas.getContext('2d', { alpha: false });
const colors = ['#7dd3fc','#a7f3d0','#fda4af','#fcd34d'];
const chartStateByIp = new Map();
let currentItem = null;
let mouseX = null, mouseY = null, isDragging = false, dragStartX = 0, dragStartMin = 0, dragStartMax = 0;

function esc(s){ return String(s??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;'); }
function fmtNum(v){ return Number(v??0).toLocaleString('en-US'); }
function fmtUtc(ms){ const d=new Date(ms); const p=n=>String(n).padStart(2,'0'); return `${d.getUTCFullYear()}-${p(d.getUTCMonth()+1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`; }
function getState(item){
  let s=chartStateByIp.get(item.ip);
  if(!s){
    const t=item.chart.timesUtc||[];
    const sr=(item.chart.series||[]).map((x,i)=>({name:x.name,values:x.values||[],color:colors[i%colors.length],visible:true}));
    s={xMin:t[0]||0,xMax:t[t.length-1]||0,times:t,series:sr};
    chartStateByIp.set(item.ip,s);
  }
  return s;
}
function resizeCanvas(){const r=Math.max(1,Math.min(2,devicePixelRatio||1));const b=canvas.getBoundingClientRect();canvas.width=Math.floor(b.width*r);canvas.height=Math.floor(b.height*r);ctx.setTransform(r,0,0,r,0,0);}
function timeToX(ms,s,w){return(ms-s.xMin)/Math.max(1,s.xMax-s.xMin)*w;}
function xToTime(x,s,w){return s.xMin+x/Math.max(1,w)*(s.xMax-s.xMin);}
function lb(a,x){let lo=0,hi=a.length;while(lo<hi){const m=(lo+hi)>>1;a[m]<x?lo=m+1:hi=m;}return lo;}
function clampX(s){if(!s.times.length)return;const g0=s.times[0],g1=s.times[s.times.length-1],mn=Math.max(60000,4*60000);if(s.xMax-s.xMin<mn){const m=(s.xMin+s.xMax)/2;s.xMin=m-mn/2;s.xMax=m+mn/2;}if(s.xMin<g0){s.xMax+=g0-s.xMin;s.xMin=g0;}if(s.xMax>g1){s.xMin-=s.xMax-g1;s.xMax=g1;}if(s.xMin<g0)s.xMin=g0;if(s.xMax>g1)s.xMax=g1;}

function drawChart(item){
  resizeCanvas();const b=canvas.getBoundingClientRect(),W=b.width,H=b.height,s=getState(item);
  ctx.clearRect(0,0,W,H);ctx.fillStyle='#0b0f14';ctx.fillRect(0,0,W,H);
  const t=s.times,sr=s.series;
  if(!t.length){ctx.fillStyle='#94a3b8';ctx.font='14px ui-sans-serif';ctx.fillText('No chart data.',24,32);return;}
  const pL=64,pR=18,pT=14,pB=44,pW=W-pL-pR,pH=H-pT-pB;
  const i0=Math.max(0,lb(t,s.xMin)-1),i1=Math.min(t.length-1,lb(t,s.xMax)+1);
  const vis=sr.filter(x=>x.visible);
  let yMin=Infinity,yMax=-Infinity;
  vis.forEach(x=>{for(let i=i0;i<=i1;i++){const v=x.values[i];if(v<yMin)yMin=v;if(v>yMax)yMax=v;}});
  if(!isFinite(yMin)){yMin=0;yMax=1;}if(yMin===yMax){yMin--;yMax++;}
  const yP=(yMax-yMin)*.08;yMin-=yP;yMax+=yP;
  const vToY=v=>pT+(1-(v-yMin)/Math.max(1e-9,yMax-yMin))*pH;
  ctx.strokeStyle='rgba(255,255,255,.08)';ctx.lineWidth=1;ctx.font='12px ui-sans-serif';ctx.fillStyle='rgba(230,237,243,.75)';
  for(let i=0;i<=5;i++){const v=yMin+i/5*(yMax-yMin),y=vToY(v);ctx.beginPath();ctx.moveTo(pL,y);ctx.lineTo(pL+pW,y);ctx.stroke();ctx.fillText(String(Math.round(v)),8,y+4);}
  for(let i=0;i<=5;i++){const ms=s.xMin+i/5*(s.xMax-s.xMin),x=pL+timeToX(ms,s,pW);ctx.beginPath();ctx.moveTo(x,pT);ctx.lineTo(x,pT+pH);ctx.stroke();const l=fmtUtc(ms),tw=ctx.measureText(l).width;ctx.fillText(l,x-tw/2,pT+pH+28);}
  vis.forEach(x=>{ctx.strokeStyle=x.color;ctx.lineWidth=2;ctx.beginPath();let st=false;for(let i=i0;i<=i1;i++){const ms=t[i];if(ms<s.xMin||ms>s.xMax)continue;const px=pL+timeToX(ms,s,pW),py=vToY(x.values[i]);st?(ctx.lineTo(px,py)):(ctx.moveTo(px,py),st=true);}ctx.stroke();});
  ctx.strokeStyle='rgba(255,255,255,.22)';ctx.strokeRect(pL,pT,pW,pH);
}

function buildToggles(item){
  const s=getState(item);toggleHost.innerHTML='';
  s.series.forEach(x=>{const b=document.createElement('button');b.type='button';b.className=`seriesToggle${x.visible?'':' off'}`;b.innerHTML=`<span class="sw" style="background:${x.color}"></span><span>${esc(x.name)}</span>`;b.onclick=()=>{x.visible=!x.visible;buildToggles(item);drawChart(item);};b.ondblclick=e=>{e.preventDefault();s.series.forEach(o=>{o.visible=o===x;});buildToggles(item);drawChart(item);};toggleHost.appendChild(b);});
}
function renderSummary(item){summaryHost.innerHTML=item.summaryHtml||'<div class="card"><div class="empty">No summary.</div></div>';}
function renderSelected(){currentItem=DATA.find(x=>x.ip===select.value)||DATA[0];buildToggles(currentItem);renderSummary(currentItem);drawChart(currentItem);}

DATA.forEach(item=>{const o=document.createElement('option');o.value=item.ip;o.textContent=`${item.ip} (${fmtNum(item.totalRows)} hits)`;select.appendChild(o);});
canvas.addEventListener('mousemove',e=>{if(!currentItem)return;const r=canvas.getBoundingClientRect();mouseX=e.clientX-r.left;mouseY=e.clientY-r.top;if(isDragging){const s=getState(currentItem),dx=mouseX-dragStartX,span=dragStartMax-dragStartMin,dt=-dx/Math.max(1,r.width-82)*span;s.xMin=dragStartMin+dt;s.xMax=dragStartMax+dt;clampX(s);}drawChart(currentItem);});
canvas.addEventListener('mouseleave',()=>{mouseX=null;mouseY=null;if(!isDragging&&currentItem)drawChart(currentItem);});
canvas.addEventListener('mousedown',e=>{if(!currentItem)return;isDragging=true;const s=getState(currentItem),r=canvas.getBoundingClientRect();dragStartX=e.clientX-r.left;dragStartMin=s.xMin;dragStartMax=s.xMax;});
window.addEventListener('mouseup',()=>{isDragging=false;});
canvas.addEventListener('wheel',e=>{if(!currentItem)return;e.preventDefault();const s=getState(currentItem),r=canvas.getBoundingClientRect(),pw=r.width-82,x=e.clientX-r.left-64,t=xToTime(x,s,pw),z=Math.exp((e.deltaY>0?1:-1)*.12),sp=(s.xMax-s.xMin)*z,lr=(t-s.xMin)/Math.max(1,s.xMax-s.xMin);s.xMin=t-sp*lr;s.xMax=s.xMin+sp;clampX(s);drawChart(currentItem);},{passive:false});
canvas.addEventListener('dblclick',()=>{if(!currentItem)return;const s=getState(currentItem);if(s.times.length){s.xMin=s.times[0];s.xMax=s.times[s.times.length-1];}drawChart(currentItem);});
document.getElementById('btnResetZoom').onclick=()=>{if(!currentItem)return;const s=getState(currentItem);if(s.times.length){s.xMin=s.times[0];s.xMax=s.times[s.times.length-1];}drawChart(currentItem);};
document.getElementById('btnShowAllSeries').onclick=()=>{if(!currentItem)return;getState(currentItem).series.forEach(x=>{x.visible=true;});buildToggles(currentItem);drawChart(currentItem);};
select.onchange=renderSelected;
window.onresize=()=>{if(currentItem)drawChart(currentItem);};
renderSelected();
</script>
</body>
</html>
""";
    }

    private static string Esc(string value)
        => (value ?? string.Empty)
            .Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal)
            .Replace("\"", "&quot;", StringComparison.Ordinal);

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0) return "0 B";
        string[] suf = { "B", "KB", "MB", "GB", "TB" };
        double b = bytes;
        int i = 0;
        while (b >= 1024 && i < suf.Length - 1) { b /= 1024; i++; }
        return $"{b:0.##} {suf[i]}";
    }

    private static string SanitizeFileComponent(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
            sb.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
        return sb.ToString();
    }
}

internal sealed record IisIpSummaryJobSnapshot(
    string JobId,
    string State,
    string Message,
    IReadOnlyList<string> RequestedIps,
    DateTime CreatedUtc,
    DateTime UpdatedUtc,
    int CurrentStep,
    int TotalSteps,
    string Phase,
    int FilesProcessed,
    int FilesTotal,
    IReadOnlyDictionary<string, long> IpRowCounts,
    string? HtmlReportPath,
    string? ExcelPath,
    string? SqlitePath,
    string? DetailMode,
    IReadOnlyList<IisIpSummaryPerIpResult>? PerIpSummaries,
    string? Error)
{
    public static IisIpSummaryJobSnapshot CreateIdle()
        => new(
            JobId: string.Empty,
            State: "idle",
            Message: "No IIS IP summary scan has been run yet.",
            RequestedIps: Array.Empty<string>(),
            CreatedUtc: DateTime.UtcNow,
            UpdatedUtc: DateTime.UtcNow,
            CurrentStep: 0,
            TotalSteps: 0,
            Phase: "idle",
            FilesProcessed: 0,
            FilesTotal: 0,
            IpRowCounts: new Dictionary<string, long>(),
            HtmlReportPath: null,
            ExcelPath: null,
            SqlitePath: null,
            DetailMode: null,
            PerIpSummaries: null,
            Error: null);
}

internal sealed record IisIpSummaryPerIpResult(
    string Ip,
    long TotalRows,
    int FilesWithHits,
    string? FirstHitUtc,
    string? LastHitUtc,
    int S2xx,
    int S3xx,
    int S4xx,
    int S5xx,
    long AvgTimeTakenMs,
    long MaxTimeTakenMs,
    long TotalCsBytes,
    long TotalScBytes,
    IReadOnlyList<IisIpSummaryUriHit> TopUris,
    IReadOnlyList<IisIpSummaryUriHit> TopMethods,
    IReadOnlyList<IisIpSummaryUriHit> TopStatuses);

internal sealed record IisIpSummaryUriHit(string Label, int Hits);
