using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using LogHunter.Services;

namespace LogHunter.Web.Orchestration;

internal sealed class AlbIpSummaryJobManager
{
    private readonly object _gate = new();
    private AlbIpSummaryJobSnapshot _snapshot = AlbIpSummaryJobSnapshot.CreateIdle();

    public AlbIpSummaryJobSnapshot GetSnapshot()
    {
        lock (_gate)
            return _snapshot;
    }

    public bool TryStart(
        IReadOnlyList<string> requestedIps,
        bool exportXlsx,
        bool chartOnly,
        AlbTopIpsInputSourceSelection inputSource,
        out AlbIpSummaryJobSnapshot snapshot,
        out string? error)
    {
        lock (_gate)
        {
            if (string.Equals(_snapshot.State, "running", StringComparison.OrdinalIgnoreCase))
            {
                snapshot = _snapshot;
                error = "An IP summary scan is already running.";
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

            var files = inputSource.Files.ToList();
            if (files.Count == 0)
            {
                snapshot = _snapshot;
                error = inputSource.SourceType == AlbTopIpsInputSourceType.DefaultFolder
                    ? $"No .log files found in: {AppFolders.ALB}"
                    : "No .log files were found in the selected input source.";
                return false;
            }

            _snapshot = new AlbIpSummaryJobSnapshot(
                JobId: Guid.NewGuid().ToString("N"),
                State: "running",
                Message: "Scanning ALB logs for IP summary.",
                RequestedIps: requestedIps.ToList(),
                InputSourceType: inputSource.SourceType.ToString(),
                InputSourceLabel: inputSource.SelectionLabel,
                InputSourceSummary: inputSource.Summary,
                CreatedUtc: DateTime.UtcNow,
                UpdatedUtc: DateTime.UtcNow,
                CurrentStep: 0,
                TotalSteps: files.Count,
                Phase: "scanning",
                FilesProcessed: 0,
                FilesTotal: files.Count,
                TotalBytes: inputSource.TotalBytes,
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
        AlbIpSummaryJobSnapshot snapshot;
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

    private bool TryOpenArtifact(string? jobId, Func<AlbIpSummaryJobSnapshot, string?> pathSelector, string label, out string message)
    {
        AlbIpSummaryJobSnapshot snapshot;
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
        // .db files have no default Windows handler — open Explorer with the file selected instead.
        var ext = Path.GetExtension(path);
        if (string.Equals(ext, ".db", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(ext, ".sqlite", StringComparison.OrdinalIgnoreCase))
        {
            if (AlbIpSummarySqliteViewerLauncher.Launch(path, null))
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
        var htmlPath = Path.Combine(outputFolder, $"alb_ip_summary_multi_{stamp}.html");
        var excelPath = Path.Combine(outputFolder, $"alb_ip_summary_multi_{stamp}.xlsx");
        var sqlitePath = Path.Combine(outputFolder, $"alb_ip_summary_multi_{stamp}.db");

        var resultsByIp = requestedIps.ToDictionary(
            ip => ip,
            ip => new AlbIpSummaryScanner.ScanResult(ip, Path.Combine(outputFolder, $"alb_ip_summary_{SanitizeFileComponent(ip)}_{stamp}.db")),
            StringComparer.OrdinalIgnoreCase);

        AlbIpSummaryExportSqlite.Writer? sharedSqliteWriter = null;
        bool sqliteAutoApproved = false;

        if (chartOnly)
        {
            foreach (var result in resultsByIp.Values)
                result.ApplyGlobalDetailMode(AlbIpSummaryScanner.DetailRetentionMode.SummaryOnly);
        }

        try
        {
            for (var i = 0; i < files.Count; i++)
            {
                await AlbIpSummaryScanner.ScanFileAsync(
                    filePath: files[i],
                    resultsByIp: resultsByIp,
                    reportBytesDelta: _ => { }).ConfigureAwait(false);

                var ipRowCounts = resultsByIp.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.TotalRows,
                    StringComparer.OrdinalIgnoreCase);

                Update(jobId, snapshot => snapshot with
                {
                    UpdatedUtc = DateTime.UtcNow,
                    Message = $"Scanning ALB logs: {i + 1} / {files.Count} files.",
                    CurrentStep = i + 1,
                    FilesProcessed = i + 1,
                    IpRowCounts = ipRowCounts
                });

                // Auto-approve SQLite when aggregate threshold reached (skip in chart-only mode)
                if (!chartOnly && !sqliteAutoApproved)
                {
                    var aggregateRows = resultsByIp.Values
                        .Where(r => r.DetailMode == AlbIpSummaryScanner.DetailRetentionMode.BelowThreshold)
                        .Sum(r => r.TotalRows);

                    var anyPending = resultsByIp.Values.Any(r => r.ThresholdPromptPending);

                    if (anyPending || aggregateRows >= AlbIpSummaryScanner.ExcelRowThreshold)
                    {
                        sqliteAutoApproved = true;
                        sharedSqliteWriter ??= AlbIpSummaryExportSqlite.Open(sqlitePath);

                        foreach (var result in resultsByIp.Values)
                        {
                            if (result.ThresholdPromptPending)
                                result.ApplyThresholdDecision(AlbIpSummaryScanner.DetailRetentionMode.SqliteApproved, sharedSqliteWriter, sqlitePath);
                            else if (result.DetailMode == AlbIpSummaryScanner.DetailRetentionMode.BelowThreshold)
                                result.ApplyGlobalDetailMode(AlbIpSummaryScanner.DetailRetentionMode.SqliteApproved, sharedSqliteWriter, sqlitePath);
                        }

                        Update(jobId, snapshot => snapshot with
                        {
                            DetailMode = "sqlite",
                            Message = $"Scanning ALB logs: {i + 1} / {files.Count} files. Switched to SQLite (>1M rows)."
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
                    Message = "No ALB hits found for any of the requested IPs.",
                    UpdatedUtc = DateTime.UtcNow,
                    CurrentStep = files.Count
                });
                return;
            }

            // Build exports
            var anySqlite = resultsByIp.Values.Any(r => r.DetailMode == AlbIpSummaryScanner.DetailRetentionMode.SqliteApproved);
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
                    AlbIpSummaryExportExcel.Export(excelPath, excelEligible);
                    finalExcelPath = excelPath;
                }
            }

            // Build HTML report
            var orderedResults = resultsByIp.Values
                .OrderBy(r => r.RequestedIp, StringComparer.OrdinalIgnoreCase)
                .ToList();

            BuildMultiIpHtmlReport(htmlPath, orderedResults, finalExcelPath, finalSqlitePath);

            // Build per-IP summaries for inline display
            var perIpSummaries = orderedResults.Select(r => new AlbIpSummaryPerIpResult(
                Ip: r.RequestedIp,
                TotalRows: r.TotalRows,
                FilesWithHits: r.SourceFiles.Count,
                FirstHitUtc: r.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                LastHitUtc: r.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                Elb2xx3xx: r.ElbResponseTotals.S2xx + r.ElbResponseTotals.S3xx,
                Elb4xx: r.ElbResponseTotals.S4xx,
                Elb5xx: r.ElbResponseTotals.S5xx,
                Fe2xx3xx: r.FeResponseTotals.S2xx + r.FeResponseTotals.S3xx,
                Fe4xx: r.FeResponseTotals.S4xx,
                Fe5xx: r.FeResponseTotals.S5xx,
                Fe5xxWhileElb2xx3xx: r.Fe5xxWhileElb2xx3xx,
                Fe4xxWhileElb2xx3xx: r.Fe4xxWhileElb2xx3xx,
                Elb5xxWhileFe2xx3xx: r.Elb5xxWhileFe2xx3xx,
                Elb4xxWhileFe2xx3xx: r.Elb4xxWhileFe2xx3xx,
                TopEndpoints: r.TopTargetEndpoints(10).Select(kvp => new AlbIpSummaryEndpointHit(kvp.Key, kvp.Value)).ToList()))
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
                Message = "IP summary scan failed.",
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

    private void Update(string jobId, Func<AlbIpSummaryJobSnapshot, AlbIpSummaryJobSnapshot> update)
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
        IReadOnlyList<AlbIpSummaryScanner.ScanResult> results,
        string? excelPath,
        string? sqlitePath)
    {
        var artifactsByIp = new Dictionary<string, (string? Kind, string? Path)>(StringComparer.OrdinalIgnoreCase);
        var anySqlite = results.Any(r => r.DetailMode == AlbIpSummaryScanner.DetailRetentionMode.SqliteApproved);

        foreach (var result in results)
        {
            if (result.TotalRows == 0)
                artifactsByIp[result.RequestedIp] = (null, null);
            else if (anySqlite)
                artifactsByIp[result.RequestedIp] = ("SQLite", sqlitePath);
            else if (result.HasRetainedRows)
                artifactsByIp[result.RequestedIp] = ("Excel", excelPath);
            else
                artifactsByIp[result.RequestedIp] = (null, null);
        }

        // Use the existing console report builder via reflection-free approach:
        // Build the same JSON payload and HTML template as AlbOption3IpSummaryMulti.BuildMultiIpSummaryReport
        var payload = results.Select(r => new
        {
            ip = r.RequestedIp,
            totalRows = r.TotalRows,
            summaryHtml = BuildPerIpSummaryHtml(r, artifactsByIp[r.RequestedIp]),
            chart = BuildChartPayload(r)
        }).ToList();

        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });

        // Reuse the same HTML template as the console version
        var html = BuildReportHtml(json);
        File.WriteAllText(htmlPath, html, Encoding.UTF8);
    }

    private static string BuildPerIpSummaryHtml(AlbIpSummaryScanner.ScanResult result, (string? Kind, string? Path) artifact)
    {
        if (result.TotalRows == 0)
            return "<div class=\"card\"><div class=\"empty\">No ALB hits found for this IP.</div></div>";

        var sb = new StringBuilder(8192);
        sb.AppendLine("<div class=\"wrap\">");
        sb.AppendLine("  <div class=\"summary-card\">");
        sb.AppendLine("    <div class=\"row\">");
        sb.AppendLine($"      <div class=\"pill\">IP: {Esc(result.RequestedIp)}</div>");
        sb.AppendLine($"      <div class=\"pill\">Total: {result.TotalRows.ToString("N0", CultureInfo.InvariantCulture)}</div>");
        sb.AppendLine($"      <div class=\"pill\">Files: {result.SourceFiles.Count.ToString("N0", CultureInfo.InvariantCulture)}</div>");

        var first = result.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
        var last = result.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
        sb.AppendLine($"      <div class=\"pill\">{Esc(first)} → {Esc(last)}</div>");
        sb.AppendLine("    </div>");

        sb.AppendLine("    <div class=\"summary-grid\">");
        sb.AppendLine(BuildStatusTableHtml("ELB Response totals", result.ElbResponseTotals));
        sb.AppendLine(BuildStatusTableHtml("FE Response totals", result.FeResponseTotals));
        sb.AppendLine(BuildMismatchHtml(result));
        sb.AppendLine(BuildTopEndpointsHtml(result));
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");
        return sb.ToString();
    }

    private static string BuildStatusTableHtml(string title, AlbIpSummaryScanner.StatusGroupCounts counts)
    {
        return $"""
<div class="summary-card">
  <div class="summary-subtitle">{Esc(title)}</div>
  <table class="summary-table">
    <tr><th>Class</th><th>Hits</th></tr>
    <tr><td>2xx/3xx</td><td>{(counts.S2xx + counts.S3xx).ToString("N0", CultureInfo.InvariantCulture)}</td></tr>
    <tr><td>4xx</td><td>{counts.S4xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>
    <tr><td>5xx</td><td>{counts.S5xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>
  </table>
</div>
""";
    }

    private static string BuildMismatchHtml(AlbIpSummaryScanner.ScanResult r)
    {
        return $"""
<div class="summary-card" style="border-color: rgba(245, 158, 11, .45);">
  <div class="summary-subtitle">Interesting Mismatches</div>
  <table class="summary-table">
    <tr><th>Signal</th><th>Hits</th></tr>
    <tr><td>FE 5xx while ELB 2xx/3xx</td><td>{r.Fe5xxWhileElb2xx3xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>
    <tr><td>FE 4xx while ELB 2xx/3xx</td><td>{r.Fe4xxWhileElb2xx3xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>
    <tr><td>ELB 5xx while FE 2xx/3xx</td><td>{r.Elb5xxWhileFe2xx3xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>
    <tr><td>ELB 4xx while FE 2xx/3xx</td><td>{r.Elb4xxWhileFe2xx3xx.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>
  </table>
</div>
""";
    }

    private static string BuildTopEndpointsHtml(AlbIpSummaryScanner.ScanResult r)
    {
        var items = r.TopTargetEndpoints(10);
        var rows = items.Count == 0
            ? "    <tr><td>(none)</td><td>0</td></tr>"
            : string.Join("\n", items.Select(kvp =>
                $"    <tr><td style=\"font-family:monospace;word-break:break-all\">{Esc(kvp.Key)}</td><td>{kvp.Value.ToString("N0", CultureInfo.InvariantCulture)}</td></tr>"));

        return $"""
<div class="summary-card">
  <div class="summary-subtitle">Top 10 FE endpoints</div>
  <table class="summary-table">
    <tr><th>Endpoint</th><th>Hits</th></tr>
{rows}
  </table>
</div>
""";
    }

    private static object BuildChartPayload(AlbIpSummaryScanner.ScanResult result)
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
        var elb2xx3xx = new double[points];
        var elb4xx = new double[points];
        var elb5xx = new double[points];
        var fe2xx3xx = new double[points];
        var fe4xx = new double[points];
        var fe5xx = new double[points];

        for (int i = 0; i < points; i++)
        {
            var bucketStart = start.AddMinutes(i * bucketSize);
            times[i] = new DateTimeOffset(bucketStart).ToUnixTimeMilliseconds();

            for (int offset = 0; offset < bucketSize; offset++)
            {
                var minute = bucketStart.AddMinutes(offset);
                if (minute > end) break;
                if (!result.BucketsByMinuteUtc.TryGetValue(minute, out var bucket)) continue;

                elb2xx3xx[i] += bucket.Elb.S2xx + bucket.Elb.S3xx;
                elb4xx[i] += bucket.Elb.S4xx;
                elb5xx[i] += bucket.Elb.S5xx;
                fe2xx3xx[i] += bucket.Fe.S2xx + bucket.Fe.S3xx;
                fe4xx[i] += bucket.Fe.S4xx;
                fe5xx[i] += bucket.Fe.S5xx;
            }
        }

        return new
        {
            timesUtc = times,
            series = new[]
            {
                new { name = "ELB Response 2xx/3xx", values = elb2xx3xx },
                new { name = "ELB Response 4xx", values = elb4xx },
                new { name = "ELB Response 5xx", values = elb5xx },
                new { name = "FE Response 2xx/3xx", values = fe2xx3xx },
                new { name = "FE Response 4xx", values = fe4xx },
                new { name = "FE Response 5xx", values = fe5xx }
            }
        };
    }

    private static string BuildReportHtml(string dataJson)
    {
        // Minimal self-contained HTML report — same structure as the console version
        return $$$"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ALB Multi-IP Summary</title>
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
.chart-meta { display:flex; gap:12px; flex-wrap:wrap; align-items:flex-start; justify-content:space-between; margin-bottom:10px; }
.hover-card { position:relative; min-width:320px; flex:1 1 360px; min-height:120px; background:#111827; border:1px solid rgba(255,255,255,.08); border-radius:12px; padding:10px 12px; }
.hover-title { font-size:13px; font-weight:600; margin:0 0 6px 0; }
.hover-subtitle { font-size:12px; opacity:.78; margin-bottom:8px; }
.hover-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:8px; }
.hover-item { border:1px solid rgba(255,255,255,.06); border-radius:10px; padding:8px 10px; background:rgba(255,255,255,.025); }
.hover-item .label { display:flex; align-items:center; gap:8px; font-size:12px; opacity:.86; }
.hover-item .value { margin-top:4px; font-size:16px; font-weight:600; }
.dot { width:10px; height:10px; border-radius:999px; display:inline-block; }
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
      <div class="note">Multi-IP summary report generated by LogHunter web UI.</div>
    </div>
  </div>
  <div class="card">
    <div class="row">
      <div class="pill">Pan: <kbd>drag</kbd></div>
      <div class="pill">Zoom X: <kbd>wheel</kbd></div>
      <div class="pill">Reset: <kbd>double click</kbd></div>
      <div class="pill">Hover: <kbd>inspect bucket</kbd></div>
      <button class="btn" id="btnResetZoom" type="button">Reset zoom</button>
      <button class="btn" id="btnShowAllSeries" type="button">Show all series</button>
    </div>
    <div class="toggleRow" id="seriesToggles"></div>
    <div class="chart-meta">
      <div class="note" id="bucketMeta"></div>
      <div class="hover-card" id="hoverInfo"></div>
    </div>
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
const hoverInfo = document.getElementById('hoverInfo');
const bucketMeta = document.getElementById('bucketMeta');
const ctx = canvas.getContext('2d', { alpha: false });
const colors = ['#7dd3fc','#a7f3d0','#fda4af','#fcd34d','#c4b5fd','#fb7185'];
const chartStateByIp = new Map();
let currentItem = null;
let mouseX = null, mouseY = null, isDragging = false, dragStartX = 0, dragStartMin = 0, dragStartMax = 0;

function esc(s){ return String(s??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;'); }
function fmtNum(v){ return Number(v??0).toLocaleString('en-US'); }
function fmtUtc(ms){ const d=new Date(ms); const p=n=>String(n).padStart(2,'0'); return `${d.getUTCFullYear()}-${p(d.getUTCMonth()+1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} UTC`; }
function shortName(n){ return String(n||'').replace(' Response ','  '); }
function deriveBucketSeconds(times){
  if(!times||times.length<2) return 60;
  const deltaMs=Math.max(1000,Math.round(times[1]-times[0]));
  return Math.max(1,Math.round(deltaMs/1000));
}
function fmtBucket(seconds){
  if(seconds%60===0) return `${seconds/60} minute${seconds===60?'':'s'}`;
  return `${seconds} seconds`;
}
function updateHoverInfo(item, hoveredMs, tooltipSeries){
  if(!hoverInfo) return;
  if(!item){
    hoverInfo.innerHTML='<div class="hover-title">Chart inspection</div><div class="hover-subtitle">Hover the chart to inspect the nearest bucket.</div>';
    return;
  }
  if(hoveredMs==null||!tooltipSeries||!tooltipSeries.length){
    hoverInfo.innerHTML=`<div class="hover-title">Chart inspection</div><div class="hover-subtitle">Bucket size: ${esc(fmtBucket(deriveBucketSeconds(item.chart.timesUtc||[])))}</div><div class="note">Hover the chart to inspect the nearest bucket, compare visible series, and read exact values.</div>`;
    return;
  }
  hoverInfo.innerHTML=`<div class="hover-title">Nearest bucket</div><div class="hover-subtitle">${esc(fmtUtc(hoveredMs))} | ${esc(fmtBucket(deriveBucketSeconds(item.chart.timesUtc||[])))}</div><div class="hover-grid">${tooltipSeries.map(entry=>`<div class="hover-item"><div class="label"><span class="dot" style="background:${entry.s.color}"></span>${esc(entry.s.name)}</div><div class="value">${fmtNum(entry.v)}</div></div>`).join('')}</div>`;
}
function roundRect(ctx,x,y,w,h,r){const rr=Math.min(r,w/2,h/2);ctx.moveTo(x+rr,y);ctx.arcTo(x+w,y,x+w,y+h,rr);ctx.arcTo(x+w,y+h,x,y+h,rr);ctx.arcTo(x,y+h,x,y,rr);ctx.arcTo(x,y,x+w,y,rr);ctx.closePath();}
function getState(item){
  let s=chartStateByIp.get(item.ip);
  if(!s){
    const t=item.chart.timesUtc||[];
    const sr=(item.chart.series||[]).map((x,i)=>({name:x.name,short:shortName(x.name),values:x.values||[],color:colors[i%colors.length],visible:true}));
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

  if(mouseX!=null&&mouseY!=null&&mouseX>=pL&&mouseX<=pL+pW&&mouseY>=pT&&mouseY<=pT+pH){
    const tx=xToTime(mouseX-pL,s,pW);
    let idx=lb(t,tx);
    if(idx<=0)idx=0;else if(idx>=t.length)idx=t.length-1;else idx=Math.abs(tx-t[idx-1])<=Math.abs(tx-t[idx])?idx-1:idx;
    const ms=t[idx],cx=pL+timeToX(ms,s,pW);
    ctx.strokeStyle='rgba(230,237,243,.35)';ctx.beginPath();ctx.moveTo(cx,pT);ctx.lineTo(cx,pT+pH);ctx.stroke();
    const tooltipSeries=vis.map(x=>({s:x,v:x.values[idx]})).sort((a,b)=>b.v-a.v).slice(0,8);
    tooltipSeries.forEach(entry=>{const y=vToY(entry.v);ctx.fillStyle='#0b0f14';ctx.beginPath();ctx.arc(cx,y,5,0,Math.PI*2);ctx.fill();ctx.strokeStyle=entry.s.color;ctx.lineWidth=2;ctx.beginPath();ctx.arc(cx,y,4,0,Math.PI*2);ctx.stroke();});
    const lines=[fmtUtc(ms),...tooltipSeries.map(x=>`${x.s.short}: ${fmtNum(x.v)}`)];
    const pad=10;let w=0;lines.forEach(l=>{w=Math.max(w,ctx.measureText(l).width);});w+=pad*2;const h=lines.length*16+pad*2;
    let bx=cx+14,by=pT+10;if(bx+w>pL+pW)bx=cx-14-w;
    ctx.fillStyle='rgba(15,22,32,.94)';ctx.strokeStyle='rgba(255,255,255,.18)';ctx.beginPath();roundRect(ctx,bx,by,w,h,10);ctx.fill();ctx.stroke();
    ctx.fillStyle='#e6edf3';let ty=by+pad+12;ctx.fillText(lines[0],bx+pad,ty);ty+=18;
    tooltipSeries.forEach(entry=>{ctx.fillStyle=entry.s.color;ctx.fillRect(bx+pad,ty-9,8,8);ctx.fillStyle='#e6edf3';ctx.fillText(`${entry.s.short}: ${fmtNum(entry.v)}`,bx+pad+14,ty);ty+=16;});
    updateHoverInfo(item,ms,tooltipSeries);
    return;
  }
  updateHoverInfo(item,null,null);
}

function buildToggles(item){
  const s=getState(item);toggleHost.innerHTML='';
  s.series.forEach(x=>{const b=document.createElement('button');b.type='button';b.className=`seriesToggle${x.visible?'':' off'}`;b.innerHTML=`<span class="sw" style="background:${x.color}"></span><span>${esc(x.short)}</span>`;b.onclick=()=>{x.visible=!x.visible;buildToggles(item);drawChart(item);};b.ondblclick=e=>{e.preventDefault();s.series.forEach(o=>{o.visible=o===x;});buildToggles(item);drawChart(item);};toggleHost.appendChild(b);});
}
function renderSummary(item){summaryHost.innerHTML=item.summaryHtml||'<div class="card"><div class="empty">No summary.</div></div>';}
function renderSelected(){currentItem=DATA.find(x=>x.ip===select.value)||DATA[0];if(bucketMeta)bucketMeta.textContent=`Bucket size: ${fmtBucket(deriveBucketSeconds(currentItem.chart.timesUtc||[]))}. Double click a legend chip to isolate one series.`;buildToggles(currentItem);renderSummary(currentItem);updateHoverInfo(currentItem,null,null);drawChart(currentItem);}

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

    private static string SanitizeFileComponent(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
            sb.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
        return sb.ToString();
    }
}

internal sealed record AlbIpSummaryJobSnapshot(
    string JobId,
    string State,
    string Message,
    IReadOnlyList<string> RequestedIps,
    string InputSourceType,
    string InputSourceLabel,
    string InputSourceSummary,
    DateTime CreatedUtc,
    DateTime UpdatedUtc,
    int CurrentStep,
    int TotalSteps,
    string Phase,
    int FilesProcessed,
    int FilesTotal,
    long TotalBytes,
    IReadOnlyDictionary<string, long> IpRowCounts,
    string? HtmlReportPath,
    string? ExcelPath,
    string? SqlitePath,
    string? DetailMode,
    IReadOnlyList<AlbIpSummaryPerIpResult>? PerIpSummaries,
    string? Error)
{
    public static AlbIpSummaryJobSnapshot CreateIdle()
        => new(
            JobId: string.Empty,
            State: "idle",
            Message: "No IP summary scan has been run yet.",
            RequestedIps: Array.Empty<string>(),
            InputSourceType: AlbTopIpsInputSourceType.DefaultFolder.ToString(),
            InputSourceLabel: AppFolders.ALB,
            InputSourceSummary: $"Default folder | {AppFolders.ALB}",
            CreatedUtc: DateTime.UtcNow,
            UpdatedUtc: DateTime.UtcNow,
            CurrentStep: 0,
            TotalSteps: 0,
            Phase: "idle",
            FilesProcessed: 0,
            FilesTotal: 0,
            TotalBytes: 0,
            IpRowCounts: new Dictionary<string, long>(),
            HtmlReportPath: null,
            ExcelPath: null,
            SqlitePath: null,
            DetailMode: null,
            PerIpSummaries: null,
            Error: null);
}

internal sealed record AlbIpSummaryPerIpResult(
    string Ip,
    long TotalRows,
    int FilesWithHits,
    string? FirstHitUtc,
    string? LastHitUtc,
    int Elb2xx3xx,
    int Elb4xx,
    int Elb5xx,
    int Fe2xx3xx,
    int Fe4xx,
    int Fe5xx,
    long Fe5xxWhileElb2xx3xx,
    long Fe4xxWhileElb2xx3xx,
    long Elb5xxWhileFe2xx3xx,
    long Elb4xxWhileFe2xx3xx,
    IReadOnlyList<AlbIpSummaryEndpointHit> TopEndpoints);

internal sealed record AlbIpSummaryEndpointHit(string Endpoint, int Hits);
