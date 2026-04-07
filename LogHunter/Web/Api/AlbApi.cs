using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using LogHunter.Services;
using LogHunter.Web.Hosting;
using LogHunter.Web.Orchestration;
using LogHunter.Web.Pages;

namespace LogHunter.Web.Api;

internal static class AlbApi
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    public static async Task<bool> TryHandleAsync(WebAppContext app, HttpListenerContext context)
    {
        var path = context.Request.Url?.AbsolutePath ?? "/";

        if (string.Equals(path, "/api/alb/options", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, AlbPageBuilder.BuildOptionsPayload()).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/download/meta", StringComparison.OrdinalIgnoreCase))
        {
            var now = DateTime.UtcNow;
            var startDefault = new DateTime(now.Year, now.Month, now.Day, 0, 0, 0, DateTimeKind.Utc);
            var endDefault = new DateTime(now.Year, now.Month, now.Day, 23, 55, 0, DateTimeKind.Utc);

            await WriteJsonAsync(context.Response, new
            {
                configs = AlbDownload.GetSavedConfigSummaries(),
                workspaceAlbPath = AppFolders.ALB,
                defaultStartUtc = startDefault.ToString("u", CultureInfo.InvariantCulture),
                defaultEndUtc = endDefault.ToString("u", CultureInfo.InvariantCulture),
                currentJob = app.AlbDownloads.GetSnapshot()
            }).ConfigureAwait(false);

            return true;
        }

        if (string.Equals(path, "/api/alb/download/job", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, app.AlbDownloads.GetSnapshot()).ConfigureAwait(false);
            return true;
        }

        if (path.StartsWith("/api/jobs/", StringComparison.OrdinalIgnoreCase))
        {
            var jobId = path["/api/jobs/".Length..];
            if (string.IsNullOrWhiteSpace(jobId) || !app.AlbDownloads.TryGetSnapshot(jobId, out var snapshot))
            {
                await WriteJsonAsync(context.Response, new { error = "Job not found." }, HttpStatusCode.NotFound).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, snapshot).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/download/start", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            AlbDownloadStartRequest? body;
            try
            {
                body = await ReadJsonAsync<AlbDownloadStartRequest>(context.Request).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (body is null)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "Request body is required." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (!TryBuildRequest(body, out var request, out var error))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (!app.AlbDownloads.TryStart(request!, out var snapshot, out error))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error, snapshot }, HttpStatusCode.Conflict).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true, snapshot }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/download/open-run-folder", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            AlbOpenFolderRequest? body = null;
            try
            {
                body = await ReadJsonAsync<AlbOpenFolderRequest>(context.Request).ConfigureAwait(false);
            }
            catch
            {
                // Optional body. Ignore parse failures and use current job.
            }

            var ok = app.AlbDownloads.TryOpenRunFolder(body?.JobId, out var message);
            await WriteJsonAsync(context.Response, new { ok, message }, ok ? HttpStatusCode.OK : HttpStatusCode.BadRequest).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/top-ips-top-paths/run", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            AlbTopIpsTopPathsRequest? body;
            try
            {
                body = await ReadJsonAsync<AlbTopIpsTopPathsRequest>(context.Request).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            var endpointFragment = body?.EndpointFragment?.Trim();
            if (string.IsNullOrWhiteSpace(endpointFragment))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "Endpoint/path fragment is required." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            var sourceType = AlbTopIpsInputSourceResolver.NormalizeSourceType(body?.SourceType);
            AlbTopIpsInputSourceSelection selection;
            string? error;

            if (sourceType == AlbTopIpsInputSourceType.DefaultFolder)
            {
                selection = AlbTopIpsInputSourceResolver.ResolveDefaultFolder();
            }
            else if (!string.IsNullOrWhiteSpace(body?.ServerPath))
            {
                selection = AlbTopIpsInputSourceResolver.ResolveServerPath(body.ServerPath, sourceType);
            }
            else if (body?.ServerFilePaths is { Count: > 0 })
            {
                selection = AlbTopIpsInputSourceResolver.ResolveServerFiles(body.ServerFilePaths);
            }
            else if (!string.IsNullOrWhiteSpace(body?.StagingId) && app.AlbTopIpsStaging.TryBuildSelection(body.StagingId, sourceType, out selection, out error))
            {
                // Staging upload path — selection already resolved above.
            }
            else
            {
                error = "A folder path, file selection, or staged upload is required.";
                await WriteJsonAsync(context.Response, new { ok = false, error }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (!app.AlbTopIps.TryStart(endpointFragment, body?.ExportXlsx == true, selection, out var snapshot, out error))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true, snapshot }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/top-ips-top-paths/meta", StringComparison.OrdinalIgnoreCase))
        {
            var selection = AlbTopIpsInputSourceResolver.ResolveDefaultFolder();
            await WriteJsonAsync(context.Response, new
            {
                defaultSelection = BuildInputSourcePayload(selection),
                currentJob = app.AlbTopIps.GetSnapshot()
            }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/top-ips-top-paths/job", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, app.AlbTopIps.GetSnapshot()).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/top-ips-top-paths/staging/start", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            AlbTopIpsStagingStartRequest? body;
            try
            {
                body = await ReadJsonAsync<AlbTopIpsStagingStartRequest>(context.Request).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            var sourceType = AlbTopIpsInputSourceResolver.NormalizeSourceType(body?.SourceType);
            if (sourceType == AlbTopIpsInputSourceType.DefaultFolder)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "Staging is only used for selected folder or selected files." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            var stagingId = app.AlbTopIpsStaging.CreateSession(sourceType);
            await WriteJsonAsync(context.Response, new { ok = true, stagingId }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/top-ips-top-paths/staging/upload", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var stagingId = context.Request.QueryString["stagingId"];
            var relativePath = context.Request.QueryString["relativePath"];
            if (string.IsNullOrWhiteSpace(stagingId) || string.IsNullOrWhiteSpace(relativePath))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "stagingId and relativePath are required." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            try
            {
                app.AlbTopIpsStaging.SaveFile(stagingId, relativePath, context.Request.InputStream);
            }
            catch (Exception ex)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/top-ips-top-paths/browse-folder", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var folderPath = await NativeFileDialogHelper.BrowseFolderAsync(AppFolders.ALB).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(folderPath))
            {
                await WriteJsonAsync(context.Response, new { ok = false, cancelled = true }).ConfigureAwait(false);
                return true;
            }

            var files = AlbScanner.GetLogFiles(folderPath);
            var selection = AlbTopIpsInputSourceResolver.BuildUploadedSelection(
                AlbTopIpsInputSourceType.SelectedFolder, folderPath, files, folderPath);

            await WriteJsonAsync(context.Response, new { ok = true, selection = BuildInputSourcePayload(selection) }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/top-ips-top-paths/browse-files", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var filePaths = await NativeFileDialogHelper.BrowseFilesAsync(AppFolders.ALB).ConfigureAwait(false);
            if (filePaths.Count == 0)
            {
                await WriteJsonAsync(context.Response, new { ok = false, cancelled = true }).ConfigureAwait(false);
                return true;
            }

            var logFiles = filePaths.Where(f => f.EndsWith(".log", StringComparison.OrdinalIgnoreCase)).ToList();
            var selection = AlbTopIpsInputSourceResolver.BuildUploadedSelection(
                AlbTopIpsInputSourceType.SelectedFiles, null, logFiles, $"{logFiles.Count} selected file(s)");

            await WriteJsonAsync(context.Response, new { ok = true, selection = BuildInputSourcePayload(selection) }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/top-ips-top-paths/open-export", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            AlbOpenFolderRequest? body = null;
            try
            {
                body = await ReadJsonAsync<AlbOpenFolderRequest>(context.Request).ConfigureAwait(false);
            }
            catch
            {
                // Optional body. Ignore parse failures and use current job.
            }

            var ok = app.AlbTopIps.TryOpenExport(body?.JobId, out var message);
            await WriteJsonAsync(context.Response, new { ok, message }, ok ? HttpStatusCode.OK : HttpStatusCode.BadRequest).ConfigureAwait(false);
            return true;
        }

        // ── IP Summary endpoints ──────────────────────────────────────

        if (string.Equals(path, "/api/alb/ip-summary/meta", StringComparison.OrdinalIgnoreCase))
        {
            var selection = AlbTopIpsInputSourceResolver.ResolveDefaultFolder();
            await WriteJsonAsync(context.Response, new
            {
                defaultSelection = BuildInputSourcePayload(selection),
                currentJob = app.AlbIpSummary.GetSnapshot()
            }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/ip-summary/job", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, app.AlbIpSummary.GetSnapshot()).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/ip-summary/run", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            AlbIpSummaryRunRequest? body;
            try
            {
                body = await ReadJsonAsync<AlbIpSummaryRunRequest>(context.Request).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (body?.Ips is null || body.Ips.Count == 0)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "At least one IP is required." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            var validIps = new List<string>();
            foreach (var raw in body.Ips)
            {
                var trimmed = raw?.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;
                if (!System.Net.IPAddress.TryParse(trimmed, out var parsed)) continue;
                var normalized = parsed.ToString();
                if (!validIps.Contains(normalized, StringComparer.OrdinalIgnoreCase))
                    validIps.Add(normalized);
            }

            if (validIps.Count == 0)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "No valid IP addresses found." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            var sourceType = AlbTopIpsInputSourceResolver.NormalizeSourceType(body.SourceType);
            AlbTopIpsInputSourceSelection selection;

            if (sourceType == AlbTopIpsInputSourceType.DefaultFolder)
            {
                selection = AlbTopIpsInputSourceResolver.ResolveDefaultFolder();
            }
            else if (!string.IsNullOrWhiteSpace(body.ServerPath))
            {
                selection = AlbTopIpsInputSourceResolver.ResolveServerPath(body.ServerPath, sourceType);
            }
            else if (body.ServerFilePaths is { Count: > 0 })
            {
                selection = AlbTopIpsInputSourceResolver.ResolveServerFiles(body.ServerFilePaths);
            }
            else
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "A folder path or file selection is required." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (!app.AlbIpSummary.TryStart(validIps, body.ExportXlsx, body.ChartOnly, selection, out var snapshot, out var error))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true, snapshot }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/ip-summary/browse-folder", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var folderPath = await NativeFileDialogHelper.BrowseFolderAsync(AppFolders.ALB).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(folderPath))
            {
                await WriteJsonAsync(context.Response, new { ok = false, cancelled = true }).ConfigureAwait(false);
                return true;
            }

            var files = AlbScanner.GetLogFiles(folderPath);
            var selection = AlbTopIpsInputSourceResolver.BuildUploadedSelection(
                AlbTopIpsInputSourceType.SelectedFolder, folderPath, files, folderPath);

            await WriteJsonAsync(context.Response, new { ok = true, selection = BuildInputSourcePayload(selection) }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/ip-summary/browse-files", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var filePaths = await NativeFileDialogHelper.BrowseFilesAsync(AppFolders.ALB).ConfigureAwait(false);
            if (filePaths.Count == 0)
            {
                await WriteJsonAsync(context.Response, new { ok = false, cancelled = true }).ConfigureAwait(false);
                return true;
            }

            var logFiles = filePaths.Where(f => f.EndsWith(".log", StringComparison.OrdinalIgnoreCase)).ToList();
            var selection = AlbTopIpsInputSourceResolver.BuildUploadedSelection(
                AlbTopIpsInputSourceType.SelectedFiles, null, logFiles, $"{logFiles.Count} selected file(s)");

            await WriteJsonAsync(context.Response, new { ok = true, selection = BuildInputSourcePayload(selection) }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/ip-summary/open-report", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var ok = app.AlbIpSummary.TryOpenReport(null, out var message);
            await WriteJsonAsync(context.Response, new { ok, message }, ok ? HttpStatusCode.OK : HttpStatusCode.BadRequest).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/ip-summary/open-export", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var ok = app.AlbIpSummary.TryOpenExport(null, out var message);
            await WriteJsonAsync(context.Response, new { ok, message }, ok ? HttpStatusCode.OK : HttpStatusCode.BadRequest).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/ip-summary/output-files", StringComparison.OrdinalIgnoreCase))
        {
            var outDir = AppFolders.Output;
            var files = new List<object>();
            if (Directory.Exists(outDir))
            {
                foreach (var fi in Directory.EnumerateFiles(outDir, "*", SearchOption.TopDirectoryOnly)
                    .Where(p => p.EndsWith(".csv", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".xlsx", StringComparison.OrdinalIgnoreCase))
                    .Select(p => new FileInfo(p))
                    .OrderByDescending(f => f.CreationTimeUtc)
                    .Take(50))
                {
                    files.Add(new
                    {
                        name = fi.Name,
                        path = fi.FullName,
                        size = fi.Length,
                        createdUtc = fi.CreationTimeUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + "Z"
                    });
                }
            }

            await WriteJsonAsync(context.Response, new { files }).ConfigureAwait(false);
            return true;
        }

        // ── Generic scan endpoints (options 4-10) ───────────────────

        if (await TryHandleGenericScanAsync(app, context, path, "alb/5xx-mismatch", app.Alb5xxMismatch,
                AlbGenericScanFunctions.ScanStatusMismatchAsync).ConfigureAwait(false))
            return true;

        if (await TryHandleGenericScanAsync(app, context, path, "alb/top-50-ips", app.AlbTop50Ips,
                AlbGenericScanFunctions.ScanTop50IpsOverallAsync).ConfigureAwait(false))
            return true;

        if (await TryHandleGenericScanAsync(app, context, path, "alb/top-50-ips-by-uri", app.AlbTop50IpUri,
                AlbGenericScanFunctions.ScanTop50IpUriNoQueryAsync).ConfigureAwait(false))
            return true;

        if (await TryHandleGenericScanAsync(app, context, path, "alb/top-50-avg-duration", app.AlbTop50AvgDuration,
                AlbGenericScanFunctions.ScanTop50AvgDurationAsync).ConfigureAwait(false))
            return true;

        if (await TryHandleGenericScanAsync(app, context, path, "alb/waf-blocked-summary", app.AlbWafBlockedSummary,
                AlbGenericScanFunctions.ScanWafBlockedSummaryAsync).ConfigureAwait(false))
            return true;

        if (await TryHandleGenericScanAsync(app, context, path, "alb/waf-blocks-over-time", app.AlbWafBlockedChart,
                AlbGenericScanFunctions.ScanWafBlockedPerMinuteChartAsync).ConfigureAwait(false))
            return true;

        // ── Option 8: Requests over time per IP (5-minute buckets) ──

        if (string.Equals(path, "/api/alb/requests-over-time/meta", StringComparison.OrdinalIgnoreCase))
        {
            var selection = AlbTopIpsInputSourceResolver.ResolveDefaultFolder();
            await WriteJsonAsync(context.Response, new
            {
                defaultSelection = BuildInputSourcePayload(selection),
                currentJob = app.AlbRequestsPerIp5Min.GetSnapshot()
            }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/requests-over-time/job", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, app.AlbRequestsPerIp5Min.GetSnapshot()).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/requests-over-time/run", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            AlbRequestsOverTimeRunRequest? body;
            try
            {
                body = await ReadJsonAsync<AlbRequestsOverTimeRunRequest>(context.Request).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (body?.Ips is null || body.Ips.Count == 0)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "At least one IP is required." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            var validIps = new List<string>();
            foreach (var raw in body.Ips)
            {
                var trimmed = raw?.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;
                if (!System.Net.IPAddress.TryParse(trimmed, out var parsed)) continue;
                var normalized = parsed.ToString();
                if (!validIps.Contains(normalized, StringComparer.OrdinalIgnoreCase))
                    validIps.Add(normalized);
            }

            if (validIps.Count == 0)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "No valid IP addresses found." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (validIps.Count > 20)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "Maximum 20 IPs per scan." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            var sourceType = AlbTopIpsInputSourceResolver.NormalizeSourceType(body.SourceType);
            AlbTopIpsInputSourceSelection selection;

            if (sourceType == AlbTopIpsInputSourceType.DefaultFolder)
            {
                selection = AlbTopIpsInputSourceResolver.ResolveDefaultFolder();
            }
            else if (!string.IsNullOrWhiteSpace(body.ServerPath))
            {
                selection = AlbTopIpsInputSourceResolver.ResolveServerPath(body.ServerPath, sourceType);
            }
            else if (body.ServerFilePaths is { Count: > 0 })
            {
                selection = AlbTopIpsInputSourceResolver.ResolveServerFiles(body.ServerFilePaths);
            }
            else
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "A folder path or file selection is required." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            var scanFunc = AlbGenericScanFunctions.CreateRequestsPerIp5MinFunc(validIps, "Web UI");

            if (!app.AlbRequestsPerIp5Min.TryStart(scanFunc, selection, out var snapshot, out var error))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true, snapshot }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/requests-over-time/browse-folder", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var folderPath = await NativeFileDialogHelper.BrowseFolderAsync(AppFolders.ALB).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(folderPath))
            {
                await WriteJsonAsync(context.Response, new { ok = false, cancelled = true }).ConfigureAwait(false);
                return true;
            }

            var files = AlbScanner.GetLogFiles(folderPath);
            var selection = AlbTopIpsInputSourceResolver.BuildUploadedSelection(
                AlbTopIpsInputSourceType.SelectedFolder, folderPath, files, folderPath);

            await WriteJsonAsync(context.Response, new { ok = true, selection = BuildInputSourcePayload(selection) }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/requests-over-time/browse-files", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var filePaths = await NativeFileDialogHelper.BrowseFilesAsync(AppFolders.ALB).ConfigureAwait(false);
            if (filePaths.Count == 0)
            {
                await WriteJsonAsync(context.Response, new { ok = false, cancelled = true }).ConfigureAwait(false);
                return true;
            }

            var logFiles = filePaths.Where(f => f.EndsWith(".log", StringComparison.OrdinalIgnoreCase)).ToList();
            var selection = AlbTopIpsInputSourceResolver.BuildUploadedSelection(
                AlbTopIpsInputSourceType.SelectedFiles, null, logFiles, $"{logFiles.Count} selected file(s)");

            await WriteJsonAsync(context.Response, new { ok = true, selection = BuildInputSourcePayload(selection) }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/requests-over-time/open-export", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var ok = app.AlbRequestsPerIp5Min.TryOpenExport(null, out var message);
            await WriteJsonAsync(context.Response, new { ok, message }, ok ? HttpStatusCode.OK : HttpStatusCode.BadRequest).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/requests-over-time/open-chart", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var snap = app.AlbRequestsPerIp5Min.GetSnapshot();
            var chartPath = snap.Result?.ChartHtmlPath;
            if (string.IsNullOrWhiteSpace(chartPath) || !File.Exists(chartPath))
            {
                await WriteJsonAsync(context.Response, new { ok = false, message = "No chart available." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo { FileName = chartPath, UseShellExecute = true });
                await WriteJsonAsync(context.Response, new { ok = true, message = chartPath }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJsonAsync(context.Response, new { ok = false, message = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
            }
            return true;
        }

        if (string.Equals(path, "/api/alb/requests-over-time/output-files", StringComparison.OrdinalIgnoreCase))
        {
            var outDir = AppFolders.Output;
            var files = new List<object>();
            if (Directory.Exists(outDir))
            {
                foreach (var fi in Directory.EnumerateFiles(outDir, "*", SearchOption.TopDirectoryOnly)
                    .Where(p => p.EndsWith(".csv", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".xlsx", StringComparison.OrdinalIgnoreCase))
                    .Select(p => new FileInfo(p))
                    .OrderByDescending(f => f.CreationTimeUtc)
                    .Take(50))
                {
                    files.Add(new
                    {
                        name = fi.Name,
                        path = fi.FullName,
                        size = fi.Length,
                        createdUtc = fi.CreationTimeUtc.ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture) + "Z"
                    });
                }
            }

            await WriteJsonAsync(context.Response, new { files }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/requests-over-time/extract-ips", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            AlbIpSummaryExtractIpsRequest? body;
            try
            {
                body = await ReadJsonAsync<AlbIpSummaryExtractIpsRequest>(context.Request).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (string.IsNullOrWhiteSpace(body?.FilePath) || !File.Exists(body.FilePath))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "File not found." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (!AlbIpExtractorHelper.TryExtractIps(body.FilePath, out var ipColumn, out var ips, out var extractError))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = extractError }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true, ipColumn, ips }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/alb/ip-summary/extract-ips", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            AlbIpSummaryExtractIpsRequest? body;
            try
            {
                body = await ReadJsonAsync<AlbIpSummaryExtractIpsRequest>(context.Request).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (string.IsNullOrWhiteSpace(body?.FilePath) || !File.Exists(body.FilePath))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "File not found." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (!AlbIpExtractorHelper.TryExtractIps(body.FilePath, out var ipColumn, out var ips, out var extractError))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = extractError }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true, ipColumn, ips }).ConfigureAwait(false);
            return true;
        }

        return false;
    }

    private static bool TryBuildRequest(AlbDownloadStartRequest body, out AlbDownloadRequest? request, out string? error)
    {
        request = null;
        error = null;

        if (!DateTime.TryParse(body.StartUtc, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var startUtc))
        {
            error = "Start time is required and must be valid.";
            return false;
        }

        if (!DateTime.TryParse(body.EndUtc, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var endUtc))
        {
            error = "End time is required and must be valid.";
            return false;
        }

        request = new AlbDownloadRequest(
            UseSavedConfig: string.Equals(body.ConfigMode, "saved", StringComparison.OrdinalIgnoreCase),
            SavedConfigName: body.SavedConfigName,
            ConfigName: body.ConfigName,
            Bucket: body.Bucket,
            AlbId: body.AlbId,
            UseInternalScope: string.Equals(body.Scope, "internal", StringComparison.OrdinalIgnoreCase),
            AccountId: body.AccountId,
            Region: null,
            IsSentry: body.IsSentry,
            AwsEnvironmentText: body.AwsEnvironmentText ?? string.Empty,
            StartUtc: DateTime.SpecifyKind(startUtc, DateTimeKind.Utc),
            EndUtc: DateTime.SpecifyKind(endUtc, DateTimeKind.Utc));

        return true;
    }

    private static async Task<T?> ReadJsonAsync<T>(HttpListenerRequest request)
    {
        using var reader = new StreamReader(request.InputStream, request.ContentEncoding ?? Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: false);
        var json = await reader.ReadToEndAsync().ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(json))
            return default;

        return JsonSerializer.Deserialize<T>(json, JsonOptions);
    }

    private static object BuildInputSourcePayload(AlbTopIpsInputSourceSelection selection)
        => new
        {
            sourceType = selection.SourceType switch
            {
                AlbTopIpsInputSourceType.SelectedFolder => "folder",
                AlbTopIpsInputSourceType.SelectedFiles => "files",
                _ => "default"
            },
            rootPath = selection.RootPath,
            filePaths = selection.Files,
            fileCount = selection.FileCount,
            totalBytes = selection.TotalBytes,
            selectionLabel = selection.SelectionLabel,
            summary = selection.Summary,
            previewItems = selection.PreviewItems,
            remainingCount = selection.RemainingCount
        };

    private static async Task WriteJsonAsync(HttpListenerResponse response, object payload, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        var json = JsonSerializer.Serialize(payload, JsonOptions);
        await WriteTextAsync(response, statusCode, json, "application/json; charset=utf-8").ConfigureAwait(false);
    }

    private static async Task WriteTextAsync(HttpListenerResponse response, HttpStatusCode statusCode, string body, string contentType)
    {
        var data = Encoding.UTF8.GetBytes(body);
        response.StatusCode = (int)statusCode;
        response.ContentType = contentType;
        response.ContentLength64 = data.Length;
        await using var stream = response.OutputStream;
        await stream.WriteAsync(data).ConfigureAwait(false);
    }

    private sealed record AlbDownloadStartRequest(
        string? ConfigMode,
        string? SavedConfigName,
        string? ConfigName,
        string? Bucket,
        string? AlbId,
        string? Scope,
        string? AccountId,
        bool IsSentry,
        string? AwsEnvironmentText,
        string? StartUtc,
        string? EndUtc);

    private sealed record AlbOpenFolderRequest(string? JobId);
    private sealed record AlbTopIpsStagingStartRequest(string? SourceType);
    private sealed record AlbTopIpsTopPathsRequest(
        string? EndpointFragment,
        bool ExportXlsx,
        string? SourceType,
        string? StagingId,
        string? ServerPath,
        IReadOnlyList<string>? ServerFilePaths);

    private sealed record AlbIpSummaryRunRequest(
        IReadOnlyList<string> Ips,
        bool ExportXlsx,
        bool ChartOnly,
        string? SourceType,
        string? ServerPath,
        IReadOnlyList<string>? ServerFilePaths);

    private sealed record AlbIpSummaryExtractIpsRequest(string? FilePath);

    private sealed record AlbGenericScanRunRequest(
        string? SourceType,
        string? ServerPath,
        IReadOnlyList<string>? ServerFilePaths);

    private sealed record AlbRequestsOverTimeRunRequest(
        IReadOnlyList<string> Ips,
        string? SourceType,
        string? ServerPath,
        IReadOnlyList<string>? ServerFilePaths);

    private static async Task<bool> TryHandleGenericScanAsync(
        WebAppContext app,
        HttpListenerContext context,
        string path,
        string optionSlug,
        AlbGenericScanJobManager manager,
        Func<List<string>, string, Action<string, int, int, string>, Task<AlbGenericScanResult>> scanFunc)
    {
        var prefix = $"/api/{optionSlug}";

        if (string.Equals(path, $"{prefix}/meta", StringComparison.OrdinalIgnoreCase))
        {
            var selection = AlbTopIpsInputSourceResolver.ResolveDefaultFolder();
            await WriteJsonAsync(context.Response, new
            {
                defaultSelection = BuildInputSourcePayload(selection),
                currentJob = manager.GetSnapshot()
            }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, $"{prefix}/job", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, manager.GetSnapshot()).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, $"{prefix}/run", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            AlbGenericScanRunRequest? body;
            try
            {
                body = await ReadJsonAsync<AlbGenericScanRunRequest>(context.Request).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            var sourceType = AlbTopIpsInputSourceResolver.NormalizeSourceType(body?.SourceType);
            AlbTopIpsInputSourceSelection selection;

            if (sourceType == AlbTopIpsInputSourceType.DefaultFolder)
            {
                selection = AlbTopIpsInputSourceResolver.ResolveDefaultFolder();
            }
            else if (!string.IsNullOrWhiteSpace(body?.ServerPath))
            {
                selection = AlbTopIpsInputSourceResolver.ResolveServerPath(body.ServerPath, sourceType);
            }
            else if (body?.ServerFilePaths is { Count: > 0 })
            {
                selection = AlbTopIpsInputSourceResolver.ResolveServerFiles(body.ServerFilePaths);
            }
            else
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "A folder path or file selection is required." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (!manager.TryStart(scanFunc, selection, out var snapshot, out var error))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true, snapshot }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, $"{prefix}/browse-folder", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var folderPath = await NativeFileDialogHelper.BrowseFolderAsync(AppFolders.ALB).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(folderPath))
            {
                await WriteJsonAsync(context.Response, new { ok = false, cancelled = true }).ConfigureAwait(false);
                return true;
            }

            var files = AlbScanner.GetLogFiles(folderPath);
            var selection = AlbTopIpsInputSourceResolver.BuildUploadedSelection(
                AlbTopIpsInputSourceType.SelectedFolder, folderPath, files, folderPath);

            await WriteJsonAsync(context.Response, new { ok = true, selection = BuildInputSourcePayload(selection) }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, $"{prefix}/browse-files", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var filePaths = await NativeFileDialogHelper.BrowseFilesAsync(AppFolders.ALB).ConfigureAwait(false);
            if (filePaths.Count == 0)
            {
                await WriteJsonAsync(context.Response, new { ok = false, cancelled = true }).ConfigureAwait(false);
                return true;
            }

            var logFiles = filePaths.Where(f => f.EndsWith(".log", StringComparison.OrdinalIgnoreCase)).ToList();
            var selection = AlbTopIpsInputSourceResolver.BuildUploadedSelection(
                AlbTopIpsInputSourceType.SelectedFiles, null, logFiles, $"{logFiles.Count} selected file(s)");

            await WriteJsonAsync(context.Response, new { ok = true, selection = BuildInputSourcePayload(selection) }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, $"{prefix}/open-export", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var ok = manager.TryOpenExport(null, out var message);
            await WriteJsonAsync(context.Response, new { ok, message }, ok ? HttpStatusCode.OK : HttpStatusCode.BadRequest).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, $"{prefix}/open-chart", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var snap = manager.GetSnapshot();
            var chartPath = snap.Result?.ChartHtmlPath;
            if (string.IsNullOrWhiteSpace(chartPath) || !File.Exists(chartPath))
            {
                await WriteJsonAsync(context.Response, new { ok = false, message = "No chart available." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo { FileName = chartPath, UseShellExecute = true });
                await WriteJsonAsync(context.Response, new { ok = true, message = chartPath }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJsonAsync(context.Response, new { ok = false, message = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
            }
            return true;
        }

        return false;
    }
}
