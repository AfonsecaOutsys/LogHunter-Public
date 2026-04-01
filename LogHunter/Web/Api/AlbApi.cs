using System;
using System.Globalization;
using System.IO;
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
            else if (!app.AlbTopIpsStaging.TryBuildSelection(body?.StagingId ?? string.Empty, sourceType, out selection, out error))
            {
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
        string? StagingId);
}
