using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using LogHunter.Services;
using LogHunter.Web.Hosting;
using LogHunter.Web.Orchestration;

namespace LogHunter.Web.Api;

internal static class AbuseIpApi
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static async Task<bool> TryHandleAsync(WebAppContext app, HttpListenerContext context)
    {
        var path = context.Request.Url?.AbsolutePath ?? "/";

        if (string.Equals(path, "/api/abuseip/meta", StringComparison.OrdinalIgnoreCase))
        {
            var cfg = app.AbuseIpChecks.GetConfig();
            var configPath = app.AbuseIpChecks.GetConfigPath();
            var keySource = string.IsNullOrWhiteSpace(cfg.ApiKey) ? "built-in default" : "config file";

            await WriteJsonAsync(context.Response, new
            {
                maxAgeInDays = cfg.MaxAgeInDays,
                verbose = cfg.Verbose,
                keySource,
                configPath,
                currentJob = app.AbuseIpChecks.GetSnapshot()
            }).ConfigureAwait(false);

            return true;
        }

        if (string.Equals(path, "/api/abuseip/job", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, app.AbuseIpChecks.GetSnapshot()).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/abuseip/run", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            AbuseIpRunRequest? body;
            try
            {
                body = await ReadJsonAsync<AbuseIpRunRequest>(context.Request).ConfigureAwait(false);
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
                if (!IPAddress.TryParse(trimmed, out var parsed)) continue;
                var normalized = parsed.ToString();
                if (!validIps.Contains(normalized, StringComparer.OrdinalIgnoreCase))
                    validIps.Add(normalized);
            }

            if (validIps.Count == 0)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "No valid IP addresses found." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            var cfg = app.AbuseIpChecks.GetConfig();
            var maxAge = body.MaxAgeInDays is > 0 and <= 365 ? body.MaxAgeInDays.Value : cfg.MaxAgeInDays;

            if (!app.AbuseIpChecks.TryStart(validIps, maxAge, body.ApiKeyOverride?.Trim(), out var snapshot, out var error))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error }, HttpStatusCode.Conflict).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true, snapshot }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/abuseip/open-export", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            AbuseIpOpenRequest? body = null;
            try
            {
                body = await ReadJsonAsync<AbuseIpOpenRequest>(context.Request).ConfigureAwait(false);
            }
            catch
            {
                // Optional body
            }

            var ok = app.AbuseIpChecks.TryOpenExport(body?.JobId, out var message);
            await WriteJsonAsync(context.Response, new { ok, message }, ok ? HttpStatusCode.OK : HttpStatusCode.BadRequest).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/abuseip/config", StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(context.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
            {
                var cfg = app.AbuseIpChecks.GetConfig();
                await WriteJsonAsync(context.Response, new
                {
                    maxAgeInDays = cfg.MaxAgeInDays,
                    verbose = cfg.Verbose,
                    hasCustomKey = !string.IsNullOrWhiteSpace(cfg.ApiKey),
                    configPath = app.AbuseIpChecks.GetConfigPath()
                }).ConfigureAwait(false);
                return true;
            }

            if (string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                AbuseIpConfigUpdateRequest? body;
                try
                {
                    body = await ReadJsonAsync<AbuseIpConfigUpdateRequest>(context.Request).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    await WriteJsonAsync(context.Response, new { ok = false, error = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                    return true;
                }

                var currentCfg = app.AbuseIpChecks.GetConfig();
                var updated = currentCfg with
                {
                    ApiKey = body?.ClearApiKey == true ? null : (!string.IsNullOrWhiteSpace(body?.ApiKey) ? body.ApiKey.Trim() : currentCfg.ApiKey),
                    MaxAgeInDays = body?.MaxAgeInDays is > 0 and <= 365 ? body.MaxAgeInDays.Value : currentCfg.MaxAgeInDays,
                    Verbose = body?.Verbose ?? currentCfg.Verbose
                };

                app.AbuseIpChecks.SaveConfig(updated);

                await WriteJsonAsync(context.Response, new
                {
                    ok = true,
                    maxAgeInDays = updated.MaxAgeInDays,
                    verbose = updated.Verbose,
                    hasCustomKey = !string.IsNullOrWhiteSpace(updated.ApiKey)
                }).ConfigureAwait(false);
                return true;
            }
        }

        if (string.Equals(path, "/api/abuseip/browse-output-file", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var result = await NativeFileDialogHelper.BrowseSingleFileAsync(AppFolders.Output, "CSV/Excel files (*.csv;*.xlsx)", "*.csv;*.xlsx").ConfigureAwait(false);
            if (result is null)
            {
                await WriteJsonAsync(context.Response, new { ok = false, cancelled = true }).ConfigureAwait(false);
                return true;
            }

            var fi = new FileInfo(result);
            await WriteJsonAsync(context.Response, new { ok = true, file = new { name = fi.Name, path = fi.FullName, size = fi.Length } }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/abuseip/extract-ips", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            AbuseIpExtractRequest? body;
            try
            {
                body = await ReadJsonAsync<AbuseIpExtractRequest>(context.Request).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (string.IsNullOrWhiteSpace(body?.FilePath))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "filePath is required." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (!AlbIpExtractorHelper.TryExtractIps(body.FilePath, out var ipColumn, out var ips, out var extractError))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = extractError }).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true, ipColumn, ips = ips.Select(x => new { x.Ip, x.Hits }) }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/abuseip/output-files", StringComparison.OrdinalIgnoreCase))
        {
            var outDir = AppFolders.Output;
            var files = new List<object>();
            if (Directory.Exists(outDir))
            {
                foreach (var fi in Directory.EnumerateFiles(outDir, "abuseipdb_*", SearchOption.TopDirectoryOnly)
                    .Select(p => new FileInfo(p))
                    .OrderByDescending(f => f.CreationTimeUtc)
                    .Take(30))
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

        return false;
    }

    private static async Task<T?> ReadJsonAsync<T>(HttpListenerRequest request)
    {
        using var reader = new StreamReader(request.InputStream, request.ContentEncoding ?? Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: false);
        var json = await reader.ReadToEndAsync().ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(json))
            return default;

        return JsonSerializer.Deserialize<T>(json, JsonOptions);
    }

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

    private sealed record AbuseIpExtractRequest(string? FilePath);

    private sealed record AbuseIpRunRequest(
        IReadOnlyList<string> Ips,
        int? MaxAgeInDays,
        string? ApiKeyOverride);

    private sealed record AbuseIpOpenRequest(string? JobId);

    private sealed record AbuseIpConfigUpdateRequest(
        string? ApiKey,
        bool? ClearApiKey,
        int? MaxAgeInDays,
        bool? Verbose);
}
