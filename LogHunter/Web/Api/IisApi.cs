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

internal static class IisApi
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    public static async Task<bool> TryHandleAsync(WebAppContext app, HttpListenerContext context)
    {
        var path = context.Request.Url?.AbsolutePath ?? "/";

        // ── IP Summary endpoints ──────────────────────────────────────

        if (string.Equals(path, "/api/iis/ip-summary/meta", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, new
            {
                iisFolder = AppFolders.IIS,
                currentJob = app.IisIpSummary.GetSnapshot()
            }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/iis/ip-summary/job", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, app.IisIpSummary.GetSnapshot()).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/iis/ip-summary/run", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            IisIpSummaryRunRequest? body;
            try { body = await ReadJsonAsync<IisIpSummaryRunRequest>(context.Request).ConfigureAwait(false); }
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

            if (!app.IisIpSummary.TryStart(validIps, body.ExportXlsx, body.ChartOnly, out var snapshot, out var error))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true, snapshot }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/iis/ip-summary/open-report", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var ok = app.IisIpSummary.TryOpenReport(null, out var message);
            await WriteJsonAsync(context.Response, new { ok, message }, ok ? HttpStatusCode.OK : HttpStatusCode.BadRequest).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/iis/ip-summary/open-export", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var ok = app.IisIpSummary.TryOpenExport(null, out var message);
            await WriteJsonAsync(context.Response, new { ok, message }, ok ? HttpStatusCode.OK : HttpStatusCode.BadRequest).ConfigureAwait(false);
            return true;
        }

        // ── Status Pivot endpoints ────────────────────────────────────

        if (string.Equals(path, "/api/iis/status-pivot/meta", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, new
            {
                iisFolder = AppFolders.IIS,
                currentJob = app.IisStatusPivot.GetSnapshot()
            }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/iis/status-pivot/job", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, app.IisStatusPivot.GetSnapshot()).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/iis/status-pivot/run", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            IisStatusPivotRunRequest? body;
            try { body = await ReadJsonAsync<IisStatusPivotRunRequest>(context.Request).ConfigureAwait(false); }
            catch (Exception ex)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (string.IsNullOrWhiteSpace(body?.StatusFilter))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "A status filter is required (e.g. 4xx, 5xx, 4xx+5xx, or comma-separated codes)." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (!app.IisStatusPivot.TryStart(body.StatusFilter, body.AppScopeFragment, body.SelectedIps ?? Array.Empty<string>(), out var snapshot, out var error))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true, snapshot }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/iis/status-pivot/open-export", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var ok = app.IisStatusPivot.TryOpenExport(null, out var message);
            await WriteJsonAsync(context.Response, new { ok, message }, ok ? HttpStatusCode.OK : HttpStatusCode.BadRequest).ConfigureAwait(false);
            return true;
        }

        // ── Burst Patterns endpoints ──────────────────────────────────

        if (string.Equals(path, "/api/iis/burst-patterns/meta", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, new
            {
                iisFolder = AppFolders.IIS,
                currentJob = app.IisBurstPatterns.GetSnapshot()
            }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/iis/burst-patterns/job", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, app.IisBurstPatterns.GetSnapshot()).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/iis/burst-patterns/run", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            IisBurstPatternsRunRequest? body;
            try { body = await ReadJsonAsync<IisBurstPatternsRunRequest>(context.Request).ConfigureAwait(false); }
            catch (Exception ex)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            var bucketSeconds = body?.BucketSeconds ?? 60;

            if (!app.IisBurstPatterns.TryStart(bucketSeconds, out var snapshot, out var error))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true, snapshot }).ConfigureAwait(false);
            return true;
        }

        // ── Bytes Intel endpoints (bandwidth + uploads) ───────────────

        if (string.Equals(path, "/api/iis/bytes-intel/meta", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, new
            {
                iisFolder = AppFolders.IIS,
                currentJob = app.IisBytesIntel.GetSnapshot()
            }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/iis/bytes-intel/job", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, app.IisBytesIntel.GetSnapshot()).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/iis/bytes-intel/run", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            IisBytesIntelRunRequest? body;
            try { body = await ReadJsonAsync<IisBytesIntelRunRequest>(context.Request).ConfigureAwait(false); }
            catch (Exception ex)
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (string.IsNullOrWhiteSpace(body?.Mode))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error = "Mode is required (bandwidth or uploads)." }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            if (!app.IisBytesIntel.TryStart(body.Mode, out var snapshot, out var error))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true, snapshot }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/iis/bytes-intel/open-export", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            var ok = app.IisBytesIntel.TryOpenExport(null, out var message);
            await WriteJsonAsync(context.Response, new { ok, message }, ok ? HttpStatusCode.OK : HttpStatusCode.BadRequest).ConfigureAwait(false);
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

    private sealed record IisIpSummaryRunRequest(
        IReadOnlyList<string> Ips,
        bool ExportXlsx,
        bool ChartOnly);

    private sealed record IisStatusPivotRunRequest(
        string? StatusFilter,
        string? AppScopeFragment,
        IReadOnlyList<string>? SelectedIps);

    private sealed record IisBurstPatternsRunRequest(
        int BucketSeconds);

    private sealed record IisBytesIntelRunRequest(
        string? Mode);
}
