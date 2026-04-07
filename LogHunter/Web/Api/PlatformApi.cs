using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using LogHunter.Services;
using LogHunter.Web.Hosting;
using LogHunter.Web.Pages;

namespace LogHunter.Web.Api;

internal static class PlatformApi
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    public static async Task<bool> TryHandleAsync(WebAppContext app, HttpListenerContext context)
    {
        var path = context.Request.Url?.AbsolutePath ?? "/";

        if (string.Equals(path, "/api/platform/options", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, PlatformPageBuilder.BuildOptionsPayload()).ConfigureAwait(false);
            return true;
        }

        // ── Suspicious extract IPs endpoints ──────────────────────────

        if (string.Equals(path, "/api/platform/suspicious/meta", StringComparison.OrdinalIgnoreCase))
        {
            var suspiciousCount = app.Session.PlatformSuspiciousIpHits?.Count ?? 0;
            var authedCount = app.Session.PlatformAuthedIpHits?.Count ?? 0;

            await WriteJsonAsync(context.Response, new
            {
                platformLogsPath = AppFolders.PlatformLogs,
                suspiciousCacheCount = suspiciousCount,
                authedCacheCount = authedCount,
                currentJob = app.PlatformSuspicious.GetSnapshot()
            }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/platform/suspicious/job", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, app.PlatformSuspicious.GetSnapshot()).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/platform/suspicious/run", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            if (!app.PlatformSuspicious.TryStart(out var snapshot, out var error))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true, snapshot }).ConfigureAwait(false);
            return true;
        }

        // ── Authenticated activity endpoints ──────────────────────────

        if (string.Equals(path, "/api/platform/auth/meta", StringComparison.OrdinalIgnoreCase))
        {
            var suspiciousCount = app.Session.PlatformSuspiciousIpHits?.Count ?? 0;
            var authedCount = app.Session.PlatformAuthedIpHits?.Count ?? 0;

            await WriteJsonAsync(context.Response, new
            {
                platformLogsPath = AppFolders.PlatformLogs,
                suspiciousCacheCount = suspiciousCount,
                authedCacheCount = authedCount,
                currentJob = app.PlatformAuth.GetSnapshot()
            }).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/platform/auth/job", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, app.PlatformAuth.GetSnapshot()).ConfigureAwait(false);
            return true;
        }

        if (string.Equals(path, "/api/platform/auth/run", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
                return true;
            }

            if (!app.PlatformAuth.TryStart(out var snapshot, out var error))
            {
                await WriteJsonAsync(context.Response, new { ok = false, error }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            await WriteJsonAsync(context.Response, new { ok = true, snapshot }).ConfigureAwait(false);
            return true;
        }

        // ── Cache view endpoint ──────────────────────────

        if (string.Equals(path, "/api/platform/cache", StringComparison.OrdinalIgnoreCase))
        {
            var suspicious = app.Session.PlatformSuspiciousIpHits;
            var authed = app.Session.PlatformAuthedIpHits;

            var suspiciousList = (suspicious ?? new Dictionary<string, int>())
                .OrderByDescending(kvp => kvp.Value)
                .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
                .Select((kvp, i) => new { rank = i + 1, ip = kvp.Key, hits = kvp.Value })
                .ToList();

            var authedList = (authed ?? new Dictionary<string, int>())
                .OrderByDescending(kvp => kvp.Value)
                .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
                .Select((kvp, i) => new { rank = i + 1, ip = kvp.Key, hits = kvp.Value })
                .ToList();

            await WriteJsonAsync(context.Response, new
            {
                suspiciousCount = suspicious?.Count ?? 0,
                authedCount = authed?.Count ?? 0,
                suspiciousUpdatedUtc = app.Session.PlatformSuspiciousIpHitsUpdatedUtc?.ToString("u"),
                authedUpdatedUtc = app.Session.PlatformAuthedIpHitsUpdatedUtc?.ToString("u"),
                suspiciousIps = suspiciousList,
                authedIps = authedList
            }).ConfigureAwait(false);
            return true;
        }

        return false;
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
}
