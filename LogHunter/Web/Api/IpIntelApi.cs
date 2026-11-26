using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Services;
using LogHunter.Web.Hosting;

namespace LogHunter.Web.Api;

internal static class IpIntelApi
{
    public const double ConfirmedShare = 0.8;
    public const double LikelyShare = 0.5;
    private const int MaxLookupIps = 5000;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static async Task<bool> TryHandleAsync(WebAppContext app, HttpListenerContext context)
    {
        var path = context.Request.Url?.AbsolutePath ?? "/";
        if (!path.StartsWith("/api/ip-ranges/", StringComparison.OrdinalIgnoreCase))
            return false;

        switch (path["/api/ip-ranges/".Length..].ToLowerInvariant())
        {
            case "status":
                await WriteJsonAsync(context.Response, BuildStatusPayload(IpIntelStore.GetStatus())).ConfigureAwait(false);
                return true;
            case "refresh" when IsPost(context):
                // Counted here, not in RefreshAsync, which the startup auto-refresh also calls.
                UsageReporter.Track(UsageFeature.IpRangesRefresh);
                var status = await IpIntelStore.RefreshAsync(force: true, CancellationToken.None).ConfigureAwait(false);
                await WriteJsonAsync(context.Response, BuildStatusPayload(status)).ConfigureAwait(false);
                return true;
            case "lookup" when IsPost(context):
                var body = await ReadJsonAsync<LookupRequest>(context.Request).ConfigureAwait(false);
                await WriteJsonAsync(context.Response, BuildLookup(body?.Ips ?? Array.Empty<string>())).ConfigureAwait(false);
                return true;
            case "custom" when IsPost(context):
                var custom = await ReadJsonAsync<CustomRangesRequest>(context.Request).ConfigureAwait(false);
                var (saved, invalid) = IpIntelStore.SaveCustomRanges(custom?.Provider, custom?.Ranges);
                UsageReporter.Track(UsageFeature.IpRangesCustomRanges);
                await WriteJsonAsync(context.Response, new { saved, invalid }).ConfigureAwait(false);
                return true;
            case "custom":
                var (provider, text) = IpIntelStore.GetCustomRanges();
                await WriteJsonAsync(context.Response, new { provider, ranges = text }).ConfigureAwait(false);
                return true;
            default:
                await WriteJsonAsync(context.Response, new { error = "Not found." }, HttpStatusCode.NotFound).ConfigureAwait(false);
                return true;
        }
    }

    /// <summary>
    /// Per-IP labels plus a dataset verdict: if most IPs belong to one CDN, the list shows CDN
    /// edges, not clients. Each IP counts once (the list is usually a top-N).
    /// </summary>
    internal static object BuildLookup(IReadOnlyList<string> ips)
    {
        var distinct = ips.Where(ip => !string.IsNullOrWhiteSpace(ip)).Select(ip => ip.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase).Take(MaxLookupIps).ToList();
        var results = distinct.Select(ip => (Ip: ip, Label: IpIntelStore.Lookup(ip))).ToList();

        var top = results.Where(r => r.Label?.Category == IpIntelCategory.Cdn)
            .GroupBy(r => r.Label!.Provider)
            .Select(g => (Provider: g.Key, Count: g.Count(), OnlyNetwork: g.All(r => r.Label!.Likely)))
            .OrderByDescending(g => g.Count)
            .FirstOrDefault();
        var share = distinct.Count == 0 || top.Provider is null ? 0 : (double)top.Count / distinct.Count;
        // A provider known only from its network ranges (Akamai ASN) never reaches "confirmed".
        var level = share >= ConfirmedShare && !top.OnlyNetwork ? "confirmed" : share >= LikelyShare ? "likely" : "none";

        return new
        {
            results = results.Where(r => r.Label is not null).Select(r => new
            {
                ip = r.Ip,
                badge = r.Label!.Badge,
                provider = r.Label.Provider,
                category = r.Label.Category.ToString(),
            }),
            fronted = new { level, provider = level == "none" ? null : top.Provider, share = Math.Round(share, 2), count = top.Count, total = distinct.Count },
        };
    }

    internal static object BuildStatusPayload(IpIntelStatus status) => new
    {
        level = status.Level,
        refreshing = status.Refreshing,
        providerCount = status.ProviderCount,
        rangeCount = status.RangeCount,
        oldestSuccessUtc = status.OldestSuccessUtc,
        label = PillLabel(status),
        feeds = status.Feeds.Select(f => new
        {
            id = f.Id,
            provider = f.Provider,
            lastSuccessUtc = f.LastSuccessUtc,
            lastAttemptUtc = f.LastAttemptUtc,
            rangeCount = f.RangeCount,
            lastError = f.LastError,
        }),
        // Ranges shipped in the exe (no download): listed so every label on a result has a source.
        builtIn = IpIntelFeeds.Static
            .GroupBy(s => s.Label.Provider)
            .Select(g => new { provider = g.Key, rangeCount = g.Count() }),
    };

    /// <summary>Short text for the topbar pill: age of the oldest feed, "updating" or "not loaded".</summary>
    internal static string PillLabel(IpIntelStatus status)
    {
        if (status.Refreshing && status.OldestSuccessUtc is null) return "updating";
        if (status.OldestSuccessUtc is not { } oldest) return "not loaded";
        var age = DateTime.UtcNow - oldest;
        return age.TotalHours < 1 ? "< 1 h" : age.TotalDays < 2 ? $"{(int)age.TotalHours} h" : $"{(int)age.TotalDays} d";
    }

    private static bool IsPost(HttpListenerContext context) =>
        string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase);

    private static async Task<T?> ReadJsonAsync<T>(HttpListenerRequest request)
    {
        using var reader = new StreamReader(request.InputStream, request.ContentEncoding ?? Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: false);
        var json = await reader.ReadToEndAsync().ConfigureAwait(false);
        return string.IsNullOrWhiteSpace(json) ? default : JsonSerializer.Deserialize<T>(json, JsonOptions);
    }

    private static async Task WriteJsonAsync(HttpListenerResponse response, object payload, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        var data = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload, JsonOptions));
        response.StatusCode = (int)statusCode;
        response.ContentType = "application/json; charset=utf-8";
        response.ContentLength64 = data.Length;
        await using var stream = response.OutputStream;
        await stream.WriteAsync(data).ConfigureAwait(false);
    }

    private sealed record LookupRequest(IReadOnlyList<string>? Ips);

    private sealed record CustomRangesRequest(string? Provider, string? Ranges);
}
