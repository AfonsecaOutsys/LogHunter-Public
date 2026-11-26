using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace LogHunter.Services;

internal sealed record FeedbackResult(bool Ok, string Message);

/// <summary>
/// User-initiated feedback, posted to the LogHunterUsage service's Feedback endpoint.
/// Uses the same embedded endpoint, key and install id as UsageReporter, but ignores
/// LOGHUNTER_NO_USAGE: sending feedback is a deliberate action. Awaited, 10 s timeout.
/// The description is never written to the trace.
/// </summary>
internal static class FeedbackSender
{
    public const int MinLength = 10;
    public const int MaxLength = 1000;

    public const string SentMessage = "Feedback sent. Thanks.";
    public const string RateLimitedMessage = "Too much feedback sent today. Try again tomorrow.";
    public const string RejectedMessage = "Couldn't send feedback.";
    public const string UnreachableMessage = "Couldn't send feedback. Check your connection and try again.";

    // Area key sent to the API -> label shown in the dropdown.
    public static readonly IReadOnlyList<(string Key, string Label)> Areas =
    [
        ("alb", "ALB"),
        ("iis", "IIS"),
        ("platform", "Platform logs"),
        ("abuseip", "AbuseIP"),
        ("other", "Other"),
    ];

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static readonly object Gate = new();
    private static HttpClient? s_http;
    private static string? s_url;
    private static string? s_installId;
    private static string? s_version;
    private static string? s_mode;

    /// <summary>False when no endpoint was embedded (Debug, or Release without certs\usage.props).</summary>
    public static bool IsAvailable
    {
        get { lock (Gate) return s_http is not null; }
    }

    /// <summary>Call once, after the startup mode is resolved.</summary>
    public static void Start(string version, string mode)
    {
        var (endpoint, key) = UsageReporter.ReadEmbeddedConfig();
        Start(version, mode, endpoint, key, AppFolders.Config, handler: null);
    }

    internal static void Start(string version, string mode, string? endpoint, string? key, string configDir, HttpMessageHandler? handler)
    {
        lock (Gate)
        {
            if (string.IsNullOrWhiteSpace(endpoint) || string.IsNullOrWhiteSpace(key))
                return;

            s_url = $"{endpoint.TrimEnd('/')}/Feedback";
            s_version = version;
            s_mode = mode;
            s_installId = UsageReporter.LoadOrCreateInstallId(configDir);
            s_http = UsageReporter.CreateClient(handler, key, version, Timeout);
        }
    }

    /// <summary>Test hook: back to the not-started state.</summary>
    internal static void Reset()
    {
        lock (Gate)
        {
            s_http?.Dispose();
            s_http = null;
            s_url = s_installId = s_version = s_mode = null;
        }
    }

    /// <summary>Returns a message for the user when the input breaks a rule, otherwise null.</summary>
    public static string? Validate(string? area, string? description)
    {
        if (!IsKnownArea(area))
            return "Choose a page.";

        var length = (description ?? string.Empty).Trim().Length;
        if (length < MinLength || length > MaxLength)
            return $"Write {MinLength} to {MaxLength} characters.";

        return null;
    }

    public static async Task<FeedbackResult> SendAsync(string? area, string? description)
    {
        var invalid = Validate(area, description);
        if (invalid is not null)
            return new FeedbackResult(false, invalid);

        HttpClient? http;
        string? url, body;
        var text = description!.Trim();
        lock (Gate)
        {
            http = s_http;
            url = s_url;
            body = JsonSerializer.Serialize(new { InstallId = s_installId, Version = s_version, Mode = s_mode, Area = area, Description = text });
        }

        if (http is null)
            return new FeedbackResult(false, UnreachableMessage);

        try
        {
            using var content = new StringContent(body, Encoding.UTF8, "application/json");
            using var response = await http.PostAsync(url, content).ConfigureAwait(false);
            var status = (int)response.StatusCode;
            var ok = response.StatusCode == HttpStatusCode.OK;
            TraceLog.Write("feedback", ok ? "sent" : "failed", new { area, status, length = text.Length });
            return new FeedbackResult(ok, MessageFor(response.StatusCode));
        }
        catch (Exception ex)
        {
            // Timeout, proxy, offline: keep the user's text and let them retry.
            TraceLog.Write("feedback", "failed", new { area, status = (int?)null, length = text.Length, error = ex.GetType().Name });
            return new FeedbackResult(false, UnreachableMessage);
        }
    }

    private static string MessageFor(HttpStatusCode status) => status switch
    {
        HttpStatusCode.OK => SentMessage,
        HttpStatusCode.TooManyRequests => RateLimitedMessage,
        HttpStatusCode.BadRequest => RejectedMessage,
        _ => UnreachableMessage,
    };

    private static bool IsKnownArea(string? area)
    {
        foreach (var (key, _) in Areas)
        {
            if (string.Equals(key, area, StringComparison.Ordinal))
                return true;
        }

        return false;
    }
}
