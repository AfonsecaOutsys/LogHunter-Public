using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace LogHunter.Services;

/// <summary>
/// Anonymous usage counts: one AppStart per launch and one FeatureUse per workflow run, sent to
/// the LogHunterUsage OutSystems service. Payload is only install id, session id, version, mode
/// and the workflow key. Fire-and-forget: 3 s timeout, every failure swallowed and traced
/// locally, never visible to the user.
/// Available only when the endpoint was embedded at publish time (Release builds with
/// certs\usage.props). On by default; the user turns it off with the toggle on the Feedback page
/// (saved in config\usage-settings.json). LOGHUNTER_NO_USAGE=1 remains a hard off for scripted setups.
/// </summary>
internal static class UsageReporter
{
    public const string OptOutVariable = "LOGHUNTER_NO_USAGE";
    private const string KeyHeader = "X-LogHunter-Key";
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(3);

    private static readonly object Gate = new();
    private static HttpClient? s_http;
    private static string? s_endpoint;
    private static string? s_installId;
    private static string? s_sessionId;
    private static string? s_version;
    private static string? s_mode;
    private static string? s_configDir;
    private static bool s_userEnabled = true;

    /// <summary>Counts are being sent: endpoint embedded and the user has not turned them off.</summary>
    public static bool IsEnabled
    {
        get { lock (Gate) return s_http is not null && s_userEnabled; }
    }

    /// <summary>The build can send counts (Release with the endpoint embedded), so the setting applies.</summary>
    public static bool IsAvailable
    {
        get { lock (Gate) return s_http is not null; }
    }

    /// <summary>
    /// Turns counts on or off from the web UI (on by default) and remembers the choice in
    /// config\usage-settings.json for later launches, console included.
    /// </summary>
    public static void SetUserEnabled(bool enabled)
    {
        string? dir;
        lock (Gate)
        {
            s_userEnabled = enabled;
            dir = s_configDir;
        }

        if (dir is null)
            return;

        try
        {
            Directory.CreateDirectory(dir);
            File.WriteAllText(SettingsPath(dir), JsonSerializer.Serialize(new { enabled }));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Read-only workspace: the choice holds for this launch only.
        }
    }

    internal static bool LoadUserEnabled(string configDir)
    {
        try
        {
            var path = SettingsPath(configDir);
            if (!File.Exists(path))
                return true;
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            return !doc.RootElement.TryGetProperty("enabled", out var value) || value.ValueKind != JsonValueKind.False;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return true;
        }
    }

    private static string SettingsPath(string configDir) => Path.Combine(configDir, "usage-settings.json");

    /// <summary>Call once, after the startup mode is resolved.</summary>
    public static void Start(string version, string mode)
    {
        var (endpoint, key) = ReadEmbeddedConfig();
        Start(version, mode, endpoint, key, AppFolders.Config, Environment.GetEnvironmentVariable(OptOutVariable), handler: null);
    }

    /// <summary>Counts one run of a workflow. No-op until Start has run, or when disabled.</summary>
    public static void Track(string feature) => _ = TrackAsync(feature);

    internal static Task? Start(string version, string mode, string? endpoint, string? key, string configDir,
        string? optOut, HttpMessageHandler? handler)
    {
        lock (Gate)
        {
            if (string.IsNullOrWhiteSpace(endpoint) || string.IsNullOrWhiteSpace(key) || optOut == "1")
                return null;

            s_endpoint = endpoint.TrimEnd('/');
            s_version = version;
            s_mode = mode;
            s_sessionId = Guid.NewGuid().ToString("D");
            s_installId = LoadOrCreateInstallId(configDir);
            s_http = CreateClient(handler, key, version, Timeout);
            s_configDir = configDir;
            s_userEnabled = LoadUserEnabled(configDir);
            if (!s_userEnabled)
                return null;
        }

        return SendAsync("AppStart", null);
    }

    internal static Task? TrackAsync(string feature)
    {
        lock (Gate)
        {
            if (s_http is null || !s_userEnabled)
                return null;
        }

        return SendAsync("FeatureUse", feature);
    }

    /// <summary>Test hook: back to the not-started state.</summary>
    internal static void Reset()
    {
        lock (Gate)
        {
            s_http?.Dispose();
            s_http = null;
            s_endpoint = s_installId = s_sessionId = s_version = s_mode = s_configDir = null;
            s_userEnabled = true;
        }
    }

    internal static string LoadOrCreateInstallId(string configDir)
    {
        var path = Path.Combine(configDir, "install-id");
        try
        {
            if (File.Exists(path) && Guid.TryParseExact(File.ReadAllText(path).Trim(), "D", out var existing))
                return existing.ToString("D");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Unreadable: replace it below.
        }

        var id = Guid.NewGuid().ToString("D");
        try
        {
            Directory.CreateDirectory(configDir);
            File.WriteAllText(path, id);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Read-only workspace: the id lives only for this process.
        }

        return id;
    }

    private static Task SendAsync(string kind, string? feature)
    {
        HttpClient http;
        string url, body;
        string? sessionId;
        lock (Gate)
        {
            http = s_http!;
            sessionId = s_sessionId;
            url = $"{s_endpoint}/{kind}";
            body = feature is null
                ? JsonSerializer.Serialize(new { InstallId = s_installId, SessionId = s_sessionId, Version = s_version, Mode = s_mode })
                : JsonSerializer.Serialize(new { InstallId = s_installId, SessionId = s_sessionId, Version = s_version, Mode = s_mode, Feature = feature });
        }

        return Task.Run(async () =>
        {
            try
            {
                using var content = new StringContent(body, Encoding.UTF8, "application/json");
                using var response = await http.PostAsync(url, content).ConfigureAwait(false);
                TraceLog.Write("usage", "sent", new { kind, feature, sessionId, status = (int)response.StatusCode });
            }
            catch (Exception ex)
            {
                // Usage counts must never affect the tool: offline, proxy, timeout, server down.
                TraceLog.Write("usage", "failed", new { kind, feature, sessionId, error = ex.GetType().Name });
            }
        });
    }

    /// <summary>Shared with FeedbackSender: system proxy, default proxy credentials, User-Agent and key header.</summary>
    internal static HttpClient CreateClient(HttpMessageHandler? handler, string key, string version, TimeSpan timeout)
    {
        handler ??= new HttpClientHandler
        {
            UseProxy = true,
            DefaultProxyCredentials = CredentialCache.DefaultCredentials,
        };
        var http = new HttpClient(handler) { Timeout = timeout };
        http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", $"LogHunter/{version}");
        http.DefaultRequestHeaders.TryAddWithoutValidation(KeyHeader, key);
        return http;
    }

    // Written by the csproj from certs\usage.props in Release builds only.
    internal static (string? Endpoint, string? Key) ReadEmbeddedConfig()
    {
        var meta = typeof(UsageReporter).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().ToList();
        string? Value(string name) => meta.FirstOrDefault(m => m.Key == name)?.Value;
        return (Value("UsageEndpoint"), Value("UsageKey"));
    }
}
