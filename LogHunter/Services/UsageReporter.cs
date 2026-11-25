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
/// Enabled only when the endpoint was embedded at publish time (Release builds with
/// certs\usage.props) and LOGHUNTER_NO_USAGE is not "1".
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

    public static bool IsEnabled
    {
        get { lock (Gate) return s_http is not null; }
    }

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
            s_http = CreateClient(handler, key, version);
        }

        return SendAsync("AppStart", null);
    }

    internal static Task? TrackAsync(string feature)
    {
        lock (Gate)
        {
            if (s_http is null)
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
            s_endpoint = s_installId = s_sessionId = s_version = s_mode = null;
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
        lock (Gate)
        {
            http = s_http!;
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
                TraceLog.Write("usage", "sent", new { kind, feature, status = (int)response.StatusCode });
            }
            catch (Exception ex)
            {
                // Usage counts must never affect the tool: offline, proxy, timeout, server down.
                TraceLog.Write("usage", "failed", new { kind, feature, error = ex.GetType().Name });
            }
        });
    }

    private static HttpClient CreateClient(HttpMessageHandler? handler, string key, string version)
    {
        handler ??= new HttpClientHandler
        {
            UseProxy = true,
            DefaultProxyCredentials = CredentialCache.DefaultCredentials,
        };
        var http = new HttpClient(handler) { Timeout = Timeout };
        http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", $"LogHunter/{version}");
        http.DefaultRequestHeaders.TryAddWithoutValidation(KeyHeader, key);
        return http;
    }

    // Written by the csproj from certs\usage.props in Release builds only.
    private static (string? Endpoint, string? Key) ReadEmbeddedConfig()
    {
        var meta = typeof(UsageReporter).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().ToList();
        string? Value(string name) => meta.FirstOrDefault(m => m.Key == name)?.Value;
        return (Value("UsageEndpoint"), Value("UsageKey"));
    }
}
