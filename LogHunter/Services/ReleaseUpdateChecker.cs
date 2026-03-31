using Spectre.Console;
using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Services;

public static class ReleaseUpdateChecker
{
    private const string Owner = "AfonsecaOutsys";
    private const string Repo = "LogHunter-Public";
    private const string ConfigFileName = "release-update-check.json";
    private static readonly TimeSpan CacheDuration = TimeSpan.FromHours(6);
    private static readonly Uri LatestReleaseUri = new($"https://api.github.com/repos/{Owner}/{Repo}/releases/latest");

    public static async Task<ReleaseUpdateCheckResult> CheckAsync(string currentVersion, CancellationToken ct = default)
    {
        var normalizedCurrentVersion = NormalizeVersion(currentVersion);
        if (string.IsNullOrWhiteSpace(normalizedCurrentVersion))
            return ReleaseUpdateCheckResult.NoUpdate(currentVersion);

        AppFolders.Ensure();

        var state = LoadState();
        if (CanUseCachedState(state, normalizedCurrentVersion))
        {
            return CreateResultFromState(state, normalizedCurrentVersion);
        }

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(4));

            using var http = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(4)
            };

            http.DefaultRequestHeaders.UserAgent.ParseAdd($"LogHunter/{normalizedCurrentVersion}");
            http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");

            using var response = await http.GetAsync(LatestReleaseUri, timeoutCts.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return CreateResultFromState(state, normalizedCurrentVersion);
            }

            await using var stream = await response.Content.ReadAsStreamAsync(timeoutCts.Token).ConfigureAwait(false);
            var release = await JsonSerializer.DeserializeAsync<GithubRelease>(stream, JsonOptions, timeoutCts.Token).ConfigureAwait(false);
            if (release is null)
            {
                return CreateResultFromState(state, normalizedCurrentVersion);
            }

            var latestVersion = NormalizeVersion(release.TagName);
            var publishedUtc = release.PublishedAt?.UtcDateTime;
            var updatedState = new ReleaseUpdateState(
                Enabled: state.Enabled,
                LastCheckedUtc: DateTime.UtcNow,
                LastCheckedForVersion: normalizedCurrentVersion,
                LatestVersion: latestVersion,
                LatestReleaseUrl: release.HtmlUrl,
                LatestReleaseName: release.Name,
                LatestPublishedUtc: publishedUtc,
                SuppressedUntilUtc: latestVersion == NormalizeVersion(state.LatestVersion)
                    ? state.SuppressedUntilUtc
                    : null);

            SaveState(updatedState);
            return CreateResultFromState(updatedState, normalizedCurrentVersion);
        }
        catch
        {
            return CreateResultFromState(state, normalizedCurrentVersion);
        }
    }

    public static void ShowStartupNotice(ReleaseUpdateCheckResult result, bool consoleMode)
    {
        if (!result.IsUpdateAvailable)
            return;

        var state = LoadState();
        if (state.SuppressedUntilUtc is { } suppressedUntilUtc && suppressedUntilUtc > DateTime.UtcNow)
            return;

        var latestLabel = result.LatestReleaseName ?? $"v{result.LatestVersion}";
        var publishedSuffix = result.PublishedUtc is null
            ? string.Empty
            : $" ({result.PublishedUtc.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)})";

        if (consoleMode)
        {
            AnsiConsole.MarkupLine($"[yellow]Update available[/]: [bold]{Markup.Escape(result.CurrentVersion)}[/] -> [bold]{Markup.Escape(latestLabel)}[/]{Markup.Escape(publishedSuffix)}");
            if (!string.IsNullOrWhiteSpace(result.ReleaseUrl))
            {
                AnsiConsole.MarkupLine($"[dim]Release:[/] {Markup.Escape(result.ReleaseUrl)}");

                var openRelease = AnsiConsole.Confirm("Open the latest release page now?", false);
                if (openRelease)
                {
                    SaveState(state with { SuppressedUntilUtc = null });
                    TryOpenBrowser(result.ReleaseUrl!);
                }
                else
                {
                    SaveState(state with { SuppressedUntilUtc = DateTime.UtcNow.Add(CacheDuration) });
                }
            }

            AnsiConsole.WriteLine();
            return;
        }

        Console.WriteLine($"Update available: {result.CurrentVersion} -> {latestLabel}{publishedSuffix}");
        if (!string.IsNullOrWhiteSpace(result.ReleaseUrl))
            Console.WriteLine($"Release: {result.ReleaseUrl}");
    }

    private static ReleaseUpdateCheckResult CreateResultFromState(ReleaseUpdateState state, string normalizedCurrentVersion)
    {
        var latestVersion = NormalizeVersion(state.LatestVersion);
        var hasUpdate = IsNewer(latestVersion, normalizedCurrentVersion);

        return new ReleaseUpdateCheckResult(
            CurrentVersion: normalizedCurrentVersion,
            LatestVersion: latestVersion,
            LatestReleaseName: state.LatestReleaseName,
            ReleaseUrl: state.LatestReleaseUrl,
            PublishedUtc: state.LatestPublishedUtc,
            CheckedUtc: state.LastCheckedUtc,
            IsUpdateAvailable: hasUpdate);
    }

    private static bool CanUseCachedState(ReleaseUpdateState state, string normalizedCurrentVersion)
    {
        if (!state.Enabled)
            return true;

        if (state.LastCheckedUtc == DateTime.MinValue)
            return false;

        if (!string.Equals(state.LastCheckedForVersion, normalizedCurrentVersion, StringComparison.OrdinalIgnoreCase))
            return false;

        // Revalidate cached update notices on every startup so deleted or replaced
        // GitHub releases do not keep surfacing for hours.
        if (IsNewer(NormalizeVersion(state.LatestVersion), normalizedCurrentVersion))
            return false;

        return DateTime.UtcNow - state.LastCheckedUtc < CacheDuration;
    }

    private static ReleaseUpdateState LoadState()
    {
        var path = GetStatePath();

        try
        {
            if (!File.Exists(path))
                return ReleaseUpdateState.Default;

            var json = File.ReadAllText(path, Encoding.UTF8);
            var state = JsonSerializer.Deserialize<ReleaseUpdateState>(json, JsonOptions);
            return state ?? ReleaseUpdateState.Default;
        }
        catch
        {
            return ReleaseUpdateState.Default;
        }
    }

    private static void SaveState(ReleaseUpdateState state)
    {
        var path = GetStatePath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        var json = JsonSerializer.Serialize(state, new JsonSerializerOptions(JsonOptions)
        {
            WriteIndented = true
        });

        File.WriteAllText(path, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private static string GetStatePath()
        => Path.Combine(AppFolders.Config, ConfigFileName);

    private static string NormalizeVersion(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
            return string.Empty;

        var trimmed = version.Trim();
        if (trimmed.StartsWith("v", StringComparison.OrdinalIgnoreCase))
            trimmed = trimmed[1..];

        var plusIndex = trimmed.IndexOf('+');
        if (plusIndex >= 0)
            trimmed = trimmed[..plusIndex];

        var dashIndex = trimmed.IndexOf('-');
        if (dashIndex >= 0)
            trimmed = trimmed[..dashIndex];

        var builder = new StringBuilder(trimmed.Length);
        foreach (var ch in trimmed)
        {
            if (char.IsDigit(ch) || ch == '.')
            {
                builder.Append(ch);
                continue;
            }

            break;
        }

        return builder.ToString().Trim('.');
    }

    private static bool IsNewer(string latestVersion, string currentVersion)
    {
        if (string.IsNullOrWhiteSpace(latestVersion) || string.IsNullOrWhiteSpace(currentVersion))
            return false;

        if (!Version.TryParse(latestVersion, out var latest))
            return false;

        if (!Version.TryParse(currentVersion, out var current))
            return false;

        return latest > current;
    }

    private static bool TryOpenBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private sealed record GithubRelease(
        [property: JsonPropertyName("tag_name")] string? TagName,
        [property: JsonPropertyName("html_url")] string? HtmlUrl,
        [property: JsonPropertyName("name")] string? Name,
        [property: JsonPropertyName("published_at")] DateTimeOffset? PublishedAt);

    private sealed record ReleaseUpdateState(
        [property: JsonPropertyName("enabled")] bool Enabled,
        [property: JsonPropertyName("lastCheckedUtc")] DateTime LastCheckedUtc,
        [property: JsonPropertyName("lastCheckedForVersion")] string? LastCheckedForVersion,
        [property: JsonPropertyName("latestVersion")] string? LatestVersion,
        [property: JsonPropertyName("latestReleaseUrl")] string? LatestReleaseUrl,
        [property: JsonPropertyName("latestReleaseName")] string? LatestReleaseName,
        [property: JsonPropertyName("latestPublishedUtc")] DateTime? LatestPublishedUtc,
        [property: JsonPropertyName("suppressedUntilUtc")] DateTime? SuppressedUntilUtc)
    {
        public static ReleaseUpdateState Default => new(
            Enabled: true,
            LastCheckedUtc: DateTime.MinValue,
            LastCheckedForVersion: null,
            LatestVersion: null,
            LatestReleaseUrl: null,
            LatestReleaseName: null,
            LatestPublishedUtc: null,
            SuppressedUntilUtc: null);
    }
}

public sealed record ReleaseUpdateCheckResult(
    string CurrentVersion,
    string LatestVersion,
    string? LatestReleaseName,
    string? ReleaseUrl,
    DateTime? PublishedUtc,
    DateTime CheckedUtc,
    bool IsUpdateAvailable)
{
    public static ReleaseUpdateCheckResult NoUpdate(string currentVersion) => new(
        CurrentVersion: currentVersion,
        LatestVersion: currentVersion,
        LatestReleaseName: null,
        ReleaseUrl: null,
        PublishedUtc: null,
        CheckedUtc: DateTime.MinValue,
        IsUpdateAvailable: false);
}
