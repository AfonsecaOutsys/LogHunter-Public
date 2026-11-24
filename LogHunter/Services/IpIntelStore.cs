using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Utils;

namespace LogHunter.Services;

internal sealed record IpIntelFeedState(
    string Id,
    string Provider,
    DateTime? LastSuccessUtc,
    DateTime? LastAttemptUtc,
    int RangeCount,
    string? ETag,
    string? LastError);

internal sealed record IpIntelStatus(
    DateTime? OldestSuccessUtc,
    int ProviderCount,
    int RangeCount,
    bool Refreshing,
    IReadOnlyList<IpIntelFeedState> Feeds)
{
    /// <summary>"ok" (all feeds &lt; 7 days), "stale", or "missing" (never downloaded).</summary>
    public string Level => Feeds.All(f => f.LastSuccessUtc is null) ? "missing"
        : Feeds.Any(f => f.LastSuccessUtc is null || DateTime.UtcNow - f.LastSuccessUtc > IpIntelStore.StaleAfter) ? "stale"
        : "ok";
}

/// <summary>
/// CDN / proxy range intelligence, always refreshed in-app: feeds download on first run, then are
/// re-checked every 24 h in the background. A feed that fails to download or validate keeps its
/// last good copy. Lookups use an immutable snapshot, so a scan never waits for a refresh.
/// </summary>
internal static class IpIntelStore
{
    public static readonly TimeSpan RefreshAfter = TimeSpan.FromHours(24);
    public static readonly TimeSpan StaleAfter = TimeSpan.FromDays(7);
    private const int MaxFeedBytes = 8 * 1024 * 1024;
    private const double MaxShrink = 0.5;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private static readonly SemaphoreSlim RefreshGate = new(1, 1);
    private static readonly object StateLock = new();
    private static IpRangeSet<IpIntelLabel> s_current = BuildSnapshot(IpIntelFeeds.Static);
    private static Dictionary<string, IpIntelFeedState> s_states = new(StringComparer.OrdinalIgnoreCase);
    private static volatile bool s_refreshing;
    private static string s_root = Path.Combine(AppFolders.Config, "ip-intel");

    public static IpRangeSet<IpIntelLabel> Current => Volatile.Read(ref s_current);

    /// <summary>Best label for an IP (most specific role first), or null.</summary>
    public static IpIntelLabel? Lookup(string? ip) => Best(Current.Match(ip));

    public static IpIntelLabel? Best(IReadOnlyList<IpIntelLabel> labels) =>
        labels.Count == 0 ? null : labels.OrderBy(l => l.Priority).First();

    /// <summary>Test hook: point the store at another folder and reload it.</summary>
    internal static void UseRoot(string root)
    {
        s_root = root;
        LoadFromDisk();
    }

    /// <summary>Loads cached feeds, then refreshes stale ones in the background. Never throws.</summary>
    public static void Initialize()
    {
        try
        {
            LoadFromDisk();
        }
        catch (Exception ex)
        {
            TraceLog.Write("ipintel", "load-failed", new { error = ex.Message });
        }

        _ = Task.Run(() => RefreshAsync(force: false, CancellationToken.None));
    }

    public static IpIntelStatus GetStatus()
    {
        Dictionary<string, IpIntelFeedState> states;
        lock (StateLock) states = s_states;
        var feeds = IpIntelFeeds.All
            .Select(f => states.TryGetValue(f.Id, out var s) ? s : new IpIntelFeedState(f.Id, f.Provider, null, null, 0, null, null))
            .ToList();
        var oldest = feeds.Where(f => f.LastSuccessUtc is not null).Select(f => f.LastSuccessUtc).DefaultIfEmpty(null).Min();
        var providers = Current.Labels.Select(l => l.Provider).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        return new IpIntelStatus(oldest, providers, Current.SegmentCount, s_refreshing, feeds);
    }

    public static async Task<IpIntelStatus> RefreshAsync(bool force, CancellationToken ct, HttpMessageHandler? handler = null)
    {
        if (!await RefreshGate.WaitAsync(0, ct).ConfigureAwait(false))
            return GetStatus(); // a refresh is already running

        s_refreshing = true;
        try
        {
            Directory.CreateDirectory(FeedDir);
            using var http = CreateClient(handler);
            var states = new Dictionary<string, IpIntelFeedState>(s_states, StringComparer.OrdinalIgnoreCase);
            foreach (var feed in IpIntelFeeds.All)
            {
                states.TryGetValue(feed.Id, out var previous);
                if (!force && previous?.LastSuccessUtc is { } ok && DateTime.UtcNow - ok < RefreshAfter)
                    continue;
                states[feed.Id] = await RefreshFeedAsync(http, feed, previous, ct).ConfigureAwait(false);
            }

            lock (StateLock) s_states = states;
            SaveManifest(states);
            Rebuild();
        }
        finally
        {
            s_refreshing = false;
            RefreshGate.Release();
        }

        return GetStatus();
    }

    internal static async Task<IpIntelFeedState> RefreshFeedAsync(HttpClient http, IpIntelFeed feed, IpIntelFeedState? previous, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var keep = previous ?? new IpIntelFeedState(feed.Id, feed.Provider, null, null, 0, null, null);
        try
        {
            using var request = new HttpRequestMessage(feed.Method, feed.Url);
            if (feed.PostBody is not null)
                request.Content = new StringContent(feed.PostBody, Encoding.UTF8, "application/x-www-form-urlencoded");
            if (previous?.ETag is { } etag && File.Exists(FeedPath(feed.Id)))
                request.Headers.TryAddWithoutValidation("If-None-Match", etag);

            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.NotModified)
                return keep with { LastSuccessUtc = now, LastAttemptUtc = now, LastError = null };
            if (!response.IsSuccessStatusCode)
                return keep with { LastAttemptUtc = now, LastError = $"HTTP {(int)response.StatusCode}" };
            if (!IsAllowedHost(response.RequestMessage?.RequestUri, feed.Url))
                return keep with { LastAttemptUtc = now, LastError = "Redirected to an unexpected host" };

            var body = await ReadCappedAsync(response, ct).ConfigureAwait(false);
            var (count, error) = Validate(feed, body, previous?.RangeCount ?? 0);
            if (error is not null)
                return keep with { LastAttemptUtc = now, LastError = error };

            WriteAtomic(FeedPath(feed.Id), body);
            TraceLog.Write("ipintel", "feed-updated", new { feed = feed.Id, ranges = count });
            return new IpIntelFeedState(feed.Id, feed.Provider, now, now, count, response.Headers.ETag?.Tag, null);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException or InvalidDataException)
        {
            TraceLog.Write("ipintel", "feed-failed", new { feed = feed.Id, error = ex.Message });
            return keep with { LastAttemptUtc = now, LastError = ex.Message };
        }
    }

    /// <summary>Parses the body and rejects empty, unparseable or suddenly shrunken feeds.</summary>
    internal static (int Count, string? Error) Validate(IpIntelFeed feed, string body, int previousCount)
    {
        List<(string Cidr, IpIntelLabel Label)> entries;
        try
        {
            entries = feed.Parse(body).ToList();
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return (0, $"Format changed ({ex.GetType().Name})");
        }

        var valid = entries.Count(e => IsUsableRange(e.Cidr));
        if (valid == 0)
            return (0, "No ranges in response");
        if (previousCount > 10 && valid < previousCount * MaxShrink)
            return (valid, $"Range count dropped from {previousCount} to {valid}; keeping the previous copy");
        return (valid, null);
    }

    // Feeds sometimes contain private ranges (Gcore published 172.31.0.24/32): never label those.
    // Anything wider than a /8 (IPv4) or /16 (IPv6) is treated as a broken feed entry.
    internal static bool IsUsableRange(string cidr)
    {
        if (!IpTargetParser.TryParse(cidr, out var target))
            return false;
        var start = cidr.Split('/')[0];
        var maxSize = target.Family == System.Net.Sockets.AddressFamily.InterNetwork ? UInt128.One << 24 : UInt128.One << 112;
        return !IisClientIpResolver.IsPrivateOrLoopback(start) && target.Size <= maxSize;
    }

    internal static IpRangeSet<IpIntelLabel> BuildSnapshot(IEnumerable<(string Cidr, IpIntelLabel Label)> entries)
    {
        var builder = new IpRangeSet<IpIntelLabel>.Builder();
        foreach (var (cidr, label) in entries)
            if (IsUsableRange(cidr))
                builder.TryAdd(cidr, label);
        return builder.Build();
    }

    private static void LoadFromDisk()
    {
        var manifestPath = Path.Combine(s_root, "manifest.json");
        var states = new Dictionary<string, IpIntelFeedState>(StringComparer.OrdinalIgnoreCase);
        if (File.Exists(manifestPath))
        {
            var list = JsonSerializer.Deserialize<List<IpIntelFeedState>>(File.ReadAllText(manifestPath), JsonOptions) ?? new();
            foreach (var s in list) states[s.Id] = s;
        }

        lock (StateLock) s_states = states;
        Rebuild();
    }

    private static void Rebuild()
    {
        var entries = new List<(string, IpIntelLabel)>(IpIntelFeeds.Static);
        foreach (var feed in IpIntelFeeds.All)
        {
            var path = FeedPath(feed.Id);
            if (!File.Exists(path)) continue;
            try
            {
                entries.AddRange(feed.Parse(File.ReadAllText(path)));
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
            {
                TraceLog.Write("ipintel", "cached-feed-unreadable", new { feed = feed.Id, error = ex.Message });
            }
        }

        Volatile.Write(ref s_current, BuildSnapshot(entries));
    }

    private static void SaveManifest(Dictionary<string, IpIntelFeedState> states)
    {
        var ordered = IpIntelFeeds.All.Where(f => states.ContainsKey(f.Id)).Select(f => states[f.Id]).ToList();
        WriteAtomic(Path.Combine(s_root, "manifest.json"), JsonSerializer.Serialize(ordered, JsonOptions));
    }

    private static string FeedDir => Path.Combine(s_root, "feeds");

    private static string FeedPath(string id) => Path.Combine(FeedDir, id + ".txt");

    private static void WriteAtomic(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp";
        File.WriteAllText(temp, content, Encoding.UTF8);
        File.Move(temp, path, overwrite: true);
    }

    private static bool IsAllowedHost(Uri? final, string original) =>
        final is not null && final.Scheme == Uri.UriSchemeHttps
        && string.Equals(final.Host, new Uri(original).Host, StringComparison.OrdinalIgnoreCase);

    private static async Task<string> ReadCappedAsync(HttpResponseMessage response, CancellationToken ct)
    {
        if (response.Content.Headers.ContentLength > MaxFeedBytes)
            throw new InvalidDataException("Feed larger than the size cap");
        var bytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        if (bytes.Length > MaxFeedBytes)
            throw new InvalidDataException("Feed larger than the size cap");
        return Encoding.UTF8.GetString(bytes);
    }

    // System proxy and default credentials, so it works on corporate networks and WorkSpaces.
    private static HttpClient CreateClient(HttpMessageHandler? handler)
    {
        handler ??= new HttpClientHandler
        {
            UseProxy = true,
            DefaultProxyCredentials = CredentialCache.DefaultCredentials,
            AutomaticDecompression = DecompressionMethods.All,
        };
        var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("LogHunter-IpRanges");
        return http;
    }
}
