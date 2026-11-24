using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Utils;

namespace LogHunter.Services;

/// <summary>A folder or file set to sweep, shown under its own label (e.g. "Prod ALB").</summary>
internal sealed record IocSweepSource(string Label, IReadOnlyList<string> Files);

/// <summary>Per-target outcome of a sweep.</summary>
internal sealed class IocSweepTargetResult
{
    public const int MaxDistinctKeys = 2000;

    public IocSweepTargetResult(IpTarget target) => Target = target;

    public IpTarget Target { get; }
    public long Hits { get; private set; }
    public DateTime? FirstSeenUtc { get; private set; }
    public DateTime? LastSeenUtc { get; private set; }
    public Dictionary<string, long> MatchedIps { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, long> Uris { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, long> Statuses { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, long> HitsBySource { get; } = new(StringComparer.OrdinalIgnoreCase);

    internal void Record(string ip, DateTime? tsUtc, string? uri, string? status, string source, long count = 1)
    {
        Hits += count;
        if (tsUtc is { } ts)
        {
            if (FirstSeenUtc is null || ts < FirstSeenUtc) FirstSeenUtc = ts;
            if (LastSeenUtc is null || ts > LastSeenUtc) LastSeenUtc = ts;
        }

        Bump(MatchedIps, ip, count);
        Bump(Uris, string.IsNullOrEmpty(uri) ? "-" : uri, count);
        Bump(Statuses, string.IsNullOrEmpty(status) ? "-" : status, count);
        Bump(HitsBySource, source, count);
    }

    internal void Merge(IocSweepTargetResult other)
    {
        if (other.Hits == 0)
            return;

        Hits += other.Hits;
        if (other.FirstSeenUtc is { } f && (FirstSeenUtc is null || f < FirstSeenUtc)) FirstSeenUtc = f;
        if (other.LastSeenUtc is { } l && (LastSeenUtc is null || l > LastSeenUtc)) LastSeenUtc = l;
        foreach (var kv in other.MatchedIps) Bump(MatchedIps, kv.Key, kv.Value);
        foreach (var kv in other.Uris) Bump(Uris, kv.Key, kv.Value);
        foreach (var kv in other.Statuses) Bump(Statuses, kv.Key, kv.Value);
        foreach (var kv in other.HitsBySource) Bump(HitsBySource, kv.Key, kv.Value);
    }

    // Caps memory on huge scans: once a dictionary holds MaxDistinctKeys keys, new keys fold into "(other)".
    private static void Bump(Dictionary<string, long> map, string key, long count)
    {
        if (!map.ContainsKey(key) && map.Count >= MaxDistinctKeys)
            key = "(other)";
        map.TryGetValue(key, out var n);
        map[key] = n + count;
    }
}

/// <summary>What was actually read for one source: the "scope" block of the report.</summary>
internal sealed class IocSweepSourceScope
{
    public IocSweepSourceScope(string label) => Label = label;

    public string Label { get; }
    public int FilesRead { get; set; }
    public int AlbFiles { get; set; }
    public int IisFiles { get; set; }
    public long LinesRead { get; set; }
    public long RecordsParsed { get; set; }
    public long ParseFailures { get; set; }
    public DateTime? MinUtc { get; set; }
    public DateTime? MaxUtc { get; set; }
    public List<string> UnreadableFiles { get; } = new();

    internal void Observe(DateTime? ts)
    {
        if (ts is not { } t) return;
        if (MinUtc is null || t < MinUtc) MinUtc = t;
        if (MaxUtc is null || t > MaxUtc) MaxUtc = t;
    }

    internal void Merge(IocSweepSourceScope other)
    {
        FilesRead += other.FilesRead;
        AlbFiles += other.AlbFiles;
        IisFiles += other.IisFiles;
        LinesRead += other.LinesRead;
        RecordsParsed += other.RecordsParsed;
        ParseFailures += other.ParseFailures;
        Observe(other.MinUtc);
        Observe(other.MaxUtc);
        UnreadableFiles.AddRange(other.UnreadableFiles);
    }
}

internal sealed record IocSweepResult(
    IReadOnlyList<IocSweepTargetResult> Targets,
    IReadOnlyList<IocSweepSourceScope> Scopes,
    IReadOnlyList<string> InvalidTokens,
    DateTime StartedUtc,
    DateTime FinishedUtc);

internal readonly record struct IocSweepProgress(int FilesDone, int FilesTotal, long LinesRead);

/// <summary>
/// Answers "were these IPs / ranges ever in our logs?" for any number of targets.
/// Reads ALB access logs and IIS W3C logs (auto-detected per file; .gz supported) and keeps only
/// small per-target aggregates, unlike IP summary which keeps per-IP minute buckets.
/// IIS uses the resolved client IP (OriginalIP / X-Forwarded-For first, then c-ip).
/// </summary>
internal static class IocSweepScanner
{
    private const int AlbTimestampToken = 1;
    private const int AlbClientToken = 3;
    private const int AlbStatusToken = 8;
    private const int AlbRequestToken = 12;
    private const int MatchCacheLimit = 100_000;

    public static async Task<IocSweepResult> RunAsync(
        IReadOnlyList<IocSweepSource> sources,
        IReadOnlyList<IpTarget> targets,
        IReadOnlyList<string> invalidTokens,
        IProgress<IocSweepProgress>? progress,
        CancellationToken ct)
    {
        var started = DateTime.UtcNow;
        var set = BuildTargetSet(targets);
        var totals = targets.Select(t => new IocSweepTargetResult(t)).ToArray();
        var scopes = sources.Select(s => new IocSweepSourceScope(s.Label)).ToArray();
        var gate = new object();
        var filesTotal = sources.Sum(s => s.Files.Count);
        int filesDone = 0;
        long linesDone = 0;

        var work = sources.SelectMany((s, si) => s.Files.Select(f => (SourceIndex: si, File: f))).ToList();
        var options = new ParallelOptions { CancellationToken = ct, MaxDegreeOfParallelism = Math.Max(1, Environment.ProcessorCount - 1) };

        await Parallel.ForEachAsync(work, options, async (item, token) =>
        {
            var label = sources[item.SourceIndex].Label;
            var (fileTargets, fileScope) = await ScanFileAsync(item.File, label, set, targets, token).ConfigureAwait(false);

            lock (gate)
            {
                for (var i = 0; i < totals.Length; i++)
                    totals[i].Merge(fileTargets[i]);
                scopes[item.SourceIndex].Merge(fileScope);
                filesDone++;
                linesDone += fileScope.LinesRead;
                progress?.Report(new IocSweepProgress(filesDone, filesTotal, linesDone));
            }
        }).ConfigureAwait(false);

        return new IocSweepResult(totals, scopes, invalidTokens, started, DateTime.UtcNow);
    }

    internal static IpRangeSet<int> BuildTargetSet(IReadOnlyList<IpTarget> targets)
    {
        // Label = target index. Equal labels would merge, so each index is unique by construction.
        var builder = new IpRangeSet<int>.Builder();
        for (var i = 0; i < targets.Count; i++)
            builder.Add(targets[i], i);
        return builder.Build();
    }

    private static async Task<(IocSweepTargetResult[] Targets, IocSweepSourceScope Scope)> ScanFileAsync(
        string file, string label, IpRangeSet<int> set, IReadOnlyList<IpTarget> targets, CancellationToken ct)
    {
        var acc = targets.Select(t => new IocSweepTargetResult(t)).ToArray();
        var scope = new IocSweepSourceScope(label) { FilesRead = 1 };
        var cache = new Dictionary<string, IReadOnlyList<int>>(StringComparer.Ordinal);

        try
        {
            var map = await IisW3cReader.ReadFieldMapAsync(file, ct).ConfigureAwait(false);
            if (map is not null)
            {
                scope.IisFiles = 1;
                await ScanIisAsync(file, map, label, set, acc, scope, cache, ct).ConfigureAwait(false);
            }
            else
            {
                scope.AlbFiles = 1;
                await ScanAlbAsync(file, label, set, acc, scope, cache, ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            // Corrupt .gz or locked file: report it, keep sweeping the rest.
            scope.UnreadableFiles.Add($"{file} ({ex.GetType().Name}: {ex.Message})");
        }

        return (acc, scope);
    }

    private static async Task ScanAlbAsync(string file, string label, IpRangeSet<int> set,
        IocSweepTargetResult[] acc, IocSweepSourceScope scope, Dictionary<string, IReadOnlyList<int>> cache, CancellationToken ct)
    {
        await using var stream = IisW3cReader.OpenPossiblyGz(file);
        using var reader = new StreamReader(stream);
        string? line;
        while ((line = await reader.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
        {
            if (line.Length == 0) continue;
            scope.LinesRead++;
            if (!TryReadAlbRecord(line, out var rec))
            {
                scope.ParseFailures++;
                continue;
            }

            scope.RecordsParsed++;
            scope.Observe(rec.TimestampUtc);
            RecordMatches(rec.ClientIp, rec.TimestampUtc, rec.Uri, rec.Status, label, set, acc, cache);
        }
    }

    private static async Task ScanIisAsync(string file, IisW3cReader.FieldMap map, string label, IpRangeSet<int> set,
        IocSweepTargetResult[] acc, IocSweepSourceScope scope, Dictionary<string, IReadOnlyList<int>> cache, CancellationToken ct)
    {
        var iDate = IndexOf(map, "date");
        var iTime = IndexOf(map, "time");
        var iUri = IndexOf(map, "cs-uri-stem");
        var iStatus = IndexOf(map, "sc-status");
        var iOriginal = IndexOf(map, "OriginalIP");
        var iCIp = IndexOf(map, "c-ip");

        await IisW3cReader.ForEachDataLineAsync(file, ct, (_, tokens) =>
        {
            scope.LinesRead++;
            var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginal, iCIp);
            if (ip is null)
            {
                scope.ParseFailures++;
                return;
            }

            scope.RecordsParsed++;
            var ts = ParseIisTimestamp(Token(tokens, iDate), Token(tokens, iTime));
            scope.Observe(ts);
            var uri = iUri >= 0 ? tokens.Get(iUri).ToString() : null;
            var status = iStatus >= 0 ? tokens.Get(iStatus).ToString() : null;
            RecordMatches(ip, ts, uri, status, label, set, acc, cache);
        }).ConfigureAwait(false);
    }

    private static void RecordMatches(string ip, DateTime? ts, string? uri, string? status, string label,
        IpRangeSet<int> set, IocSweepTargetResult[] acc, Dictionary<string, IReadOnlyList<int>> cache)
    {
        if (!cache.TryGetValue(ip, out var ids))
        {
            ids = set.Match(ip);
            if (cache.Count < MatchCacheLimit)
                cache[ip] = ids;
        }

        foreach (var id in ids)
            acc[id].Record(ip, ts, uri, status, label);
    }

    internal readonly record struct AlbRecord(string ClientIp, DateTime? TimestampUtc, string Uri, string Status);

    internal static bool TryReadAlbRecord(string line, out AlbRecord record)
    {
        record = default;
        var span = line.AsSpan();
        if (!AlbScanner.TryGetToken(span, AlbClientToken, out var client) || client.Length == 0)
            return false;

        // client is "ip:port"; accept "[v6]:port" and bracket-less "v6:port" (port after the last colon).
        ReadOnlySpan<char> ipSpan;
        if (client[0] == '[')
        {
            var close = client.IndexOf(']');
            if (close < 2) return false;
            ipSpan = client[1..close];
        }
        else
        {
            var colon = client.LastIndexOf(':');
            ipSpan = colon > 0 ? client[..colon] : client;
        }
        if (!System.Net.IPAddress.TryParse(ipSpan, out var addr))
            return false;

        DateTime? ts = null;
        if (AlbScanner.TryGetToken(span, AlbTimestampToken, out var tsSpan)
            && DateTime.TryParse(tsSpan, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt))
            ts = DateTime.SpecifyKind(dt, DateTimeKind.Utc);

        var status = AlbScanner.TryGetToken(span, AlbStatusToken, out var st) ? st.ToString() : "-";
        var uri = AlbScanner.TryGetToken(span, AlbRequestToken, out var req) ? AlbScanner.ExtractUriNoQueryFromRequest(req) : "";
        record = new AlbRecord(addr.ToString(), ts, uri, status);
        return true;
    }

    internal static DateTime? ParseIisTimestamp(string? date, string? time)
    {
        if (string.IsNullOrEmpty(date) || string.IsNullOrEmpty(time))
            return null;
        return DateTime.TryParseExact($"{date} {time}", "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt)
            ? DateTime.SpecifyKind(dt, DateTimeKind.Utc)
            : null;
    }

    private static int IndexOf(IisW3cReader.FieldMap map, string field) => map.TryGetIndex(field, out var i) ? i : -1;

    private static string? Token(IisW3cReader.TokenReader tokens, int index) => index >= 0 ? tokens.Get(index).ToString() : null;
}
