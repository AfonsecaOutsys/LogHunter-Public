using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Services;
using LogHunter.Utils;

namespace LogHunter.Web.Orchestration;

internal sealed class IisStatusPivotJobManager
{
    private readonly object _gate = new();
    private IisStatusPivotJobSnapshot _snapshot = IisStatusPivotJobSnapshot.CreateIdle();

    public IisStatusPivotJobSnapshot GetSnapshot()
    {
        lock (_gate)
            return _snapshot;
    }

    public bool TryStart(
        string statusFilter,
        string? appScopeFragment,
        IReadOnlyList<string> selectedIps,
        out IisStatusPivotJobSnapshot snapshot,
        out string? error)
    {
        lock (_gate)
        {
            if (string.Equals(_snapshot.State, "running", StringComparison.OrdinalIgnoreCase))
            {
                snapshot = _snapshot;
                error = "An IIS status pivot scan is already running.";
                return false;
            }

            var files = IisW3cReader.EnumerateLogFiles(AppFolders.IIS);
            if (files.Count == 0)
            {
                snapshot = _snapshot;
                error = $"No .log files found in: {AppFolders.IIS}";
                return false;
            }

            Func<int, bool> matchFn;
            string filterLabel;
            if (!TryBuildStatusFilter(statusFilter, out matchFn!, out filterLabel!))
            {
                snapshot = _snapshot;
                error = "Invalid status filter.";
                return false;
            }

            _snapshot = new IisStatusPivotJobSnapshot(
                JobId: Guid.NewGuid().ToString("N"),
                State: "running",
                Message: $"Scanning IIS logs for {filterLabel} errors (pass 1/2).",
                StatusFilter: filterLabel,
                AppScope: string.IsNullOrWhiteSpace(appScopeFragment) ? "All" : appScopeFragment,
                CreatedUtc: DateTime.UtcNow,
                UpdatedUtc: DateTime.UtcNow,
                CurrentStep: 0,
                TotalSteps: files.Count * 2,
                Phase: "pass1",
                FilesProcessed: 0,
                FilesTotal: files.Count,
                UniqueErrorIps: 0,
                ExportedLines: 0,
                ExportPath: null,
                TopErrorIps: null,
                TopErrorUris: null,
                PivotResults: null,
                Error: null);

            snapshot = _snapshot;
            error = null;
            _ = RunAsync(_snapshot.JobId, files, matchFn, filterLabel, appScopeFragment, selectedIps);
            return true;
        }
    }

    public bool TryOpenExport(string? jobId, out string message)
    {
        IisStatusPivotJobSnapshot snapshot;
        lock (_gate)
        {
            snapshot = _snapshot;
            if (!string.IsNullOrWhiteSpace(jobId) && !string.Equals(snapshot.JobId, jobId, StringComparison.Ordinal))
            {
                message = "Job not found.";
                return false;
            }
        }

        var path = snapshot.ExportPath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            message = "The exported log file is not available.";
            return false;
        }

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true
            });
            message = path;
            return true;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return false;
        }
    }

    private static bool TryBuildStatusFilter(string filter, out Func<int, bool> matchFn, out string label)
    {
        matchFn = null!;
        label = filter;

        switch (filter?.ToLowerInvariant())
        {
            case "4xx":
                matchFn = static code => code is >= 400 and <= 499;
                label = "4xx";
                return true;
            case "5xx":
                matchFn = static code => code is >= 500 and <= 599;
                label = "5xx";
                return true;
            case "4xx+5xx":
                matchFn = static code => code is >= 400 and <= 599;
                label = "4xx + 5xx";
                return true;
            default:
                if (string.IsNullOrWhiteSpace(filter))
                    return false;
                var codes = filter.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(part => int.TryParse(part, out var code) ? code : -1)
                    .Where(code => code is >= 100 and <= 599)
                    .Distinct()
                    .ToHashSet();
                if (codes.Count == 0)
                    return false;
                matchFn = code => codes.Contains(code);
                label = string.Join(", ", codes.OrderBy(c => c));
                return true;
        }
    }

    private async Task RunAsync(
        string jobId,
        List<string> files,
        Func<int, bool> matchFn,
        string filterLabel,
        string? appScopeFragment,
        IReadOnlyList<string> preSelectedIps)
    {
        try
        {
            var statsByIp = new Dictionary<string, ErrorPivotStats>(StringComparer.OrdinalIgnoreCase);
            var errorUriCounts = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            IisW3cReader.FieldMap? firstMap = null;

            var ignoreUAPrefixes = new[] { "ELB-HealthChecker/" };

            // Pass 1: find error IPs
            for (var f = 0; f < files.Count; f++)
            {
                var file = files[f];

                var map = await IisW3cReader.ReadFieldMapAsync(file, CancellationToken.None).ConfigureAwait(false);
                if (map is null) continue;

                firstMap ??= map;

                if (!map.TryGetIndex("sc-status", out var iStatus)) continue;
                map.TryGetIndex("OriginalIP", out var iOriginalIp);
                map.TryGetIndex("c-ip", out var iCIp);
                map.TryGetIndex("cs(User-Agent)", out var iUA);
                map.TryGetIndex("cs-uri-stem", out var iUriStem);

                await IisW3cReader.ForEachDataLineAsync(file, CancellationToken.None, (_, tokens) =>
                {
                    if (!TryParseInt(tokens.Get(iStatus), out var status)) return;
                    if (!matchFn(status)) return;

                    var uriStem = NormalizeToken(tokens.Get(iUriStem));
                    if (!string.IsNullOrWhiteSpace(appScopeFragment) &&
                        uriStem.IndexOf(appScopeFragment, StringComparison.OrdinalIgnoreCase) < 0)
                        return;

                    if (iUA >= 0)
                    {
                        var ua = tokens.Get(iUA);
                        if (!ua.IsEmpty && ua[0] != '-')
                        {
                            var uaStr = ua.ToString();
                            for (var k = 0; k < ignoreUAPrefixes.Length; k++)
                            {
                                if (uaStr.StartsWith(ignoreUAPrefixes[k], StringComparison.OrdinalIgnoreCase))
                                    return;
                            }
                        }
                    }

                    var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                    if (ip is null || IisClientIpResolver.IsPrivateOrLoopback(ip)) return;

                    if (!statsByIp.TryGetValue(ip, out var stats))
                    {
                        stats = new ErrorPivotStats(ip);
                        statsByIp[ip] = stats;
                    }

                    stats.Add(status, uriStem);
                    IncrementCount(errorUriCounts, uriStem);
                }).ConfigureAwait(false);

                Update(jobId, snapshot => snapshot with
                {
                    UpdatedUtc = DateTime.UtcNow,
                    Message = $"Scanning IIS logs for {filterLabel} errors (pass 1/2): {f + 1} / {files.Count} files.",
                    CurrentStep = f + 1,
                    Phase = "pass1",
                    FilesProcessed = f + 1,
                    UniqueErrorIps = statsByIp.Count
                });
            }

            if (statsByIp.Count == 0)
            {
                Update(jobId, snapshot => snapshot with
                {
                    State = "completed",
                    Phase = "completed",
                    Message = $"No public-client {filterLabel} traffic found.",
                    UpdatedUtc = DateTime.UtcNow,
                    CurrentStep = files.Count * 2,
                    UniqueErrorIps = 0
                });
                return;
            }

            var topIps = statsByIp.Values
                .OrderByDescending(s => s.TotalHits)
                .ThenBy(s => s.Ip, StringComparer.OrdinalIgnoreCase)
                .Take(15)
                .ToList();

            var topErrorUris = errorUriCounts
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(15)
                .Select(kv => new StatusPivotUriCount(kv.Key, kv.Value))
                .ToList();

            var topIpResults = topIps.Select(s => new StatusPivotIpResult(
                Ip: s.Ip,
                TotalHits: s.TotalHits,
                StatusCounts: s.StatusCounts.OrderBy(kv => kv.Key).ToDictionary(kv => kv.Key.ToString(CultureInfo.InvariantCulture), kv => kv.Value),
                TopUris: s.TopUris(5).Select(u => new StatusPivotUriCount(u.UriStem, u.Count)).ToList()))
            .ToList();

            // Determine which IPs to pivot
            HashSet<string> selectedIps;
            if (preSelectedIps.Count > 0)
                selectedIps = preSelectedIps.ToHashSet(StringComparer.OrdinalIgnoreCase);
            else
                selectedIps = topIps.Select(x => x.Ip).ToHashSet(StringComparer.OrdinalIgnoreCase);

            // Pass 2: export 2xx/3xx lines for selected IPs
            var outDir = AppFolders.Output;
            Directory.CreateDirectory(outDir);
            var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
            var outFile = Path.Combine(outDir, $"iis_status_pivot_2xx3xx_{stamp}.log");

            var pivotResults = new Dictionary<string, PivotResult>(StringComparer.OrdinalIgnoreCase);
            foreach (var ip in selectedIps)
                pivotResults[ip] = new PivotResult(ip);

            long exportedLines = 0;

            await using var outStream = File.Create(outFile);
            await using var outWriter = new StreamWriter(outStream, Encoding.UTF8);

            if (firstMap is not null)
            {
                foreach (var h in firstMap.HeaderLines)
                    await outWriter.WriteLineAsync(h).ConfigureAwait(false);
                await outWriter.WriteLineAsync(firstMap.FieldsLine).ConfigureAwait(false);
            }

            for (var f = 0; f < files.Count; f++)
            {
                var file = files[f];

                var map = await IisW3cReader.ReadFieldMapAsync(file, CancellationToken.None).ConfigureAwait(false);
                if (map is null) continue;

                if (!map.TryGetIndex("sc-status", out var iStatus)) continue;
                map.TryGetIndex("OriginalIP", out var iOriginalIp);
                map.TryGetIndex("c-ip", out var iCIp);
                map.TryGetIndex("cs-uri-stem", out var iUriStem);

                await IisW3cReader.ForEachDataLineAsync(file, CancellationToken.None, (rawLine, tokens) =>
                {
                    if (!TryParseInt(tokens.Get(iStatus), out var status)) return;
                    if (status < 200 || status > 399) return;

                    var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                    if (ip is null || !selectedIps.Contains(ip)) return;

                    outWriter.WriteLine(rawLine);
                    exportedLines++;

                    if (pivotResults.TryGetValue(ip, out var result))
                    {
                        result.Add(status);
                        var uriStem = NormalizeToken(tokens.Get(iUriStem));
                        if (!string.IsNullOrWhiteSpace(uriStem) && uriStem != "-")
                            result.AddUri(uriStem);
                    }
                }).ConfigureAwait(false);

                Update(jobId, snapshot => snapshot with
                {
                    UpdatedUtc = DateTime.UtcNow,
                    Message = $"Exporting 2xx/3xx pivot (pass 2/2): {f + 1} / {files.Count} files.",
                    CurrentStep = files.Count + f + 1,
                    Phase = "pass2",
                    FilesProcessed = f + 1,
                    ExportedLines = exportedLines
                });
            }

            await outWriter.FlushAsync().ConfigureAwait(false);

            var pivotIpResults = pivotResults.Values
                .OrderBy(r => r.Ip, StringComparer.OrdinalIgnoreCase)
                .Select(r => new StatusPivotPivotIpResult(
                    Ip: r.Ip,
                    Total2xx: r.Total2xx,
                    Total3xx: r.Total3xx,
                    StatusCounts: r.StatusCounts.OrderBy(kv => kv.Key).ToDictionary(kv => kv.Key.ToString(CultureInfo.InvariantCulture), kv => kv.Value),
                    TopUris: r.TopUris(10).Select(u => new StatusPivotUriCount(u.UriStem, u.Count)).ToList()))
                .ToList();

            Update(jobId, snapshot => snapshot with
            {
                State = "completed",
                Phase = "completed",
                Message = $"Status pivot complete. {exportedLines:N0} lines exported for {selectedIps.Count} IP(s).",
                UpdatedUtc = DateTime.UtcNow,
                CurrentStep = files.Count * 2,
                FilesProcessed = files.Count,
                UniqueErrorIps = statsByIp.Count,
                ExportedLines = exportedLines,
                ExportPath = outFile,
                TopErrorIps = topIpResults,
                TopErrorUris = topErrorUris,
                PivotResults = pivotIpResults
            });
        }
        catch (Exception ex)
        {
            Update(jobId, snapshot => snapshot with
            {
                State = "failed",
                Phase = "failed",
                Message = "IIS status pivot scan failed.",
                UpdatedUtc = DateTime.UtcNow,
                Error = ex.Message
            });
        }
    }

    private void Update(string jobId, Func<IisStatusPivotJobSnapshot, IisStatusPivotJobSnapshot> update)
    {
        lock (_gate)
        {
            if (!string.Equals(_snapshot.JobId, jobId, StringComparison.Ordinal))
                return;
            _snapshot = update(_snapshot);
        }
    }

    private static string NormalizeToken(ReadOnlySpan<char> token)
    {
        if (token.IsEmpty) return "-";
        var text = token.ToString().Trim();
        return string.IsNullOrWhiteSpace(text) ? "-" : text;
    }

    private static bool TryParseInt(ReadOnlySpan<char> s, out int value)
    {
        value = 0;
        if (s.IsEmpty || s[0] == '-') return false;
        return int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static void IncrementCount(Dictionary<string, long> counts, string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value == "-") return;
        if (counts.TryGetValue(value, out var current))
            counts[value] = current + 1;
        else
            counts[value] = 1;
    }

    private sealed class ErrorPivotStats
    {
        private readonly Dictionary<string, long> _uriCounts = new(StringComparer.OrdinalIgnoreCase);

        public ErrorPivotStats(string ip) => Ip = ip;

        public string Ip { get; }
        public long TotalHits { get; private set; }
        public Dictionary<int, long> StatusCounts { get; } = new();

        public void Add(int status, string uriStem)
        {
            TotalHits++;
            if (StatusCounts.TryGetValue(status, out var c))
                StatusCounts[status] = c + 1;
            else
                StatusCounts[status] = 1;

            if (!string.IsNullOrWhiteSpace(uriStem) && uriStem != "-")
            {
                if (_uriCounts.TryGetValue(uriStem, out var uc))
                    _uriCounts[uriStem] = uc + 1;
                else
                    _uriCounts[uriStem] = 1;
            }
        }

        public List<(string UriStem, long Count)> TopUris(int take)
            => _uriCounts.OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(take)
                .Select(kv => (kv.Key, kv.Value))
                .ToList();
    }

    private sealed class PivotResult
    {
        private readonly Dictionary<string, long> _uriCounts = new(StringComparer.OrdinalIgnoreCase);

        public PivotResult(string ip) => Ip = ip;

        public string Ip { get; }
        public long Total2xx { get; private set; }
        public long Total3xx { get; private set; }
        public Dictionary<int, long> StatusCounts { get; } = new();

        public void Add(int status)
        {
            if (status >= 200 && status <= 299) Total2xx++;
            else if (status >= 300 && status <= 399) Total3xx++;

            if (StatusCounts.TryGetValue(status, out var c))
                StatusCounts[status] = c + 1;
            else
                StatusCounts[status] = 1;
        }

        public void AddUri(string uriStem)
        {
            if (_uriCounts.TryGetValue(uriStem, out var c))
                _uriCounts[uriStem] = c + 1;
            else
                _uriCounts[uriStem] = 1;
        }

        public List<(string UriStem, long Count)> TopUris(int take)
            => _uriCounts.OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(take)
                .Select(kv => (kv.Key, kv.Value))
                .ToList();
    }
}

internal sealed record IisStatusPivotJobSnapshot(
    string JobId,
    string State,
    string Message,
    string StatusFilter,
    string AppScope,
    DateTime CreatedUtc,
    DateTime UpdatedUtc,
    int CurrentStep,
    int TotalSteps,
    string Phase,
    int FilesProcessed,
    int FilesTotal,
    int UniqueErrorIps,
    long ExportedLines,
    string? ExportPath,
    IReadOnlyList<StatusPivotIpResult>? TopErrorIps,
    IReadOnlyList<StatusPivotUriCount>? TopErrorUris,
    IReadOnlyList<StatusPivotPivotIpResult>? PivotResults,
    string? Error)
{
    public static IisStatusPivotJobSnapshot CreateIdle()
        => new(
            JobId: string.Empty,
            State: "idle",
            Message: "No IIS status pivot scan has been run yet.",
            StatusFilter: string.Empty,
            AppScope: "All",
            CreatedUtc: DateTime.UtcNow,
            UpdatedUtc: DateTime.UtcNow,
            CurrentStep: 0,
            TotalSteps: 0,
            Phase: "idle",
            FilesProcessed: 0,
            FilesTotal: 0,
            UniqueErrorIps: 0,
            ExportedLines: 0,
            ExportPath: null,
            TopErrorIps: null,
            TopErrorUris: null,
            PivotResults: null,
            Error: null);
}

internal sealed record StatusPivotIpResult(
    string Ip,
    long TotalHits,
    IReadOnlyDictionary<string, long> StatusCounts,
    IReadOnlyList<StatusPivotUriCount> TopUris);

internal sealed record StatusPivotPivotIpResult(
    string Ip,
    long Total2xx,
    long Total3xx,
    IReadOnlyDictionary<string, long> StatusCounts,
    IReadOnlyList<StatusPivotUriCount> TopUris);

internal sealed record StatusPivotUriCount(string Uri, long Count);
