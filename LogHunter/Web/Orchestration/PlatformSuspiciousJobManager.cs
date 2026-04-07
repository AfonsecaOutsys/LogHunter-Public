using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Services;

namespace LogHunter.Web.Orchestration;

internal sealed class PlatformSuspiciousJobManager
{
    private readonly object _gate = new();
    private readonly SessionState _session;
    private PlatformSuspiciousJobSnapshot _snapshot = PlatformSuspiciousJobSnapshot.CreateIdle();

    public PlatformSuspiciousJobManager(SessionState session)
    {
        _session = session;
    }

    public PlatformSuspiciousJobSnapshot GetSnapshot()
    {
        lock (_gate)
            return _snapshot;
    }

    public bool TryStart(out PlatformSuspiciousJobSnapshot snapshot, out string? error)
    {
        lock (_gate)
        {
            if (string.Equals(_snapshot.State, "running", StringComparison.OrdinalIgnoreCase))
            {
                snapshot = _snapshot;
                error = "A suspicious request scan is already running.";
                return false;
            }

            var platformDir = AppFolders.PlatformLogs;
            if (!Directory.Exists(platformDir))
            {
                snapshot = _snapshot;
                error = $"Platform logs folder not found: {platformDir}";
                return false;
            }

            var files = Directory.EnumerateFiles(platformDir, "*.*", SearchOption.AllDirectories)
                .Where(p => p.EndsWith(".csv", StringComparison.OrdinalIgnoreCase) ||
                            p.EndsWith(".xlsx", StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (files.Count == 0)
            {
                snapshot = _snapshot;
                error = $"No CSV/XLSX files found in: {platformDir}";
                return false;
            }

            _snapshot = new PlatformSuspiciousJobSnapshot(
                JobId: Guid.NewGuid().ToString("N"),
                State: "running",
                Phase: "scanning",
                Message: "Scanning platform logs for suspicious requests.",
                CreatedUtc: DateTime.UtcNow,
                UpdatedUtc: DateTime.UtcNow,
                CurrentStep: 0,
                TotalSteps: files.Count,
                FilesScanned: 0,
                FilesMatched: 0,
                MatchedRows: 0,
                DistinctIps: 0,
                RowsWithXff: 0,
                RowsWithoutXff: 0,
                ByErrorType: null,
                TopIpsOverall: null,
                TopIpsByErrorType: null,
                SelectionsAdded: 0,
                SelectionsUpdated: 0,
                CachedIpCount: 0,
                Error: null);

            snapshot = _snapshot;
            error = null;
            _ = RunAsync(_snapshot.JobId);
            return true;
        }
    }

    private async Task RunAsync(string jobId)
    {
        try
        {
            var platformDir = AppFolders.PlatformLogs;
            var result = await PlatformScanner.ScanSuspiciousRequestsAsync(platformDir, CancellationToken.None)
                .ConfigureAwait(false);

            // Update session state (same as console)
            int added = 0, updated = 0;
            if (result.MatchedRows > 0)
            {
                (added, updated) = UpsertSelections(_session.SavedSelections, result);
                _session.PlatformSuspiciousIpHits = result.TopEffectiveIpsOverall
                    .ToDictionary(x => x.Ip, x => x.Hits, StringComparer.OrdinalIgnoreCase);
                _session.PlatformSuspiciousIpHitsUpdatedUtc = DateTime.UtcNow;
            }
            else
            {
                _session.PlatformSuspiciousIpHits = null;
                _session.PlatformSuspiciousIpHitsUpdatedUtc = null;
            }

            // Build error type breakdown for display
            var byErrorType = result.ByErrorType
                .OrderByDescending(x => x.Value.Rows)
                .Select(x => new PlatformErrorTypeBreakdown(x.Key, x.Value.Rows, x.Value.DistinctEffectiveIps))
                .ToList();

            var topIpsOverall = result.TopEffectiveIpsOverall
                .Take(20)
                .Select((x, i) => new PlatformIpHit(i + 1, x.Ip, x.Hits))
                .ToList();

            var topIpsByErrorType = result.TopEffectiveIpsByErrorType
                .OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    x => x.Key,
                    x => (IReadOnlyList<PlatformIpHit>)x.Value
                        .Take(20)
                        .Select((ip, i) => new PlatformIpHit(i + 1, ip.Ip, ip.Hits))
                        .ToList(),
                    StringComparer.OrdinalIgnoreCase);

            Update(jobId, s => s with
            {
                State = "completed",
                Phase = "completed",
                Message = result.MatchedRows > 0
                    ? $"Found {result.MatchedRows} suspicious rows across {result.FilesMatched} files. {result.DistinctEffectiveIps} distinct IPs."
                    : "No matching suspicious rows were found.",
                UpdatedUtc = DateTime.UtcNow,
                CurrentStep = result.FilesScanned,
                TotalSteps = result.FilesScanned,
                FilesScanned = result.FilesScanned,
                FilesMatched = result.FilesMatched,
                MatchedRows = result.MatchedRows,
                DistinctIps = result.DistinctEffectiveIps,
                RowsWithXff = result.RowsWithXff,
                RowsWithoutXff = result.RowsWithoutXff,
                ByErrorType = byErrorType,
                TopIpsOverall = topIpsOverall,
                TopIpsByErrorType = topIpsByErrorType,
                SelectionsAdded = added,
                SelectionsUpdated = updated,
                CachedIpCount = _session.PlatformSuspiciousIpHits?.Count ?? 0
            });
        }
        catch (Exception ex)
        {
            Update(jobId, s => s with
            {
                State = "failed",
                Phase = "failed",
                Message = "Suspicious request scan failed.",
                UpdatedUtc = DateTime.UtcNow,
                Error = ex.Message
            });
        }
    }

    private void Update(string jobId, Func<PlatformSuspiciousJobSnapshot, PlatformSuspiciousJobSnapshot> update)
    {
        lock (_gate)
        {
            if (!string.Equals(_snapshot.JobId, jobId, StringComparison.Ordinal))
                return;
            _snapshot = update(_snapshot);
        }
    }

    private static (int Added, int Updated) UpsertSelections(
        List<Models.SavedSelection> savedSelections,
        PlatformSuspiciousScanResult result)
    {
        int added = 0, updated = 0;
        var now = DateTime.UtcNow;

        foreach (var typeKvp in result.EffectiveIpCountsByErrorType)
        {
            var errorType = typeKvp.Key;
            var counts = typeKvp.Value
                .OrderByDescending(k => k.Value)
                .ThenBy(k => k.Key, StringComparer.OrdinalIgnoreCase)
                .ToList();

            for (int i = 0; i < counts.Count; i++)
            {
                var ip = counts[i].Key;
                var hits = counts[i].Value;
                var endpoint = $"Platform | {errorType}";
                const string source = "Platform";
                var rank = i + 1;

                var idx = savedSelections.FindIndex(s =>
                    string.Equals(s.Source, source, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(s.Endpoint, endpoint, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(s.IP, ip, StringComparison.OrdinalIgnoreCase));

                var item = new Models.SavedSelection(
                    SavedAtUtc: now,
                    Source: source,
                    Endpoint: endpoint,
                    Rank: rank,
                    IP: ip,
                    Hits: hits);

                if (idx >= 0)
                {
                    savedSelections[idx] = item;
                    updated++;
                }
                else
                {
                    savedSelections.Add(item);
                    added++;
                }
            }
        }

        return (added, updated);
    }
}

internal sealed record PlatformSuspiciousJobSnapshot(
    string JobId,
    string State,
    string Phase,
    string Message,
    DateTime CreatedUtc,
    DateTime UpdatedUtc,
    int CurrentStep,
    int TotalSteps,
    int FilesScanned,
    int FilesMatched,
    int MatchedRows,
    int DistinctIps,
    int RowsWithXff,
    int RowsWithoutXff,
    IReadOnlyList<PlatformErrorTypeBreakdown>? ByErrorType,
    IReadOnlyList<PlatformIpHit>? TopIpsOverall,
    IReadOnlyDictionary<string, IReadOnlyList<PlatformIpHit>>? TopIpsByErrorType,
    int SelectionsAdded,
    int SelectionsUpdated,
    int CachedIpCount,
    string? Error)
{
    public static PlatformSuspiciousJobSnapshot CreateIdle()
        => new(
            JobId: string.Empty,
            State: "idle",
            Phase: "idle",
            Message: "No suspicious request scan has been run yet.",
            CreatedUtc: DateTime.UtcNow,
            UpdatedUtc: DateTime.UtcNow,
            CurrentStep: 0,
            TotalSteps: 0,
            FilesScanned: 0,
            FilesMatched: 0,
            MatchedRows: 0,
            DistinctIps: 0,
            RowsWithXff: 0,
            RowsWithoutXff: 0,
            ByErrorType: null,
            TopIpsOverall: null,
            TopIpsByErrorType: null,
            SelectionsAdded: 0,
            SelectionsUpdated: 0,
            CachedIpCount: 0,
            Error: null);
}

internal sealed record PlatformErrorTypeBreakdown(string ErrorType, int Rows, int DistinctIps);
internal sealed record PlatformIpHit(int Rank, string Ip, int Hits);
