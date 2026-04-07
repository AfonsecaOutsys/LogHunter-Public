using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Services;

namespace LogHunter.Web.Orchestration;

internal sealed class PlatformAuthJobManager
{
    private readonly object _gate = new();
    private readonly SessionState _session;
    private PlatformAuthJobSnapshot _snapshot = PlatformAuthJobSnapshot.CreateIdle();

    public PlatformAuthJobManager(SessionState session)
    {
        _session = session;
    }

    public PlatformAuthJobSnapshot GetSnapshot()
    {
        lock (_gate)
            return _snapshot;
    }

    public bool TryStart(out PlatformAuthJobSnapshot snapshot, out string? error)
    {
        lock (_gate)
        {
            if (string.Equals(_snapshot.State, "running", StringComparison.OrdinalIgnoreCase))
            {
                snapshot = _snapshot;
                error = "An authenticated activity check is already running.";
                return false;
            }

            // Gather suspicious IPs from session
            var suspicious = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (_session.PlatformSuspiciousIpHits is not null)
            {
                foreach (var ip in _session.PlatformSuspiciousIpHits.Keys)
                    if (!string.IsNullOrWhiteSpace(ip))
                        suspicious.Add(ip);
            }

            foreach (var s in _session.SavedSelections)
            {
                if (!string.Equals(s.Source, "Platform", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!string.IsNullOrWhiteSpace(s.IP))
                    suspicious.Add(s.IP);
            }

            if (suspicious.Count == 0)
            {
                snapshot = _snapshot;
                error = "No suspicious IPs found in session. Run 'Suspicious requests: extract IPs' first.";
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

            _snapshot = new PlatformAuthJobSnapshot(
                JobId: Guid.NewGuid().ToString("N"),
                State: "running",
                Phase: "scanning",
                Message: $"Scanning platform logs for authenticated activity ({suspicious.Count} suspicious IPs).",
                CreatedUtc: DateTime.UtcNow,
                UpdatedUtc: DateTime.UtcNow,
                CurrentStep: 0,
                TotalSteps: files.Count,
                SuspiciousIpsInput: suspicious.Count,
                FilesScanned: 0,
                FilesMatched: 0,
                TotalMatchedRows: 0,
                DistinctMatchedIps: 0,
                RowsByKind: null,
                TopIps: null,
                CachedIpCount: 0,
                Error: null);

            snapshot = _snapshot;
            error = null;
            _ = RunAsync(_snapshot.JobId, suspicious);
            return true;
        }
    }

    private async Task RunAsync(string jobId, HashSet<string> suspicious)
    {
        try
        {
            var platformDir = AppFolders.PlatformLogs;
            var result = await PlatformAuthScanner.ScanAuthenticatedActivityAsync(platformDir, suspicious, CancellationToken.None)
                .ConfigureAwait(false);

            // Update session state (same as console)
            _session.PlatformAuthedIpHits = result.HitsByIp
                .ToDictionary(k => k.Key, v => v.Value.Total, StringComparer.OrdinalIgnoreCase);
            _session.PlatformAuthedIpHitsUpdatedUtc = DateTime.UtcNow;

            var rowsByKind = new Dictionary<string, int>
            {
                ["General"] = result.RowsMatchedByKind.GetValueOrDefault(PlatformLogKind.General),
                ["Traditional"] = result.RowsMatchedByKind.GetValueOrDefault(PlatformLogKind.TraditionalWebRequests),
                ["Screen"] = result.RowsMatchedByKind.GetValueOrDefault(PlatformLogKind.ScreenRequests),
                ["Error"] = result.RowsMatchedByKind.GetValueOrDefault(PlatformLogKind.Error)
            };

            var topIps = result.HitsByIp
                .OrderByDescending(kvp => kvp.Value.Total)
                .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
                .Take(80)
                .Select((kvp, i) => new PlatformAuthIpResult(
                    Rank: i + 1,
                    Ip: kvp.Key,
                    Total: kvp.Value.Total,
                    General: kvp.Value.General,
                    Traditional: kvp.Value.Traditional,
                    Screen: kvp.Value.Screen,
                    Error: kvp.Value.Error))
                .ToList();

            Update(jobId, s => s with
            {
                State = "completed",
                Phase = "completed",
                Message = result.DistinctMatchedIps > 0
                    ? $"Found {result.TotalMatchedRows} authenticated rows across {result.DistinctMatchedIps} IPs."
                    : "None of the suspicious IPs were found with authenticated activity.",
                UpdatedUtc = DateTime.UtcNow,
                CurrentStep = result.FilesScanned,
                TotalSteps = result.FilesScanned,
                SuspiciousIpsInput = result.SuspiciousIpsInput,
                FilesScanned = result.FilesScanned,
                FilesMatched = result.FilesMatched,
                TotalMatchedRows = result.TotalMatchedRows,
                DistinctMatchedIps = result.DistinctMatchedIps,
                RowsByKind = rowsByKind,
                TopIps = topIps,
                CachedIpCount = _session.PlatformAuthedIpHits?.Count ?? 0
            });
        }
        catch (Exception ex)
        {
            Update(jobId, s => s with
            {
                State = "failed",
                Phase = "failed",
                Message = "Authenticated activity check failed.",
                UpdatedUtc = DateTime.UtcNow,
                Error = ex.Message
            });
        }
    }

    private void Update(string jobId, Func<PlatformAuthJobSnapshot, PlatformAuthJobSnapshot> update)
    {
        lock (_gate)
        {
            if (!string.Equals(_snapshot.JobId, jobId, StringComparison.Ordinal))
                return;
            _snapshot = update(_snapshot);
        }
    }
}

internal sealed record PlatformAuthJobSnapshot(
    string JobId,
    string State,
    string Phase,
    string Message,
    DateTime CreatedUtc,
    DateTime UpdatedUtc,
    int CurrentStep,
    int TotalSteps,
    int SuspiciousIpsInput,
    int FilesScanned,
    int FilesMatched,
    int TotalMatchedRows,
    int DistinctMatchedIps,
    IReadOnlyDictionary<string, int>? RowsByKind,
    IReadOnlyList<PlatformAuthIpResult>? TopIps,
    int CachedIpCount,
    string? Error)
{
    public static PlatformAuthJobSnapshot CreateIdle()
        => new(
            JobId: string.Empty,
            State: "idle",
            Phase: "idle",
            Message: "No authenticated activity check has been run yet.",
            CreatedUtc: DateTime.UtcNow,
            UpdatedUtc: DateTime.UtcNow,
            CurrentStep: 0,
            TotalSteps: 0,
            SuspiciousIpsInput: 0,
            FilesScanned: 0,
            FilesMatched: 0,
            TotalMatchedRows: 0,
            DistinctMatchedIps: 0,
            RowsByKind: null,
            TopIps: null,
            CachedIpCount: 0,
            Error: null);
}

internal sealed record PlatformAuthIpResult(
    int Rank,
    string Ip,
    int Total,
    int General,
    int Traditional,
    int Screen,
    int Error);
