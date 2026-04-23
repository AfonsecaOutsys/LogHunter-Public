using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ClosedXML.Excel;
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

    public bool TryStart(List<string>? manualIps, out PlatformAuthJobSnapshot snapshot, out string? error)
    {
        lock (_gate)
        {
            if (string.Equals(_snapshot.State, "running", StringComparison.OrdinalIgnoreCase))
            {
                snapshot = _snapshot;
                error = "An authenticated activity check is already running.";
                return false;
            }

            var suspicious = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (manualIps is { Count: > 0 })
            {
                // Manual IP input — use only the provided IPs
                foreach (var ip in manualIps)
                    if (!string.IsNullOrWhiteSpace(ip))
                        suspicious.Add(ip.Trim());
            }
            else
            {
                // Cache mode — gather suspicious IPs from session
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
            }

            if (suspicious.Count == 0)
            {
                snapshot = _snapshot;
                error = manualIps is { Count: > 0 }
                    ? "No valid IPs provided."
                    : "No suspicious IPs found in session. Run 'Suspicious requests: extract IPs' first.";
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
                ExportPath: null,
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

            // Generate Excel export
            string? exportPath = null;
            if (result.CollectedRows.Count > 0)
                exportPath = GenerateExcel(result);

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
                CachedIpCount = _session.PlatformAuthedIpHits?.Count ?? 0,
                ExportPath = exportPath
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

    private static string GenerateExcel(PlatformAuthScanResult result)
    {
        var ts = DateTime.Now.ToString("yyyy-MM-dd_HHmmss");
        var path = Path.Combine(AppFolders.Output, $"platform-auth-activity_{ts}.xlsx");

        using var wb = new XLWorkbook();
        var ws = wb.Worksheets.Add("Activity");

        var headers = new[] { "IP", "UserId", "Authenticated", "Log Type", "Source File" };
        ExcelHelper.WriteHeaderRow(ws, 1, headers);

        var rows = result.CollectedRows
            .OrderBy(r => r.Ip, StringComparer.OrdinalIgnoreCase)
            .ThenByDescending(r => r.IsAuthenticated)
            .ThenBy(r => r.LogKind)
            .ToList();

        var redFill = XLColor.FromHtml("#4D1F1F");
        var redFont = XLColor.FromHtml("#FF9999");

        for (int i = 0; i < rows.Count; i++)
        {
            var r = rows[i];
            int row = i + 2;

            ws.Cell(row, 1).Value = r.Ip;
            ws.Cell(row, 2).Value = r.UserId;
            ws.Cell(row, 3).Value = r.IsAuthenticated ? "Yes" : "No";
            ws.Cell(row, 4).Value = r.LogKind switch
            {
                PlatformLogKind.General => "General",
                PlatformLogKind.TraditionalWebRequests => "Traditional",
                PlatformLogKind.ScreenRequests => "Screen",
                PlatformLogKind.Error => "Error",
                _ => "Unknown"
            };
            ws.Cell(row, 5).Value = r.SourceFile;

            if (r.IsAuthenticated)
            {
                var range = ws.Range(row, 1, row, headers.Length);
                range.Style.Fill.BackgroundColor = redFill;
                range.Style.Font.FontColor = redFont;
            }
        }

        ws.Range(1, 1, rows.Count + 1, headers.Length).SetAutoFilter();
        ExcelHelper.AutoFitColumns(ws);
        ws.SheetView.FreezeRows(1);

        wb.SaveAs(path);
        return path;
    }

    public bool TryOpenExport(out string message)
    {
        PlatformAuthJobSnapshot snapshot;
        lock (_gate) { snapshot = _snapshot; }

        var path = snapshot.ExportPath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            message = "The exported Excel file is not available.";
            return false;
        }

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo { FileName = path, UseShellExecute = true });
            message = path;
            return true;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return false;
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
    string? ExportPath,
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
            ExportPath: null,
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
