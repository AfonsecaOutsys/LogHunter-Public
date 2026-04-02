using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using LogHunter.Services;

namespace LogHunter.Web.Orchestration;

internal sealed class AlbTopIpsJobManager
{
    private readonly object _gate = new();
    private readonly string _outputRoot;
    private AlbTopIpsJobSnapshot _snapshot = AlbTopIpsJobSnapshot.CreateIdle();

    public AlbTopIpsJobManager(string outputRoot)
    {
        _outputRoot = outputRoot;
    }

    public AlbTopIpsJobSnapshot GetSnapshot()
    {
        lock (_gate)
            return _snapshot;
    }

    public bool TryOpenExport(string? jobId, out string message)
    {
        AlbTopIpsJobSnapshot snapshot;
        lock (_gate)
        {
            snapshot = _snapshot;
            if (!string.IsNullOrWhiteSpace(jobId) && !string.Equals(snapshot.JobId, jobId, StringComparison.Ordinal))
            {
                message = "The requested ALB option 2 job was not found.";
                return false;
            }
        }

        var exportPath = snapshot.ExportPath;
        if (string.IsNullOrWhiteSpace(exportPath) || !File.Exists(exportPath))
        {
            message = "The exported workbook is not available.";
            return false;
        }

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = exportPath,
                UseShellExecute = true
            });

            message = exportPath;
            return true;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return false;
        }
    }

    public bool TryStart(string endpointFragment, bool exportXlsx, out AlbTopIpsJobSnapshot snapshot, out string? error)
        => TryStart(
            endpointFragment,
            exportXlsx,
            AlbTopIpsInputSourceResolver.ResolveDefaultFolder(),
            out snapshot,
            out error);

    public bool TryStart(
        string endpointFragment,
        bool exportXlsx,
        AlbTopIpsInputSourceSelection inputSource,
        out AlbTopIpsJobSnapshot snapshot,
        out string? error)
    {
        lock (_gate)
        {
            if (string.Equals(_snapshot.State, "running", StringComparison.OrdinalIgnoreCase))
            {
                snapshot = _snapshot;
                error = "An ALB option 2 scan is already running.";
                return false;
            }

            var files = inputSource.Files.ToList();
            if (files.Count == 0)
            {
                snapshot = _snapshot;
                error = inputSource.SourceType == AlbTopIpsInputSourceType.DefaultFolder
                    ? $"No .log files found in: {AppFolders.ALB}"
                    : "No .log files were found in the selected input source.";
                return false;
            }

            _snapshot = new AlbTopIpsJobSnapshot(
                JobId: Guid.NewGuid().ToString("N"),
                State: "running",
                Message: "Scanning ALB logs (pass 1/2).",
                EndpointFragment: endpointFragment,
                InputSourceType: inputSource.SourceType.ToString(),
                InputSourceLabel: inputSource.SelectionLabel,
                InputSourceSummary: inputSource.Summary,
                CreatedUtc: DateTime.UtcNow,
                UpdatedUtc: DateTime.UtcNow,
                CurrentStep: 0,
                TotalSteps: files.Count * 2,
                Phase: "pass1",
                FilesProcessed: 0,
                FilesTotal: files.Count,
                TotalBytes: inputSource.TotalBytes,
                ExportPath: null,
                Result: null,
                Error: null);

            snapshot = _snapshot;
            error = null;
            _ = RunAsync(_snapshot.JobId, files, endpointFragment, exportXlsx);
            return true;
        }
    }

    private async Task RunAsync(string jobId, List<string> files, string endpointFragment, bool exportXlsx)
    {
        try
        {
            var endpointIpCounts = new Dictionary<string, int>(StringComparer.Ordinal);

            for (var i = 0; i < files.Count; i++)
            {
                await AlbScanner.ScanFileForEndpointIpCountsAsync(
                    files[i],
                    endpointFragment,
                    endpointIpCounts,
                    _ => { }).ConfigureAwait(false);

                Update(jobId, snapshot => snapshot with
                {
                    UpdatedUtc = DateTime.UtcNow,
                    Message = $"Scanning ALB logs (pass 1/2): {i + 1} / {files.Count} files.",
                    CurrentStep = i + 1,
                    Phase = "pass1",
                    FilesProcessed = i + 1
                });
            }

            if (endpointIpCounts.Count == 0)
            {
                Update(jobId, snapshot => snapshot with
                {
                    State = "completed",
                    Message = "No ALB hits matched the requested fragment.",
                    UpdatedUtc = DateTime.UtcNow,
                    CurrentStep = snapshot.TotalSteps,
                    Phase = "completed",
                    FilesProcessed = files.Count,
                    Result = new AlbTopIpsForEndpointResult(endpointFragment, files.Count, 0, Array.Empty<AlbTopIpResult>())
                });
                return;
            }

            var selectedIps = endpointIpCounts
                .OrderByDescending(kvp => kvp.Value)
                .ThenBy(kvp => kvp.Key, StringComparer.Ordinal)
                .Take(AlbTopIpsForEndpointWorkflow.DefaultTopIpCount)
                .Select(kvp => kvp.Key)
                .ToHashSet(StringComparer.Ordinal);

            var uriCountsByIp = new Dictionary<string, Dictionary<string, int>>(StringComparer.Ordinal);
            for (var i = 0; i < files.Count; i++)
            {
                await AlbScanner.ScanFileForEndpointUriCountsBySelectedIpsAsync(
                    files[i],
                    endpointFragment,
                    selectedIps,
                    uriCountsByIp,
                    _ => { }).ConfigureAwait(false);

                Update(jobId, snapshot => snapshot with
                {
                    UpdatedUtc = DateTime.UtcNow,
                    Message = $"Scanning ALB logs (pass 2/2): {i + 1} / {files.Count} files.",
                    CurrentStep = files.Count + i + 1,
                    Phase = "pass2",
                    FilesProcessed = i + 1
                });
            }

            var result = AlbTopIpsForEndpointWorkflow.BuildResult(
                endpointFragment,
                files.Count,
                endpointIpCounts,
                uriCountsByIp);

            string? exportPath = null;
            if (exportXlsx)
                exportPath = AlbTopIpsForEndpointWorkflow.ExportXlsx(AppFolders.Output, result);

            Update(jobId, snapshot => snapshot with
            {
                State = "completed",
                Message = result.TopIps.Count > 0
                    ? $"Scan complete. {result.TotalMatchingIps} matching IP(s) found."
                    : "No ALB hits matched the requested fragment.",
                UpdatedUtc = DateTime.UtcNow,
                CurrentStep = snapshot.TotalSteps,
                Phase = "completed",
                FilesProcessed = files.Count,
                ExportPath = exportPath,
                Result = result
            });
        }
        catch (Exception ex)
        {
            Update(jobId, snapshot => snapshot with
            {
                State = "failed",
                Message = "ALB option 2 scan failed.",
                UpdatedUtc = DateTime.UtcNow,
                Phase = "failed",
                Error = ex.Message
            });
        }
    }

    private void Update(string jobId, Func<AlbTopIpsJobSnapshot, AlbTopIpsJobSnapshot> update)
    {
        lock (_gate)
        {
            if (!string.Equals(_snapshot.JobId, jobId, StringComparison.Ordinal))
                return;

            _snapshot = update(_snapshot);
        }
    }

}

internal sealed record AlbTopIpsJobSnapshot(
    string JobId,
    string State,
    string Message,
    string EndpointFragment,
    string InputSourceType,
    string InputSourceLabel,
    string InputSourceSummary,
    DateTime CreatedUtc,
    DateTime UpdatedUtc,
    int CurrentStep,
    int TotalSteps,
    string Phase,
    int FilesProcessed,
    int FilesTotal,
    long TotalBytes,
    string? ExportPath,
    AlbTopIpsForEndpointResult? Result,
    string? Error)
{
    public static AlbTopIpsJobSnapshot CreateIdle()
        => new(
            JobId: string.Empty,
            State: "idle",
            Message: "No ALB endpoint-fragment scan has been run yet.",
            EndpointFragment: string.Empty,
            InputSourceType: AlbTopIpsInputSourceType.DefaultFolder.ToString(),
            InputSourceLabel: AppFolders.ALB,
            InputSourceSummary: $"Default folder | {AppFolders.ALB}",
            CreatedUtc: DateTime.UtcNow,
            UpdatedUtc: DateTime.UtcNow,
            CurrentStep: 0,
            TotalSteps: 0,
            Phase: "idle",
            FilesProcessed: 0,
            FilesTotal: 0,
            TotalBytes: 0,
            ExportPath: null,
            Result: null,
            Error: null);
}
