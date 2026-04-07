using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using LogHunter.Services;

namespace LogHunter.Web.Orchestration;

/// <summary>
/// A reusable job manager for ALB scan options that follow the pattern:
/// scan files -> accumulate results -> optionally export CSV/chart.
/// Used by options 4, 5, 6, 7, 8, and 9.
/// </summary>
internal sealed class AlbGenericScanJobManager
{
    private readonly object _gate = new();
    private AlbGenericScanSnapshot _snapshot = AlbGenericScanSnapshot.CreateIdle();

    public AlbGenericScanSnapshot GetSnapshot()
    {
        lock (_gate)
            return _snapshot;
    }

    public bool TryOpenExport(string? jobId, out string message)
    {
        AlbGenericScanSnapshot snapshot;
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
            message = "No export artifact is available.";
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

    public bool TryStart(
        Func<List<string>, string, Action<string, int, int, string>, Task<AlbGenericScanResult>> scanFunc,
        AlbTopIpsInputSourceSelection inputSource,
        out AlbGenericScanSnapshot snapshot,
        out string? error)
    {
        lock (_gate)
        {
            if (string.Equals(_snapshot.State, "running", StringComparison.OrdinalIgnoreCase))
            {
                snapshot = _snapshot;
                error = "A scan is already running.";
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

            var outputFolder = AppFolders.Output;

            _snapshot = new AlbGenericScanSnapshot(
                JobId: Guid.NewGuid().ToString("N"),
                State: "running",
                Message: "Scanning ALB logs.",
                CreatedUtc: DateTime.UtcNow,
                UpdatedUtc: DateTime.UtcNow,
                CurrentStep: 0,
                TotalSteps: files.Count,
                Phase: "scanning",
                FilesProcessed: 0,
                FilesTotal: files.Count,
                TotalBytes: inputSource.TotalBytes,
                InputSourceSummary: inputSource.Summary,
                ExportPath: null,
                Result: null,
                Error: null);

            snapshot = _snapshot;
            error = null;
            _ = RunAsync(_snapshot.JobId, files, outputFolder, scanFunc);
            return true;
        }
    }

    private async Task RunAsync(
        string jobId,
        List<string> files,
        string outputFolder,
        Func<List<string>, string, Action<string, int, int, string>, Task<AlbGenericScanResult>> scanFunc)
    {
        try
        {
            void ReportProgress(string message, int currentStep, int totalSteps, string phase)
            {
                Update(jobId, snapshot => snapshot with
                {
                    UpdatedUtc = DateTime.UtcNow,
                    Message = message,
                    CurrentStep = currentStep,
                    TotalSteps = totalSteps,
                    Phase = phase,
                    FilesProcessed = currentStep
                });
            }

            var result = await scanFunc(files, outputFolder, ReportProgress).ConfigureAwait(false);

            Update(jobId, snapshot => snapshot with
            {
                State = "completed",
                Phase = "completed",
                Message = result.CompletionMessage,
                UpdatedUtc = DateTime.UtcNow,
                CurrentStep = files.Count,
                FilesProcessed = files.Count,
                ExportPath = result.ExportPath,
                Result = result
            });
        }
        catch (Exception ex)
        {
            Update(jobId, snapshot => snapshot with
            {
                State = "failed",
                Phase = "failed",
                Message = "Scan failed.",
                UpdatedUtc = DateTime.UtcNow,
                Error = ex.Message
            });
        }
    }

    private void Update(string jobId, Func<AlbGenericScanSnapshot, AlbGenericScanSnapshot> update)
    {
        lock (_gate)
        {
            if (!string.Equals(_snapshot.JobId, jobId, StringComparison.Ordinal))
                return;
            _snapshot = update(_snapshot);
        }
    }
}

internal sealed record AlbGenericScanSnapshot(
    string JobId,
    string State,
    string Message,
    DateTime CreatedUtc,
    DateTime UpdatedUtc,
    int CurrentStep,
    int TotalSteps,
    string Phase,
    int FilesProcessed,
    int FilesTotal,
    long TotalBytes,
    string InputSourceSummary,
    string? ExportPath,
    AlbGenericScanResult? Result,
    string? Error)
{
    public static AlbGenericScanSnapshot CreateIdle()
        => new(
            JobId: string.Empty,
            State: "idle",
            Message: "No scan has been run yet.",
            CreatedUtc: DateTime.UtcNow,
            UpdatedUtc: DateTime.UtcNow,
            CurrentStep: 0,
            TotalSteps: 0,
            Phase: "idle",
            FilesProcessed: 0,
            FilesTotal: 0,
            TotalBytes: 0,
            InputSourceSummary: string.Empty,
            ExportPath: null,
            Result: null,
            Error: null);
}

internal sealed record AlbGenericScanResult(
    string CompletionMessage,
    string? ExportPath,
    IReadOnlyList<AlbGenericResultRow> Rows,
    IReadOnlyList<string> Columns,
    long TotalMatches,
    string? FirstHitUtc,
    string? LastHitUtc,
    int FilesWithHits,
    string? ChartHtmlPath);

internal sealed record AlbGenericResultRow(IReadOnlyList<string> Values);
