using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Services;

namespace LogHunter.Web.Orchestration;

internal sealed class AlbDownloadJobManager
{
    private const int MaxOutputLines = 250;
    private static readonly Regex AlbTimestampRegex =
        new(@"_(\d{8})T(\d{4})Z_", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly object _gate = new();
    private readonly string _rootPath;
    private readonly string _workingDirectory;
    private readonly Dictionary<string, AlbDownloadJobSnapshot> _jobs = new(StringComparer.Ordinal);
    private readonly Dictionary<string, AlbDownloadRuntimeState> _runtime = new(StringComparer.Ordinal);
    private string _currentJobId = string.Empty;

    public AlbDownloadJobManager(string rootPath, string workingDirectory)
    {
        _rootPath = rootPath;
        _workingDirectory = workingDirectory;
    }

    public AlbDownloadJobSnapshot GetSnapshot()
    {
        lock (_gate)
        {
            if (!string.IsNullOrWhiteSpace(_currentJobId) && _jobs.TryGetValue(_currentJobId, out var snapshot))
                return snapshot;

            return AlbDownloadJobSnapshot.CreateIdle();
        }
    }

    public bool TryGetSnapshot(string jobId, out AlbDownloadJobSnapshot snapshot)
    {
        lock (_gate)
        {
            if (_jobs.TryGetValue(jobId, out snapshot!))
                return true;

            snapshot = AlbDownloadJobSnapshot.CreateIdle();
            return false;
        }
    }

    public bool TryStart(AlbDownloadRequest request, out AlbDownloadJobSnapshot snapshot, out string? error)
    {
        lock (_gate)
        {
            if (_jobs.Values.Any(x => string.Equals(x.State, "running", StringComparison.OrdinalIgnoreCase)))
            {
                snapshot = GetSnapshot();
                error = "An ALB download is already running.";
                return false;
            }

            var jobId = Guid.NewGuid().ToString("N");
            snapshot = new AlbDownloadJobSnapshot(
                JobId: jobId,
                State: "running",
                Stage: "planning",
                Message: "Planning ALB download.",
                CreatedUtc: DateTime.UtcNow,
                UpdatedUtc: DateTime.UtcNow,
                CurrentStep: 0,
                TotalSteps: 0,
                Error: null,
                Plan: null,
                Progress: AlbDownloadWebProgress.CreateEmpty(),
                Result: null,
                OutputLines: Array.Empty<AlbJobOutputLine>());

            _jobs[jobId] = snapshot;
            _runtime[jobId] = new AlbDownloadRuntimeState();
            _currentJobId = jobId;
            error = null;
            _ = RunJobAsync(jobId, request);
            return true;
        }
    }

    public bool TryOpenRunFolder(string? jobId, out string message)
    {
        if (!TryResolveSnapshot(jobId, out var snapshot))
        {
            message = "The requested ALB job was not found.";
            return false;
        }

        var folder = snapshot.Result?.RunFolder ?? snapshot.Plan?.RunFolder;
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
        {
            message = "The ALB run folder is not available.";
            return false;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = folder,
                UseShellExecute = true
            });

            message = folder;
            return true;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return false;
        }
    }

    private async Task RunJobAsync(string jobId, AlbDownloadRequest request)
    {
        var requestFile = Path.Combine(Path.GetTempPath(), $"loghunter-alb-download-{jobId}.json");
        Process? process = null;
        ChildProcessLifetime? childLifetime = null;
        CancellationTokenSource? observerCts = null;
        Task? observerTask = null;

        try
        {
            var plan = await AlbDownloadPlanner.BuildPlanAsync(
                request,
                (completed, total, message) => UpdatePlanning(jobId, completed, total, message)).ConfigureAwait(false);

            var baselineObservation = ScanRunFolder(plan.RunFolder);
            lock (_gate)
            {
                if (_runtime.TryGetValue(jobId, out var runtime))
                    runtime.SetBaseline(baselineObservation);
            }

            UpdateSnapshot(jobId, snapshot => snapshot with
            {
                Stage = "planning",
                Message = $"Plan ready. {plan.TotalFiles} file(s) discovered across {plan.Days.Count} day(s).",
                UpdatedUtc = DateTime.UtcNow,
                CurrentStep = plan.Days.Count,
                TotalSteps = plan.Days.Count,
                Plan = new AlbDownloadWebPlan(
                    plan.RunFolder,
                    plan.TotalFiles,
                    plan.TotalBytes,
                    plan.InWindowFiles,
                    plan.InWindowBytes,
                    plan.Days.Select(x => new AlbDownloadWebDayPlan(
                        x.DayUtc,
                        x.TotalFiles,
                        x.TotalBytes,
                        x.InWindowFiles,
                        x.InWindowBytes)).ToArray()),
                Progress = BuildProgress(jobId, plan)
            });

            AppendOutputLine(jobId, "planner", $"Plan ready: {plan.TotalFiles} file(s), {FormatBytes(plan.TotalBytes)} total.");

            await File.WriteAllTextAsync(requestFile, JsonSerializer.Serialize(request)).ConfigureAwait(false);

            var startInfo = BuildStartInfo(requestFile);
            process = new Process
            {
                StartInfo = startInfo,
                EnableRaisingEvents = true
            };

            process.OutputDataReceived += (_, e) =>
            {
                if (e.Data is not null)
                    HandleProcessLine(jobId, "stdout", e.Data);
            };

            process.ErrorDataReceived += (_, e) =>
            {
                if (e.Data is not null)
                    HandleProcessLine(jobId, "stderr", e.Data);
            };

            childLifetime = ChildProcessLifetime.TryCreate();
            process.Start();
            childLifetime?.Add(process);
            SetChildStarted(jobId);

            observerCts = new CancellationTokenSource();
            observerTask = MonitorRunFolderAsync(jobId, plan, observerCts.Token);

            UpdateSnapshot(jobId, snapshot => snapshot with
            {
                Stage = "downloading",
                Message = "ALB download process started.",
                UpdatedUtc = DateTime.UtcNow,
                Progress = BuildProgress(jobId, plan)
            });

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            await process.WaitForExitAsync().ConfigureAwait(false);

            observerCts.Cancel();
            if (observerTask is not null)
            {
                try { await observerTask.ConfigureAwait(false); }
                catch (OperationCanceledException) { }
            }

            ApplyObservedProgress(jobId, plan);

            UpdateSnapshot(jobId, snapshot =>
            {
                var state = process.ExitCode == 0 ? "completed" : "failed";
                var error = process.ExitCode == 0 ? snapshot.Error : snapshot.Error ?? $"Process exited with code {process.ExitCode}.";
                return snapshot with
                {
                    State = state,
                    Stage = state,
                    Message = process.ExitCode == 0 ? "ALB download completed." : "ALB download failed.",
                    UpdatedUtc = DateTime.UtcNow,
                    Error = error,
                    Progress = BuildProgress(jobId, plan)
                };
            });
        }
        catch (Exception ex)
        {
            UpdateSnapshot(jobId, snapshot => snapshot with
            {
                State = "failed",
                Stage = "failed",
                Message = "ALB download failed to start.",
                UpdatedUtc = DateTime.UtcNow,
                Error = ex.Message
            });

            AppendOutputLine(jobId, "stderr", ex.Message);
        }
        finally
        {
            observerCts?.Cancel();

            if (observerTask is not null)
            {
                try { await observerTask.ConfigureAwait(false); }
                catch { }
            }

            process?.Dispose();
            childLifetime?.Dispose();

            try
            {
                if (File.Exists(requestFile))
                    File.Delete(requestFile);
            }
            catch
            {
                // ignore temp cleanup failures
            }
        }
    }

    private async Task MonitorRunFolderAsync(string jobId, AlbDownloadExecutionPlan plan, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            ApplyObservedProgress(jobId, plan);
            await Task.Delay(1000, cancellationToken).ConfigureAwait(false);
        }
    }

    private void ApplyObservedProgress(string jobId, AlbDownloadExecutionPlan plan)
    {
        var observation = ScanRunFolder(plan.RunFolder);

        lock (_gate)
        {
            if (!_jobs.TryGetValue(jobId, out var snapshot) || !_runtime.TryGetValue(jobId, out var runtime))
                return;

            runtime.ApplyObservation(observation);
            var progress = runtime.BuildProgress(plan);
            var stage = DeriveStage(snapshot.State, snapshot.Stage, runtime, plan);
            var message = DeriveMessage(snapshot.Message, stage, progress, plan);

            _jobs[jobId] = snapshot with
            {
                UpdatedUtc = DateTime.UtcNow,
                Stage = stage,
                Message = message,
                Progress = progress
            };
        }
    }

    private void UpdatePlanning(string jobId, int completed, int total, string message)
    {
        lock (_gate)
        {
            if (!_jobs.TryGetValue(jobId, out var snapshot) || !_runtime.TryGetValue(jobId, out var runtime))
                return;

            runtime.PlanningDaysCompleted = completed;
            runtime.PlanningDaysTotal = total;
            _jobs[jobId] = snapshot with
            {
                Stage = "planning",
                Message = message,
                UpdatedUtc = DateTime.UtcNow,
                CurrentStep = completed,
                TotalSteps = total,
                Progress = runtime.BuildProgress(snapshot.Plan is null
                    ? null
                    : new AlbDownloadExecutionPlan(
                        ConfigName: string.Empty,
                        Bucket: string.Empty,
                        PrefixRoot: string.Empty,
                        AlbKey: string.Empty,
                        RunFolder: snapshot.Plan.RunFolder,
                        TotalFiles: snapshot.Plan.TotalFiles,
                        TotalBytes: snapshot.Plan.TotalBytes,
                        InWindowFiles: snapshot.Plan.InWindowFiles,
                        InWindowBytes: snapshot.Plan.InWindowBytes,
                        Days: snapshot.Plan.Days.Select(x => new AlbDownloadDayPlan(
                            x.DayUtc,
                            x.TotalFiles,
                            x.TotalBytes,
                            x.InWindowFiles,
                            x.InWindowBytes)).ToArray()))
            };
        }

        AppendOutputLine(jobId, "planner", message);
    }

    private void SetChildStarted(string jobId)
    {
        lock (_gate)
        {
            if (_runtime.TryGetValue(jobId, out var runtime))
                runtime.ChildStarted = true;
        }
    }

    private ProcessStartInfo BuildStartInfo(string requestFile)
    {
        var processPath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? "dotnet";
        var isDotnetHost = Path.GetFileName(processPath).Equals("dotnet", StringComparison.OrdinalIgnoreCase)
            || Path.GetFileName(processPath).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase);

        if (isDotnetHost)
        {
            var appDllPath = Path.Combine(AppContext.BaseDirectory, "LogHunter.dll");
            var startInfo = new ProcessStartInfo
            {
                FileName = processPath,
                WorkingDirectory = _workingDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            startInfo.ArgumentList.Add(appDllPath);
            startInfo.ArgumentList.Add("--root");
            startInfo.ArgumentList.Add(_rootPath);
            startInfo.ArgumentList.Add("--run-alb-download-job");
            startInfo.ArgumentList.Add(requestFile);
            return startInfo;
        }

        var fallbackStartInfo = new ProcessStartInfo
        {
            FileName = processPath,
            WorkingDirectory = _workingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        fallbackStartInfo.ArgumentList.Add("--root");
        fallbackStartInfo.ArgumentList.Add(_rootPath);
        fallbackStartInfo.ArgumentList.Add("--run-alb-download-job");
        fallbackStartInfo.ArgumentList.Add(requestFile);
        return fallbackStartInfo;
    }

    private void HandleProcessLine(string jobId, string stream, string line)
    {
        if (TryHandleStructuredLine(jobId, line))
            return;

        AppendOutputLine(jobId, stream, line);
    }

    private bool TryHandleStructuredLine(string jobId, string line)
    {
        if (line.StartsWith("__LHJOB_PROGRESS__", StringComparison.Ordinal))
        {
            var json = line["__LHJOB_PROGRESS__".Length..];
            var progress = JsonSerializer.Deserialize<AlbDownloadRunProgress>(json);
            if (progress is null)
                return true;

            lock (_gate)
            {
                if (_jobs.TryGetValue(jobId, out var snapshot))
                {
                    _jobs[jobId] = snapshot with
                    {
                        Stage = progress.Stage,
                        Message = progress.Message,
                        UpdatedUtc = DateTime.UtcNow,
                        CurrentStep = progress.CurrentStep,
                        TotalSteps = progress.TotalSteps
                    };
                }
            }

            AppendOutputLine(jobId, "stdout", progress.Message);
            return true;
        }

        if (line.StartsWith("__LHJOB_RESULT__", StringComparison.Ordinal))
        {
            var json = line["__LHJOB_RESULT__".Length..];
            var result = JsonSerializer.Deserialize<AlbDownloadRunResult>(json);
            if (result is null)
                return true;

            UpdateSnapshot(jobId, snapshot => snapshot with
            {
                UpdatedUtc = DateTime.UtcNow,
                Result = result,
                Error = result.Success ? null : result.Message
            });

            return true;
        }

        return false;
    }

    private void AppendOutputLine(string jobId, string stream, string line)
    {
        UpdateSnapshot(jobId, snapshot =>
        {
            var lines = snapshot.OutputLines.ToList();
            lines.Add(new AlbJobOutputLine(DateTime.UtcNow, stream, line));
            TrimLines(lines);
            return snapshot with
            {
                UpdatedUtc = DateTime.UtcNow,
                OutputLines = lines
            };
        });
    }

    private AlbDownloadWebProgress BuildProgress(string jobId, AlbDownloadExecutionPlan? plan)
    {
        lock (_gate)
        {
            if (!_runtime.TryGetValue(jobId, out var runtime))
                return AlbDownloadWebProgress.CreateEmpty();

            return runtime.BuildProgress(plan);
        }
    }

    private void UpdateSnapshot(string jobId, Func<AlbDownloadJobSnapshot, AlbDownloadJobSnapshot> update)
    {
        lock (_gate)
        {
            if (!_jobs.TryGetValue(jobId, out var snapshot))
                return;

            _jobs[jobId] = update(snapshot);
        }
    }

    private bool TryResolveSnapshot(string? jobId, out AlbDownloadJobSnapshot snapshot)
    {
        lock (_gate)
        {
            if (!string.IsNullOrWhiteSpace(jobId) && _jobs.TryGetValue(jobId, out snapshot!))
                return true;

            if (!string.IsNullOrWhiteSpace(_currentJobId) && _jobs.TryGetValue(_currentJobId, out snapshot!))
                return true;

            snapshot = AlbDownloadJobSnapshot.CreateIdle();
            return false;
        }
    }

    private static AlbRunFolderObservation ScanRunFolder(string runFolder)
    {
        var gzipFiles = 0;
        var gzipBytes = 0L;
        var logFiles = 0;
        var logBytes = 0L;
        var gzipByDay = new Dictionary<string, AlbObservedDayCounts>(StringComparer.Ordinal);
        var logByDay = new Dictionary<string, AlbObservedDayCounts>(StringComparer.Ordinal);

        if (!Directory.Exists(runFolder))
            return new AlbRunFolderObservation(gzipFiles, gzipBytes, logFiles, logBytes, gzipByDay, logByDay);

        foreach (var path in Directory.EnumerateFiles(runFolder, "*", SearchOption.AllDirectories))
        {
            var extension = Path.GetExtension(path);
            long size;
            try { size = new FileInfo(path).Length; }
            catch { size = 0; }

            var dayKey = TryParseAlbTimestampUtc(Path.GetFileName(path))?.ToString("yyyy-MM-dd");

            if (string.Equals(extension, ".gz", StringComparison.OrdinalIgnoreCase))
            {
                gzipFiles++;
                gzipBytes += size;
                if (!string.IsNullOrWhiteSpace(dayKey))
                    IncrementObserved(gzipByDay, dayKey!, size);
            }
            else if (string.Equals(extension, ".log", StringComparison.OrdinalIgnoreCase))
            {
                logFiles++;
                logBytes += size;
                if (!string.IsNullOrWhiteSpace(dayKey))
                    IncrementObserved(logByDay, dayKey!, size);
            }
        }

        return new AlbRunFolderObservation(gzipFiles, gzipBytes, logFiles, logBytes, gzipByDay, logByDay);
    }

    private static void IncrementObserved(IDictionary<string, AlbObservedDayCounts> map, string dayKey, long bytes)
    {
        if (!map.TryGetValue(dayKey, out var existing))
            existing = new AlbObservedDayCounts(0, 0);

        map[dayKey] = existing with
        {
            Files = existing.Files + 1,
            Bytes = existing.Bytes + bytes
        };
    }

    private static DateTime? TryParseAlbTimestampUtc(string fileName)
    {
        var match = AlbTimestampRegex.Match(fileName);
        if (!match.Success)
            return null;

        var ymd = match.Groups[1].Value;
        var hm = match.Groups[2].Value;

        if (!int.TryParse(ymd[..4], out var year)) return null;
        if (!int.TryParse(ymd[4..6], out var month)) return null;
        if (!int.TryParse(ymd[6..8], out var day)) return null;
        if (!int.TryParse(hm[..2], out var hour)) return null;
        if (!int.TryParse(hm[2..4], out var minute)) return null;

        return new DateTime(year, month, day, hour, minute, 0, DateTimeKind.Utc);
    }

    private static string DeriveStage(string state, string currentStage, AlbDownloadRuntimeState runtime, AlbDownloadExecutionPlan plan)
    {
        if (!string.Equals(state, "running", StringComparison.OrdinalIgnoreCase))
            return currentStage;

        if (!runtime.ChildStarted)
            return "planning";

        if (runtime.ExtractedFiles > 0)
            return "extracting";

        if (plan.TotalFiles > 0 && runtime.MaxDownloadedFiles >= plan.TotalFiles)
            return "pruning";

        return "downloading";
    }

    private static string DeriveMessage(string currentMessage, string stage, AlbDownloadWebProgress progress, AlbDownloadExecutionPlan plan)
    {
        return stage switch
        {
            "planning" => currentMessage,
            "downloading" when plan.TotalFiles > 0 => $"Downloading files: {progress.DownloadedFiles} / {plan.TotalFiles}.",
            "pruning" => "Pruning files outside the selected UTC window.",
            "extracting" when plan.InWindowFiles > 0 => $"Extracting logs: {progress.ExtractedFiles} / {plan.InWindowFiles}.",
            _ => currentMessage
        };
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        var unitIndex = 0;
        while (value >= 1024 && unitIndex < units.Length - 1)
        {
            value /= 1024;
            unitIndex++;
        }

        return $"{value:0.#} {units[unitIndex]}";
    }

    private static void TrimLines(List<AlbJobOutputLine> lines)
    {
        if (lines.Count <= MaxOutputLines)
            return;

        lines.RemoveRange(0, lines.Count - MaxOutputLines);
    }
}

internal sealed record AlbJobOutputLine(
    DateTime TimestampUtc,
    string Stream,
    string Text);

internal sealed record AlbDownloadJobSnapshot(
    string JobId,
    string State,
    string Stage,
    string Message,
    DateTime CreatedUtc,
    DateTime UpdatedUtc,
    int? CurrentStep,
    int? TotalSteps,
    string? Error,
    AlbDownloadWebPlan? Plan,
    AlbDownloadWebProgress Progress,
    AlbDownloadRunResult? Result,
    IReadOnlyList<AlbJobOutputLine> OutputLines)
{
    public static AlbDownloadJobSnapshot CreateIdle()
        => new(
            JobId: string.Empty,
            State: "idle",
            Stage: "idle",
            Message: "No ALB download has been started yet.",
            CreatedUtc: DateTime.UtcNow,
            UpdatedUtc: DateTime.UtcNow,
            CurrentStep: null,
            TotalSteps: null,
            Error: null,
            Plan: null,
            Progress: AlbDownloadWebProgress.CreateEmpty(),
            Result: null,
            OutputLines: Array.Empty<AlbJobOutputLine>());
}

internal sealed record AlbDownloadWebPlan(
    string RunFolder,
    int TotalFiles,
    long TotalBytes,
    int InWindowFiles,
    long InWindowBytes,
    IReadOnlyList<AlbDownloadWebDayPlan> Days);

internal sealed record AlbDownloadWebDayPlan(
    string DayUtc,
    int TotalFiles,
    long TotalBytes,
    int InWindowFiles,
    long InWindowBytes);

internal sealed record AlbDownloadWebProgress(
    int PlanningDaysCompleted,
    int PlanningDaysTotal,
    int DownloadedFiles,
    long DownloadedBytes,
    int ExtractedFiles,
    long ExtractedBytes,
    double? BytesPerSecond,
    int? EtaSeconds,
    IReadOnlyList<AlbDownloadWebDayProgress> Days)
{
    public static AlbDownloadWebProgress CreateEmpty()
        => new(0, 0, 0, 0, 0, 0, null, null, Array.Empty<AlbDownloadWebDayProgress>());
}

internal sealed record AlbDownloadWebDayProgress(
    string DayUtc,
    int TotalFiles,
    long TotalBytes,
    int InWindowFiles,
    long InWindowBytes,
    int DownloadedFiles,
    long DownloadedBytes,
    int ExtractedFiles,
    long ExtractedBytes);

internal sealed record AlbObservedDayCounts(int Files, long Bytes);

internal sealed record AlbRunFolderObservation(
    int GzipFiles,
    long GzipBytes,
    int LogFiles,
    long LogBytes,
    IReadOnlyDictionary<string, AlbObservedDayCounts> GzipByDay,
    IReadOnlyDictionary<string, AlbObservedDayCounts> LogByDay);

internal sealed class AlbDownloadRuntimeState
{
    private readonly Dictionary<string, AlbObservedDayCounts> _maxDownloadedByDay = new(StringComparer.Ordinal);
    private readonly Dictionary<string, AlbObservedDayCounts> _extractedByDay = new(StringComparer.Ordinal);
    private readonly Queue<(DateTime TimestampUtc, long Bytes)> _throughputSamples = new();
    private AlbRunFolderObservation _baseline = new(
        0,
        0,
        0,
        0,
        new Dictionary<string, AlbObservedDayCounts>(StringComparer.Ordinal),
        new Dictionary<string, AlbObservedDayCounts>(StringComparer.Ordinal));

    public int PlanningDaysCompleted { get; set; }
    public int PlanningDaysTotal { get; set; }
    public bool ChildStarted { get; set; }
    public int MaxDownloadedFiles { get; private set; }
    public long MaxDownloadedBytes { get; private set; }
    public int ExtractedFiles { get; private set; }
    public long ExtractedBytes { get; private set; }

    public void SetBaseline(AlbRunFolderObservation observation)
    {
        _baseline = observation;
    }

    public void ApplyObservation(AlbRunFolderObservation observation)
    {
        var currentDownloadedFiles = Math.Max(0, observation.GzipFiles - _baseline.GzipFiles);
        var currentDownloadedBytes = Math.Max(0, observation.GzipBytes - _baseline.GzipBytes);
        var currentExtractedFiles = Math.Max(0, observation.LogFiles - _baseline.LogFiles);
        var currentExtractedBytes = Math.Max(0, observation.LogBytes - _baseline.LogBytes);

        MaxDownloadedFiles = Math.Max(MaxDownloadedFiles, currentDownloadedFiles);
        MaxDownloadedBytes = Math.Max(MaxDownloadedBytes, currentDownloadedBytes);
        ExtractedFiles = currentExtractedFiles;
        ExtractedBytes = currentExtractedBytes;

        foreach (var pair in observation.GzipByDay)
        {
            _baseline.GzipByDay.TryGetValue(pair.Key, out var baseline);
            var delta = new AlbObservedDayCounts(
                Math.Max(0, pair.Value.Files - (baseline?.Files ?? 0)),
                Math.Max(0, pair.Value.Bytes - (baseline?.Bytes ?? 0)));

            _maxDownloadedByDay[pair.Key] = _maxDownloadedByDay.TryGetValue(pair.Key, out var existing)
                ? new AlbObservedDayCounts(Math.Max(existing.Files, delta.Files), Math.Max(existing.Bytes, delta.Bytes))
                : delta;
        }

        foreach (var pair in observation.LogByDay)
        {
            _baseline.LogByDay.TryGetValue(pair.Key, out var baseline);
            _extractedByDay[pair.Key] = new AlbObservedDayCounts(
                Math.Max(0, pair.Value.Files - (baseline?.Files ?? 0)),
                Math.Max(0, pair.Value.Bytes - (baseline?.Bytes ?? 0)));
        }

        var now = DateTime.UtcNow;
        _throughputSamples.Enqueue((now, MaxDownloadedBytes));
        while (_throughputSamples.Count > 0 && (now - _throughputSamples.Peek().TimestampUtc).TotalSeconds > 12)
            _throughputSamples.Dequeue();
    }

    public AlbDownloadWebProgress BuildProgress(AlbDownloadExecutionPlan? plan)
    {
        double? bytesPerSecond = null;
        int? etaSeconds = null;

        if (_throughputSamples.Count >= 2)
        {
            var first = _throughputSamples.Peek();
            var last = _throughputSamples.Last();
            var seconds = (last.TimestampUtc - first.TimestampUtc).TotalSeconds;
            var bytesDelta = last.Bytes - first.Bytes;

            if (seconds > 0.5 && bytesDelta > 0)
            {
                bytesPerSecond = bytesDelta / seconds;
                if (plan is not null && plan.TotalBytes > 0 && MaxDownloadedBytes < plan.TotalBytes)
                {
                    var remaining = plan.TotalBytes - MaxDownloadedBytes;
                    etaSeconds = (int)Math.Max(0, Math.Round(remaining / bytesPerSecond.Value));
                }
            }
        }

        var dayProgress = plan?.Days.Select(day =>
        {
            _maxDownloadedByDay.TryGetValue(day.DayUtc, out var downloaded);
            _extractedByDay.TryGetValue(day.DayUtc, out var extracted);

            return new AlbDownloadWebDayProgress(
                day.DayUtc,
                day.TotalFiles,
                day.TotalBytes,
                day.InWindowFiles,
                day.InWindowBytes,
                downloaded?.Files ?? 0,
                downloaded?.Bytes ?? 0,
                extracted?.Files ?? 0,
                extracted?.Bytes ?? 0);
        }).ToArray() ?? Array.Empty<AlbDownloadWebDayProgress>();

        return new AlbDownloadWebProgress(
            PlanningDaysCompleted,
            PlanningDaysTotal,
            MaxDownloadedFiles,
            MaxDownloadedBytes,
            ExtractedFiles,
            ExtractedBytes,
            bytesPerSecond,
            etaSeconds,
            dayProgress);
    }
}
