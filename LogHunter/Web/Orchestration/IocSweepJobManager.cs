using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Services;
using LogHunter.Utils;

namespace LogHunter.Web.Orchestration;

internal sealed record IocSweepSourceRequest(string Label, string Path);

internal sealed record IocSweepTargetRow(
    string Target, string Kind, long Hits, string FirstSeenUtc, string LastSeenUtc,
    int DistinctIps, IReadOnlyList<string> TopIps, string TopPaths, string Statuses, string Sources);

internal sealed record IocSweepScopeRow(
    string Label, int AlbFiles, int IisFiles, long LinesRead, long RecordsParsed, long ParseFailures,
    string MinUtc, string MaxUtc, int UnreadableFiles, string Path = "", long Bytes = 0);

internal sealed record IocSweepJobSnapshot(
    string JobId,
    string State,
    string Message,
    int TargetCount,
    IReadOnlyList<string> InvalidTokens,
    IReadOnlyList<string> SourceLabels,
    int FilesProcessed,
    int FilesTotal,
    long LinesRead,
    DateTime CreatedUtc,
    DateTime UpdatedUtc,
    string? HtmlReportPath,
    string? ExcelPath,
    IReadOnlyList<IocSweepTargetRow>? Targets,
    IReadOnlyList<IocSweepScopeRow>? Scopes,
    string? Error)
{
    public static IocSweepJobSnapshot CreateIdle() => new(
        "", "idle", "Idle.", 0, Array.Empty<string>(), Array.Empty<string>(), 0, 0, 0,
        DateTime.UtcNow, DateTime.UtcNow, null, null, null, null, null);
}

/// <summary>One IP sweep at a time; results stay available until the next run.</summary>
internal sealed class IocSweepJobManager
{
    public const int MaxSources = 12;
    public const int MaxTargets = 100_000;

    private readonly object _gate = new();
    private IocSweepJobSnapshot _snapshot = IocSweepJobSnapshot.CreateIdle();

    public IocSweepJobSnapshot GetSnapshot()
    {
        lock (_gate)
            return _snapshot;
    }

    public bool TryStart(string? targetsText, IReadOnlyList<IocSweepSourceRequest> requests,
        out IocSweepJobSnapshot snapshot, out string? error)
    {
        var (targets, invalid) = IpTargetParser.ParseList(targetsText);
        var sources = ResolveSources(requests, out error);

        lock (_gate)
        {
            snapshot = _snapshot;
            if (string.Equals(_snapshot.State, "running", StringComparison.OrdinalIgnoreCase))
            {
                error = "An IP sweep is already running.";
                return false;
            }

            if (error is not null)
                return false;

            if (targets.Count == 0)
            {
                error = invalid.Count > 0 ? $"No valid IPs or ranges. Ignored: {string.Join(", ", invalid.Take(10))}" : "Paste at least one IP, CIDR or range.";
                return false;
            }

            if (targets.Count > MaxTargets)
            {
                error = $"Too many targets ({targets.Count:N0}). The limit is {MaxTargets:N0}.";
                return false;
            }

            var filesTotal = sources.Sum(s => s.Files.Count);
            _snapshot = new IocSweepJobSnapshot(
                Guid.NewGuid().ToString("N"), "running", "Sweeping logs.", targets.Count, invalid,
                sources.Select(s => s.Label).ToList(), 0, filesTotal, 0, DateTime.UtcNow, DateTime.UtcNow,
                null, null, null, null, null);
            snapshot = _snapshot;
            _ = RunAsync(_snapshot.JobId, sources, targets, invalid);
            return true;
        }
    }

    internal static List<IocSweepSource> ResolveSources(IReadOnlyList<IocSweepSourceRequest> requests, out string? error)
    {
        error = null;
        var sources = new List<IocSweepSource>();
        if (requests.Count == 0)
        {
            error = "Add at least one log folder.";
            return sources;
        }

        if (requests.Count > MaxSources)
        {
            error = $"At most {MaxSources} folders per sweep.";
            return sources;
        }

        foreach (var req in requests)
        {
            if (string.IsNullOrWhiteSpace(req.Path) || !Directory.Exists(req.Path))
            {
                error = $"Folder not found: {req.Path}";
                return sources;
            }

            var files = IisW3cReader.EnumerateLogFiles(req.Path);
            if (files.Count == 0)
            {
                error = $"No .log or .log.gz files in: {req.Path}";
                return sources;
            }

            var label = string.IsNullOrWhiteSpace(req.Label) ? Path.GetFileName(req.Path.TrimEnd('\\', '/')) : req.Label.Trim();
            sources.Add(new IocSweepSource(UniqueLabel(label, sources), files, req.Path));
        }

        return sources;
    }

    private static string UniqueLabel(string label, List<IocSweepSource> existing)
    {
        var candidate = label;
        for (var n = 2; existing.Any(s => string.Equals(s.Label, candidate, StringComparison.OrdinalIgnoreCase)); n++)
            candidate = $"{label} ({n})";
        return candidate;
    }

    private async Task RunAsync(string jobId, List<IocSweepSource> sources, List<IpTarget> targets, List<string> invalid)
    {
        try
        {
            // Progress callbacks run on the thread pool and can land after completion: only apply while running.
            var progress = new Progress<IocSweepProgress>(p => Update(jobId, s => s.State != "running" ? s : s with
            {
                FilesProcessed = p.FilesDone,
                LinesRead = p.LinesRead,
                Message = $"Sweeping logs: {p.FilesDone:N0} / {p.FilesTotal:N0} files.",
                UpdatedUtc = DateTime.UtcNow
            }));

            var result = await Task.Run(() => IocSweepScanner.RunAsync(sources, targets, invalid, progress, CancellationToken.None)).ConfigureAwait(false);

            Directory.CreateDirectory(AppFolders.Output);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
            var htmlPath = Path.Combine(AppFolders.Output, $"ip_sweep_{stamp}.html");
            var excelPath = Path.Combine(AppFolders.Output, $"ip_sweep_{stamp}.xlsx");
            IocSweepReport.WriteHtml(result, htmlPath);
            IocSweepReport.WriteExcel(result, excelPath);

            var hitCount = result.Targets.Count(t => t.Hits > 0);
            Update(jobId, s => s with
            {
                State = "completed",
                Message = $"{hitCount:N0} of {result.Targets.Count:N0} targets found in the logs.",
                FilesProcessed = s.FilesTotal,
                LinesRead = result.Scopes.Sum(x => x.LinesRead),
                HtmlReportPath = htmlPath,
                ExcelPath = excelPath,
                Targets = BuildTargetRows(result),
                Scopes = BuildScopeRows(result, sources),
                UpdatedUtc = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            Update(jobId, s => s with { State = "failed", Message = "IP sweep failed.", Error = ex.Message, UpdatedUtc = DateTime.UtcNow });
        }
    }

    internal static List<IocSweepTargetRow> BuildTargetRows(IocSweepResult result) =>
        result.Targets
            .OrderByDescending(t => t.Hits)
            .ThenBy(t => t.Target.Text, StringComparer.Ordinal)
            .Select(t => new IocSweepTargetRow(
                t.Target.Text,
                IocSweepReport.TargetKind(t.Target),
                t.Hits,
                IocSweepReport.FormatUtc(t.FirstSeenUtc),
                IocSweepReport.FormatUtc(t.LastSeenUtc),
                t.MatchedIps.Count,
                IocSweepReport.Top(t.MatchedIps, 50).Select(kv => kv.Key).ToList(),
                IocSweepReport.FormatTop(t.Uris, 3),
                IocSweepReport.FormatTop(t.Statuses, 4),
                IocSweepReport.FormatTop(t.HitsBySource, 6)))
            .ToList();

    // Scopes come back in source order; path and size let the page hand a folder to IP summary.
    private static List<IocSweepScopeRow> BuildScopeRows(IocSweepResult result, IReadOnlyList<IocSweepSource> sources) =>
        result.Scopes.Select((s, i) => new IocSweepScopeRow(
            s.Label, s.AlbFiles, s.IisFiles, s.LinesRead, s.RecordsParsed, s.ParseFailures,
            IocSweepReport.FormatUtc(s.MinUtc), IocSweepReport.FormatUtc(s.MaxUtc), s.UnreadableFiles.Count,
            i < sources.Count ? sources[i].Path : "",
            i < sources.Count ? TotalBytes(sources[i].Files) : 0)).ToList();

    private static long TotalBytes(IEnumerable<string> files)
    {
        long total = 0;
        foreach (var f in files)
        {
            try { total += new FileInfo(f).Length; }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        return total;
    }

    public bool TryOpenReport(out string message) => TryOpen(GetSnapshot().HtmlReportPath, "report", out message);

    public bool TryOpenExport(out string message) => TryOpen(GetSnapshot().ExcelPath, "Excel file", out message);

    private static bool TryOpen(string? path, string label, out string message)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            message = $"The {label} is not available.";
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

    private void Update(string jobId, Func<IocSweepJobSnapshot, IocSweepJobSnapshot> change)
    {
        lock (_gate)
        {
            if (string.Equals(_snapshot.JobId, jobId, StringComparison.Ordinal))
                _snapshot = change(_snapshot);
        }
    }
}
