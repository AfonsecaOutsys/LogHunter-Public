using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ClosedXML.Excel;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static class IisOption_IpSummary
{
    private const string AggregateThresholdPrompt =
        "1M rows have been processed across the selected IPs. Continue with one aggregated SQLite database for deep analysis instead of Excel?";
    private const string IpSummaryThresholdPrompt =
        "1M rows have been processed so far for this IP, continuing means there will be no Excel export for that IP, only the Charts View and summary. Proceed with SQLite for deep analysis?";

    private const string SelectAllSentinel = "__ALL__";
    private const int MaxRequestedIps = 10;
    private const int TopListPickerCap = 20;
    private const int MaxChartPointsPerIp = 2400;
    private const int ShortRangeBucketSeconds = 15;
    private const int MediumRangeBucketSeconds = 30;
    private const int LongRangeBucketSeconds = 60;
    private static readonly TimeSpan ShortRangeMax = TimeSpan.FromHours(2);
    private static readonly TimeSpan MediumRangeMax = TimeSpan.FromHours(8);

    public static async Task RunAsync(SessionState session, CancellationToken ct = default)
    {
        var iisFolder = AppFolders.IIS;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("IIS: IP Summary", $"Reading logs from: {iisFolder}");

        if (!Directory.Exists(iisFolder))
        {
            ConsoleEx.Error($"IIS folder not found: {iisFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var requestedSet = PromptForIpSet(session);
        if (requestedSet is null || requestedSet.Ips.Count == 0)
            return;

        var requestedIps = requestedSet.Ips;

        var files = IisW3cReader.EnumerateLogFiles(iisFolder);
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No IIS logs found in: {iisFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        Directory.CreateDirectory(outputFolder);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var htmlPath = Path.Combine(outputFolder, $"iis_ip_summary_multi_{stamp}.html");
        var excelPath = Path.Combine(outputFolder, $"iis_ip_summary_multi_{stamp}.xlsx");
        var sqlitePath = Path.Combine(outputFolder, $"iis_ip_summary_multi_{stamp}.db");

        var resultsByIp = requestedIps.ToDictionary(
            ip => ip,
            ip => new IisIpSummaryScanner.ScanResult(ip, Path.Combine(outputFolder, $"iis_ip_summary_{SanitizeFileComponent(ip)}_{stamp}.db")),
            StringComparer.OrdinalIgnoreCase);

        IisIpSummaryExportSqlite.Writer? sharedSqliteWriter = null;
        try
        {
            InfoPanel("Scan plan",
                ("Mode", "Multi-IP summary with one HTML page and a shared Excel workbook"),
                ("Requested IPs", string.Join(", ", requestedIps)),
                ("IP source", requestedSet.SourceLabel),
                ("Files", files.Count.ToString("N0", CultureInfo.InvariantCulture)),
                ("Input", iisFolder),
                ("IP cap", MaxRequestedIps.ToString(CultureInfo.InvariantCulture)),
                ("Excel threshold", "Rows < 1,000,000 across the combined retained result set"),
                ("1M-row behavior", "Prompt once, then use one aggregated SQLite database for all selected IPs if approved"),
                ("HTML", "Single report with IP selector"),
                ("Output", outputFolder));

            sharedSqliteWriter = await ScanWithPhasedProgressAsync(files, resultsByIp, sqlitePath, ct).ConfigureAwait(false);

            foreach (var result in resultsByIp.Values)
                result.CompleteStreamingExports();
            sharedSqliteWriter?.Complete();
            sharedSqliteWriter?.Dispose();
            sharedSqliteWriter = null;

            var artifactsByIp = new Dictionary<string, DetailArtifact>(StringComparer.OrdinalIgnoreCase);
            var anySqlite = resultsByIp.Values.Any(r => r.DetailMode == IisIpSummaryScanner.DetailRetentionMode.SqliteApproved);

            var excelEligible = resultsByIp.Values
                .Where(r => !anySqlite && r.TotalRows > 0 && r.HasRetainedRows)
                .OrderBy(r => r.RequestedIp, StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var result in excelEligible)
                result.Rows.Sort((a, b) => a.TimestampUtc.CompareTo(b.TimestampUtc));

            if (excelEligible.Count > 0)
                IisIpSummaryExportExcel.Export(excelPath, excelEligible);

            foreach (var result in resultsByIp.Values)
            {
                if (result.TotalRows == 0)
                    artifactsByIp[result.RequestedIp] = new DetailArtifact(null, null);
                else if (result.DetailMode == IisIpSummaryScanner.DetailRetentionMode.SqliteApproved)
                    artifactsByIp[result.RequestedIp] = new DetailArtifact("SQLite", sqlitePath);
                else if (!anySqlite && result.HasRetainedRows)
                    artifactsByIp[result.RequestedIp] = new DetailArtifact("Excel", excelPath);
                else
                    artifactsByIp[result.RequestedIp] = new DetailArtifact(null, null);
            }

            BuildMultiReport(htmlPath, resultsByIp.Values.OrderBy(r => r.RequestedIp, StringComparer.OrdinalIgnoreCase).ToList(), artifactsByIp);

            if (TryOpenFile(htmlPath))
                ConsoleEx.Success($"HTML report opened: {htmlPath}");
            else
                ConsoleEx.Success($"HTML report generated: {htmlPath}");

            if (excelEligible.Count > 0)
                ConsoleEx.Success($"Detailed Excel workbook generated: {excelPath}");

            var sqliteApproved = resultsByIp.Values
                .Where(r => artifactsByIp[r.RequestedIp].Kind == "SQLite")
                .OrderBy(r => r.RequestedIp, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (sqliteApproved.Count > 0)
            {
                ConsoleEx.Success($"SQLite deep analysis database created for {sqliteApproved.Count} IPs: {sqlitePath}");
                if (IisIpSummarySqliteViewerLauncher.Launch(sqlitePath, null))
                    ConsoleEx.Success("Local SQLite viewer launched for the aggregated IIS IP summary database.");
                else
                    ConsoleEx.Warn("SQLite viewer could not be launched automatically for the aggregated IIS IP summary database.");
            }

            foreach (var result in resultsByIp.Values.OrderBy(r => r.RequestedIp, StringComparer.OrdinalIgnoreCase))
            {
                if (result.TotalRows == 0)
                    ConsoleEx.Warn($"No IIS hits found for IP: {result.RequestedIp}");
            }

            ConsoleEx.Pause("Press Enter to return...");
        }
        finally
        {
            sharedSqliteWriter?.Dispose();
            foreach (var result in resultsByIp.Values)
                result.Dispose();
        }
    }

    private static RequestedIpSet? PromptForIpSet(SessionState session)
    {
        var choice = ConsoleEx.Menu("IIS IP Summary: choose input mode", new[]
        {
            new ConsoleEx.MenuItem(
                "Manually enter IPs",
                "Type one IP per prompt. Enter a blank line when the set is complete and the IIS scan should begin."),
            new ConsoleEx.MenuItem(
                "Use IP list",
                "Pick a list source such as an output CSV/XLSX file, the IIS burst session cache, or the Platform suspicious cache. IIS IP Summary will analyze the full gathered set."),
            new ConsoleEx.MenuItem(
                "Back",
                "Return to the IIS menu.")
        }, pageSize: 10);

        return choice switch
        {
            null => null,
            0 => PromptForManualIps(),
            1 => PromptForSourceIps(session),
            _ => null
        };
    }

    private static RequestedIpSet? PromptForManualIps()
    {
        var ips = new List<string>();

        while (ips.Count < MaxRequestedIps)
        {
            var input = ConsoleEx.ReadLineWithEsc($"Client IP #{ips.Count + 1} (blank to start):");
            if (input is null)
                return null;

            if (string.IsNullOrWhiteSpace(input))
            {
                if (ips.Count == 0)
                {
                    ConsoleEx.Warn("Enter at least one IP before starting the scan.");
                    continue;
                }

                break;
            }

            input = input.Trim();
            if (!System.Net.IPAddress.TryParse(input, out var parsedIp))
            {
                ConsoleEx.Warn($"Invalid IP address: {input}");
                continue;
            }

            var normalized = parsedIp.ToString();
            if (ips.Contains(normalized, StringComparer.OrdinalIgnoreCase))
            {
                ConsoleEx.Warn("That IP is already in the set.");
                continue;
            }

            ips.Add(normalized);
        }

        if (ips.Count == MaxRequestedIps)
            ConsoleEx.Warn($"Reached the current cap of {MaxRequestedIps} IPs for one IIS IP Summary run.");

        return new RequestedIpSet("Manual entry", ips);
    }

    private static RequestedIpSet? PromptForSourceIps(SessionState session)
    {
        while (true)
        {
            ConsoleEx.Header("IIS: IP Summary - IP list source", $"Workspace: {session.Root}");

            var burstCount = session.IisBurstIps.Count;
            var burstUpdated = session.IisBurstIpsUpdatedUtc is null
                ? "never"
                : session.IisBurstIpsUpdatedUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") + "Z";
            var platformCount = session.PlatformSuspiciousIpHits?.Count ?? 0;
            var platformUpdated = session.PlatformSuspiciousIpHitsUpdatedUtc is null
                ? "never"
                : session.PlatformSuspiciousIpHitsUpdatedUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") + "Z";

            var picked = ConsoleEx.Menu("Use IP list", new[]
            {
                new ConsoleEx.MenuItem(
                    "Output file (CSV/XLSX)",
                    "Pick a file from /output, detect an IP column, and gather the full IP list from that file."),
                new ConsoleEx.MenuItem(
                    $"IIS burst session ({burstCount})",
                    $"Use the current IIS burst cache saved in this run.\nLast updated: {burstUpdated}"),
                new ConsoleEx.MenuItem(
                    $"Platform suspicious cache ({platformCount})",
                    $"Use the current Platform suspicious IP cache saved in this run.\nLast updated: {platformUpdated}"),
                new ConsoleEx.MenuItem(
                    "Back",
                    "Return to the previous prompt.")
            }, pageSize: 10);

            RequestedIpSet? result = picked switch
            {
                null => null,
                0 => PromptForOutputFileIps(),
                1 => PromptForIisBurstSessionIps(session),
                2 => PromptForPlatformSuspiciousIps(session),
                _ => null
            };

            if (picked is null || picked == 3)
                return null;

            if (result is not null)
                return result;
        }
    }

    private static RequestedIpSet? PromptForIisBurstSessionIps(SessionState session)
    {
        ConsoleEx.Header("IIS: IP Summary - IIS burst session", $"Workspace: {session.Root}");

        var set = session.IisBurstIps;
        var ipHits = session.IisBurstIpHits;
        var updated = session.IisBurstIpsUpdatedUtc;

        if (set.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey](no burst IPs saved in session)[/]");
            AnsiConsole.MarkupLine("[dim]Run IIS -> Burst patterns and choose to save burst IPs to session.[/]");
            ConsoleEx.Pause("Press Enter to return...");
            return null;
        }

        var ordered = (ipHits is { Count: > 0 }
                ? ipHits.OrderByDescending(kvp => kvp.Value).ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase).Select(kvp => new IpChoice(kvp.Key, kvp.Value))
                : set.OrderBy(ip => ip, StringComparer.OrdinalIgnoreCase).Select(ip => new IpChoice(ip, 0)))
            .ToList();

        AnsiConsole.MarkupLine($"[dim]Burst IPs in session:[/] {set.Count}");
        AnsiConsole.MarkupLine($"[dim]Last updated:[/] {(updated is null ? "unknown" : updated.Value.ToString("yyyy-MM-dd HH:mm:ss") + "Z")}");
        AnsiConsole.WriteLine();

        RenderTopIpTable(ordered, 30, includeHits: ordered.Any(x => x.Hits > 0));
        return ConfirmAnalyzeAll(
            sourceLabel: "IIS burst session",
            ips: ordered.Select(x => x.Ip).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            previewChoices: ordered,
            includeHits: ordered.Any(x => x.Hits > 0));
    }

    private static RequestedIpSet? PromptForPlatformSuspiciousIps(SessionState session)
    {
        ConsoleEx.Header("IIS: IP Summary - Platform suspicious cache", $"Workspace: {session.Root}");

        var dict = session.PlatformSuspiciousIpHits;
        var updated = session.PlatformSuspiciousIpHitsUpdatedUtc;
        if (dict is null || dict.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey](no Platform suspicious IPs saved in session)[/]");
            AnsiConsole.MarkupLine("[dim]Run Platform -> Suspicious requests: extract IPs to populate this cache.[/]");
            ConsoleEx.Pause("Press Enter to return...");
            return null;
        }

        var ordered = dict
            .OrderByDescending(kvp => kvp.Value)
            .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
            .Select(kvp => new IpChoice(kvp.Key, kvp.Value))
            .ToList();

        AnsiConsole.MarkupLine($"[dim]Platform suspicious IPs in session:[/] {dict.Count}");
        AnsiConsole.MarkupLine($"[dim]Last updated:[/] {(updated is null ? "unknown" : updated.Value.ToString("yyyy-MM-dd HH:mm:ss") + "Z")}");
        AnsiConsole.WriteLine();

        RenderTopIpTable(ordered, 30, includeHits: true);
        return ConfirmAnalyzeAll(
            sourceLabel: "Platform suspicious cache",
            ips: ordered.Select(x => x.Ip).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            previewChoices: ordered,
            includeHits: true);
    }

    private static RequestedIpSet? PromptForOutputFileIps()
    {
        ConsoleEx.Header("IIS: IP Summary - select file", $"Output folder: {AppFolders.Output}");

        var outDir = AppFolders.Output;
        if (!Directory.Exists(outDir))
        {
            AnsiConsole.MarkupLine($"[yellow]/output folder not found[/] at: {Markup.Escape(outDir)}");
            ConsoleEx.Pause("Press Enter to return...");
            return null;
        }

        var files = Directory.EnumerateFiles(outDir, "*", SearchOption.TopDirectoryOnly)
            .Where(p => p.EndsWith(".csv", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".xlsx", StringComparison.OrdinalIgnoreCase))
            .Select(p => new FileInfo(p))
            .OrderByDescending(f => SafeCreationUtc(f))
            .ThenByDescending(f => f.LastWriteTimeUtc)
            .ToList();

        if (files.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey](no .csv/.xlsx files found in /output)[/]");
            ConsoleEx.Pause("Press Enter to return...");
            return null;
        }

        var choices = files.Select(f => new FileChoice(f.FullName, BuildFileDisplay(f))).ToList();
        var picked = AnsiConsole.Prompt(
            new SelectionPrompt<FileChoice>()
                .Title("Pick a file from /output (CSV/XLSX, newest first):")
                .PageSize(15)
                .WrapAround()
                .AddChoices(choices)
                .UseConverter(x => x.Display));

        ConsoleEx.Header("IIS: IP Summary - gather IPs", Path.GetFileName(picked.FullPath));

        if (!TryExtractIpCountsFromFile(
                filePath: picked.FullPath,
                out var ipColumnName,
                out var counts,
                out var orderedChoices,
                out var error))
        {
            AnsiConsole.MarkupLine($"[red]Failed[/]: {Markup.Escape(error)}");
            ConsoleEx.Pause("Press Enter to return...");
            return null;
        }

        AnsiConsole.MarkupLine($"[dim]Detected IP column:[/] [bold]{Markup.Escape(ipColumnName)}[/]");
        AnsiConsole.MarkupLine($"[dim]Unique IPs found:[/] {counts.Count}");
        AnsiConsole.WriteLine();

        RenderTopIpTable(orderedChoices, 50, includeHits: true);
        return ConfirmAnalyzeAll(
            sourceLabel: $"File: {Path.GetFileName(picked.FullPath)}",
            ips: orderedChoices.Select(x => x.Ip).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            previewChoices: orderedChoices,
            includeHits: true);
    }

    private static RequestedIpSet? ConfirmAnalyzeAll(string sourceLabel, List<string> ips, IReadOnlyList<IpChoice> previewChoices, bool includeHits)
    {
        if (ips.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey](no IPs available from this source)[/]");
            ConsoleEx.Pause("Press Enter to return...");
            return null;
        }

        AnsiConsole.MarkupLine($"[dim]Source:[/] {Markup.Escape(sourceLabel)}");
        AnsiConsole.MarkupLine($"[dim]IPs to analyze:[/] {ips.Count}");
        if (previewChoices.Count > 0)
        {
            var preview = string.Join(", ", previewChoices.Take(8).Select(x => includeHits && x.Hits > 0 ? $"{x.Ip} ({x.Hits})" : x.Ip));
            AnsiConsole.MarkupLine($"[dim]Preview:[/] {Markup.Escape(preview)}{(previewChoices.Count > 8 ? " ..." : "")}");
        }
        AnsiConsole.WriteLine();

        if (ips.Count > MaxRequestedIps)
        {
            AnsiConsole.MarkupLine($"[yellow]This source has more than {MaxRequestedIps} IPs.[/]");
            AnsiConsole.MarkupLine($"[dim]Pick up to {MaxRequestedIps} IPs from the top {Math.Min(TopListPickerCap, previewChoices.Count)} by hits.[/]");
            AnsiConsole.WriteLine();

            var limited = PromptForTopIps(previewChoices, includeHits);
            if (limited is null || limited.Count == 0)
                return null;

            ips = limited;
            sourceLabel += $" (top selection)";
        }

        if (!ConsoleEx.ReadYesNo($"Analyze {ips.Count} IPs from {sourceLabel}?", defaultYes: true))
            return null;

        return new RequestedIpSet(sourceLabel, ips);
    }

    private static List<string>? PromptForTopIps(IReadOnlyList<IpChoice> previewChoices, bool includeHits)
    {
        while (true)
        {
            var topChoices = previewChoices
                .Take(TopListPickerCap)
                .ToList();

            var selected = AnsiConsole.Prompt(
                new MultiSelectionPrompt<IpChoice>()
                    .Title($"Select up to {MaxRequestedIps} IPs to analyze:")
                    .PageSize(TopListPickerCap)
                    .WrapAround()
                    .NotRequired()
                    .InstructionsText($"[grey](Space: toggle, Enter: confirm. Showing top {topChoices.Count} IPs.)[/]")
                    .AddChoices(topChoices)
                    .UseConverter(x => includeHits ? $"{x.Ip} [grey]({x.Hits})[/]" : x.Ip));

            if (selected.Count == 0)
            {
                AnsiConsole.MarkupLine("[grey](no IPs selected)[/]");
                ConsoleEx.Pause("Press Enter to return...");
                return null;
            }

            if (selected.Count > MaxRequestedIps)
            {
                ConsoleEx.Warn($"Select at most {MaxRequestedIps} IPs.");
                continue;
            }

            return selected
                .Select(x => x.Ip)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }

    private static IisIpSummaryScanner.DetailRetentionMode PromptForDetailMode(string ip)
        => ConsoleEx.ReadYesNo($"{ip}: {IpSummaryThresholdPrompt}", defaultYes: true)
            ? IisIpSummaryScanner.DetailRetentionMode.SqliteApproved
            : IisIpSummaryScanner.DetailRetentionMode.SummaryOnly;

    private static IisIpSummaryScanner.DetailRetentionMode PromptForAggregateDetailMode()
        => ConsoleEx.ReadYesNo(AggregateThresholdPrompt, defaultYes: true)
            ? IisIpSummaryScanner.DetailRetentionMode.SqliteApproved
            : IisIpSummaryScanner.DetailRetentionMode.SummaryOnly;

    private static async Task<IisIpSummaryExportSqlite.Writer?> ScanWithPhasedProgressAsync(List<string> files, IReadOnlyDictionary<string, IisIpSummaryScanner.ScanResult> resultsByIp, string sharedSqlitePath, CancellationToken ct)
    {
        int nextFileIndex = 0;
        IisIpSummaryScanner.DetailRetentionMode? rememberedMode = null;
        IisIpSummaryExportSqlite.Writer? sharedSqliteWriter = null;
        while (nextFileIndex < files.Count)
        {
            nextFileIndex = await RunScanPhaseAsync(files, nextFileIndex, resultsByIp, ct).ConfigureAwait(false);

            var pending = resultsByIp.Values
                .Where(r => r.ThresholdPromptPending)
                .OrderBy(r => r.RequestedIp, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var aggregateRows = resultsByIp.Values
                .Where(r => r.DetailMode == IisIpSummaryScanner.DetailRetentionMode.BelowThreshold)
                .Sum(r => r.TotalRows);
            var aggregateThresholdReached = aggregateRows >= IisIpSummaryScanner.ExcelRowThreshold;

            if (pending.Count == 0 && !aggregateThresholdReached)
                continue;

            if (!rememberedMode.HasValue)
            {
                rememberedMode = aggregateThresholdReached
                    ? PromptForAggregateDetailMode()
                    : PromptForDetailMode(pending[0].RequestedIp);
            }

            if (rememberedMode == IisIpSummaryScanner.DetailRetentionMode.SqliteApproved && sharedSqliteWriter is null)
                sharedSqliteWriter = IisIpSummaryExportSqlite.Open(sharedSqlitePath);

            if (aggregateThresholdReached)
            {
                foreach (var result in resultsByIp.Values)
                    result.ApplyGlobalDetailMode(rememberedMode.Value, sharedSqliteWriter, sharedSqlitePath);
            }
            else
            {
                foreach (var result in pending)
                    result.ApplyThresholdDecision(rememberedMode.Value, sharedSqliteWriter, sharedSqlitePath);
            }
        }

        return sharedSqliteWriter;
    }

    private static async Task<int> RunScanPhaseAsync(List<string> files, int startIndex, IReadOnlyDictionary<string, IisIpSummaryScanner.ScanResult> resultsByIp, CancellationToken ct)
    {
        int nextFileIndex = startIndex;

        await AnsiConsole.Status().AutoRefresh(true).Spinner(Spinner.Known.Dots).StartAsync(
            BuildStatusText(startIndex + 1, files.Count, files[startIndex], resultsByIp.Values),
            async ctx =>
            {
                for (int i = startIndex; i < files.Count; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.Status(BuildStatusText(i + 1, files.Count, files[i], resultsByIp.Values));
                    await IisIpSummaryScanner.ScanFileAsync(files[i], resultsByIp, ct).ConfigureAwait(false);
                    nextFileIndex = i + 1;
                    if (resultsByIp.Values.Any(r => r.ThresholdPromptPending))
                        break;
                }
            }).ConfigureAwait(false);

        AnsiConsole.WriteLine();
        return nextFileIndex;
    }

    private static string BuildStatusText(int currentFileIndex, int totalFiles, string filePath, IEnumerable<IisIpSummaryScanner.ScanResult> results)
    {
        var sqliteCount = results.Count(r => r.DetailMode == IisIpSummaryScanner.DetailRetentionMode.SqliteApproved);
        var summaryOnlyCount = results.Count(r => r.DetailMode == IisIpSummaryScanner.DetailRetentionMode.SummaryOnly);
        var fileName = TruncateProgressText(Path.GetFileName(filePath), 48);

        return $"Scanning IIS logs (IP summary): file {currentFileIndex.ToString(CultureInfo.InvariantCulture)} of {totalFiles.ToString(CultureInfo.InvariantCulture)} | SQLite:{sqliteCount} Summary-only:{summaryOnlyCount} | {Markup.Escape(fileName)}";
    }

    private static void BuildMultiReport(string htmlPath, IReadOnlyList<IisIpSummaryScanner.ScanResult> results, IReadOnlyDictionary<string, DetailArtifact> artifactsByIp)
    {
        var payload = results.Select(r => new ReportPayload(
            Ip: r.RequestedIp,
            TotalRows: r.TotalRows,
            FilesWithHits: r.SourceFiles.Count,
            FirstHitUtc: r.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC",
            LastHitUtc: r.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC",
            AverageTimeTakenMs: r.AverageTimeTakenMs,
            MaxTimeTakenMs: r.MaxTimeTakenMs,
            TotalCsBytes: r.TotalCsBytes,
            TotalScBytes: r.TotalScBytes,
            Status2xx3xx: r.StatusTotals.S2xx + r.StatusTotals.S3xx,
            Status4xx: r.StatusTotals.S4xx,
            Status5xx: r.StatusTotals.S5xx,
            TopUris: r.TopUris(10).Select(x => new SimpleCount(x.Key, x.Value)).ToList(),
            TopMethods: r.TopMethods(10).Select(x => new SimpleCount(x.Key, x.Value)).ToList(),
            TopStatuses: r.TopExactStatuses(10).Select(x => new SimpleCount(x.Key, x.Value)).ToList(),
            DetailKind: artifactsByIp[r.RequestedIp].Kind,
            DetailPath: artifactsByIp[r.RequestedIp].Path,
            DetailUrl: ToFileUrl(artifactsByIp[r.RequestedIp].Path),
            Chart: BuildChartData(r)))
            .ToList();

        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        var html = $$"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>IIS Multi-IP Summary</title>
<style>
:root { color-scheme: dark; }
body { margin:0; background:#0b0f14; color:#e6edf3; font-family: ui-sans-serif, system-ui, Segoe UI, Roboto, Arial; }
.wrap { padding:16px; max-width: 1600px; margin: 0 auto; }
.card { margin-top:12px; background:#0f1620; border:1px solid rgba(255,255,255,.08); border-radius:14px; padding:12px; box-shadow:0 12px 28px rgba(0,0,0,.35); }
.toolbar { display:grid; grid-template-columns: minmax(260px, 420px) 1fr; gap:12px; align-items:end; }
.field { display:flex; flex-direction:column; gap:6px; }
.field label { font-size:13px; opacity:.8; }
select { background:#0b0f14; color:#e6edf3; border:1px solid rgba(255,255,255,.14); border-radius:8px; padding:10px 12px; }
.row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:8px; }
.pill { display:inline-block; font-size:12px; padding:6px 10px; border:1px solid rgba(255,255,255,.10); border-radius:999px; background:rgba(255,255,255,.03); margin:0 6px 6px 0; }
.btn { border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.03); color:#e6edf3; padding:5px 9px; border-radius:8px; cursor:pointer; font-size:12px; }
.btn:hover { background:rgba(255,255,255,.08); }
.toggleRow { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:8px; }
.seriesToggle { display:inline-flex; align-items:center; gap:8px; padding:5px 9px; border-radius:999px; border:1px solid rgba(255,255,255,.12); background:rgba(255,255,255,.03); cursor:pointer; font-size:12px; user-select:none; }
.seriesToggle.off { opacity:.45; }
.sw { width:10px; height:10px; border-radius:3px; display:inline-block; }
.chart-meta { display:flex; gap:12px; flex-wrap:wrap; align-items:flex-start; justify-content:space-between; margin-bottom:10px; }
.hover-card { min-width:320px; flex:1 1 360px; background:#111827; border:1px solid rgba(255,255,255,.08); border-radius:12px; padding:10px 12px; }
.hover-title { font-size:13px; font-weight:600; margin:0 0 6px 0; }
.hover-subtitle { font-size:12px; opacity:.78; margin-bottom:8px; }
.hover-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:8px; }
.hover-item { border:1px solid rgba(255,255,255,.06); border-radius:10px; padding:8px 10px; background:rgba(255,255,255,.025); }
.hover-item .label { display:flex; align-items:center; gap:8px; font-size:12px; opacity:.86; }
.hover-item .value { margin-top:4px; font-size:16px; font-weight:600; }
.dot { width:10px; height:10px; border-radius:999px; display:inline-block; }
.summary-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:12px; }
.summary-card { background:#111827; border:1px solid rgba(255,255,255,.08); border-radius:12px; padding:12px; }
.summary-title { font-size:14px; font-weight:600; margin:0 0 8px 0; }
.summary-table { width:100%; border-collapse:collapse; font-size:12px; }
.summary-table th,.summary-table td { padding:6px 8px; border-bottom:1px solid rgba(255,255,255,.07); text-align:left; vertical-align:top; }
.summary-table th:last-child,.summary-table td:last-child { text-align:right; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break:break-word; }
.note { font-size:12px; opacity:.8; line-height:1.45; }
.link { color:#7dd3fc; text-decoration:none; }
.link:hover { text-decoration:underline; }
canvas { width:100%; height:520px; display:block; background:#0b0f14; border-radius:12px; }
.empty { opacity:.7; font-size:13px; }
kbd { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:11px; padding:2px 6px; border-radius:6px; border:1px solid rgba(255,255,255,.15); background: rgba(255,255,255,.04); }
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="toolbar">
      <div class="field">
        <label for="ipSelect">Selected IP</label>
        <select id="ipSelect"></select>
      </div>
      <div class="note">One report covers the full requested IP set. The chart and summary switch per IP. Excel remains a shared workbook with one sheet per IP and one combined Hits sheet.</div>
    </div>
  </div>
  <div class="card">
    <div class="row">
      <div class="pill">Pan: <kbd>drag</kbd></div>
      <div class="pill">Zoom X: <kbd>wheel</kbd></div>
      <div class="pill">Reset: <kbd>double click</kbd></div>
      <div class="pill">Hover: <kbd>inspect bucket</kbd></div>
      <button class="btn" id="btnResetZoom" type="button">Reset zoom</button>
      <button class="btn" id="btnShowAllSeries" type="button">Show all series</button>
    </div>
    <div class="toggleRow" id="seriesToggles"></div>
    <div class="chart-meta">
      <div class="note" id="bucketMeta"></div>
      <div class="hover-card" id="hoverInfo"></div>
    </div>
    <canvas id="chart"></canvas>
  </div>
  <div id="summaryHost"></div>
</div>
<script>
const DATA = {{json}};
const select = document.getElementById('ipSelect');
const summaryHost = document.getElementById('summaryHost');
const canvas = document.getElementById('chart');
const toggleHost = document.getElementById('seriesToggles');
const hoverInfo = document.getElementById('hoverInfo');
const bucketMeta = document.getElementById('bucketMeta');
const ctx = canvas.getContext('2d', { alpha: false });
const colors = ['#7dd3fc','#a7f3d0','#fda4af','#fcd34d'];
const chartStateByIp = new Map();
let currentItem = null;
let mouseX = null;
let mouseY = null;
let isDragging = false;
let dragStartX = 0;
let dragStartMin = 0;
let dragStartMax = 0;

function esc(s){
  return String(s ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
}
function fmtNum(v){ return Number(v ?? 0).toLocaleString('en-US'); }
function fmtMs(v){ return Number(v ?? 0).toLocaleString('en-US', { maximumFractionDigits: 1 }); }
function fmtUtc(ms){
  const d = new Date(ms);
  const pad = n => String(n).padStart(2,'0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
}
function fmtBucket(seconds){
  if(seconds % 60 === 0) return `${seconds / 60} minute${seconds === 60 ? '' : 's'}`;
  return `${seconds} seconds`;
}
function buildRows(items, label){
  if(!items || !items.length) return `<tr><td>(none)</td><td>0</td></tr>`;
  return items.map(x => `<tr><td class="mono">${esc(x.label)}</td><td>${fmtNum(x.count)}</td></tr>`).join('');
}
function seriesShortName(name){
  const m = String(name || '').match(/(\dxx)/i);
  return m ? m[1].toUpperCase() : String(name || '');
}
function detailBlock(item){
  if(!item.detailKind || !item.detailPath){
    if(item.totalRows >= 1000000) return '<div class="note">Detailed export was skipped after the threshold prompt for this IP.</div>';
    if(item.totalRows === 0) return '<div class="note">No detailed export exists because there were no hits for this IP.</div>';
    return '<div class="note">No detailed export was generated.</div>';
  }
  const openLink = item.detailUrl
    ? `<div class="note" style="margin-top:8px"><a class="link" href="${esc(item.detailUrl)}">Open ${esc(item.detailKind)}</a></div>`
    : '';
  return `<div class="note">Detailed export: <strong>${esc(item.detailKind)}</strong></div><div class="note mono" style="margin-top:8px">${esc(item.detailPath)}</div>${openLink}`;
}
function renderSummary(item){
  summaryHost.innerHTML = `
  <div class="card">
    <div>
      <span class="pill">Requested IP: ${esc(item.ip)}</span>
      <span class="pill">Total matching requests: ${fmtNum(item.totalRows)}</span>
      <span class="pill">Files with hits: ${fmtNum(item.filesWithHits)}</span>
      <span class="pill">Time range: ${esc(item.firstHitUtc || '-')} -> ${esc(item.lastHitUtc || '-')}</span>
    </div>
    <div class="summary-grid">
      <div class="summary-card">
        <div class="summary-title">HTTP status totals</div>
        <table class="summary-table">
          <tr><th>Class</th><th>Hits</th></tr>
          <tr><td>2xx/3xx</td><td>${fmtNum(item.status2xx3xx)}</td></tr>
          <tr><td>4xx</td><td>${fmtNum(item.status4xx)}</td></tr>
          <tr><td>5xx</td><td>${fmtNum(item.status5xx)}</td></tr>
        </table>
      </div>
      <div class="summary-card">
        <div class="summary-title">Latency and bytes</div>
        <table class="summary-table">
          <tr><td>Average time-taken</td><td>${fmtMs(item.averageTimeTakenMs)} ms</td></tr>
          <tr><td>Max time-taken</td><td>${fmtNum(item.maxTimeTakenMs)} ms</td></tr>
          <tr><td>Total cs-bytes</td><td>${fmtNum(item.totalCsBytes)}</td></tr>
          <tr><td>Total sc-bytes</td><td>${fmtNum(item.totalScBytes)}</td></tr>
        </table>
      </div>
      <div class="summary-card">
        <div class="summary-title">Detailed export</div>
        ${detailBlock(item)}
      </div>
      <div class="summary-card">
        <div class="summary-title">Top 10 URIs</div>
        <table class="summary-table"><tr><th>URI</th><th>Hits</th></tr>${buildRows(item.topUris, 'URI')}</table>
      </div>
      <div class="summary-card">
        <div class="summary-title">Top 10 methods</div>
        <table class="summary-table"><tr><th>Method</th><th>Hits</th></tr>${buildRows(item.topMethods, 'Method')}</table>
      </div>
      <div class="summary-card">
        <div class="summary-title">Top exact status codes</div>
        <table class="summary-table"><tr><th>Status</th><th>Hits</th></tr>${buildRows(item.topStatuses, 'Status')}</table>
      </div>
    </div>
  </div>`;
}

function updateHoverInfo(item, hoveredMs, tooltipSeries){
  if(!item){
    hoverInfo.innerHTML = '<div class="hover-title">Chart inspection</div><div class="hover-subtitle">Hover the chart to inspect the nearest bucket.</div>';
    return;
  }

  if(hoveredMs == null || !tooltipSeries || !tooltipSeries.length){
    hoverInfo.innerHTML = `
      <div class="hover-title">Chart inspection</div>
      <div class="hover-subtitle">Bucket size: ${esc(fmtBucket(item.chart.bucketSeconds || 60))}</div>
      <div class="note">Hover the chart to inspect the nearest bucket, compare visible series, and read exact values.</div>`;
    return;
  }

  hoverInfo.innerHTML = `
    <div class="hover-title">Nearest bucket</div>
    <div class="hover-subtitle">${esc(fmtUtc(hoveredMs))} | ${esc(fmtBucket(item.chart.bucketSeconds || 60))}</div>
    <div class="hover-grid">${tooltipSeries.map(entry => `
      <div class="hover-item">
        <div class="label"><span class="dot" style="background:${entry.s.color}"></span>${esc(entry.s.name)}</div>
        <div class="value">${fmtNum(entry.v)}</div>
      </div>`).join('')}
    </div>`;
}

function getState(item){
  let state = chartStateByIp.get(item.ip);
  if(!state){
    const times = item.chart.timesUtc || [];
    const series = (item.chart.series || []).map((s, index) => ({
      name: s.name,
      shortName: seriesShortName(s.name),
      values: s.values || [],
      color: colors[index % colors.length],
      visible: true
    }));
    state = {
      xMin: times.length ? times[0] : 0,
      xMax: times.length ? times[times.length - 1] : 0,
      times,
      bucketSeconds: item.chart.bucketSeconds || 60,
      series
    };
    chartStateByIp.set(item.ip, state);
  }
  return state;
}

function resizeCanvas() {
  const dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
  const rect = canvas.getBoundingClientRect();
  canvas.width = Math.floor(rect.width * dpr);
  canvas.height = Math.floor(rect.height * dpr);
  ctx.setTransform(dpr,0,0,dpr,0,0);
}

function buildSeriesToggles(item){
  const state = getState(item);
  toggleHost.innerHTML = '';
  state.series.forEach((series) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `seriesToggle${series.visible ? '' : ' off'}`;
    button.title = 'Click to show or hide. Double click to isolate this series.';
    button.innerHTML = `<span class="sw" style="background:${series.color}"></span><span>${esc(series.shortName)}</span>`;
    button.addEventListener('click', () => {
      series.visible = !series.visible;
      buildSeriesToggles(item);
      drawChart(item);
    });
    button.addEventListener('dblclick', (e) => {
      e.preventDefault();
      state.series.forEach(other => { other.visible = other === series; });
      buildSeriesToggles(item);
      drawChart(item);
    });
    toggleHost.appendChild(button);
  });
}

function resetZoom(item){
  const state = getState(item);
  if(!state.times.length) return;
  state.xMin = state.times[0];
  state.xMax = state.times[state.times.length - 1];
}

function clampX(state){
  if(!state.times.length) return;
  const globalMin = state.times[0];
  const globalMax = state.times[state.times.length - 1];
  const minSpan = Math.max(60 * 1000, state.bucketSeconds * 4 * 1000);
  if((state.xMax - state.xMin) < minSpan){
    const mid = (state.xMin + state.xMax) / 2;
    state.xMin = mid - minSpan / 2;
    state.xMax = mid + minSpan / 2;
  }
  if(state.xMin < globalMin){ const d = globalMin - state.xMin; state.xMin += d; state.xMax += d; }
  if(state.xMax > globalMax){ const d = state.xMax - globalMax; state.xMin -= d; state.xMax -= d; }
  if(state.xMin < globalMin) state.xMin = globalMin;
  if(state.xMax > globalMax) state.xMax = globalMax;
}

function timeToX(ms, state, width) { return (ms - state.xMin) / Math.max(1, (state.xMax - state.xMin)) * width; }
function xToTime(x, state, width) { return state.xMin + (x / Math.max(1, width)) * (state.xMax - state.xMin); }
function lowerBound(arr, x) {
  let lo = 0, hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (arr[mid] < x) lo = mid + 1; else hi = mid;
  }
  return lo;
}

function drawChart(item){
  resizeCanvas();
  const rect = canvas.getBoundingClientRect();
  const W = rect.width;
  const H = rect.height;
  const state = getState(item);
  ctx.clearRect(0,0,W,H);
  ctx.fillStyle = '#0b0f14';
  ctx.fillRect(0,0,W,H);

  const times = state.times;
  const series = state.series;
  if(!times.length || !series.length){
    ctx.fillStyle = '#94a3b8';
    ctx.font = '14px ui-sans-serif, system-ui';
    ctx.fillText('No chart data for this IP.', 24, 32);
    updateHoverInfo(item, null, null);
    return;
  }

  const padL = 64, padR = 18, padT = 14, padB = 44;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;
  const i0 = Math.max(0, lowerBound(times, state.xMin) - 1);
  const i1 = Math.min(times.length - 1, lowerBound(times, state.xMax) + 1);
  const visibleSeries = series.filter(s => s.visible);

  let yMin = Infinity, yMax = -Infinity;
  visibleSeries.forEach(s => {
    for(let i = i0; i <= i1; i++){
      const v = s.values[i];
      if(v < yMin) yMin = v;
      if(v > yMax) yMax = v;
    }
  });
  if(!isFinite(yMin) || !isFinite(yMax)){ yMin = 0; yMax = 1; }
  if(yMin === yMax){ yMin -= 1; yMax += 1; }
  const yPad = (yMax - yMin) * 0.08;
  yMin -= yPad;
  yMax += yPad;

  function valToY(v){ return padT + (1 - (v - yMin) / Math.max(1e-9, (yMax - yMin))) * plotH; }

  ctx.strokeStyle = 'rgba(255,255,255,.08)';
  ctx.lineWidth = 1;
  ctx.font = '12px ui-sans-serif, system-ui';
  ctx.fillStyle = 'rgba(230,237,243,.75)';
  for(let i = 0; i <= 5; i++){
    const yVal = yMin + (i / 5) * (yMax - yMin);
    const y = valToY(yVal);
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(padL + plotW, y); ctx.stroke();
    ctx.fillText(String(Math.round(yVal)), 8, y + 4);
  }

  const tickCount = 5;
  for(let i = 0; i <= tickCount; i++){
    const ms = state.xMin + (i / tickCount) * (state.xMax - state.xMin);
    const x = padL + timeToX(ms, state, plotW);
    ctx.beginPath(); ctx.moveTo(x, padT); ctx.lineTo(x, padT + plotH); ctx.stroke();
    const label = fmtUtc(ms);
    const tw = ctx.measureText(label).width;
    ctx.fillText(label, x - tw / 2, padT + plotH + 28);
  }

  visibleSeries.forEach((s) => {
    ctx.strokeStyle = s.color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    let started = false;
    for(let idx = i0; idx <= i1; idx++){
      const ms = times[idx];
      if(ms < state.xMin || ms > state.xMax) continue;
      const x = padL + timeToX(ms, state, plotW);
      const v = s.values[idx];
      const y = valToY(v);
      if(!started){ ctx.moveTo(x, y); started = true; } else ctx.lineTo(x, y);
    }
    ctx.stroke();
  });

  ctx.strokeStyle = 'rgba(255,255,255,.22)';
  ctx.strokeRect(padL, padT, plotW, plotH);

  if (mouseX != null && mouseY != null && mouseX >= padL && mouseX <= padL + plotW && mouseY >= padT && mouseY <= padT + plotH) {
    const tx = xToTime(mouseX - padL, state, plotW);
    let idx = lowerBound(times, tx);
    if (idx <= 0) idx = 0;
    else if (idx >= times.length) idx = times.length - 1;
    else idx = Math.abs(tx - times[idx - 1]) <= Math.abs(tx - times[idx]) ? idx - 1 : idx;

    const ms = times[idx];
    const cx = padL + timeToX(ms, state, plotW);
    ctx.strokeStyle = 'rgba(230,237,243,.35)';
    ctx.beginPath();
    ctx.moveTo(cx, padT);
    ctx.lineTo(cx, padT + plotH);
    ctx.stroke();

    const tooltipSeries = visibleSeries
      .map(s => ({ s, v: s.values[idx] }))
      .sort((a,b) => b.v - a.v)
      .slice(0, 8);

    tooltipSeries.forEach(entry => {
      const y = valToY(entry.v);
      ctx.fillStyle = '#0b0f14';
      ctx.beginPath();
      ctx.arc(cx, y, 5, 0, Math.PI * 2);
      ctx.fill();
      ctx.strokeStyle = entry.s.color;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(cx, y, 4, 0, Math.PI * 2);
      ctx.stroke();
    });

    const lines = [fmtUtc(ms), ...tooltipSeries.map(x => `${x.s.shortName}: ${fmtNum(x.v)}`)];
    const padding = 10;
    let w = 0;
    lines.forEach(line => { w = Math.max(w, ctx.measureText(line).width); });
    w += padding * 2;
    const h = lines.length * 16 + padding * 2;
    let bx = cx + 14;
    let by = padT + 10;
    if (bx + w > padL + plotW) bx = cx - 14 - w;

    ctx.fillStyle = 'rgba(15,22,32,.94)';
    ctx.strokeStyle = 'rgba(255,255,255,.18)';
    ctx.beginPath();
    roundRect(ctx, bx, by, w, h, 10);
    ctx.fill();
    ctx.stroke();

    ctx.fillStyle = '#e6edf3';
    let ty = by + padding + 12;
    ctx.fillText(lines[0], bx + padding, ty);
    ty += 18;
    tooltipSeries.forEach(entry => {
      ctx.fillStyle = entry.s.color;
      ctx.fillRect(bx + padding, ty - 9, 8, 8);
      ctx.fillStyle = '#e6edf3';
      ctx.fillText(`${entry.s.shortName}: ${fmtNum(entry.v)}`, bx + padding + 14, ty);
      ty += 16;
    });
    updateHoverInfo(item, ms, tooltipSeries);
    return;
  }

  updateHoverInfo(item, null, null);
}

function renderSelected(){
  currentItem = DATA.find(x => x.ip === select.value) || DATA[0];
  const item = currentItem;
  bucketMeta.textContent = `Bucket size: ${fmtBucket(item.chart.bucketSeconds || 60)}. Double click a legend chip to isolate one series.`;
  buildSeriesToggles(item);
  renderSummary(item);
  updateHoverInfo(item, null, null);
  drawChart(item);
}

function roundRect(ctx, x, y, w, h, r) {
  const rr = Math.min(r, w/2, h/2);
  ctx.moveTo(x + rr, y);
  ctx.arcTo(x + w, y, x + w, y + h, rr);
  ctx.arcTo(x + w, y + h, x, y + h, rr);
  ctx.arcTo(x, y + h, x, y, rr);
  ctx.arcTo(x, y, x + w, y, rr);
  ctx.closePath();
}

DATA.forEach(item => {
  const opt = document.createElement('option');
  opt.value = item.ip;
  opt.textContent = `${item.ip} (${fmtNum(item.totalRows)} hits)`;
  select.appendChild(opt);
});

canvas.addEventListener('mousemove', (e) => {
  if(!currentItem) return;
  const r = canvas.getBoundingClientRect();
  mouseX = e.clientX - r.left;
  mouseY = e.clientY - r.top;
  if (isDragging) {
    const state = getState(currentItem);
    const dx = mouseX - dragStartX;
    const span = dragStartMax - dragStartMin;
    const dt = -dx / Math.max(1, r.width - 82) * span;
    state.xMin = dragStartMin + dt;
    state.xMax = dragStartMax + dt;
    clampX(state);
  }
  drawChart(currentItem);
});
canvas.addEventListener('mouseleave', () => {
  mouseX = null;
  mouseY = null;
  if (!isDragging && currentItem) drawChart(currentItem);
});
canvas.addEventListener('mousedown', (e) => {
  if(!currentItem) return;
  isDragging = true;
  const state = getState(currentItem);
  const r = canvas.getBoundingClientRect();
  dragStartX = e.clientX - r.left;
  dragStartMin = state.xMin;
  dragStartMax = state.xMax;
});
window.addEventListener('mouseup', () => { isDragging = false; });
canvas.addEventListener('wheel', (e) => {
  if(!currentItem) return;
  e.preventDefault();
  const state = getState(currentItem);
  const r = canvas.getBoundingClientRect();
  const plotW = r.width - 82;
  const x = e.clientX - r.left - 64;
  const t = xToTime(x, state, plotW);
  const zoom = Math.exp((e.deltaY > 0 ? 1 : -1) * 0.12);
  const span = (state.xMax - state.xMin) * zoom;
  const leftRatio = (t - state.xMin) / Math.max(1, (state.xMax - state.xMin));
  state.xMin = t - span * leftRatio;
  state.xMax = state.xMin + span;
  clampX(state);
  drawChart(currentItem);
}, { passive: false });
canvas.addEventListener('dblclick', () => {
  if(!currentItem) return;
  resetZoom(currentItem);
  drawChart(currentItem);
});
document.getElementById('btnResetZoom').addEventListener('click', () => {
  if(!currentItem) return;
  resetZoom(currentItem);
  drawChart(currentItem);
});
document.getElementById('btnShowAllSeries').addEventListener('click', () => {
  if(!currentItem) return;
  const state = getState(currentItem);
  state.series.forEach(series => { series.visible = true; });
  buildSeriesToggles(currentItem);
  drawChart(currentItem);
});
select.addEventListener('change', renderSelected);
window.addEventListener('resize', () => { if (currentItem) drawChart(currentItem); });
renderSelected();
</script>
</body>
</html>
""";

        File.WriteAllText(htmlPath, html, Encoding.UTF8);
    }

    private static ChartPayload BuildChartData(IisIpSummaryScanner.ScanResult result)
    {
        if (result.TotalRows == 0 || !result.FirstHitUtc.HasValue || !result.LastHitUtc.HasValue)
            return new ChartPayload(Array.Empty<long>(), Array.Empty<ChartSeries>(), LongRangeBucketSeconds);

        var start = result.FirstHitUtc.Value;
        var end = result.LastHitUtc.Value;
        var bucketSeconds = ChooseBucketSeconds(start, end);
        start = FloorToBucketUtc(start, bucketSeconds);
        end = FloorToBucketUtc(end, bucketSeconds);

        var totalSeconds = Math.Max(bucketSeconds, (int)Math.Ceiling((end - start).TotalSeconds) + bucketSeconds);
        var points = Math.Max(1, (int)Math.Ceiling(totalSeconds / (double)bucketSeconds));
        var times = new long[points];
        var s2xx = new double[points];
        var s3xx = new double[points];
        var s4xx = new double[points];
        var s5xx = new double[points];

        for (int i = 0; i < points; i++)
        {
            var bucketStartUtc = start.AddSeconds(i * bucketSeconds);
            times[i] = new DateTimeOffset(bucketStartUtc).ToUnixTimeMilliseconds();

            for (int secondOffset = 0; secondOffset < bucketSeconds; secondOffset += ShortRangeBucketSeconds)
            {
                var bucketUtc = bucketStartUtc.AddSeconds(secondOffset);
                if (bucketUtc > end)
                    break;

                if (!result.BucketsBy15SecondUtc.TryGetValue(bucketUtc, out var bucket))
                    continue;

                s2xx[i] += bucket.S2xx;
                s3xx[i] += bucket.S3xx;
                s4xx[i] += bucket.S4xx;
                s5xx[i] += bucket.S5xx;
            }
        }

        return new ChartPayload(
            times,
            [
                new ChartSeries("HTTP 2xx", s2xx),
                new ChartSeries("HTTP 3xx", s3xx),
                new ChartSeries("HTTP 4xx", s4xx),
                new ChartSeries("HTTP 5xx", s5xx)
            ],
            bucketSeconds);
    }

    private static int ChooseBucketSeconds(DateTime startUtc, DateTime endUtc)
    {
        var range = endUtc - startUtc;
        var preferredBucketSeconds =
            range <= ShortRangeMax ? ShortRangeBucketSeconds :
            range <= MediumRangeMax ? MediumRangeBucketSeconds :
            LongRangeBucketSeconds;

        var guardrailBucketSeconds = RoundUpToMultiple(
            (int)Math.Ceiling(Math.Max(1, range.TotalSeconds + 1) / MaxChartPointsPerIp),
            ShortRangeBucketSeconds);

        return Math.Max(preferredBucketSeconds, guardrailBucketSeconds);
    }

    private static int RoundUpToMultiple(int value, int multiple)
    {
        if (multiple <= 0)
            return value;

        var safeValue = Math.Max(value, multiple);
        return ((safeValue + multiple - 1) / multiple) * multiple;
    }

    private static DateTime FloorToBucketUtc(DateTime dtUtc, int bucketSeconds)
    {
        if (bucketSeconds <= 0)
            bucketSeconds = LongRangeBucketSeconds;

        dtUtc = dtUtc.Kind == DateTimeKind.Utc ? dtUtc : dtUtc.ToUniversalTime();
        var bucketTicks = TimeSpan.FromSeconds(bucketSeconds).Ticks;
        var flooredTicks = dtUtc.Ticks - (dtUtc.Ticks % bucketTicks);
        return new DateTime(flooredTicks, DateTimeKind.Utc);
    }

    private static void InfoPanel(string title, params (string Key, string Value)[] rows)
    {
        var t = new Table().RoundedBorder().AddColumn("Field").AddColumn("Value");
        foreach (var (k, v) in rows)
            t.AddRow(Markup.Escape(k), Markup.Escape(v));
        AnsiConsole.Write(new Panel(t) { Header = new PanelHeader(Markup.Escape(title)), Border = BoxBorder.Rounded });
        AnsiConsole.WriteLine();
    }

    private static string TruncateProgressText(string value, int maxLength)
        => string.IsNullOrEmpty(value) || value.Length <= maxLength ? value : maxLength <= 3 ? value[..maxLength] : value[..(maxLength - 3)] + "...";

    private static bool TryOpenFile(string filePath)
    {
        try
        {
            Process.Start(new ProcessStartInfo { FileName = filePath, UseShellExecute = true });
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string SanitizeFileComponent(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
            sb.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
        return sb.ToString();
    }

    private static string BuildFileDisplay(FileInfo f)
    {
        var ts = $"{SafeCreationUtc(f):yyyy-MM-dd HH:mm:ss}Z";
        var size = $"({FormatBytes(f.Length)})";
        var name = f.Name;

        var width = GetConsoleWidthSafe();
        var reserve = ts.Length + 3 + 1 + size.Length;
        var maxName = Math.Max(20, width - reserve);
        name = TrimMiddle(name, maxName);
        return $"{ts} - {name} {size}";
    }

    private static int GetConsoleWidthSafe()
    {
        try
        {
            var w = Console.WindowWidth;
            return w > 0 ? w : 120;
        }
        catch
        {
            return 120;
        }
    }

    private static string TrimMiddle(string s, int max)
    {
        if (string.IsNullOrEmpty(s) || s.Length <= max) return s;
        if (max <= 3) return s[..max];

        var cut = max - 3;
        var head = cut / 2;
        var tail = cut - head;
        return s[..head] + "..." + s[^tail..];
    }

    private static DateTime SafeCreationUtc(FileInfo f)
    {
        try { return f.CreationTimeUtc; }
        catch { return f.LastWriteTimeUtc; }
    }

    private static string FormatBytes(long bytes)
    {
        var suf = new[] { "B", "KB", "MB", "GB", "TB" };
        double b = bytes;
        var i = 0;
        while (b >= 1024 && i < suf.Length - 1) { b /= 1024; i++; }
        return $"{b:0.##} {suf[i]}";
    }

    private static void RenderTopIpTable(IReadOnlyList<IpChoice> choices, int top, bool includeHits)
    {
        var table = new Table().RoundedBorder();
        table.AddColumn("#");
        table.AddColumn("IP");
        if (includeHits)
            table.AddColumn("Hits");

        var ordered = choices.Take(top).ToList();
        for (var i = 0; i < ordered.Count; i++)
        {
            var row = ordered[i];
            if (includeHits)
                table.AddRow((i + 1).ToString(CultureInfo.InvariantCulture), row.Ip, row.Hits.ToString(CultureInfo.InvariantCulture));
            else
                table.AddRow((i + 1).ToString(CultureInfo.InvariantCulture), row.Ip);
        }

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();
    }

    private static bool TryExtractIpCountsFromFile(
        string filePath,
        out string ipColumnName,
        out Dictionary<string, int> counts,
        out List<IpChoice> orderedChoices,
        out string error)
    {
        var ext = Path.GetExtension(filePath);
        if (ext.Equals(".xlsx", StringComparison.OrdinalIgnoreCase))
            return TryExtractIpCountsFromXlsxFirstTable(filePath, out ipColumnName, out counts, out orderedChoices, out error);

        return TryExtractIpCountsFromCsv(filePath, out ipColumnName, out counts, out orderedChoices, out error);
    }

    private static bool TryExtractIpCountsFromCsv(
        string csvPath,
        out string ipColumnName,
        out Dictionary<string, int> counts,
        out List<IpChoice> orderedChoices,
        out string error)
    {
        ipColumnName = "";
        counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        orderedChoices = new List<IpChoice>();
        error = "";

        try
        {
            using var fs = File.OpenRead(csvPath);
            using var sr = new StreamReader(fs);
            var headerLine = sr.ReadLine();
            if (string.IsNullOrWhiteSpace(headerLine))
            {
                error = "CSV is empty.";
                return false;
            }

            var delimiter = CsvLite.DetectDelimiter(headerLine);
            var headers = CsvLite.Split(headerLine, delimiter);
            var ipIndex = FindIpColumnIndex(headers);
            if (ipIndex < 0)
            {
                error = $"Could not detect an IP column. Headers: {string.Join(", ", headers)}";
                return false;
            }

            ipColumnName = headers[ipIndex];
            string? line;
            while ((line = sr.ReadLine()) is not null)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                var cols = CsvLite.Split(line, delimiter);
                if (ipIndex >= cols.Count)
                    continue;

                var ip = NormalizeIp(cols[ipIndex]);
                if (ip is null)
                    continue;

                counts.TryGetValue(ip, out var cur);
                counts[ip] = cur + 1;
            }

            if (counts.Count == 0)
            {
                error = $"Detected IP column '{ipColumnName}', but no valid IPs were found in that column.";
                return false;
            }

            orderedChoices = counts
                .OrderByDescending(kvp => kvp.Value)
                .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
                .Select(kvp => new IpChoice(kvp.Key, kvp.Value))
                .ToList();

            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool TryExtractIpCountsFromXlsxFirstTable(
        string xlsxPath,
        out string ipColumnName,
        out Dictionary<string, int> counts,
        out List<IpChoice> orderedChoices,
        out string error)
    {
        ipColumnName = "";
        counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        orderedChoices = new List<IpChoice>();
        error = "";

        try
        {
            using var fs = new FileStream(xlsxPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var wb = new XLWorkbook(fs);
            var ws = wb.Worksheets.FirstOrDefault();
            if (ws is null)
            {
                error = "XLSX has no worksheets.";
                return false;
            }

            var usedRange = ws.RangeUsed();
            if (usedRange is null)
            {
                error = "XLSX worksheet is empty.";
                return false;
            }

            var firstRow = usedRange.RangeAddress.FirstAddress.RowNumber;
            var lastRow = usedRange.RangeAddress.LastAddress.RowNumber;
            var firstCol = usedRange.RangeAddress.FirstAddress.ColumnNumber;
            var lastCol = usedRange.RangeAddress.LastAddress.ColumnNumber;

            int summaryRow = -1;
            for (int r = firstRow; r <= Math.Min(lastRow, firstRow + 80); r++)
            {
                var marker = ws.Cell(r, firstCol).GetString().Trim();
                if (marker.Equals("Top IP Summary", StringComparison.OrdinalIgnoreCase))
                {
                    summaryRow = r;
                    break;
                }
            }

            if (summaryRow < 0)
            {
                error = "Could not find 'Top IP Summary' section in the first sheet.";
                return false;
            }

            int headerRow = -1;
            int ipCol = -1;
            int hitsCol = -1;

            for (int r = summaryRow + 1; r <= Math.Min(lastRow, summaryRow + 5); r++)
            {
                var headers = new List<string>();
                for (int c = firstCol; c <= lastCol; c++)
                    headers.Add(ws.Cell(r, c).GetString());

                var idx = FindIpColumnIndex(headers);
                if (idx >= 0)
                {
                    headerRow = r;
                    ipCol = firstCol + idx;
                    ipColumnName = headers[idx];
                    var hitsIdx = headers.FindIndex(h => h.Trim().Equals("Hits", StringComparison.OrdinalIgnoreCase));
                    if (hitsIdx >= 0)
                        hitsCol = firstCol + hitsIdx;
                    break;
                }
            }

            if (headerRow < 0 || ipCol < 0)
            {
                error = "Could not detect an IP column under 'Top IP Summary'.";
                return false;
            }

            for (int r = headerRow + 1; r <= lastRow; r++)
            {
                bool allBlank = true;
                for (int c = firstCol; c <= Math.Min(firstCol + 2, lastCol); c++)
                {
                    if (!string.IsNullOrWhiteSpace(ws.Cell(r, c).GetString()))
                    {
                        allBlank = false;
                        break;
                    }
                }
                if (allBlank)
                    break;

                var sectionMarker = ws.Cell(r, firstCol).GetString();
                if (!string.IsNullOrWhiteSpace(sectionMarker) && sectionMarker.StartsWith("IP #", StringComparison.OrdinalIgnoreCase))
                    break;

                var ip = NormalizeIp(ws.Cell(r, ipCol).GetString());
                if (ip is null)
                    continue;

                var hits = 1;
                if (hitsCol > 0)
                {
                    var hitsText = ws.Cell(r, hitsCol).GetString();
                    if (int.TryParse(hitsText.Replace(",", ""), out var parsedHits) && parsedHits > 0)
                        hits = parsedHits;
                }

                counts[ip] = hits;
                orderedChoices.Add(new IpChoice(ip, hits));
            }

            if (counts.Count == 0)
            {
                error = $"Detected IP column '{ipColumnName}', but no valid IPs were found in the first table.";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static int FindIpColumnIndex(IReadOnlyList<string> headers)
    {
        var preferred = new[] { "ip", "ipaddress", "ip_address", "clientip", "client_ip", "client ip", "sourceip", "source_ip", "source ip" };
        for (var i = 0; i < headers.Count; i++)
        {
            var h = headers[i].Trim().ToLowerInvariant();
            if (preferred.Contains(h))
                return i;
        }

        for (var i = 0; i < headers.Count; i++)
        {
            var h = headers[i].Trim().ToLowerInvariant();
            if (h.Contains("ip") && !h.Contains("zip") && !h.Contains("ship"))
                return i;
        }

        return -1;
    }

    private static string? NormalizeIp(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var s = raw.Trim().Trim('"').Trim();
        if (s.Contains('.') && s.Count(c => c == ':') == 1)
            s = s.Split(':', 2)[0];
        if (s.StartsWith('[') && s.EndsWith(']') && s.Length > 2)
            s = s[1..^1];

        return System.Net.IPAddress.TryParse(s, out _) ? s : null;
    }

    private static string? ToFileUrl(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;

        try
        {
            return new Uri(Path.GetFullPath(path)).AbsoluteUri;
        }
        catch
        {
            return null;
        }
    }

    private sealed record FileChoice(string FullPath, string Display);
    private sealed record IpChoice(string Ip, int Hits);
    private sealed record RequestedIpSet(string SourceLabel, List<string> Ips);
    private sealed record DetailArtifact(string? Kind, string? Path);
    private sealed record SimpleCount(string Label, int Count);
    private sealed record ChartSeries(string Name, double[] Values);
    private sealed record ChartPayload(long[] TimesUtc, ChartSeries[] Series, int BucketSeconds);
    private sealed record ReportPayload(
        string Ip,
        long TotalRows,
        int FilesWithHits,
        string? FirstHitUtc,
        string? LastHitUtc,
        double AverageTimeTakenMs,
        long MaxTimeTakenMs,
        long TotalCsBytes,
        long TotalScBytes,
        int Status2xx3xx,
        int Status4xx,
        int Status5xx,
        List<SimpleCount> TopUris,
        List<SimpleCount> TopMethods,
        List<SimpleCount> TopStatuses,
        string? DetailKind,
        string? DetailPath,
        string? DetailUrl,
        ChartPayload Chart);
}
