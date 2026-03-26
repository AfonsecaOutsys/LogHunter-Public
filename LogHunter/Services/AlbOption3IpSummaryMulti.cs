using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static partial class AlbOptions
{
    private const string AggregateIpSummaryThresholdPrompt =
        "1M rows have been processed across the selected IPs. Continue with one aggregated SQLite database for deep analysis instead of Excel?";
    private const int MaxRequestedIps = 10;
    private const int TopListPickerCap = 20;
    private const int MaxChartPointsPerIp = 2400;

    private static RequestedIpSet? PromptForAlbIpSet(SessionState session)
    {
        var choice = ConsoleEx.Menu("ALB IP Summary: choose input mode", new[]
        {
            new ConsoleEx.MenuItem(
                "Manually enter IPs",
                "Type one IP per prompt. Enter a blank line when the set is complete and the ALB scan should begin."),
            new ConsoleEx.MenuItem(
                "Use IP list",
                "Pick a list source such as an output CSV/XLSX file, the IIS burst session cache, or the Platform suspicious cache. ALB IP Summary will analyze the full gathered set."),
            new ConsoleEx.MenuItem(
                "Back",
                "Return to the ALB menu.")
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
                    return null;

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
                continue;

            ips.Add(normalized);
        }

        if (ips.Count == MaxRequestedIps)
            ConsoleEx.Warn($"Reached the current cap of {MaxRequestedIps} IPs for one ALB IP Summary run.");

        return new RequestedIpSet("Manual entry", ips);
    }

    private static RequestedIpSet? PromptForSourceIps(SessionState session)
    {
        while (true)
        {
            ConsoleEx.Header("ALB: IP Summary - IP list source", $"Workspace: {session.Root}");

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
        ConsoleEx.Header("ALB: IP Summary - IIS burst session", $"Workspace: {session.Root}");

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
        ConsoleEx.Header("ALB: IP Summary - Platform suspicious cache", $"Workspace: {session.Root}");

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
        ConsoleEx.Header("ALB: IP Summary - select file", $"Output folder: {AppFolders.Output}");

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

        ConsoleEx.Header("ALB: IP Summary - gather IPs", Path.GetFileName(picked.FullPath));

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
            sourceLabel += " (top selection)";
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

    private static AlbIpSummaryScanner.DetailRetentionMode PromptForAggregateIpSummaryDetailMode()
        => ConsoleEx.ReadYesNo(AggregateIpSummaryThresholdPrompt, defaultYes: true)
            ? AlbIpSummaryScanner.DetailRetentionMode.SqliteApproved
            : AlbIpSummaryScanner.DetailRetentionMode.SummaryOnly;

    private static async Task<AlbIpSummaryExportSqlite.Writer?> ScanIpSummaryMultiWithPhasedProgressAsync(
        List<string> files,
        IReadOnlyDictionary<string, AlbIpSummaryScanner.ScanResult> resultsByIp,
        string sharedSqlitePath)
    {
        int nextFileIndex = 0;
        AlbIpSummaryScanner.DetailRetentionMode? rememberedMode = null;
        AlbIpSummaryExportSqlite.Writer? sharedSqliteWriter = null;

        while (nextFileIndex < files.Count)
        {
            nextFileIndex = await RunIpSummaryScanPhaseAsyncMulti(files, nextFileIndex, resultsByIp).ConfigureAwait(false);

            var pending = resultsByIp.Values
                .Where(r => r.ThresholdPromptPending)
                .OrderBy(r => r.RequestedIp, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var aggregateRows = resultsByIp.Values
                .Where(r => r.DetailMode == AlbIpSummaryScanner.DetailRetentionMode.BelowThreshold)
                .Sum(r => r.TotalRows);
            var aggregateThresholdReached = aggregateRows >= AlbIpSummaryScanner.ExcelRowThreshold;

            if (pending.Count == 0 && !aggregateThresholdReached)
                continue;

            if (!rememberedMode.HasValue)
            {
                rememberedMode = aggregateThresholdReached
                    ? PromptForAggregateIpSummaryDetailMode()
                    : PromptForIpSummaryDetailMode();
            }

            if (rememberedMode == AlbIpSummaryScanner.DetailRetentionMode.SqliteApproved && sharedSqliteWriter is null)
                sharedSqliteWriter = AlbIpSummaryExportSqlite.Open(sharedSqlitePath);

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

    private static async Task<int> RunIpSummaryScanPhaseAsyncMulti(
        List<string> files,
        int startIndex,
        IReadOnlyDictionary<string, AlbIpSummaryScanner.ScanResult> resultsByIp)
    {
        int nextFileIndex = startIndex;

        await AnsiConsole.Status()
            .AutoRefresh(true)
            .Spinner(Spinner.Known.Dots)
            .StartAsync(
                BuildIpSummaryStatusTextMulti(startIndex + 1, files.Count, files[startIndex], resultsByIp.Values),
                async ctx =>
                {
                    for (int i = startIndex; i < files.Count; i++)
                    {
                        ctx.Status(BuildIpSummaryStatusTextMulti(i + 1, files.Count, files[i], resultsByIp.Values));

                        await AlbIpSummaryScanner.ScanFileAsync(
                            filePath: files[i],
                            resultsByIp: resultsByIp,
                            reportBytesDelta: _ => { }).ConfigureAwait(false);

                        nextFileIndex = i + 1;
                        if (resultsByIp.Values.Any(r => r.ThresholdPromptPending) ||
                            resultsByIp.Values.Where(r => r.DetailMode == AlbIpSummaryScanner.DetailRetentionMode.BelowThreshold).Sum(r => r.TotalRows) >= AlbIpSummaryScanner.ExcelRowThreshold)
                        {
                            break;
                        }
                    }
                }).ConfigureAwait(false);

        AnsiConsole.WriteLine();
        return nextFileIndex;
    }

    private static string BuildIpSummaryStatusTextMulti(
        int currentFileIndex,
        int totalFiles,
        string filePath,
        IEnumerable<AlbIpSummaryScanner.ScanResult> results)
    {
        var sqliteCount = results.Count(r => r.DetailMode == AlbIpSummaryScanner.DetailRetentionMode.SqliteApproved);
        var summaryOnlyCount = results.Count(r => r.DetailMode == AlbIpSummaryScanner.DetailRetentionMode.SummaryOnly);
        var fileName = TruncateProgressText(Path.GetFileName(filePath), 48);

        return $"Scanning ALB logs (IP summary): file {currentFileIndex.ToString(CultureInfo.InvariantCulture)} of {totalFiles.ToString(CultureInfo.InvariantCulture)} | SQLite:{sqliteCount} Summary-only:{summaryOnlyCount} | {Markup.Escape(fileName)}";
    }

    private static void BuildMultiIpSummaryReport(
        string htmlPath,
        IReadOnlyList<AlbIpSummaryScanner.ScanResult> results,
        IReadOnlyDictionary<string, DetailArtifact> artifactsByIp)
    {
        var payload = results.Select(r => new ReportPayload(
            Ip: r.RequestedIp,
            TotalRows: r.TotalRows,
            SummaryHtml: BuildPerIpSummaryHtml(r, artifactsByIp[r.RequestedIp]),
            Chart: BuildMultiChartData(r)))
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
<title>ALB Multi-IP Summary</title>
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
      <button class="btn" id="btnResetZoom" type="button">Reset zoom</button>
    </div>
    <div class="toggleRow" id="seriesToggles"></div>
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
const ctx = canvas.getContext('2d', { alpha: false });
const colors = ['#7dd3fc','#a7f3d0','#fda4af','#fcd34d','#c4b5fd','#fb7185'];
const chartStateByIp = new Map();
let currentItem = null;
let mouseX = null;
let mouseY = null;
let isDragging = false;
let dragStartX = 0;
let dragStartMin = 0;
let dragStartMax = 0;

function esc(s){ return String(s ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'); }
function fmtNum(v){ return Number(v ?? 0).toLocaleString('en-US'); }
function fmtUtc(ms){ const d = new Date(ms); const pad = n => String(n).padStart(2,'0'); return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`; }
function seriesShortName(name){
  const text = String(name || '');
  if (text.startsWith('ELB')) return text.replace(' Response ', ' ');
  if (text.startsWith('FE')) return text.replace(' Response ', ' ');
  return text;
}
function renderSummary(item){ summaryHost.innerHTML = item.summaryHtml || '<div class="card"><div class="empty">No summary available.</div></div>'; }

function getState(item){
  let state = chartStateByIp.get(item.ip);
  if(!state){
    const times = item.chart.timesUtc || [];
    const series = (item.chart.series || []).map((s, index) => ({ name: s.name, shortName: seriesShortName(s.name), values: s.values || [], color: colors[index % colors.length], visible: true }));
    state = { xMin: times.length ? times[0] : 0, xMax: times.length ? times[times.length - 1] : 0, times, series };
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
    button.innerHTML = `<span class="sw" style="background:${series.color}"></span><span>${esc(series.shortName)}</span>`;
    button.addEventListener('click', () => {
      series.visible = !series.visible;
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
  const minSpan = 60 * 1000;
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
}

function renderSelected(){
  currentItem = DATA.find(x => x.ip === select.value) || DATA[0];
  const item = currentItem;
  buildSeriesToggles(item);
  renderSummary(item);
  drawChart(item);
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
select.addEventListener('change', renderSelected);
window.addEventListener('resize', () => { if (currentItem) drawChart(currentItem); });
renderSelected();
</script>
</body>
</html>
""";

        File.WriteAllText(htmlPath, html, Encoding.UTF8);
    }

    private static string BuildPerIpSummaryHtml(AlbIpSummaryScanner.ScanResult result, DetailArtifact artifact)
    {
        if (result.TotalRows == 0)
        {
            return $$"""
<div class="card">
  <div class="pill">Requested IP: {{Html(result.RequestedIp)}}</div>
  <div class="pill">Total matching requests: 0</div>
  <div class="summary-card" style="margin-top:12px;">
    <div class="summary-title">No hits</div>
    <div class="note">No ALB hits were found for this IP in the scanned logs.</div>
  </div>
</div>
""";
        }

        return BuildSummarySectionHtml(result, artifact.Kind, artifact.Path);
    }

    private static ChartPayload BuildMultiChartData(AlbIpSummaryScanner.ScanResult result)
    {
        if (result.TotalRows == 0 || !result.FirstHitUtc.HasValue || !result.LastHitUtc.HasValue)
            return new ChartPayload(Array.Empty<long>(), Array.Empty<ChartSeriesPayload>());

        var start = result.FirstHitUtc.Value;
        var end = result.LastHitUtc.Value;
        start = new DateTime(start.Year, start.Month, start.Day, start.Hour, start.Minute, 0, DateTimeKind.Utc);
        end = new DateTime(end.Year, end.Month, end.Day, end.Hour, end.Minute, 0, DateTimeKind.Utc);

        var minuteCount = (int)Math.Max(1, (end - start).TotalMinutes + 1);
        var bucketSizeMinutes = Math.Max(1, (int)Math.Ceiling(minuteCount / (double)MaxChartPointsPerIp));
        var points = (int)Math.Ceiling(minuteCount / (double)bucketSizeMinutes);
        var times = new long[points];
        var elb2xx3xx = new double[points];
        var elb4xx = new double[points];
        var elb5xx = new double[points];
        var fe2xx3xx = new double[points];
        var fe4xx = new double[points];
        var fe5xx = new double[points];

        for (int i = 0; i < points; i++)
        {
            var bucketStartUtc = start.AddMinutes(i * bucketSizeMinutes);
            times[i] = new DateTimeOffset(bucketStartUtc).ToUnixTimeMilliseconds();

            for (int minuteOffset = 0; minuteOffset < bucketSizeMinutes; minuteOffset++)
            {
                var minuteUtc = bucketStartUtc.AddMinutes(minuteOffset);
                if (minuteUtc > end)
                    break;

                if (!result.BucketsByMinuteUtc.TryGetValue(minuteUtc, out var bucket))
                    continue;

                elb2xx3xx[i] += bucket.Elb.S2xx + bucket.Elb.S3xx;
                elb4xx[i] += bucket.Elb.S4xx;
                elb5xx[i] += bucket.Elb.S5xx;
                fe2xx3xx[i] += bucket.Fe.S2xx + bucket.Fe.S3xx;
                fe4xx[i] += bucket.Fe.S4xx;
                fe5xx[i] += bucket.Fe.S5xx;
            }
        }

        return new ChartPayload(
            times,
            [
                new ChartSeriesPayload("ELB Response 2xx/3xx", elb2xx3xx),
                new ChartSeriesPayload("ELB Response 4xx", elb4xx),
                new ChartSeriesPayload("ELB Response 5xx", elb5xx),
                new ChartSeriesPayload("FE Response 2xx/3xx", fe2xx3xx),
                new ChartSeriesPayload("FE Response 4xx", fe4xx),
                new ChartSeriesPayload("FE Response 5xx", fe5xx)
            ]);
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
            using var wb = new ClosedXML.Excel.XLWorkbook(fs);
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

    private sealed record DetailArtifact(string? Kind, string? Path);
    private sealed record FileChoice(string FullPath, string Display);
    private sealed record IpChoice(string Ip, int Hits);
    private sealed record RequestedIpSet(string SourceLabel, List<string> Ips);
    private sealed record ChartSeriesPayload(string Name, double[] Values);
    private sealed record ChartPayload(long[] TimesUtc, ChartSeriesPayload[] Series);
    private sealed record ReportPayload(string Ip, long TotalRows, string SummaryHtml, ChartPayload Chart);
}
