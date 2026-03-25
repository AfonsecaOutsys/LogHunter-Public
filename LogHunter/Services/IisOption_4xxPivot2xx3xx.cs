using LogHunter.Models;
using LogHunter.Utils;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Services;

public static class IisOption_4xxPivot2xx3xx
{
    private const string SelectAllSentinel = "__ALL__";

    /// <summary>
    /// Flow:
    ///  Pass 1: scan IIS logs for 4xx per (real) public IP -> show Top 15 with per-status breakdown.
    ///  Select suspicious IPs -> Pass 2: export all 2xx/3xx lines for those IPs to a W3C .log + show a pivot summary.
    ///
    /// Input folder:  {root}\IIS
    /// Output folder: {root}\output
    /// </summary>
    public static async Task RunAsync(string root, CancellationToken ct = default)
    {
        ConsoleEx.Header("IIS: 4xx -> select IPs -> pivot to 2xx/3xx");

        var iisDir = Path.Combine(root, "IIS");
        if (!Directory.Exists(iisDir))
        {
            ConsoleEx.Error($"Missing IIS folder: {iisDir}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = IisW3cReader.EnumerateLogFiles(iisDir);
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No IIS logs found under: {iisDir}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        // ---------- Pass 1: 4xx stats ----------
        var statsByIp = new Dictionary<string, IisFourxxStats>(StringComparer.OrdinalIgnoreCase);
        IisW3cReader.FieldMap? firstMap = null;

        // Noise filters
        var ignoreUAPrefixes = new[]
        {
            "ELB-HealthChecker/",
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Pass 1/2: scanning 4xx...", async ctx =>
            {
                for (var f = 0; f < files.Count; f++)
                {
                    ct.ThrowIfCancellationRequested();

                    var file = files[f];
                    ctx.Status($"Pass 1/2: scanning 4xx... ({f + 1}/{files.Count}) {Path.GetFileName(file)}");

                    var map = await IisW3cReader.ReadFieldMapAsync(file, ct).ConfigureAwait(false);
                    if (map is null)
                        continue;

                    firstMap ??= map;

                    if (!map.TryGetIndex("sc-status", out var iStatus))
                        continue;

                    map.TryGetIndex("OriginalIP", out var iOriginalIp);
                    map.TryGetIndex("c-ip", out var iCIp);
                    map.TryGetIndex("cs(User-Agent)", out var iUA);

                    await IisW3cReader.ForEachDataLineAsync(file, ct, (rawLine, tokens) =>
                    {
                        if (!TryParseInt(tokens.Get(iStatus), out var status))
                            return;

                        if (status < 400 || status > 499)
                            return;

                        // Ignore health checker noise
                        if (iUA >= 0)
                        {
                            var ua = tokens.Get(iUA);
                            if (!ua.IsEmpty && ua[0] != '-')
                            {
                                var uaStr = ua.ToString();
                                for (int k = 0; k < ignoreUAPrefixes.Length; k++)
                                {
                                    if (uaStr.StartsWith(ignoreUAPrefixes[k], StringComparison.OrdinalIgnoreCase))
                                        return;
                                }
                            }
                        }

                        var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                        if (ip is null)
                            return;

                        // Focus on public clients
                        if (IisClientIpResolver.IsPrivateOrLoopback(ip))
                            return;

                        if (!statsByIp.TryGetValue(ip, out var s))
                        {
                            s = new IisFourxxStats(ip);
                            statsByIp[ip] = s;
                        }

                        s.Add(status);
                    }).ConfigureAwait(false);
                }
            });

        if (statsByIp.Count == 0)
        {
            ConsoleEx.Info("No public-client 4xx traffic found (after filters).");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var top = statsByIp.Values
            .OrderByDescending(s => s.Total4xx)
            .ThenBy(s => s.Ip, StringComparer.OrdinalIgnoreCase)
            .Take(15)
            .ToList();

        // ---------- Display Top 15 ----------
        ConsoleEx.Header("IIS: Top 4xx IPs", $"Workspace: {root}");

        for (int rank = 0; rank < top.Count; rank++)
        {
            var s = top[rank];
            AnsiConsole.MarkupLine($"[bold]Rank {rank + 1}[/] IP: [yellow]{Markup.Escape(s.Ip)}[/]  [dim]4xx:[/] [bold]{s.Total4xx:n0}[/] hits");

            foreach (var kv in s.StatusCounts.OrderBy(k => k.Key))
                AnsiConsole.MarkupLine($"  [dim]{kv.Key}:[/] {kv.Value:n0} hits");

            AnsiConsole.WriteLine();
        }

        // ---------- Pick suspicious IPs ----------
        var pick = new MultiSelectionPrompt<IpPick>()
            .Title("Select IPs to pivot (2xx/3xx)")
            .NotRequired()
            .PageSize(16)
            .InstructionsText("[grey](Space: toggle, Enter: confirm)[/]")
            .UseConverter(p => p.Display);

        // "Select ALL" pseudo-choice (handled after the prompt)
        pick.AddChoice(new IpPick(
            SelectAllSentinel,
            "[bold][[Select ALL]][/] Select all IPs shown above (Top 15)"
        ));

        foreach (var s in top)
            pick.AddChoice(new IpPick(s.Ip, MakePickLabel(s)));

        var selected = AnsiConsole.Prompt(pick);
        if (selected.Count == 0)
        {
            ConsoleEx.Info("No IPs selected.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        HashSet<string> selectedIps;
        if (selected.Any(x => x.Ip == SelectAllSentinel))
            selectedIps = top.Select(x => x.Ip).ToHashSet(StringComparer.OrdinalIgnoreCase);
        else
            selectedIps = selected.Select(x => x.Ip).ToHashSet(StringComparer.OrdinalIgnoreCase);

        // ---------- Pass 2: export 2xx/3xx lines + pivot summaries ----------
        var outDir = Path.Combine(root, "output");
        Directory.CreateDirectory(outDir);

        var outFile = Path.Combine(outDir, $"iis_pivot_2xx3xx_{DateTime.UtcNow:yyyyMMdd_HHmmss}.log");

        var pivot = new Dictionary<string, IisPivotResult>(StringComparer.OrdinalIgnoreCase);
        foreach (var ip in selectedIps)
            pivot[ip] = new IisPivotResult(ip) { OutputFilePath = outFile };

        long exportedLines = 0;

        await using var outStream = File.Create(outFile);
        await using var outWriter = new StreamWriter(outStream);

        // Write header once (W3C format)
        if (firstMap is not null)
        {
            foreach (var h in firstMap.HeaderLines)
                await outWriter.WriteLineAsync(h).ConfigureAwait(false);

            await outWriter.WriteLineAsync(firstMap.FieldsLine).ConfigureAwait(false);
        }
        else
        {
            // Fallback minimal header (rare)
            await outWriter.WriteLineAsync("#Software: Microsoft Internet Information Services 10.0").ConfigureAwait(false);
            await outWriter.WriteLineAsync("#Version: 1.0").ConfigureAwait(false);
            await outWriter.WriteLineAsync($"#Date: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}").ConfigureAwait(false);
        }

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Pass 2/2: exporting 2xx/3xx for selected IPs...", async ctx =>
            {
                for (var f = 0; f < files.Count; f++)
                {
                    ct.ThrowIfCancellationRequested();

                    var file = files[f];
                    ctx.Status($"Pass 2/2: exporting 2xx/3xx... ({f + 1}/{files.Count}) {Path.GetFileName(file)}");

                    var map = await IisW3cReader.ReadFieldMapAsync(file, ct).ConfigureAwait(false);
                    if (map is null)
                        continue;

                    if (!map.TryGetIndex("sc-status", out var iStatus))
                        continue;

                    map.TryGetIndex("OriginalIP", out var iOriginalIp);
                    map.TryGetIndex("c-ip", out var iCIp);
                    map.TryGetIndex("cs-uri-stem", out var iUriStem);

                    await IisW3cReader.ForEachDataLineAsync(file, ct, (rawLine, tokens) =>
                    {
                        if (!TryParseInt(tokens.Get(iStatus), out var status))
                            return;

                        if (status < 200 || status > 399)
                            return;

                        var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                        if (ip is null)
                            return;

                        if (IisClientIpResolver.IsPrivateOrLoopback(ip))
                            return;

                        if (!selectedIps.Contains(ip))
                            return;

                        // Export raw line
                        outWriter.WriteLine(rawLine);
                        exportedLines++;

                        // Update pivot stats
                        var res = pivot[ip];
                        res.Add(status);

                        if (iUriStem >= 0)
                        {
                            var uri = tokens.Get(iUriStem);
                            if (!uri.IsEmpty && uri[0] != '-')
                                res.AddUri(uri.ToString());
                        }
                    }).ConfigureAwait(false);
                }
            });

        await outWriter.FlushAsync().ConfigureAwait(false);

        // ---------- Show pivot summary ----------
        ConsoleEx.Header("IIS: Pivot results (2xx/3xx)");

        AnsiConsole.MarkupLine($"[dim]Selected IPs:[/] {selectedIps.Count}");
        AnsiConsole.MarkupLine($"[dim]Exported lines:[/] {exportedLines:n0}");
        AnsiConsole.MarkupLine($"[dim]Output:[/] {Markup.Escape(outFile)}");
        AnsiConsole.WriteLine();

        foreach (var ip in selectedIps.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
        {
            var r = pivot[ip];

            AnsiConsole.MarkupLine($"[bold]{Markup.Escape(ip)}[/]  [dim]2xx:[/] {r.Total2xx:n0}  [dim]3xx:[/] {r.Total3xx:n0}");

            foreach (var kv in r.StatusCounts.OrderBy(k => k.Key))
                AnsiConsole.MarkupLine($"  [dim]{kv.Key}:[/] {kv.Value:n0}");

            var topUris = r.TopUris(10);
            if (topUris.Count > 0)
            {
                AnsiConsole.MarkupLine("  [dim]Top URIs (2xx/3xx):[/]");
                foreach (var (uri, count) in topUris)
                {
                    var sensitive = LooksSensitiveOutSystems(uri);
                    var uriMarkup = sensitive ? $"[red]{Markup.Escape(uri)}[/]" : Markup.Escape(uri);
                    AnsiConsole.MarkupLine($"    {uriMarkup}  [dim]({count:n0})[/]");
                }
            }

            AnsiConsole.WriteLine();
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    // -------------------- Helpers --------------------

    private sealed record IpPick(string Ip, string Display);

    private static string MakePickLabel(IisFourxxStats s)
    {
        var parts = new List<string>();

        if (s.StatusCounts.TryGetValue(404, out var c404) && c404 > 0) parts.Add($"404:{c404:n0}");
        if (s.StatusCounts.TryGetValue(403, out var c403) && c403 > 0) parts.Add($"403:{c403:n0}");
        if (s.StatusCounts.TryGetValue(401, out var c401) && c401 > 0) parts.Add($"401:{c401:n0}");
        if (s.StatusCounts.TryGetValue(400, out var c400) && c400 > 0) parts.Add($"400:{c400:n0}");

        var tail = parts.Count > 0 ? $" ({string.Join(", ", parts)})" : "";
        return $"{s.Ip} | 4xx:{s.Total4xx:n0}{tail}";
    }

    private static bool TryParseInt(ReadOnlySpan<char> s, out int value)
    {
        value = 0;
        if (s.IsEmpty || s[0] == '-') return false;
        return int.TryParse(s, out value);
    }

    private static bool LooksSensitiveOutSystems(string uriStem)
    {
        if (uriStem.StartsWith("/ServiceCenter", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.StartsWith("/LifeTime", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("PlatformServices", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("/moduleservices", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("/rest/", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("/soap/", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains(".asmx", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.StartsWith("/server.", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }
}
