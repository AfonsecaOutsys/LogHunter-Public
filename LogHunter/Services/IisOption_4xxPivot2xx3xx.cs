using LogHunter.Models;
using LogHunter.Utils;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Services;

public static class IisOption_4xxPivot2xx3xx
{
    private const string SelectAllSentinel = "__ALL__";

    public static async Task RunAsync(string root, CancellationToken ct = default)
    {
        var filter = PromptForStatusPivotFilter();
        if (filter is null)
            return;

        var appScope = PromptForAppScope();
        if (appScope is null)
            return;

        ConsoleEx.Header("IIS: Status Pivot", $"Errors: {filter.DisplayLabel} | Scope: {appScope.DisplayLabel}");

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

        var statsByIp = new Dictionary<string, IisErrorPivotStats>(StringComparer.OrdinalIgnoreCase);
        var errorUriCounts = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        IisW3cReader.FieldMap? firstMap = null;

        var ignoreUAPrefixes = new[]
        {
            "ELB-HealthChecker/",
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync($"Pass 1/2: scanning {filter.DisplayLabel}...", async ctx =>
            {
                for (var f = 0; f < files.Count; f++)
                {
                    ct.ThrowIfCancellationRequested();

                    var file = files[f];
                    ctx.Status($"Pass 1/2: scanning {filter.DisplayLabel}... ({f + 1}/{files.Count}) {Path.GetFileName(file)}");

                    var map = await IisW3cReader.ReadFieldMapAsync(file, ct).ConfigureAwait(false);
                    if (map is null)
                        continue;

                    firstMap ??= map;

                    if (!map.TryGetIndex("sc-status", out var iStatus))
                        continue;

                    map.TryGetIndex("OriginalIP", out var iOriginalIp);
                    map.TryGetIndex("c-ip", out var iCIp);
                    map.TryGetIndex("cs(User-Agent)", out var iUA);
                    map.TryGetIndex("cs-uri-stem", out var iUriStem);

                    await IisW3cReader.ForEachDataLineAsync(file, ct, (_, tokens) =>
                    {
                        if (!TryParseInt(tokens.Get(iStatus), out var status))
                            return;

                        if (!filter.Matches(status))
                            return;

                        var uriStem = NormalizeUri(tokens.Get(iUriStem));
                        if (!appScope.Matches(uriStem))
                            return;

                        if (iUA >= 0)
                        {
                            var ua = tokens.Get(iUA);
                            if (!ua.IsEmpty && ua[0] != '-')
                            {
                                var uaStr = ua.ToString();
                                for (var k = 0; k < ignoreUAPrefixes.Length; k++)
                                {
                                    if (uaStr.StartsWith(ignoreUAPrefixes[k], StringComparison.OrdinalIgnoreCase))
                                        return;
                                }
                            }
                        }

                        var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
                        if (ip is null)
                            return;

                        if (IisClientIpResolver.IsPrivateOrLoopback(ip))
                            return;

                        if (!statsByIp.TryGetValue(ip, out var stats))
                        {
                            stats = new IisErrorPivotStats(ip);
                            statsByIp[ip] = stats;
                        }

                        stats.Add(status, uriStem);
                        IncrementCount(errorUriCounts, uriStem);
                    }).ConfigureAwait(false);
                }
            });

        if (statsByIp.Count == 0)
        {
            ConsoleEx.Info($"No public-client {filter.DisplayLabel} traffic found for scope '{appScope.DisplayLabel}'.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var topIps = statsByIp.Values
            .OrderByDescending(s => s.TotalHits)
            .ThenBy(s => s.Ip, StringComparer.OrdinalIgnoreCase)
            .Take(15)
            .ToList();

        var topErrorUris = errorUriCounts
            .OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .Take(15)
            .ToList();

        ConsoleEx.Header("IIS: Error-side summary", $"Errors: {filter.DisplayLabel} | Scope: {appScope.DisplayLabel}");
        AnsiConsole.MarkupLine($"[dim]Unique public IPs:[/] {statsByIp.Count:n0}");
        AnsiConsole.MarkupLine($"[dim]Top IPs shown:[/] {topIps.Count:n0}");
        AnsiConsole.MarkupLine($"[dim]Top error URIs shown:[/] {topErrorUris.Count:n0}");
        AnsiConsole.WriteLine();

        if (topErrorUris.Count > 0)
        {
            AnsiConsole.MarkupLine($"[bold]{Markup.Escape(filter.DisplayLabel)} URIs[/]");
            foreach (var (uri, count) in topErrorUris)
            {
                var uriMarkup = LooksSensitiveOutSystems(uri) ? $"[red]{Markup.Escape(uri)}[/]" : Markup.Escape(uri);
                AnsiConsole.MarkupLine($"  {uriMarkup}  [dim]({count:n0})[/]");
            }

            AnsiConsole.WriteLine();
        }

        for (var rank = 0; rank < topIps.Count; rank++)
        {
            var stats = topIps[rank];
            AnsiConsole.MarkupLine($"[bold]Rank {rank + 1}[/] IP: [yellow]{Markup.Escape(stats.Ip)}[/]  [dim]{Markup.Escape(filter.DisplayLabel)}:[/] [bold]{stats.TotalHits:n0}[/] hits");

            foreach (var kv in stats.StatusCounts.OrderBy(k => k.Key))
                AnsiConsole.MarkupLine($"  [dim]{kv.Key}:[/] {kv.Value:n0} hits");

            var topUrisForIp = stats.TopUris(5);
            if (topUrisForIp.Count > 0)
            {
                AnsiConsole.MarkupLine("  [dim]Top error URIs:[/]");
                foreach (var (uri, count) in topUrisForIp)
                {
                    var uriMarkup = LooksSensitiveOutSystems(uri) ? $"[red]{Markup.Escape(uri)}[/]" : Markup.Escape(uri);
                    AnsiConsole.MarkupLine($"    {uriMarkup}  [dim]({count:n0})[/]");
                }
            }

            AnsiConsole.WriteLine();
        }

        var pick = new MultiSelectionPrompt<IpPick>()
            .Title("Select IPs to pivot into 2xx/3xx")
            .NotRequired()
            .PageSize(16)
            .InstructionsText("[grey](Space: toggle, Enter: confirm)[/]")
            .UseConverter(p => p.Display);

        pick.AddChoice(new IpPick(
            SelectAllSentinel,
            "[bold][[Select ALL]][/] Select all IPs shown above (Top 15)"));

        foreach (var stats in topIps)
            pick.AddChoice(new IpPick(stats.Ip, MakePickLabel(stats, filter.DisplayLabel)));

        var selected = AnsiConsole.Prompt(pick);
        if (selected.Count == 0)
        {
            ConsoleEx.Info("No IPs selected.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        HashSet<string> selectedIps = selected.Any(x => x.Ip == SelectAllSentinel)
            ? topIps.Select(x => x.Ip).ToHashSet(StringComparer.OrdinalIgnoreCase)
            : selected.Select(x => x.Ip).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var outDir = Path.Combine(root, "output");
        Directory.CreateDirectory(outDir);

        var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        var outFile = Path.Combine(outDir, $"iis_status_pivot_2xx3xx_{stamp}.log");

        var pivot = new Dictionary<string, IisPivotResult>(StringComparer.OrdinalIgnoreCase);
        foreach (var ip in selectedIps)
            pivot[ip] = new IisPivotResult(ip) { OutputFilePath = outFile };

        long exportedLines = 0;

        await using var outStream = File.Create(outFile);
        await using var outWriter = new StreamWriter(outStream);

        if (firstMap is not null)
        {
            foreach (var h in firstMap.HeaderLines)
                await outWriter.WriteLineAsync(h).ConfigureAwait(false);

            await outWriter.WriteLineAsync(firstMap.FieldsLine).ConfigureAwait(false);
        }
        else
        {
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
                        if (ip is null || IisClientIpResolver.IsPrivateOrLoopback(ip) || !selectedIps.Contains(ip))
                            return;

                        outWriter.WriteLine(rawLine);
                        exportedLines++;

                        var result = pivot[ip];
                        result.Add(status);

                        var uriStem = NormalizeUri(tokens.Get(iUriStem));
                        if (!string.IsNullOrWhiteSpace(uriStem) && uriStem != "-")
                            result.AddUri(uriStem);
                    }).ConfigureAwait(false);
                }
            });

        await outWriter.FlushAsync().ConfigureAwait(false);

        ConsoleEx.Header("IIS: Success-side pivot (2xx/3xx)", $"Source errors: {filter.DisplayLabel} | Scope: {appScope.DisplayLabel}");
        AnsiConsole.MarkupLine($"[dim]Selected IPs:[/] {selectedIps.Count}");
        AnsiConsole.MarkupLine($"[dim]Exported lines:[/] {exportedLines:n0}");
        AnsiConsole.MarkupLine($"[dim]Output:[/] {Markup.Escape(outFile)}");
        AnsiConsole.WriteLine();

        foreach (var ip in selectedIps.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
        {
            var result = pivot[ip];
            var errorStats = statsByIp[ip];

            AnsiConsole.MarkupLine($"[bold]{Markup.Escape(ip)}[/]  [dim]{Markup.Escape(filter.DisplayLabel)}:[/] {errorStats.TotalHits:n0}  [dim]2xx:[/] {result.Total2xx:n0}  [dim]3xx:[/] {result.Total3xx:n0}");

            foreach (var kv in result.StatusCounts.OrderBy(k => k.Key))
                AnsiConsole.MarkupLine($"  [dim]{kv.Key}:[/] {kv.Value:n0}");

            var topUris = result.TopUris(10);
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

    private static StatusPivotFilter? PromptForStatusPivotFilter()
    {
        var items = new[]
        {
            new ConsoleEx.MenuItem("4xx", "Filter IIS requests to HTTP 4xx errors only."),
            new ConsoleEx.MenuItem("5xx", "Filter IIS requests to HTTP 5xx errors only."),
            new ConsoleEx.MenuItem("4xx + 5xx", "Filter IIS requests to both 4xx and 5xx error ranges."),
            new ConsoleEx.MenuItem("Exact status codes", "Enter one or more exact HTTP status codes such as 401,403,404,502."),
            new ConsoleEx.MenuItem("Back", "Return to the IIS menu.")
        };

        var selected = ConsoleEx.Menu("IIS Status Pivot: error filter", items, pageSize: 10);
        if (selected is null || selected.Value == 4)
            return null;

        return selected.Value switch
        {
            0 => StatusPivotFilter.ForRange("4xx", static code => code is >= 400 and <= 499),
            1 => StatusPivotFilter.ForRange("5xx", static code => code is >= 500 and <= 599),
            2 => StatusPivotFilter.ForRange("4xx + 5xx", static code => code is >= 400 and <= 599),
            3 => PromptForExactStatusCodes(),
            _ => null
        };
    }

    private static StatusPivotFilter? PromptForExactStatusCodes()
    {
        while (true)
        {
            var input = ConsoleEx.ReadLineWithEsc("Enter status codes (comma-separated):");
            if (input is null)
                return null;

            var codes = input.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(static part => int.TryParse(part, out var code) ? code : -1)
                .Where(static code => code is >= 100 and <= 599)
                .Distinct()
                .OrderBy(static code => code)
                .ToArray();

            if (codes.Length == 0)
            {
                ConsoleEx.Warn("Enter at least one valid HTTP status code, such as 404 or 502.");
                continue;
            }

            var set = codes.ToHashSet();
            return StatusPivotFilter.ForExact(string.Join(", ", codes), code => set.Contains(code));
        }
    }

    private static AppScopeFilter? PromptForAppScope()
    {
        var items = new[]
        {
            new ConsoleEx.MenuItem("All IIS apps", "Do not filter by URI stem or application area."),
            new ConsoleEx.MenuItem("Service Center only", "Limit matches to Service Center requests."),
            new ConsoleEx.MenuItem("LifeTime only", "Limit matches to LifeTime requests."),
            new ConsoleEx.MenuItem("Custom URI fragment", "Enter a URI fragment such as /MyApp/ to narrow the scan."),
            new ConsoleEx.MenuItem("Back", "Return to the previous step.")
        };

        var selected = ConsoleEx.Menu("IIS Status Pivot: app scope", items, pageSize: 10);
        if (selected is null || selected.Value == 4)
            return null;

        return selected.Value switch
        {
            0 => AppScopeFilter.ForAll(),
            1 => AppScopeFilter.ForFragment("Service Center", "/ServiceCenter"),
            2 => AppScopeFilter.ForFragment("LifeTime", "/LifeTime"),
            3 => PromptForCustomFragment(),
            _ => null
        };
    }

    private static AppScopeFilter? PromptForCustomFragment()
    {
        while (true)
        {
            var input = ConsoleEx.ReadLineWithEsc("Enter URI fragment:");
            if (input is null)
                return null;

            if (string.IsNullOrWhiteSpace(input))
            {
                ConsoleEx.Warn("Enter a URI fragment such as /ServiceCenter or /MyApp/.");
                continue;
            }

            return AppScopeFilter.ForFragment(input.Trim(), input.Trim());
        }
    }

    private static string MakePickLabel(IisErrorPivotStats stats, string filterLabel)
    {
        var parts = stats.StatusCounts
            .OrderBy(kv => kv.Key)
            .Take(4)
            .Select(kv => $"{kv.Key}:{kv.Value:n0}")
            .ToList();

        var tail = parts.Count > 0 ? $" ({string.Join(", ", parts)})" : string.Empty;
        return $"{stats.Ip} | {filterLabel}:{stats.TotalHits:n0}{tail}";
    }

    private static string NormalizeUri(ReadOnlySpan<char> uriStem)
    {
        if (uriStem.IsEmpty)
            return "-";

        var value = uriStem.ToString().Trim();
        return string.IsNullOrWhiteSpace(value) ? "-" : value;
    }

    private static void IncrementCount(Dictionary<string, long> counts, string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value == "-")
            return;

        if (counts.TryGetValue(value, out var current))
            counts[value] = current + 1;
        else
            counts[value] = 1;
    }

    private static bool TryParseInt(ReadOnlySpan<char> s, out int value)
    {
        value = 0;
        if (s.IsEmpty || s[0] == '-')
            return false;

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

    private sealed record IpPick(string Ip, string Display);

    private sealed class IisErrorPivotStats
    {
        private readonly Dictionary<string, long> _uriCounts = new(StringComparer.OrdinalIgnoreCase);

        public IisErrorPivotStats(string ip) => Ip = ip;

        public string Ip { get; }
        public long TotalHits { get; private set; }
        public Dictionary<int, long> StatusCounts { get; } = new();

        public void Add(int status, string uriStem)
        {
            TotalHits++;

            if (StatusCounts.TryGetValue(status, out var statusCount))
                StatusCounts[status] = statusCount + 1;
            else
                StatusCounts[status] = 1;

            if (!string.IsNullOrWhiteSpace(uriStem) && uriStem != "-")
            {
                if (_uriCounts.TryGetValue(uriStem, out var uriCount))
                    _uriCounts[uriStem] = uriCount + 1;
                else
                    _uriCounts[uriStem] = 1;
            }
        }

        public List<(string UriStem, long Count)> TopUris(int take)
            => _uriCounts
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(take)
                .Select(kv => (kv.Key, kv.Value))
                .ToList();
    }

    private sealed class StatusPivotFilter
    {
        private readonly Func<int, bool> _match;

        private StatusPivotFilter(string displayLabel, Func<int, bool> match)
        {
            DisplayLabel = displayLabel;
            _match = match;
        }

        public string DisplayLabel { get; }

        public bool Matches(int statusCode) => _match(statusCode);

        public static StatusPivotFilter ForRange(string displayLabel, Func<int, bool> match)
            => new(displayLabel, match);

        public static StatusPivotFilter ForExact(string displayLabel, Func<int, bool> match)
            => new(displayLabel, match);
    }

    private sealed class AppScopeFilter
    {
        private readonly string? _fragment;

        private AppScopeFilter(string displayLabel, string? fragment)
        {
            DisplayLabel = displayLabel;
            _fragment = fragment;
        }

        public string DisplayLabel { get; }

        public bool Matches(string uriStem)
        {
            if (string.IsNullOrWhiteSpace(_fragment))
                return true;

            if (string.IsNullOrWhiteSpace(uriStem) || uriStem == "-")
                return false;

            return uriStem.IndexOf(_fragment, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static AppScopeFilter ForAll() => new("All IIS apps", null);

        public static AppScopeFilter ForFragment(string displayLabel, string fragment)
            => new(displayLabel, fragment);
    }
}
