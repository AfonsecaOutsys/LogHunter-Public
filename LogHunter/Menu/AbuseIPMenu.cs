using ClosedXML.Excel;
using LogHunter.Services;
using LogHunter.Utils;
using Spectre.Console;
using Spectre.Console.Rendering;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Menus;

public sealed class AbuseIpMenu : IMenu
{
    private readonly SessionState _session;

    private const string SelectAllSentinel = "__ALL__";

    public AbuseIpMenu(SessionState session) => _session = session;

    public async Task<IMenu?> ShowAsync(CancellationToken ct = default)
    {
        ConsoleEx.Header("AbuseIPDB", $"Workspace: {_session.Root}");

        var cfg = AbuseIpDbClient.LoadConfig(_session.Root);
        var keySource = string.IsNullOrWhiteSpace(cfg.ApiKey) ? "built-in default" : "config file";

        var burstCount = _session.IisBurstIps?.Count ?? 0;
        var burstUpdated = _session.IisBurstIpsUpdatedUtc is null
            ? "never"
            : _session.IisBurstIpsUpdatedUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") + "Z";

        var platCount = _session.PlatformSuspiciousIpHits?.Count ?? 0;
        var platUpdated = _session.PlatformSuspiciousIpHitsUpdatedUtc is null
            ? "never"
            : _session.PlatformSuspiciousIpHitsUpdatedUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") + "Z";

        var items = new[]
        {
            new ConsoleEx.MenuItem(
                "Check IPs from ALB output file (CSV/XLSX)",
                "Mainly for ALB CSV/XLSX exports in /output: detect an IP column, select IPs and run checks.\n" +
                $"API key: {keySource}\n" +
                $"maxAgeInDays: {cfg.MaxAgeInDays}"),

            new ConsoleEx.MenuItem(
                $"Check IPs from IIS burst session ({burstCount})",
                "Uses the last saved burst IP set from IIS -> Burst patterns.\n" +
                $"Last updated: {burstUpdated}\n" +
                $"API key: {keySource}\n" +
                $"maxAgeInDays: {cfg.MaxAgeInDays}"),

            new ConsoleEx.MenuItem(
                $"Check IPs from Platform suspicious cache ({platCount})",
                "Uses the last saved IP set from Platform -> Suspicious requests: extract IPs.\n" +
                $"Last updated: {platUpdated}\n" +
                $"API key: {keySource}\n" +
                $"maxAgeInDays: {cfg.MaxAgeInDays}"),

            new ConsoleEx.MenuItem(
                "Set or update API key (writes config)",
                $"Config file: {AbuseIpDbClient.GetConfigPath(_session.Root)}"),

            new ConsoleEx.MenuItem("Back", "Return to the main menu.")
        };

        var selected = ConsoleEx.Menu("AbuseIPDB menu", items, pageSize: 10);

        // Esc = back
        if (selected is null)
            return new MainMenu(_session);

        switch (selected.Value)
        {
            case 0:
                await CheckFromOutputFileAsync(ct).ConfigureAwait(false);
                return this;

            case 1:
                await CheckFromIisBurstSessionAsync(ct).ConfigureAwait(false);
                return this;

            case 2:
                await CheckFromPlatformSuspiciousSessionAsync(ct).ConfigureAwait(false);
                return this;

            case 3:
                await ConfigureAsync(ct).ConfigureAwait(false);
                return this;

            case 4:
                return new MainMenu(_session);

            default:
                return this;
        }
    }

    private async Task ConfigureAsync(CancellationToken ct)
    {
        ConsoleEx.Header("AbuseIPDB: config", $"Workspace: {_session.Root}");

        var cfg = AbuseIpDbClient.LoadConfig(_session.Root);
        var path = AbuseIpDbClient.GetConfigPath(_session.Root);

        AnsiConsole.MarkupLine($"[dim]Config path:[/] {Markup.Escape(path)}");
        AnsiConsole.WriteLine();

        var key = AnsiConsole.Prompt(
            new TextPrompt<string>("API key (leave empty to use built-in default):")
                .AllowEmpty()
                .Secret());

        var maxAge = AnsiConsole.Prompt(
            new TextPrompt<int>("maxAgeInDays (1-365):")
                .DefaultValue(cfg.MaxAgeInDays)
                .ValidationErrorMessage("Enter a number between 1 and 365.")
                .Validate(v => v is >= 1 and <= 365));

        // Avoid API differences across Spectre versions
        var verbose = AnsiConsole.Confirm("Include verbose report payload? (heavier response)", cfg.Verbose);

        var updated = cfg with
        {
            ApiKey = string.IsNullOrWhiteSpace(key) ? null : key.Trim(),
            MaxAgeInDays = maxAge,
            Verbose = verbose
        };

        AbuseIpDbClient.SaveConfig(_session.Root, updated);

        ConsoleEx.Success("Saved.");
        ConsoleEx.Pause("Press Enter to return...");
        await Task.CompletedTask.ConfigureAwait(false);
    }

    private async Task CheckFromIisBurstSessionAsync(CancellationToken ct)
    {
        ConsoleEx.Header("AbuseIPDB: IIS burst session", $"Workspace: {_session.Root}");

        var set = _session.IisBurstIps;
        var ipHits = _session.IisBurstIpHits;
        var updated = _session.IisBurstIpsUpdatedUtc;

        if (set is null || set.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey](no burst IPs saved in session)[/]");
            AnsiConsole.MarkupLine("[dim]Run IIS -> Burst patterns and choose to save burst IPs to session.[/]");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        AnsiConsole.MarkupLine($"[dim]Burst IPs in session:[/] {set.Count}");
        AnsiConsole.MarkupLine($"[dim]Last updated:[/] {(updated is null ? "unknown" : updated.Value.ToString("yyyy-MM-dd HH:mm:ss") + "Z")}");
        AnsiConsole.WriteLine();

        var choices = (ipHits is { Count: > 0 }
                ? ipHits
                    .OrderByDescending(kvp => kvp.Value)
                    .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(kvp => new IpChoice(kvp.Key, kvp.Value))
                : set
                    .OrderBy(ip => ip, StringComparer.OrdinalIgnoreCase)
                    .Select(ip => new IpChoice(ip, 0)))
            .Take(20)
            .ToList();

        var selectedIps = SelectIpsWithEsc(
            title: "Select IPs to check (IIS burst session)",
            allCount: set.Count,
            choices: choices,
            includeHits: choices.Any(x => x.Hits > 0));

        if (selectedIps is null)
            return;

        if (selectedIps.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey](no IPs selected)[/]");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        List<string> ipsToCheck;
        if (selectedIps.Any(x => x.Ip == SelectAllSentinel))
        {
            ipsToCheck = set.OrderBy(ip => ip, StringComparer.OrdinalIgnoreCase).ToList();
        }
        else
        {
            ipsToCheck = selectedIps
                .Select(x => x.Ip)
                .Where(ip => ip != SelectAllSentinel)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        await CheckIpsAsync(ipsToCheck, sourceLabel: "IIS burst session", ct).ConfigureAwait(false);
    }

    private async Task CheckFromPlatformSuspiciousSessionAsync(CancellationToken ct)
    {
        ConsoleEx.Header("AbuseIPDB: Platform suspicious cache", $"Workspace: {_session.Root}");

        var dict = _session.PlatformSuspiciousIpHits;
        var updated = _session.PlatformSuspiciousIpHitsUpdatedUtc;

        if (dict is null || dict.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey](no Platform suspicious IPs saved in session)[/]");
            AnsiConsole.MarkupLine("[dim]Run Platform -> Suspicious requests: extract IPs to populate this cache.[/]");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        AnsiConsole.MarkupLine($"[dim]Platform suspicious IPs in session:[/] {dict.Count}");
        AnsiConsole.MarkupLine($"[dim]Last updated:[/] {(updated is null ? "unknown" : updated.Value.ToString("yyyy-MM-dd HH:mm:ss") + "Z")}");
        AnsiConsole.WriteLine();

        var choices = dict
            .OrderByDescending(kvp => kvp.Value)
            .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
            .Take(800)
            .Select(kvp => new IpChoice(kvp.Key, kvp.Value))
            .ToList();

        var selectedIps = AnsiConsole.Prompt(
            new MultiSelectionPrompt<IpChoice>()
                .Title("Select IPs to check:")
                .PageSize(18)
                .WrapAround()
                .NotRequired()
                .InstructionsText("[grey](Space: toggle, Enter: run. List is capped to top 800; Select ALL checks the full set.)[/]")
                .AddChoices(new[] { new IpChoice(SelectAllSentinel, -1) }.Concat(choices))
                .UseConverter(x =>
                {
                    if (x.Ip == SelectAllSentinel) return "[bold][[Select ALL]][/]";
                    return $"{x.Ip} [grey]({x.Hits})[/]";
                }));

        if (selectedIps.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey](no IPs selected)[/]");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        List<string> ipsToCheck;
        if (selectedIps.Any(x => x.Ip == SelectAllSentinel))
        {
            ipsToCheck = dict.Keys.OrderBy(ip => ip, StringComparer.OrdinalIgnoreCase).ToList();
        }
        else
        {
            ipsToCheck = selectedIps
                .Select(x => x.Ip)
                .Where(ip => ip != SelectAllSentinel)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        await CheckIpsAsync(ipsToCheck, sourceLabel: "Platform suspicious cache", ct).ConfigureAwait(false);
    }

    private async Task CheckFromOutputFileAsync(CancellationToken ct)
    {
        ConsoleEx.Header("AbuseIPDB: select file", $"Workspace: {_session.Root}");

        var outDir = AppFolders.Output;
        if (!Directory.Exists(outDir))
        {
            AnsiConsole.MarkupLine($"[yellow]/output folder not found[/] at: {Markup.Escape(outDir)}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
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
            return;
        }

        // Keep display line short to avoid wrapping issues in some hosts.
        var choices = files
            .Select(f => new FileChoice(f.FullName, BuildFileDisplay(f)))
            .ToList();

        var picked = AnsiConsole.Prompt(
            new SelectionPrompt<FileChoice>()
                .Title("Pick a file from /output (CSV/XLSX, newest first):")
                .PageSize(15)
                .WrapAround()
                .AddChoices(choices)
                .UseConverter(x => x.Display));

        ConsoleEx.Header("AbuseIPDB: extract IPs", Path.GetFileName(picked.FullPath));

        if (!TryExtractIpCountsFromFile(
                filePath: picked.FullPath,
                out var ipColumnName,
                out var counts,
                out var orderedChoices,
                out var error))
        {
            AnsiConsole.MarkupLine($"[red]Failed[/]: {Markup.Escape(error)}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        AnsiConsole.MarkupLine($"[dim]Detected IP column:[/] [bold]{Markup.Escape(ipColumnName)}[/]");
        AnsiConsole.MarkupLine($"[dim]Unique IPs found:[/] {counts.Count}");
        AnsiConsole.WriteLine();

        RenderTopIpTable(counts, top: 50);

        var topChoices = orderedChoices
            .Take(400)
            .ToList();

        topChoices.Insert(0, new IpChoice(SelectAllSentinel, counts.Values.Sum()));

        var selectedIps = AnsiConsole.Prompt(
            new MultiSelectionPrompt<IpChoice>()
                .Title("Select IPs to check:")
                .PageSize(18)
                .WrapAround()
                .NotRequired()
                .InstructionsText("[grey](Space: toggle, Enter: run. List is capped to top 400 by hits.)[/]")
                .AddChoices(topChoices)
                .UseConverter(x => x.Ip == SelectAllSentinel
                    ? $"[bold]Select all[/] [grey]({counts.Count} IPs)[/]"
                    : $"{x.Ip} [grey]({x.Hits})[/]"));

        if (selectedIps.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey](no IPs selected)[/]");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        List<string> ipsToCheck;
        if (selectedIps.Any(x => x.Ip == SelectAllSentinel))
            ipsToCheck = topChoices.Where(x => x.Ip != SelectAllSentinel).Select(x => x.Ip).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        else
            ipsToCheck = selectedIps.Select(x => x.Ip).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        await CheckIpsAsync(ipsToCheck, sourceLabel: $"File: {Path.GetFileName(picked.FullPath)}", ct).ConfigureAwait(false);
    }

    private async Task CheckIpsAsync(List<string> ipsToCheck, string sourceLabel, CancellationToken ct)
    {
        ConsoleEx.Header("AbuseIPDB: running checks", $"{sourceLabel} | IPs: {ipsToCheck.Count}");

        var cfg = AbuseIpDbClient.LoadConfig(_session.Root);

        string? sessionApiKeyOverride = null;
        var client = new AbuseIpDbClient(_session.Root, sessionApiKeyOverride);

        var results = new List<AbuseIpCheckResult>(ipsToCheck.Count);
        var failures = new List<(string Ip, string Error)>();

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var runtimeToken = linkedCts.Token;

        _ = Task.Run(() =>
        {
            while (!runtimeToken.IsCancellationRequested)
            {
                var maybe = AnsiConsole.Console.Input.ReadKey(intercept: true);
                if (maybe is not null && maybe.Value.Key == ConsoleKey.Escape)
                {
                    linkedCts.Cancel();
                    return;
                }
            }
        }, runtimeToken);

        await AnsiConsole.Progress()
            .AutoClear(true)
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask("Checking IP reputation...", maxValue: ipsToCheck.Count);

                foreach (var ip in ipsToCheck)
                {
                    if (runtimeToken.IsCancellationRequested)
                        break;

                    var done = false;
                    while (!done)
                    {
                        try
                        {
                            var r = await client.CheckAsync(ip, cfg.MaxAgeInDays, cfg.Verbose, runtimeToken).ConfigureAwait(false);
                            results.Add(r);
                            done = true;
                        }
                        catch (AbuseIpQuotaExceededException qex)
                        {
                            var reset = qex.RateLimit.ResetAtUtc?.ToString("yyyy-MM-dd HH:mm:ss") + "Z";
                            AnsiConsole.MarkupLine($"[yellow]Quota reached[/] (resets {Markup.Escape(reset ?? "unknown")}).");

                            var action = AnsiConsole.Prompt(
                                new SelectionPrompt<string>()
                                    .Title("Switch API key?")
                                    .AddChoices("Enter different key (this run only)", "Save different key to config", "Cancel"));

                            if (action == "Cancel")
                            {
                                failures.Add((ip, qex.Message));
                                done = true;
                                break;
                            }

                            var newKey = AnsiConsole.Prompt(
                                new TextPrompt<string>("New API key:")
                                    .Secret()
                                    .ValidationErrorMessage("API key cannot be empty.")
                                    .Validate(s => !string.IsNullOrWhiteSpace(s)));

                            if (action == "Save different key to config")
                            {
                                var updated = cfg with { ApiKey = newKey.Trim() };
                                AbuseIpDbClient.SaveConfig(_session.Root, updated);
                                cfg = updated;
                                sessionApiKeyOverride = null;
                            }
                            else
                            {
                                sessionApiKeyOverride = newKey.Trim();
                            }

                            client.Dispose();
                            client = new AbuseIpDbClient(_session.Root, sessionApiKeyOverride);
                            // retry same IP
                        }
                        catch (AbuseIpAuthException aex)
                        {
                            AnsiConsole.MarkupLine($"[red]Auth error[/]: {Markup.Escape(aex.Message)}");

                            var action = AnsiConsole.Prompt(
                                new SelectionPrompt<string>()
                                    .Title("Fix API key?")
                                    .AddChoices("Enter different key (this run only)", "Save different key to config", "Skip this IP"));

                            if (action == "Skip this IP")
                            {
                                failures.Add((ip, aex.Message));
                                done = true;
                                break;
                            }

                            var newKey = AnsiConsole.Prompt(
                                new TextPrompt<string>("New API key:")
                                    .Secret()
                                    .ValidationErrorMessage("API key cannot be empty.")
                                    .Validate(s => !string.IsNullOrWhiteSpace(s)));

                            if (action == "Save different key to config")
                            {
                                var updated = cfg with { ApiKey = newKey.Trim() };
                                AbuseIpDbClient.SaveConfig(_session.Root, updated);
                                cfg = updated;
                                sessionApiKeyOverride = null;
                            }
                            else
                            {
                                sessionApiKeyOverride = newKey.Trim();
                            }

                            client.Dispose();
                            client = new AbuseIpDbClient(_session.Root, sessionApiKeyOverride);
                            // retry same IP
                        }
                        catch (Exception ex)
                        {
                            failures.Add((ip, ex.Message));
                            done = true;
                        }
                    }

                    task.Increment(1);
                }
            });

        client.Dispose();

        ConsoleEx.Header("AbuseIPDB: results", $"Source: {sourceLabel} | Checked: {results.Count} | Failed: {failures.Count}");

        if (runtimeToken.IsCancellationRequested)
            ConsoleEx.Warn("Run cancelled (Esc pressed). Showing partial results.");

        RenderResultsTable(results);

        if (failures.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[yellow]Failures:[/]");
            foreach (var f in failures)
                AnsiConsole.MarkupLine($"[grey]- {Markup.Escape(f.Ip)}:[/] {Markup.Escape(f.Error)}");
        }

        var exportPath = Path.Combine(AppFolders.Output, $"abuseipdb_checks_{DateTime.UtcNow:yyyyMMdd_HHmmss}.csv");
        Directory.CreateDirectory(AppFolders.Output);
        AbuseIpDbClient.ExportResultsCsv(exportPath, results);

        AnsiConsole.WriteLine();
        ConsoleEx.Success($"Exported: {exportPath}");

        ConsoleEx.Pause("Press Enter to return...");
    }

    // ---- Display helpers ----

    private static string BuildFileDisplay(FileInfo f)
    {
        var ts = $"{SafeCreationUtc(f):yyyy-MM-dd HH:mm:ss}Z";
        var size = $"({FormatBytes(f.Length)})";
        var name = f.Name;

        var width = GetConsoleWidthSafe();

        // Reserve: "{ts} - " + " " + "{size}"
        var reserve = ts.Length + 3 + 1 + size.Length;
        var maxName = Math.Max(20, width - reserve);

        name = TrimMiddle(name, maxName);

        // Plain text (no markup) to keep hosts happy.
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

    // ---- UI renderers ----

    private static void RenderTopIpTable(Dictionary<string, int> counts, int top)
    {
        var table = new Table().RoundedBorder();
        table.AddColumn("#");
        table.AddColumn("IP");
        table.AddColumn("Hits");

        var ordered = counts
            .OrderByDescending(kvp => kvp.Value)
            .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
            .Take(top)
            .ToList();

        for (var i = 0; i < ordered.Count; i++)
        {
            var (ip, hits) = ordered[i];
            table.AddRow((i + 1).ToString(), ip, hits.ToString());
        }

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();
    }

    private static void RenderResultsTable(List<AbuseIpCheckResult> results)
    {
        var table = new Table().RoundedBorder();
        table.AddColumn("IP");
        table.AddColumn("Score");
        table.AddColumn("Reports");
        table.AddColumn("Country");
        table.AddColumn("Usage");
        table.AddColumn("ISP");
        table.AddColumn("Last Report");

        foreach (var r in results.OrderByDescending(x => x.AbuseConfidenceScore).ThenByDescending(x => x.TotalReports))
        {
            table.AddRow(
                r.IpAddress,
                r.AbuseConfidenceScore.ToString(),
                r.TotalReports.ToString(),
                r.CountryCode ?? "",
                Trunc(r.UsageType, 26),
                Trunc(r.Isp, 26),
                r.LastReportedAt?.ToString("yyyy-MM-dd") ?? "");
        }

        AnsiConsole.Write(table);
    }

    private static string Trunc(string? s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Length <= max ? s : s[..Math.Max(0, max - 3)] + "...";
    }

    // ---- File/time helpers ----

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

    // ---- CSV/IP extraction ----

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

                var raw = cols[ipIndex];
                var ip = NormalizeIp(raw);
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
            using var fs = new FileStream(
                xlsxPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
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
                // Stop when we leave the summary table region.
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
        var preferred = new[]
        {
            "ip", "ipaddress", "ip_address", "clientip", "client_ip", "client ip", "sourceip", "source_ip", "source ip"
        };

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

        // ipv4:port
        if (s.Contains('.') && s.Count(c => c == ':') == 1)
            s = s.Split(':', 2)[0];

        // [::1]
        if (s.StartsWith('[') && s.EndsWith(']') && s.Length > 2)
            s = s[1..^1];

        return System.Net.IPAddress.TryParse(s, out _) ? s : null;
    }

    private sealed record FileChoice(string FullPath, string Display);
    private sealed record IpChoice(string Ip, int Hits);

    private static List<IpChoice>? SelectIpsWithEsc(string title, int allCount, List<IpChoice> choices, bool includeHits)
    {
        var allChoices = new List<IpChoice> { new(SelectAllSentinel, -1) };
        allChoices.AddRange(choices);

        var selected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var selectedIndex = 0;
        List<IpChoice>? result = null;

        AnsiConsole.Live(BuildIpPicker(title, allChoices, selected, selectedIndex, allCount, includeHits))
            .AutoClear(true)
            .Start(ctx =>
            {
                while (true)
                {
                    var maybe = AnsiConsole.Console.Input.ReadKey(intercept: true);
                    if (maybe is null)
                        continue;

                    var key = maybe.Value;
                    if (key.Key == ConsoleKey.Escape)
                    {
                        result = null;
                        break;
                    }

                    if (key.Key == ConsoleKey.UpArrow)
                    {
                        selectedIndex = (selectedIndex - 1 + allChoices.Count) % allChoices.Count;
                    }
                    else if (key.Key == ConsoleKey.DownArrow)
                    {
                        selectedIndex = (selectedIndex + 1) % allChoices.Count;
                    }
                    else if (key.Key == ConsoleKey.Spacebar)
                    {
                        var current = allChoices[selectedIndex];
                        if (current.Ip == SelectAllSentinel)
                        {
                            if (selected.Contains(SelectAllSentinel))
                            {
                                selected.Clear();
                            }
                            else
                            {
                                selected.Clear();
                                selected.Add(SelectAllSentinel);
                            }
                        }
                        else
                        {
                            selected.Remove(SelectAllSentinel);
                            if (!selected.Add(current.Ip))
                                selected.Remove(current.Ip);
                        }
                    }
                    else if (key.Key == ConsoleKey.Enter)
                    {
                        result = allChoices.Where(x => selected.Contains(x.Ip)).ToList();
                        break;
                    }

                    ctx.UpdateTarget(BuildIpPicker(title, allChoices, selected, selectedIndex, allCount, includeHits));
                    ctx.Refresh();
                }
            });

        return result;
    }

    private static IRenderable BuildIpPicker(string title, List<IpChoice> allChoices, HashSet<string> selected, int selectedIndex, int allCount, bool includeHits)
    {
        var table = new Table().NoBorder();
        table.AddColumn("");

        for (var i = 0; i < allChoices.Count; i++)
        {
            var c = allChoices[i];
            var cursor = i == selectedIndex ? "[green]>[/]" : " ";
            var mark = selected.Contains(c.Ip) ? "[x]" : "[ ]";
            var label = c.Ip == SelectAllSentinel
                ? $"[bold]Select ALL[/] [grey]({allCount} IPs)[/]"
                : includeHits ? $"{c.Ip} [grey]({c.Hits})[/]" : c.Ip;
            table.AddRow($"{cursor} {mark} {label}");
        }

        return new Rows(
            new Markup($"[bold]{Markup.Escape(title)}[/]"),
            new Markup("[grey](Up/Down: move, Space: toggle, Enter: run, Esc: back)[/]"),
            table);
    }
}
