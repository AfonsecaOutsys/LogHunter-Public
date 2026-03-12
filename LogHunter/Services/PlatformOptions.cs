// Services/PlatformOptions.cs
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

public static class PlatformOptions
{
    public static async Task SuspiciousRequestsExtractIpsAsync(SessionState session, CancellationToken ct = default)
    {
        ConsoleEx.Header("Platform: suspicious requests -> extract IPs", $"Workspace: {session.Root}");

        var platformDir = AppFolders.PlatformLogs; // keep folder naming consistent
        if (!Directory.Exists(platformDir))
        {
            ConsoleEx.Warn($"Folder not found: {platformDir}");
            ConsoleEx.Info("Create it and drop Platform log exports (CSV/XLSX) inside.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        PlatformSuspiciousScanResult result = null!;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Processing platform logs...", async ctx =>
            {
                ctx.Status("Processing platform logs... (suspicious request scan)");
                result = await PlatformScanner.ScanSuspiciousRequestsAsync(platformDir, ct).ConfigureAwait(false);
            });

        AnsiConsole.MarkupLine($"[dim]Scanned files:[/] {result.FilesScanned}  [dim]Matched files:[/] {result.FilesMatched}");
        AnsiConsole.MarkupLine($"[dim]Matched rows:[/] {result.MatchedRows}  [dim]Distinct effective IPs:[/] {result.DistinctEffectiveIps}");
        AnsiConsole.MarkupLine($"[dim]Used X-Forwarded-For:[/] {result.RowsWithXff}  [dim]Only ClientIp:[/] {result.RowsWithoutXff}");
        AnsiConsole.WriteLine();

        if (result.MatchedRows == 0)
        {
            ConsoleEx.Warn("No matching suspicious rows were found in the scanned logs.");
            session.PlatformSuspiciousIpHits = null;
            session.PlatformSuspiciousIpHitsUpdatedUtc = null;
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var breakdown = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("Error type")
            .AddColumn(new TableColumn("Rows").RightAligned())
            .AddColumn(new TableColumn("Distinct IPs").RightAligned());

        foreach (var b in result.ByErrorType.OrderByDescending(x => x.Value.Rows))
        {
            breakdown.AddRow(
                Markup.Escape(b.Key),
                b.Value.Rows.ToString(),
                b.Value.DistinctEffectiveIps.ToString());
        }

        AnsiConsole.Write(breakdown);
        AnsiConsole.WriteLine();

        WriteTopTable("Top IPs (overall)", result.TopEffectiveIpsOverall, maxRows: 20);

        foreach (var type in result.TopEffectiveIpsByErrorType.Keys.OrderBy(k => k, StringComparer.OrdinalIgnoreCase))
            WriteTopTable($"Top IPs ({type})", result.TopEffectiveIpsByErrorType[type], maxRows: 20);

        var (added, updated) = UpsertSelections(session.SavedSelections, result);

        // Cache for AbuseIP menu
        session.PlatformSuspiciousIpHits = result.TopEffectiveIpsOverall
            .ToDictionary(x => x.Ip, x => x.Hits, StringComparer.OrdinalIgnoreCase);
        session.PlatformSuspiciousIpHitsUpdatedUtc = DateTime.UtcNow;

        AnsiConsole.WriteLine();
        ConsoleEx.Success($"Saved to session selections: {added} added, {updated} updated.");
        ConsoleEx.Success($"Updated suspicious IP cache: {session.PlatformSuspiciousIpHits.Count} IP(s).");
        ConsoleEx.Pause("Press Enter to return...");
    }

    public static async Task CheckSuspiciousIpsAuthenticatedAsync(SessionState session, CancellationToken ct = default)
    {
        ConsoleEx.Header("Platform: suspicious IPs -> authenticated activity", $"Workspace: {session.Root}");

        var suspicious = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (session.PlatformSuspiciousIpHits is not null)
        {
            foreach (var ip in session.PlatformSuspiciousIpHits.Keys)
                if (!string.IsNullOrWhiteSpace(ip))
                    suspicious.Add(ip);
        }

        foreach (var s in session.SavedSelections)
        {
            if (!string.Equals(s.Source, "Platform", StringComparison.OrdinalIgnoreCase))
                continue;

            if (!string.IsNullOrWhiteSpace(s.IP))
                suspicious.Add(s.IP);
        }

        if (suspicious.Count == 0)
        {
            ConsoleEx.Warn("No suspicious IPs found in session.");
            ConsoleEx.Info("Run: Platform -> Suspicious requests: extract IPs");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var platformDir = AppFolders.PlatformLogs;
        if (!Directory.Exists(platformDir))
        {
            ConsoleEx.Warn($"Folder not found: {platformDir}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        PlatformAuthScanResult result = null!;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Processing platform logs...", async ctx =>
            {
                ctx.Status("Processing platform logs... (authenticated activity check)");
                result = await PlatformAuthScanner.ScanAuthenticatedActivityAsync(platformDir, suspicious, ct).ConfigureAwait(false);
            });

        AnsiConsole.MarkupLine($"[dim]Suspicious IPs (input):[/] {result.SuspiciousIpsInput}");
        AnsiConsole.MarkupLine($"[dim]Scanned files:[/] {result.FilesScanned}  [dim]Matched files:[/] {result.FilesMatched}");
        AnsiConsole.MarkupLine($"[dim]Authenticated hits (UserId != 0):[/] {result.TotalMatchedRows}  [dim]IPs matched:[/] {result.DistinctMatchedIps}");
        AnsiConsole.WriteLine();

        var kTable = new Table().RoundedBorder();
        kTable.AddColumn("Log type");
        kTable.AddColumn(new TableColumn("Auth hits").RightAligned());

        foreach (var k in new[]
        {
            PlatformLogKind.General,
            PlatformLogKind.TraditionalWebRequests,
            PlatformLogKind.ScreenRequests,
            PlatformLogKind.Error
        })
        {
            var hits = result.RowsMatchedByKind.TryGetValue(k, out var v) ? v : 0;
            kTable.AddRow(k.ToString(), hits.ToString());
        }

        AnsiConsole.Write(kTable);
        AnsiConsole.WriteLine();

        // Always update cache (even if empty) so the "count" in the menu is accurate.
        session.PlatformAuthedIpHits = result.HitsByIp.ToDictionary(k => k.Key, v => v.Value.Total, StringComparer.OrdinalIgnoreCase);
        session.PlatformAuthedIpHitsUpdatedUtc = DateTime.UtcNow;

        if (result.DistinctMatchedIps == 0)
        {
            ConsoleEx.Warn("None of the suspicious IPs were found with UserId != 0 in the scanned logs.");
            ConsoleEx.Success("Authenticated IP cache updated (0 matches).");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var table = new Table().RoundedBorder();
        table.AddColumn("#");
        table.AddColumn("IP");
        table.AddColumn(new TableColumn("Total").RightAligned());
        table.AddColumn(new TableColumn("General").RightAligned());
        table.AddColumn(new TableColumn("Traditional").RightAligned());
        table.AddColumn(new TableColumn("Screen").RightAligned());
        table.AddColumn(new TableColumn("Error").RightAligned());

        var ordered = result.HitsByIp
            .OrderByDescending(kvp => kvp.Value.Total)
            .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
            .Take(80)
            .ToList();

        for (int i = 0; i < ordered.Count; i++)
        {
            var ip = ordered[i].Key;
            var h = ordered[i].Value;

            table.AddRow(
                (i + 1).ToString(),
                Markup.Escape(ip),
                h.Total.ToString(),
                h.General.ToString(),
                h.Traditional.ToString(),
                h.Screen.ToString(),
                h.Error.ToString());
        }

        AnsiConsole.Write(table);

        AnsiConsole.WriteLine();
        ConsoleEx.Success($"Authenticated IP cache updated: {session.PlatformAuthedIpHits.Count} IP(s).");
        ConsoleEx.Pause("Press Enter to return...");
    }

    private static void WriteTopTable(string title, IReadOnlyList<(string Ip, int Hits)> top, int maxRows)
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .Title($"[bold]{Markup.Escape(title)}[/]")
            .AddColumn(new TableColumn("#").RightAligned())
            .AddColumn("IP")
            .AddColumn(new TableColumn("Hits").RightAligned());

        var rows = top.Take(maxRows).ToList();
        if (rows.Count == 0)
        {
            AnsiConsole.Write(table);
            AnsiConsole.MarkupLine("[grey](no data)[/]");
            AnsiConsole.WriteLine();
            return;
        }

        for (int i = 0; i < rows.Count; i++)
        {
            table.AddRow(
                (i + 1).ToString(),
                Markup.Escape(rows[i].Ip),
                rows[i].Hits.ToString());
        }

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();
    }

    private static (int Added, int Updated) UpsertSelections(List<SavedSelection> savedSelections, PlatformSuspiciousScanResult result)
    {
        int added = 0, updated = 0;
        var now = DateTime.UtcNow;

        foreach (var typeKvp in result.EffectiveIpCountsByErrorType)
        {
            var errorType = typeKvp.Key;
            var counts = typeKvp.Value
                .OrderByDescending(k => k.Value)
                .ThenBy(k => k.Key, StringComparer.OrdinalIgnoreCase)
                .ToList();

            for (int i = 0; i < counts.Count; i++)
            {
                var ip = counts[i].Key;
                var hits = counts[i].Value;

                var endpoint = $"Platform | {errorType}";
                const string source = "Platform";
                var rank = i + 1;

                var idx = savedSelections.FindIndex(s =>
                    string.Equals(s.Source, source, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(s.Endpoint, endpoint, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(s.IP, ip, StringComparison.OrdinalIgnoreCase));

                var item = new SavedSelection(
                    SavedAtUtc: now,
                    Source: source,
                    Endpoint: endpoint,
                    Rank: rank,
                    IP: ip,
                    Hits: hits);

                if (idx >= 0)
                {
                    savedSelections[idx] = item;
                    updated++;
                }
                else
                {
                    savedSelections.Add(item);
                    added++;
                }
            }
        }

        return (added, updated);
    }
}