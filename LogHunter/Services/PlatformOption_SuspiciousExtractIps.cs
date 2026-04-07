using LogHunter.Models;
using LogHunter.Utils;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Services;

public static partial class PlatformOptions
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
