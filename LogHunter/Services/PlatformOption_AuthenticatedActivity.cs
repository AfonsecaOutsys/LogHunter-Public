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
}
