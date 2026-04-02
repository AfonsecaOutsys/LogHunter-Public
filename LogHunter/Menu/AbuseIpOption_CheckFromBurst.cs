using LogHunter.Services;
using LogHunter.Utils;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Menus;

public sealed partial class AbuseIpMenu
{
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
}
