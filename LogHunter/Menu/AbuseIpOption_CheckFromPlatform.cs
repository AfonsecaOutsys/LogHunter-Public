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

        const int pickerCap = 250;

        var choices = dict
            .OrderByDescending(kvp => kvp.Value)
            .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
            .Take(pickerCap)
            .Select(kvp => new IpChoice(kvp.Key, kvp.Value))
            .ToList();

        AnsiConsole.MarkupLine($"[dim]Picker list:[/] top {choices.Count} by hits (Select ALL still checks full set).");
        AnsiConsole.WriteLine();

        var selectedIps = SelectIpsWithEsc(
            title: "Select IPs to check (Platform suspicious cache)",
            allCount: dict.Count,
            choices: choices,
            includeHits: true);

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
}
