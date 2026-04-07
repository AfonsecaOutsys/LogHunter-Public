using ClosedXML.Excel;
using LogHunter.Services;
using LogHunter.Utils;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Menus;

public sealed partial class AbuseIpMenu
{
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
}
