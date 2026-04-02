using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ClosedXML.Excel;
using LogHunter.Models;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static partial class AlbOptions
{
    // ---------- OPTION 2 ----------

    public static async Task TopIpsForEndpointAsync(string root, List<SavedSelection> _savedSelections)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Top full paths by IP for endpoint/path fragment",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var endpoint = ConsoleEx.ReadLineWithEsc("Endpoint/path fragment (e.g., login or /login/):");
        if (endpoint is null)
            return;

        if (string.IsNullOrWhiteSpace(endpoint))
        {
            ConsoleEx.Warn("No endpoint provided.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        const int topIpCount = AlbTopIpsForEndpointWorkflow.DefaultTopIpCount;
        const int topUriPerIpCount = AlbTopIpsForEndpointWorkflow.DefaultTopUriPerIpCount;

        InfoPanel("Scan plan",
            ("Mode", "Top IPs for endpoint fragment + top full paths per IP (no query)"),
            ("Endpoint fragment", endpoint),
            ("Passes", "2"),
            ("Top IPs", topIpCount.ToString(CultureInfo.InvariantCulture)),
            ("Top URIs per IP", topUriPerIpCount.ToString(CultureInfo.InvariantCulture)),
            ("Files", files.Count.ToString("N0")),
            ("Input", albFolder));

        var endpointIpCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        await RunScanWithProgressAsync(
            title: "Scanning ALB logs (pass 1/2: top IPs for fragment)",
            files: files,
            scanFileAsync: (file, reportDelta) =>
                AlbScanner.ScanFileForEndpointIpCountsAsync(
                    filePath: file,
                    endpointFragment: endpoint,
                    ipCounts: endpointIpCounts,
                    reportBytesDelta: reportDelta)
        );

        if (endpointIpCounts.Count == 0)
        {
            ConsoleEx.Warn($"No hits found for: {endpoint}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var topIps = endpointIpCounts
            .OrderByDescending(kvp => kvp.Value)
            .ThenBy(kvp => kvp.Key, StringComparer.Ordinal)
            .Take(topIpCount)
            .Select((kvp, idx) => new TopIpRow(idx + 1, kvp.Key, kvp.Value))
            .ToList();

        var selectedIps = new HashSet<string>(topIps.Select(x => x.IP), StringComparer.Ordinal);

        // Pass 2: only for top IPs, count URI hits by IP.
        var uriCountsByIp = new Dictionary<string, Dictionary<string, int>>(StringComparer.Ordinal);

        await RunScanWithProgressAsync(
            title: "Scanning ALB logs (pass 2/2: top full paths per top IP)",
            files: files,
            scanFileAsync: (file, reportDelta) =>
                AlbScanner.ScanFileForEndpointUriCountsBySelectedIpsAsync(
                    filePath: file,
                    endpointFragment: endpoint,
                    selectedIps: selectedIps,
                    uriCountsByIp: uriCountsByIp,
                    reportBytesDelta: reportDelta)
        );

        var result = AlbTopIpsForEndpointWorkflow.BuildResult(
            endpoint,
            files.Count,
            endpointIpCounts,
            uriCountsByIp,
            topIpCount,
            topUriPerIpCount);

        var topIpsTable = TopTable("IP Rank", "Hits", "IP");
        foreach (var row in result.TopIps)
            topIpsTable.AddRow(
                row.Rank.ToString(CultureInfo.InvariantCulture),
                row.Hits.ToString("N0", CultureInfo.InvariantCulture),
                Markup.Escape(row.IP));

        AnsiConsole.Write(new Panel(topIpsTable)
        {
            Header = new PanelHeader($"Top IPs matching fragment: {Markup.Escape(endpoint)} (max {topIpCount})"),
            Border = BoxBorder.Rounded
        });
        AnsiConsole.WriteLine();

        foreach (var group in result.TopIps)
        {
            var urisTable = TopTable("URI Rank", "Hits", "URI (no query)");
            if (group.TopUris.Count == 0)
            {
                urisTable.AddRow("-", "0", "(no URI matches)");
            }
            else
            {
                for (int i = 0; i < group.TopUris.Count; i++)
                {
                    var row = group.TopUris[i];
                    urisTable.AddRow(
                        row.Rank.ToString(CultureInfo.InvariantCulture),
                        row.Hits.ToString("N0", CultureInfo.InvariantCulture),
                        Markup.Escape(row.URI));
                }
            }

            AnsiConsole.Write(new Panel(urisTable)
            {
                Header = new PanelHeader(
                    $"IP #{group.Rank}: {Markup.Escape(group.IP)} ({group.Hits:N0} hits)"),
                Border = BoxBorder.Rounded
            });
            AnsiConsole.WriteLine();
        }

        var doExport = ConsoleEx.ReadYesNo("Export these results now?", defaultYes: true);
        if (doExport)
        {
            var outFile = AlbTopIpsForEndpointWorkflow.ExportXlsx(outputFolder, result);
            ConsoleEx.Success($"Exported: {outFile}");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }
}
