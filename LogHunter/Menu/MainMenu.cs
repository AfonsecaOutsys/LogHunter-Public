// Menus/MainMenu.cs
using LogHunter.Services;
using LogHunter.Utils;
using Spectre.Console;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Menus;

public sealed class MainMenu : IMenu
{
    private readonly SessionState _session;

    public MainMenu(SessionState session) => _session = session;

    public Task<IMenu?> ShowAsync(CancellationToken ct = default)
    {
        ConsoleEx.Header("LogHunter", $"Workspace: {_session.Root}");
        if (TraceLog.IsEnabled)
            ConsoleEx.Warn(TraceLog.ReportNotice);

        var savedCount = _session.SavedSelections.Count;

        var items = new[]
        {
            new ConsoleEx.MenuItem(
                "ALB",
                "AWS Application Load Balancer logs.\nDownload, scan, and summarize traffic."),

            new ConsoleEx.MenuItem(
                "IIS",
                "IIS W3C logs.\nBursts, status-code pivots, bandwidth, and payload intel."),

            new ConsoleEx.MenuItem(
                "Platform",
                "OutSystems Platform logs.\nSuspicious request patterns and authenticated-activity checks."),

            new ConsoleEx.MenuItem(
                "IP reputation (AbuseIPDB)",
                "Check IP reputation and export results to CSV."),

            new ConsoleEx.MenuItem(
                $"Saved selections ({savedCount})",
                "View items saved in this session."),

            new ConsoleEx.MenuItem(
                $"Export saved selections ({savedCount})",
                "Export all saved selections to CSV in the output folder."),

            new ConsoleEx.MenuItem(
                $"Clear saved selections ({savedCount})",
                "Remove all saved selections from this session."),

            new ConsoleEx.MenuItem(
                "Exit",
                "Quit LogHunter.")
        };

        var selected = ConsoleEx.Menu("Main menu", items, pageSize: 10);

        // Esc exits from the main menu.
        if (selected is null)
            return Task.FromResult<IMenu?>(null);

        switch (selected.Value)
        {
            case 0:
                return Task.FromResult<IMenu?>(new AlbMenu(_session));

            case 1:
                return Task.FromResult<IMenu?>(new IisMenu(_session));

            case 2:
                return Task.FromResult<IMenu?>(new PlatformMenu(_session));

            case 3:
                return Task.FromResult<IMenu?>(new AbuseIpMenu(_session));

            case 4:
                ConsoleEx.Header("Saved selections", $"Count: {savedCount}");

                if (savedCount == 0)
                    AnsiConsole.MarkupLine("[grey](no saved selections)[/]");
                else
                    SelectionService.ShowSavedSelections(_session.SavedSelections);

                ConsoleEx.Pause("Press Enter to return...");
                return Task.FromResult<IMenu?>(this);

            case 5:
                ConsoleEx.Header("Export saved selections", $"Count: {savedCount}");

                if (savedCount == 0)
                {
                    AnsiConsole.MarkupLine("[grey](no saved selections to export)[/]");
                    ConsoleEx.Pause("Press Enter to return...");
                    return Task.FromResult<IMenu?>(this);
                }

                var outDir = AppFolders.Output; // consistent location
                SelectionService.ExportAll(outDir, _session.SavedSelections);

                ConsoleEx.Success("Export complete.");
                AnsiConsole.MarkupLine($"[dim]Output:[/] {Markup.Escape(outDir)}");

                ConsoleEx.Pause("Press Enter to return...");
                return Task.FromResult<IMenu?>(this);

            case 6:
                ConsoleEx.Header("Clear saved selections", $"Count: {savedCount}");

                if (savedCount == 0)
                {
                    AnsiConsole.MarkupLine("[grey](no saved selections to clear)[/]");
                    ConsoleEx.Pause("Press Enter to return...");
                    return Task.FromResult<IMenu?>(this);
                }

                if (ConsoleEx.ReadYesNo("Clear all saved selections for this session?", defaultYes: false))
                {
                    SelectionService.ClearSavedSelections(_session.SavedSelections);
                    ConsoleEx.Success("Cleared.");
                }
                else
                {
                    ConsoleEx.Info("Cancelled.");
                }

                ConsoleEx.Pause("Press Enter to return...");
                return Task.FromResult<IMenu?>(this);

            case 7:
                return Task.FromResult<IMenu?>(null);

            default:
                return Task.FromResult<IMenu?>(this);
        }
    }
}