using LogHunter.Services;
using LogHunter.Utils;
using Spectre.Console;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Menus;

public sealed partial class AbuseIpMenu
{
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
}
