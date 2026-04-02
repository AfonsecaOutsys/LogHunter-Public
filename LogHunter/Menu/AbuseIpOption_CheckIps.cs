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
        using var escListenerCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var escToken = escListenerCts.Token;
        var userCancelled = false;

        // Keep ESC-to-cancel support without spawning a lingering blocking ReadKey task.
        // The listener is scoped to this run and explicitly stopped in finally.
        var escListener = Task.Run(async () =>
        {
            while (!escToken.IsCancellationRequested && !runtimeToken.IsCancellationRequested)
            {
                try
                {
                    if (Console.KeyAvailable)
                    {
                        var maybe = AnsiConsole.Console.Input.ReadKey(intercept: true);
                        if (maybe is not null && maybe.Value.Key == ConsoleKey.Escape)
                        {
                            userCancelled = true;
                            linkedCts.Cancel();
                            return;
                        }
                    }
                }
                catch
                {
                    // Some hosts can throw for KeyAvailable; ignore and keep running checks.
                }

                try
                {
                    await Task.Delay(40, escToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }, escToken);

        try
        {
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
                                        .AddChoices("Enter different key (this run only)", "Save different key to config", "Skip this ip"));

                                if (action == "Skip this ip")
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
        }
        finally
        {
            if (!escListenerCts.IsCancellationRequested)
                escListenerCts.Cancel();

            try
            {
                await escListener.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected when leaving the check loop.
            }
        }

        client.Dispose();

        ConsoleEx.Header("AbuseIPDB: results", $"Source: {sourceLabel} | Checked: {results.Count} | Failed: {failures.Count}");

        if (userCancelled)
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
}
