using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace LogHunter.Web.Orchestration;

internal static class NativeFileDialogHelper
{
    public static async Task<string?> BrowseFolderAsync(string? initialDirectory = null)
    {
        var escapedDir = EscapePowerShell(initialDirectory ?? string.Empty);
        var script = $@"
Add-Type -AssemblyName System.Windows.Forms
$f = New-Object System.Windows.Forms.FolderBrowserDialog
$f.Description = 'Select a folder containing ALB log files'
$f.UseDescriptionForTitle = $true
$f.ShowNewFolderButton = $false
if ('{escapedDir}' -ne '') {{ $f.InitialDirectory = '{escapedDir}' }}
if ($f.ShowDialog() -eq 'OK') {{ $f.SelectedPath }}";

        var output = await RunPowerShellAsync(script).ConfigureAwait(false);
        return string.IsNullOrWhiteSpace(output) ? null : output.Trim();
    }

    public static async Task<IReadOnlyList<string>> BrowseFilesAsync(string? initialDirectory = null)
    {
        var escapedDir = EscapePowerShell(initialDirectory ?? string.Empty);
        var script = $@"
Add-Type -AssemblyName System.Windows.Forms
$f = New-Object System.Windows.Forms.OpenFileDialog
$f.Title = 'Select ALB log files'
$f.Filter = 'Log files (*.log)|*.log|All files (*.*)|*.*'
$f.Multiselect = $true
if ('{escapedDir}' -ne '') {{ $f.InitialDirectory = '{escapedDir}' }}
if ($f.ShowDialog() -eq 'OK') {{ $f.FileNames -join '|' }}";

        var output = await RunPowerShellAsync(script).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(output))
            return Array.Empty<string>();

        return output.Trim().Split('|', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    private static async Task<string> RunPowerShellAsync(string script)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -Command \"{EscapeCommandLine(script)}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            }
        };

        process.Start();
        var output = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
        await process.WaitForExitAsync().ConfigureAwait(false);
        return output;
    }

    private static string EscapePowerShell(string value)
        => value.Replace("'", "''");

    private static string EscapeCommandLine(string script)
        => script
            .Replace("\r\n", "; ")
            .Replace("\n", "; ")
            .Replace("\"", "\\\"");
}
