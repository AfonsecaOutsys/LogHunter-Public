using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace LogHunter.Web.Orchestration;

internal static class WindowsPathPicker
{
    public static bool TryPickFolder(out string? folderPath, out string? error)
    {
        var script = """
Add-Type -AssemblyName System.Windows.Forms
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = 'Select ALB log folder'
$dialog.ShowNewFolderButton = $false
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
  Write-Output $dialog.SelectedPath
}
""";

        if (!TryRunPicker(script, out var lines, out error))
        {
            folderPath = null;
            return false;
        }

        folderPath = lines.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(folderPath))
        {
            error = "Folder selection was canceled.";
            return false;
        }

        return true;
    }

    public static bool TryPickFiles(out IReadOnlyList<string> files, out string? error)
    {
        var script = """
Add-Type -AssemblyName System.Windows.Forms
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = 'Select ALB log files'
$dialog.Filter = 'Log files (*.log)|*.log|All files (*.*)|*.*'
$dialog.Multiselect = $true
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
  $dialog.FileNames | ForEach-Object { Write-Output $_ }
}
""";

        if (!TryRunPicker(script, out var lines, out error))
        {
            files = Array.Empty<string>();
            return false;
        }

        files = lines
            .Where(static line => !string.IsNullOrWhiteSpace(line))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (files.Count == 0)
        {
            error = "File selection was canceled.";
            return false;
        }

        return true;
    }

    private static bool TryRunPicker(string script, out IReadOnlyList<string> lines, out string? error)
    {
        lines = Array.Empty<string>();
        error = null;

        try
        {
            var encodedScript = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -STA -EncodedCommand {encodedScript}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            using var process = Process.Start(psi);
            if (process is null)
            {
                error = "Unable to start the Windows picker process.";
                return false;
            }

            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                error = string.IsNullOrWhiteSpace(stderr)
                    ? "The Windows picker process failed."
                    : stderr.Trim();
                return false;
            }

            lines = stdout
                .Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries)
                .Select(static line => line.Trim())
                .Where(static line => line.Length > 0)
                .ToList();

            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }
}
