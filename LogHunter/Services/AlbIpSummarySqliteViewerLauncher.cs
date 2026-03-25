using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;

namespace LogHunter.Services;

public static class AlbIpSummarySqliteViewerLauncher
{
    public static bool Launch(string dbPath, string? requestedIp)
    {
        if (string.IsNullOrWhiteSpace(dbPath) || !File.Exists(dbPath))
            return false;

        var executablePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
            return false;

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                Arguments = BuildArguments(dbPath, requestedIp),
                UseShellExecute = true,
                WorkingDirectory = AppContext.BaseDirectory
            };

            _ = Process.Start(startInfo);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string BuildArguments(string dbPath, string? requestedIp)
    {
        var args = $"--viewer-sqlite {QuoteArg(Path.GetFullPath(dbPath))}";
        if (!string.IsNullOrWhiteSpace(requestedIp))
            args += $" --viewer-ip {QuoteArg(requestedIp)}";
        return args;
    }

    private static string QuoteArg(string value)
        => value.Contains(' ', StringComparison.Ordinal) || value.Contains('"', StringComparison.Ordinal)
            ? '"' + value.Replace("\"", "\\\"", StringComparison.Ordinal) + '"'
            : value;
}
