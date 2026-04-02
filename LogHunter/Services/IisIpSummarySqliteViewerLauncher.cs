using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace LogHunter.Services;

public static class IisIpSummarySqliteViewerLauncher
{
    public static bool Launch(string dbPath, string? requestedIp)
    {
        if (string.IsNullOrWhiteSpace(dbPath) || !File.Exists(dbPath))
            return false;

        var executablePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
            return false;

        var viewerPort = GetFreePort();
        var viewerUrl = $"http://127.0.0.1:{viewerPort}/";

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                Arguments = BuildArguments(dbPath, requestedIp, viewerPort),
                UseShellExecute = true,
                WorkingDirectory = AppContext.BaseDirectory
            };

            _ = Process.Start(startInfo);
            TryOpenBrowser(viewerUrl);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string BuildArguments(string dbPath, string? requestedIp, int viewerPort)
    {
        var args = $"--viewer-sqlite {QuoteArg(Path.GetFullPath(dbPath))} --viewer-port {viewerPort}";
        if (!string.IsNullOrWhiteSpace(requestedIp))
            args += $" --viewer-ip {QuoteArg(requestedIp)}";
        return args;
    }

    private static bool TryOpenBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static int GetFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static string QuoteArg(string value)
        => value.Contains(' ', StringComparison.Ordinal) || value.Contains('"', StringComparison.Ordinal)
            ? '"' + value.Replace("\"", "\\\"", StringComparison.Ordinal) + '"'
            : value;
}
