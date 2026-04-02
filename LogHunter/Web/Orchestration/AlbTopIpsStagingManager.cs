using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using LogHunter.Services;

namespace LogHunter.Web.Orchestration;

internal sealed class AlbTopIpsStagingManager
{
    private readonly string _stagingRoot;

    public AlbTopIpsStagingManager(string stagingRoot)
    {
        _stagingRoot = stagingRoot;
        Directory.CreateDirectory(_stagingRoot);
    }

    public string CreateSession(AlbTopIpsInputSourceType sourceType)
    {
        CleanupExpiredSessions();

        var sessionId = Guid.NewGuid().ToString("N");
        var sessionPath = GetSessionPath(sessionId);
        Directory.CreateDirectory(sessionPath);
        File.WriteAllText(Path.Combine(sessionPath, ".source"), sourceType.ToString());
        return sessionId;
    }

    public void SaveFile(string sessionId, string relativePath, Stream source)
    {
        var sessionPath = GetSessionPath(sessionId);
        if (!Directory.Exists(sessionPath))
            throw new DirectoryNotFoundException("The upload session was not found.");

        var safeRelativePath = NormalizeRelativePath(relativePath);
        var destinationPath = Path.Combine(sessionPath, safeRelativePath);
        var destinationDirectory = Path.GetDirectoryName(destinationPath);
        if (!string.IsNullOrWhiteSpace(destinationDirectory))
            Directory.CreateDirectory(destinationDirectory);

        using var destination = File.Create(destinationPath);
        source.CopyTo(destination);
    }

    public bool TryBuildSelection(string sessionId, AlbTopIpsInputSourceType sourceType, out AlbTopIpsInputSourceSelection selection, out string? error)
    {
        var sessionPath = GetSessionPath(sessionId);
        if (!Directory.Exists(sessionPath))
        {
            selection = AlbTopIpsInputSourceSelection.Empty(sourceType);
            error = "The selected upload session is no longer available.";
            return false;
        }

        var files = Directory.EnumerateFiles(sessionPath, "*.log", SearchOption.AllDirectories)
            .ToList();

        if (files.Count == 0)
        {
            selection = AlbTopIpsInputSourceSelection.Empty(sourceType);
            error = sourceType == AlbTopIpsInputSourceType.SelectedFolder
                ? "The selected folder did not contain any .log files."
                : "No .log files were uploaded.";
            return false;
        }

        var label = sourceType == AlbTopIpsInputSourceType.SelectedFolder
            ? BuildFolderLabel(sessionPath, files)
            : $"{files.Count} uploaded file(s)";

        selection = AlbTopIpsInputSourceResolver.BuildUploadedSelection(sourceType, sessionPath, files, label);
        error = null;
        return true;
    }

    private void CleanupExpiredSessions()
    {
        try
        {
            var cutoffUtc = DateTime.UtcNow.AddHours(-12);
            foreach (var directory in Directory.EnumerateDirectories(_stagingRoot))
            {
                try
                {
                    var info = new DirectoryInfo(directory);
                    if (info.LastWriteTimeUtc < cutoffUtc)
                        info.Delete(recursive: true);
                }
                catch
                {
                }
            }
        }
        catch
        {
        }
    }

    private string GetSessionPath(string sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId) || sessionId.Any(static ch => !char.IsLetterOrDigit(ch)))
            throw new InvalidOperationException("Invalid upload session id.");

        return Path.Combine(_stagingRoot, sessionId);
    }

    private static string NormalizeRelativePath(string relativePath)
    {
        var sanitized = (relativePath ?? string.Empty)
            .Replace('/', Path.DirectorySeparatorChar)
            .Replace('\\', Path.DirectorySeparatorChar)
            .TrimStart(Path.DirectorySeparatorChar);

        if (string.IsNullOrWhiteSpace(sanitized))
            throw new InvalidOperationException("Uploaded file path is missing.");

        var parts = sanitized
            .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries)
            .Where(static part => part != ".")
            .ToArray();

        if (parts.Length == 0 || parts.Any(static part => part == ".."))
            throw new InvalidOperationException("Uploaded file path is invalid.");

        return Path.Combine(parts);
    }

    private static string BuildFolderLabel(string sessionPath, IReadOnlyList<string> files)
    {
        if (files.Count == 0)
            return "Uploaded folder";

        var relativePath = Path.GetRelativePath(sessionPath, files[0]);
        if (string.IsNullOrWhiteSpace(relativePath))
            return "Uploaded folder";

        var normalized = relativePath.Replace('\\', '/');
        var firstSegment = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return string.IsNullOrWhiteSpace(firstSegment) ? "Uploaded folder" : firstSegment;
    }
}
