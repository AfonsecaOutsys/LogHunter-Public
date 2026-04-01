using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using LogHunter.Services;

namespace LogHunter.Web.Orchestration;

internal static class AlbTopIpsInputSourceResolver
{
    public static AlbTopIpsInputSourceSelection ResolveDefaultFolder()
    {
        var files = AlbScanner.GetLogFiles(AppFolders.ALB);
        return BuildSelection(
            sourceType: AlbTopIpsInputSourceType.DefaultFolder,
            rootPath: AppFolders.ALB,
            files: files,
            selectionLabel: AppFolders.ALB);
    }

    public static bool TryResolve(AlbTopIpsInputSourceRequest request, out AlbTopIpsInputSourceSelection selection, out string? error)
    {
        error = null;

        var sourceType = NormalizeSourceType(request.SourceType);
        if (sourceType == AlbTopIpsInputSourceType.DefaultFolder)
        {
            selection = ResolveDefaultFolder();
            return true;
        }

        if (sourceType == AlbTopIpsInputSourceType.SelectedFolder)
        {
            var folderPath = request.FolderPath?.Trim();
            if (string.IsNullOrWhiteSpace(folderPath))
            {
                selection = AlbTopIpsInputSourceSelection.Empty(sourceType);
                error = "Select a folder before running the scan.";
                return false;
            }

            if (!Directory.Exists(folderPath))
            {
                selection = AlbTopIpsInputSourceSelection.Empty(sourceType);
                error = $"Folder not found: {folderPath}";
                return false;
            }

            var files = AlbScanner.GetLogFiles(folderPath);
            selection = BuildSelection(sourceType, folderPath, files, folderPath);
            return true;
        }

        var selectedFiles = (request.FilePaths ?? Array.Empty<string>())
            .Where(static path => !string.IsNullOrWhiteSpace(path))
            .Select(static path => path.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (selectedFiles.Count == 0)
        {
            selection = AlbTopIpsInputSourceSelection.Empty(sourceType);
            error = "Select one or more log files before running the scan.";
            return false;
        }

        var existingFiles = selectedFiles
            .Where(File.Exists)
            .ToList();

        if (existingFiles.Count == 0)
        {
            selection = AlbTopIpsInputSourceSelection.Empty(sourceType);
            error = "None of the selected files are available anymore.";
            return false;
        }

        selection = BuildSelection(sourceType, null, existingFiles, $"{existingFiles.Count} selected file(s)");
        return true;
    }

    public static AlbTopIpsInputSourceType NormalizeSourceType(string? value)
        => string.Equals(value, "folder", StringComparison.OrdinalIgnoreCase)
            ? AlbTopIpsInputSourceType.SelectedFolder
            : string.Equals(value, "files", StringComparison.OrdinalIgnoreCase)
                ? AlbTopIpsInputSourceType.SelectedFiles
                : AlbTopIpsInputSourceType.DefaultFolder;

    private static AlbTopIpsInputSourceSelection BuildSelection(
        AlbTopIpsInputSourceType sourceType,
        string? rootPath,
        IReadOnlyList<string> files,
        string selectionLabel)
    {
        var totalBytes = SumFileSizesSafe(files);
        var fileCount = files.Count;
        var summary = sourceType switch
        {
            AlbTopIpsInputSourceType.DefaultFolder => $"Default folder | {selectionLabel} | {fileCount:N0} files | {FormatBytes(totalBytes)}",
            AlbTopIpsInputSourceType.SelectedFolder => $"Selected folder | {selectionLabel} | {fileCount:N0} files | {FormatBytes(totalBytes)}",
            _ => $"Selected files | {fileCount:N0} files | {FormatBytes(totalBytes)}"
        };

        return new AlbTopIpsInputSourceSelection(
            SourceType: sourceType,
            RootPath: rootPath,
            Files: files.ToList(),
            FileCount: fileCount,
            TotalBytes: totalBytes,
            SelectionLabel: selectionLabel,
            Summary: summary,
            PreviewItems: BuildPreviewItems(files));
    }

    private static IReadOnlyList<string> BuildPreviewItems(IReadOnlyList<string> files)
        => files
            .Take(3)
            .Select(Path.GetFileName)
            .Where(static name => !string.IsNullOrWhiteSpace(name))
            .Cast<string>()
            .ToList();

    private static long SumFileSizesSafe(IEnumerable<string> files)
    {
        long total = 0;
        foreach (var path in files)
        {
            try
            {
                total += new FileInfo(path).Length;
            }
            catch
            {
            }
        }

        return total;
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0)
            return "0 B";

        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double size = bytes;
        int index = 0;
        while (size >= 1024 && index < units.Length - 1)
        {
            size /= 1024;
            index++;
        }

        return $"{size.ToString(size >= 10 || index == 0 ? "0" : "0.0")} {units[index]}";
    }
}

internal sealed record AlbTopIpsInputSourceRequest(
    string SourceType,
    string? FolderPath,
    IReadOnlyList<string> FilePaths);

internal enum AlbTopIpsInputSourceType
{
    DefaultFolder,
    SelectedFolder,
    SelectedFiles
}

internal sealed record AlbTopIpsInputSourceSelection(
    AlbTopIpsInputSourceType SourceType,
    string? RootPath,
    IReadOnlyList<string> Files,
    int FileCount,
    long TotalBytes,
    string SelectionLabel,
    string Summary,
    IReadOnlyList<string> PreviewItems)
{
    public static AlbTopIpsInputSourceSelection Empty(AlbTopIpsInputSourceType sourceType)
        => new(sourceType, null, Array.Empty<string>(), 0, 0, string.Empty, string.Empty, Array.Empty<string>());
}
