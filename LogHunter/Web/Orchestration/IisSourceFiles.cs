using System.Collections.Generic;
using System.IO;
using System.Linq;
using LogHunter.Services;
using LogHunter.Utils;

namespace LogHunter.Web.Orchestration;

/// <summary>
/// IIS log files for a run: selected files, else a selected folder, else the workspace IIS folder.
/// Same rule as Burst Patterns, shared by Status Pivot and Bytes Intel.
/// </summary>
internal static class IisSourceFiles
{
    public static List<string> Resolve(IReadOnlyList<string>? customFiles, string? customFolderPath)
    {
        if (customFiles is { Count: > 0 })
            return customFiles.Where(File.Exists).ToList();
        if (!string.IsNullOrWhiteSpace(customFolderPath) && Directory.Exists(customFolderPath))
            return IisW3cReader.EnumerateLogFiles(customFolderPath);
        return IisW3cReader.EnumerateLogFiles(AppFolders.IIS);
    }

    public static string Describe(IReadOnlyList<string>? customFiles, string? customFolderPath) =>
        customFiles is { Count: > 0 } ? "the selected files"
        : !string.IsNullOrWhiteSpace(customFolderPath) ? customFolderPath
        : AppFolders.IIS;
}
