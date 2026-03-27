using System;
using System.Collections.Generic;

namespace LogHunter.Services;

internal sealed record AlbDownloadRequest(
    bool UseSavedConfig,
    string? SavedConfigName,
    string? ConfigName,
    string? Bucket,
    string? AlbId,
    bool UseInternalScope,
    string? AccountId,
    string? Region,
    bool IsSentry,
    string AwsEnvironmentText,
    DateTime StartUtc,
    DateTime EndUtc);

internal sealed record AlbDownloadConfigSummary(
    string Name,
    string Bucket,
    string AlbId,
    string Scope,
    string AccountId,
    string Region,
    bool IsSentry,
    DateTime LastUsedUtc);

internal sealed record AlbDownloadRunProgress(
    string Stage,
    string Message,
    int? CurrentStep = null,
    int? TotalSteps = null);

internal sealed record AlbDownloadRunResult(
    bool Success,
    string Message,
    string ConfigName,
    string PrefixRoot,
    string AlbKey,
    string RunFolder,
    int DaysRequested,
    int DaySyncFailures,
    int DownloadedGzipFiles,
    int PrunedFiles,
    int UnknownTimestampFilesKept,
    int KeptForExtraction,
    int ExtractedLogFiles,
    int ExtractFailedCount,
    int FinalLogFileCount,
    IReadOnlyList<string> SampleLogFiles);
