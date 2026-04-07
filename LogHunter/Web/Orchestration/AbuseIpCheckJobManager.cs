using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Services;

namespace LogHunter.Web.Orchestration;

internal sealed class AbuseIpCheckJobManager
{
    private readonly object _gate = new();
    private readonly string _workspaceRoot;
    private AbuseIpCheckJobSnapshot _snapshot = AbuseIpCheckJobSnapshot.CreateIdle();

    public AbuseIpCheckJobManager(string workspaceRoot)
    {
        _workspaceRoot = workspaceRoot;
    }

    public AbuseIpCheckJobSnapshot GetSnapshot()
    {
        lock (_gate)
            return _snapshot;
    }

    public bool TryStart(
        IReadOnlyList<string> ips,
        int maxAgeInDays,
        string? apiKeyOverride,
        out AbuseIpCheckJobSnapshot snapshot,
        out string? error)
    {
        lock (_gate)
        {
            if (string.Equals(_snapshot.State, "running", StringComparison.OrdinalIgnoreCase))
            {
                snapshot = _snapshot;
                error = "An AbuseIPDB check is already running.";
                return false;
            }

            if (ips.Count == 0)
            {
                snapshot = _snapshot;
                error = "At least one IP is required.";
                return false;
            }

            _snapshot = new AbuseIpCheckJobSnapshot(
                JobId: Guid.NewGuid().ToString("N"),
                State: "running",
                Phase: "checking",
                Message: $"Checking {ips.Count} IP(s) against AbuseIPDB.",
                Ips: ips.ToList(),
                CreatedUtc: DateTime.UtcNow,
                UpdatedUtc: DateTime.UtcNow,
                CurrentStep: 0,
                TotalSteps: ips.Count,
                Results: null,
                Failures: null,
                CsvExportPath: null,
                Error: null);

            snapshot = _snapshot;
            error = null;
            _ = RunAsync(_snapshot.JobId, ips, maxAgeInDays, apiKeyOverride);
            return true;
        }
    }

    public bool TryOpenExport(string? jobId, out string message)
    {
        AbuseIpCheckJobSnapshot snapshot;
        lock (_gate)
        {
            snapshot = _snapshot;
            if (!string.IsNullOrWhiteSpace(jobId) && !string.Equals(snapshot.JobId, jobId, StringComparison.Ordinal))
            {
                message = "Job not found.";
                return false;
            }
        }

        var path = snapshot.CsvExportPath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            message = "No export artifact is available.";
            return false;
        }

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true
            });
            message = path;
            return true;
        }
        catch
        {
            try
            {
                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{path}\"");
                message = path;
                return true;
            }
            catch (Exception ex)
            {
                message = ex.Message;
                return false;
            }
        }
    }

    public AbuseIpDbClient.AbuseIpConfig GetConfig()
        => AbuseIpDbClient.LoadConfig(_workspaceRoot);

    public string GetConfigPath()
        => AbuseIpDbClient.GetConfigPath(_workspaceRoot);

    public void SaveConfig(AbuseIpDbClient.AbuseIpConfig config)
        => AbuseIpDbClient.SaveConfig(_workspaceRoot, config);

    private async Task RunAsync(string jobId, IReadOnlyList<string> ips, int maxAgeInDays, string? apiKeyOverride)
    {
        var results = new List<AbuseIpCheckResultDto>();
        var failures = new List<AbuseIpCheckFailureDto>();

        try
        {
            var cfg = AbuseIpDbClient.LoadConfig(_workspaceRoot);
            using var client = new AbuseIpDbClient(_workspaceRoot, apiKeyOverride);

            for (var i = 0; i < ips.Count; i++)
            {
                var ip = ips[i];

                Update(jobId, s => s with
                {
                    Message = $"Checking IP {i + 1} of {ips.Count}: {ip}",
                    CurrentStep = i,
                    UpdatedUtc = DateTime.UtcNow
                });

                try
                {
                    var result = await client.CheckAsync(ip, maxAgeInDays, cfg.Verbose, CancellationToken.None).ConfigureAwait(false);

                    results.Add(new AbuseIpCheckResultDto(
                        IpAddress: result.IpAddress,
                        AbuseConfidenceScore: result.AbuseConfidenceScore,
                        ScoreBand: GetScoreBand(result.AbuseConfidenceScore),
                        TotalReports: result.TotalReports,
                        CountryCode: result.CountryCode,
                        UsageType: result.UsageType,
                        Isp: result.Isp,
                        Domain: result.Domain,
                        LastReportedAt: result.LastReportedAt?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + "Z"));
                }
                catch (AbuseIpQuotaExceededException ex)
                {
                    failures.Add(new AbuseIpCheckFailureDto(ip, $"Quota exceeded: {ex.Message}"));
                    // Stop checking further IPs on quota exhaustion
                    Update(jobId, s => s with
                    {
                        Phase = "quota-exceeded",
                        Message = $"Quota exceeded after {i + 1} of {ips.Count} IPs. Partial results available.",
                        UpdatedUtc = DateTime.UtcNow
                    });
                    break;
                }
                catch (AbuseIpAuthException ex)
                {
                    failures.Add(new AbuseIpCheckFailureDto(ip, $"Auth error: {ex.Message}"));
                    // Stop on auth failures
                    Update(jobId, s => s with
                    {
                        Phase = "auth-failed",
                        Message = $"Authentication failed after {i + 1} of {ips.Count} IPs. Check your API key.",
                        UpdatedUtc = DateTime.UtcNow
                    });
                    break;
                }
                catch (Exception ex)
                {
                    failures.Add(new AbuseIpCheckFailureDto(ip, ex.Message));
                }

                Update(jobId, s => s with
                {
                    CurrentStep = i + 1,
                    UpdatedUtc = DateTime.UtcNow,
                    Results = results.ToList(),
                    Failures = failures.ToList()
                });
            }

            // Export CSV
            string? csvPath = null;
            if (results.Count > 0)
            {
                var outputFolder = AppFolders.Output;
                Directory.CreateDirectory(outputFolder);
                csvPath = Path.Combine(outputFolder, $"abuseipdb_checks_{DateTime.UtcNow:yyyyMMdd_HHmmss}.csv");

                var coreResults = results.Select(r => new AbuseIpCheckResult(
                    IpAddress: r.IpAddress,
                    AbuseConfidenceScore: r.AbuseConfidenceScore,
                    TotalReports: r.TotalReports,
                    CountryCode: r.CountryCode,
                    UsageType: r.UsageType,
                    Isp: r.Isp,
                    Domain: r.Domain,
                    LastReportedAt: string.IsNullOrWhiteSpace(r.LastReportedAt)
                        ? null
                        : DateTimeOffset.Parse(r.LastReportedAt, CultureInfo.InvariantCulture)));

                AbuseIpDbClient.ExportResultsCsv(csvPath, coreResults);
            }

            Update(jobId, s => s with
            {
                State = "completed",
                Phase = "completed",
                Message = $"Checked {results.Count} IP(s). {failures.Count} failure(s).",
                CurrentStep = ips.Count,
                UpdatedUtc = DateTime.UtcNow,
                Results = results,
                Failures = failures,
                CsvExportPath = csvPath
            });
        }
        catch (Exception ex)
        {
            Update(jobId, s => s with
            {
                State = "failed",
                Phase = "failed",
                Message = "AbuseIPDB check failed.",
                UpdatedUtc = DateTime.UtcNow,
                Error = ex.Message,
                Results = results.Count > 0 ? results : null,
                Failures = failures.Count > 0 ? failures : null
            });
        }
    }

    private void Update(string jobId, Func<AbuseIpCheckJobSnapshot, AbuseIpCheckJobSnapshot> update)
    {
        lock (_gate)
        {
            if (!string.Equals(_snapshot.JobId, jobId, StringComparison.Ordinal))
                return;
            _snapshot = update(_snapshot);
        }
    }

    private static string GetScoreBand(int score)
    {
        if (score <= 0) return "Clean";
        if (score <= 25) return "Low";
        if (score <= 50) return "Medium";
        if (score <= 75) return "High";
        return "Critical";
    }
}

internal sealed record AbuseIpCheckJobSnapshot(
    string JobId,
    string State,
    string Phase,
    string Message,
    IReadOnlyList<string> Ips,
    DateTime CreatedUtc,
    DateTime UpdatedUtc,
    int CurrentStep,
    int TotalSteps,
    IReadOnlyList<AbuseIpCheckResultDto>? Results,
    IReadOnlyList<AbuseIpCheckFailureDto>? Failures,
    string? CsvExportPath,
    string? Error)
{
    public static AbuseIpCheckJobSnapshot CreateIdle()
        => new(
            JobId: string.Empty,
            State: "idle",
            Phase: "idle",
            Message: "No AbuseIPDB check has been run yet.",
            Ips: Array.Empty<string>(),
            CreatedUtc: DateTime.UtcNow,
            UpdatedUtc: DateTime.UtcNow,
            CurrentStep: 0,
            TotalSteps: 0,
            Results: null,
            Failures: null,
            CsvExportPath: null,
            Error: null);
}

internal sealed record AbuseIpCheckResultDto(
    string IpAddress,
    int AbuseConfidenceScore,
    string ScoreBand,
    int TotalReports,
    string? CountryCode,
    string? UsageType,
    string? Isp,
    string? Domain,
    string? LastReportedAt);

internal sealed record AbuseIpCheckFailureDto(string Ip, string Error);
