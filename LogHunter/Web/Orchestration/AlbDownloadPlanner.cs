using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using LogHunter.Services;

namespace LogHunter.Web.Orchestration;

internal static class AlbDownloadPlanner
{
    private static readonly Regex AlbTimestampRegex =
        new(@"_(\d{8})T(\d{4})Z_", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex AwsRegionAtEndRegex =
        new(@"(?<region>(?:af|ap|ca|eu|me|sa|us|cn)-[a-z0-9-]+-\d)$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex AwsLsLineRegex =
        new(@"^(?<date>\d{4}-\d{2}-\d{2})\s+\d{2}:\d{2}:\d{2}\s+(?<size>\d+)\s+(?<key>.+)$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static async Task<AlbDownloadExecutionPlan> BuildPlanAsync(
        AlbDownloadRequest request,
        Action<int, int, string>? reportPlanningProgress = null)
    {
        AppFolders.Ensure();

        var awsExe = ResolveAwsExePath();
        if (string.IsNullOrWhiteSpace(awsExe))
            throw new InvalidOperationException("AWS CLI (aws.exe) was not found. Install AWS CLI v2 or ensure it is available on PATH.");

        var creds = ParseAwsEnvVars(request.AwsEnvironmentText ?? string.Empty);
        if (!creds.IsValid)
            throw new InvalidOperationException("AWS credentials could not be parsed. Paste the 3 AWS environment lines for access key, secret key, and session token.");

        if (request.EndUtc < request.StartUtc)
            throw new InvalidOperationException("End time must be greater than or equal to start time.");

        var resolved = ResolveConfig(request);
        var runFolder = AlbDownload.BuildRunFolder(resolved.ConfigName, request.StartUtc, request.EndUtc);
        var prefixRoot = resolved.IsSentry ? "sentry" : "standard";
        var albKey = resolved.UseInternalScope ? $"{resolved.AlbId}-internal" : resolved.AlbId;

        var days = EachDayUtc(request.StartUtc.Date, request.EndUtc.Date).ToList();
        var dayPlans = new List<AlbDownloadDayPlan>(days.Count);

        for (var i = 0; i < days.Count; i++)
        {
            var day = days[i];
            reportPlanningProgress?.Invoke(i, days.Count, $"Planning {day:yyyy-MM-dd}");

            var dayPrefix =
                $"{prefixRoot}/{albKey}/AWSLogs/{resolved.AccountId}/elasticloadbalancing/{resolved.Region}/{day:yyyy}/{day:MM}/{day:dd}/";

            var s3Uri = $"s3://{resolved.Bucket}/{dayPrefix}";
            var lines = await RunAwsListAsync(awsExe, s3Uri, creds).ConfigureAwait(false);

            var totalFiles = 0;
            var totalBytes = 0L;
            var inWindowFiles = 0;
            var inWindowBytes = 0L;

            foreach (var line in lines)
            {
                var match = AwsLsLineRegex.Match(line);
                if (!match.Success)
                    continue;

                var key = match.Groups["key"].Value.Trim();
                if (!key.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!long.TryParse(match.Groups["size"].Value, out var size))
                    size = 0;

                totalFiles++;
                totalBytes += size;

                var stamp = TryParseAlbTimestampUtc(Path.GetFileName(key));
                if (!stamp.HasValue)
                    continue;

                var intervalEnd = stamp.Value;
                var intervalStart = intervalEnd.AddMinutes(-5);
                var overlaps = intervalStart <= request.EndUtc && intervalEnd >= request.StartUtc;
                if (!overlaps)
                    continue;

                inWindowFiles++;
                inWindowBytes += size;
            }

            dayPlans.Add(new AlbDownloadDayPlan(
                day.ToString("yyyy-MM-dd"),
                totalFiles,
                totalBytes,
                inWindowFiles,
                inWindowBytes));

            reportPlanningProgress?.Invoke(i + 1, days.Count, $"Planned {day:yyyy-MM-dd}: {totalFiles} file(s)");
        }

        return new AlbDownloadExecutionPlan(
            resolved.ConfigName,
            resolved.Bucket,
            prefixRoot,
            albKey,
            runFolder,
            dayPlans.Sum(x => x.TotalFiles),
            dayPlans.Sum(x => x.TotalBytes),
            dayPlans.Sum(x => x.InWindowFiles),
            dayPlans.Sum(x => x.InWindowBytes),
            dayPlans);
    }

    private static AlbDownloadResolvedConfig ResolveConfig(AlbDownloadRequest request)
    {
        if (request.UseSavedConfig)
        {
            var name = request.SavedConfigName?.Trim();
            if (string.IsNullOrWhiteSpace(name))
                throw new InvalidOperationException("Saved configuration is required.");

            var saved = AlbDownload.GetSavedConfigSummaries()
                .FirstOrDefault(x => string.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase));

            if (saved is null)
                throw new InvalidOperationException($"Saved configuration '{name}' was not found.");

            return new AlbDownloadResolvedConfig(
                saved.Name,
                saved.Bucket,
                saved.AlbId,
                string.Equals(saved.Scope, "Internal", StringComparison.OrdinalIgnoreCase),
                saved.AccountId,
                saved.Region,
                saved.IsSentry);
        }

        var bucket = request.Bucket?.Trim();
        var albId = request.AlbId?.Trim();
        var accountId = request.AccountId?.Trim();

        if (string.IsNullOrWhiteSpace(bucket))
            throw new InvalidOperationException("S3 bucket is required for a new configuration.");

        if (string.IsNullOrWhiteSpace(albId))
            throw new InvalidOperationException("ALB identifier is required for a new configuration.");

        if (string.IsNullOrWhiteSpace(accountId))
            throw new InvalidOperationException("AWS account ID is required for a new configuration.");

        var region = request.Region?.Trim();
        if (string.IsNullOrWhiteSpace(region))
            region = TryDeriveRegionFromBucket(bucket);

        if (string.IsNullOrWhiteSpace(region))
            throw new InvalidOperationException("Region is required when it cannot be derived from the bucket name.");

        var defaultName = request.UseInternalScope ? $"{albId}-internal" : albId;
        var configName = string.IsNullOrWhiteSpace(request.ConfigName) ? defaultName : request.ConfigName.Trim();

        return new AlbDownloadResolvedConfig(
            SanitizeFileName(configName),
            bucket,
            albId,
            request.UseInternalScope,
            accountId,
            region,
            request.IsSentry);
    }

    private static async Task<IReadOnlyList<string>> RunAwsListAsync(string awsExePath, string s3Uri, AwsCreds creds)
    {
        var psi = new ProcessStartInfo
        {
            FileName = awsExePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = GetWorkingDirectorySafe()
        };

        psi.ArgumentList.Add("s3");
        psi.ArgumentList.Add("ls");
        psi.ArgumentList.Add(s3Uri);
        psi.ArgumentList.Add("--recursive");

        psi.Environment["AWS_ACCESS_KEY_ID"] = creds.AccessKeyId;
        psi.Environment["AWS_SECRET_ACCESS_KEY"] = creds.SecretAccessKey;
        psi.Environment["AWS_SESSION_TOKEN"] = creds.SessionToken;
        psi.Environment["AWS_PAGER"] = "";
        psi.Environment["AWS_EC2_METADATA_DISABLED"] = "true";

        using var proc = new Process { StartInfo = psi };

        try
        {
            proc.Start();

            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();

            await proc.WaitForExitAsync().ConfigureAwait(false);

            var stdout = await stdoutTask.ConfigureAwait(false);
            var stderr = await stderrTask.ConfigureAwait(false);

            if (proc.ExitCode != 0)
                throw new InvalidOperationException(string.IsNullOrWhiteSpace(stderr) ? $"aws s3 ls failed for {s3Uri}." : stderr.Trim());

            return stdout
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.TrimEnd())
                .ToArray();
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 2)
        {
            throw new InvalidOperationException("aws.exe was not found when starting the planning process.");
        }
    }

    private static AwsCreds ParseAwsEnvVars(string text)
    {
        string? ak = null;
        string? sk = null;
        string? st = null;

        foreach (var raw in text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.Trim();

            if (line.StartsWith("SET ", StringComparison.OrdinalIgnoreCase)) line = line[4..].Trim();
            if (line.StartsWith("$env:", StringComparison.OrdinalIgnoreCase)) line = line[5..].Trim();
            if (line.StartsWith("export ", StringComparison.OrdinalIgnoreCase)) line = line[7..].Trim();

            var idxEq = line.IndexOf('=');
            var idxCol = line.IndexOf(':');

            int idx;
            if (idxEq > 0) idx = idxEq;
            else if (idxCol > 0) idx = idxCol;
            else continue;

            var key = line[..idx].Trim();
            var val = line[(idx + 1)..].Trim().Trim('"');

            if (key.Equals("AWS_ACCESS_KEY_ID", StringComparison.OrdinalIgnoreCase)) ak = val;
            else if (key.Equals("AWS_SECRET_ACCESS_KEY", StringComparison.OrdinalIgnoreCase)) sk = val;
            else if (key.Equals("AWS_SESSION_TOKEN", StringComparison.OrdinalIgnoreCase)) st = val;
        }

        return new AwsCreds(
            !string.IsNullOrWhiteSpace(ak) && !string.IsNullOrWhiteSpace(sk) && !string.IsNullOrWhiteSpace(st),
            ak ?? string.Empty,
            sk ?? string.Empty,
            st ?? string.Empty);
    }

    private static string? ResolveAwsExePath()
    {
        if (CanStartAwsFromPath())
            return "aws";

        var fromWhere = TryGetAwsFromWhere();
        if (!string.IsNullOrWhiteSpace(fromWhere) && File.Exists(fromWhere))
            return fromWhere;

        var defaultPaths = new[]
        {
            @"C:\Program Files\Amazon\AWSCLIV2\aws.exe",
            @"C:\Program Files (x86)\Amazon\AWSCLIV2\aws.exe"
        };

        return defaultPaths.FirstOrDefault(File.Exists);
    }

    private static bool CanStartAwsFromPath()
    {
        try
        {
            using var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "aws",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = GetWorkingDirectorySafe()
                }
            };

            p.StartInfo.ArgumentList.Add("--version");
            p.Start();
            p.WaitForExit(3000);
            return p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static string? TryGetAwsFromWhere()
    {
        try
        {
            using var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "where",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = GetWorkingDirectorySafe()
                }
            };

            p.StartInfo.ArgumentList.Add("aws");
            p.Start();
            var stdout = p.StandardOutput.ReadToEnd();
            p.WaitForExit(3000);

            if (p.ExitCode != 0)
                return null;

            return stdout
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Trim())
                .FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
        }
        catch
        {
            return null;
        }
    }

    private static IEnumerable<DateTime> EachDayUtc(DateTime startDateUtc, DateTime endDateUtc)
    {
        for (var d = startDateUtc.Date; d <= endDateUtc.Date; d = d.AddDays(1))
            yield return DateTime.SpecifyKind(d, DateTimeKind.Utc);
    }

    private static DateTime? TryParseAlbTimestampUtc(string fileNameOrKey)
    {
        var match = AlbTimestampRegex.Match(fileNameOrKey);
        if (!match.Success)
            return null;

        var ymd = match.Groups[1].Value;
        var hm = match.Groups[2].Value;

        if (!int.TryParse(ymd[..4], out var year)) return null;
        if (!int.TryParse(ymd[4..6], out var month)) return null;
        if (!int.TryParse(ymd[6..8], out var day)) return null;
        if (!int.TryParse(hm[..2], out var hour)) return null;
        if (!int.TryParse(hm[2..4], out var minute)) return null;

        return new DateTime(year, month, day, hour, minute, 0, DateTimeKind.Utc);
    }

    private static string? TryDeriveRegionFromBucket(string bucket)
    {
        if (string.IsNullOrWhiteSpace(bucket))
            return null;

        var value = bucket.Trim();
        if (value.EndsWith("-alblogs", StringComparison.OrdinalIgnoreCase))
            value = value[..^"-alblogs".Length];

        var match = AwsRegionAtEndRegex.Match(value);
        return match.Success ? match.Groups["region"].Value : null;
    }

    private static string SanitizeFileName(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "config";

        foreach (var c in Path.GetInvalidFileNameChars())
            value = value.Replace(c, '_');

        return value.Trim();
    }

    private static string GetWorkingDirectorySafe()
    {
        try { return Directory.GetCurrentDirectory(); }
        catch { return AppContext.BaseDirectory; }
    }

    private sealed record AwsCreds(bool IsValid, string AccessKeyId, string SecretAccessKey, string SessionToken);
}

internal sealed record AlbDownloadExecutionPlan(
    string ConfigName,
    string Bucket,
    string PrefixRoot,
    string AlbKey,
    string RunFolder,
    int TotalFiles,
    long TotalBytes,
    int InWindowFiles,
    long InWindowBytes,
    IReadOnlyList<AlbDownloadDayPlan> Days);

internal sealed record AlbDownloadDayPlan(
    string DayUtc,
    int TotalFiles,
    long TotalBytes,
    int InWindowFiles,
    long InWindowBytes);

internal sealed record AlbDownloadResolvedConfig(
    string ConfigName,
    string Bucket,
    string AlbId,
    bool UseInternalScope,
    string AccountId,
    string Region,
    bool IsSentry);
