using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Utils;

namespace LogHunter.Services;

public static class IisIpSummaryScanner
{
    public const int ExcelRowThreshold = 1_000_000;

    public enum DetailRetentionMode
    {
        BelowThreshold = 0,
        SqliteApproved = 1,
        SummaryOnly = 2
    }

    public sealed class ScanResult : IDisposable
    {
        private string _sqlitePath;
        private IisIpSummaryExportSqlite.Writer? _sqliteWriter;
        private bool _ownsSqliteWriter;

        public ScanResult(string requestedIp, string sqlitePath)
        {
            RequestedIp = requestedIp;
            _sqlitePath = sqlitePath;
        }

        public string RequestedIp { get; }
        public bool HasRetainedRows => Rows.Count > 0;
        public List<IisIpSummaryRow> Rows { get; } = new();
        public SortedDictionary<DateTime, StatusGroupCounts> BucketsBy15SecondUtc { get; } = new();
        public SortedDictionary<DateTime, StatusGroupCounts> BucketsByMinuteUtc { get; } = new();
        public HashSet<string> SourceFiles { get; } = new(StringComparer.OrdinalIgnoreCase);
        public StatusGroupCounts StatusTotals { get; } = new();
        public Dictionary<int, int> ExactStatusCounts { get; } = new();
        public Dictionary<string, int> MethodCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> UriCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public long TotalRows { get; private set; }
        public long TotalTimeTakenMs { get; private set; }
        public long MaxTimeTakenMs { get; private set; }
        public long TotalCsBytes { get; private set; }
        public long TotalScBytes { get; private set; }
        public DateTime? FirstHitUtc { get; private set; }
        public DateTime? LastHitUtc { get; private set; }
        public bool ThresholdReached { get; private set; }
        public bool ThresholdPromptPending { get; private set; }
        public DetailRetentionMode DetailMode { get; private set; } = DetailRetentionMode.BelowThreshold;
        public string SqlitePath => _sqlitePath;

        public void AddRow(IisIpSummaryRow row, string sourceFile)
        {
            TotalRows++;

            if (!FirstHitUtc.HasValue || row.TimestampUtc < FirstHitUtc.Value)
                FirstHitUtc = row.TimestampUtc;

            if (!LastHitUtc.HasValue || row.TimestampUtc > LastHitUtc.Value)
                LastHitUtc = row.TimestampUtc;

            if (row.TimeTakenMs.HasValue)
            {
                TotalTimeTakenMs += row.TimeTakenMs.Value;
                if (row.TimeTakenMs.Value > MaxTimeTakenMs)
                    MaxTimeTakenMs = row.TimeTakenMs.Value;
            }

            if (row.CsBytes.HasValue)
                TotalCsBytes += row.CsBytes.Value;

            if (row.ScBytes.HasValue)
                TotalScBytes += row.ScBytes.Value;

            SourceFiles.Add(sourceFile);
            AddBucket(row);
            IncrementStatusBucket(StatusTotals, row.StatusCode);
            IncrementExactStatus(row.StatusCode);
            IncrementCount(MethodCounts, row.Method);
            IncrementCount(UriCounts, row.UriStem);

            if (DetailMode == DetailRetentionMode.SummaryOnly)
                return;

            if (_sqliteWriter is not null)
            {
                _sqliteWriter.WriteRow(row);
                return;
            }

            Rows.Add(row);
            if (DetailMode == DetailRetentionMode.BelowThreshold && TotalRows >= ExcelRowThreshold)
            {
                ThresholdReached = true;
                ThresholdPromptPending = true;
            }
        }

        public void CompleteStreamingExports()
        {
            if (_ownsSqliteWriter)
                _sqliteWriter?.Complete();
        }

        public void ApplyThresholdDecision(DetailRetentionMode mode, IisIpSummaryExportSqlite.Writer? sharedWriter = null, string? sharedSqlitePath = null)
        {
            if (!ThresholdPromptPending || DetailMode != DetailRetentionMode.BelowThreshold)
                return;

            ApplyDetailMode(mode, sharedWriter, sharedSqlitePath);
        }

        public void ApplyGlobalDetailMode(DetailRetentionMode mode, IisIpSummaryExportSqlite.Writer? sharedWriter = null, string? sharedSqlitePath = null)
        {
            if (DetailMode != DetailRetentionMode.BelowThreshold)
                return;

            ApplyDetailMode(mode, sharedWriter, sharedSqlitePath);
        }

        private void ApplyDetailMode(DetailRetentionMode mode, IisIpSummaryExportSqlite.Writer? sharedWriter, string? sharedSqlitePath)
        {
            ThresholdPromptPending = false;
            ThresholdReached = ThresholdReached || TotalRows >= ExcelRowThreshold;
            DetailMode = mode == DetailRetentionMode.SummaryOnly
                ? DetailRetentionMode.SummaryOnly
                : DetailRetentionMode.SqliteApproved;

            if (DetailMode == DetailRetentionMode.SqliteApproved)
            {
                if (sharedWriter is not null)
                {
                    _sqliteWriter = sharedWriter;
                    _ownsSqliteWriter = false;
                    if (!string.IsNullOrWhiteSpace(sharedSqlitePath))
                        _sqlitePath = sharedSqlitePath;
                }
                else
                {
                    _sqliteWriter = IisIpSummaryExportSqlite.Open(_sqlitePath);
                    _ownsSqliteWriter = true;
                }

                _sqliteWriter.WriteRows(Rows);
            }

            Rows.Clear();
            Rows.TrimExcess();
        }

        public List<KeyValuePair<string, int>> TopUris(int take)
            => TopCounts(UriCounts, take);

        public List<KeyValuePair<string, int>> TopMethods(int take)
            => TopCounts(MethodCounts, take);

        public List<KeyValuePair<string, int>> TopExactStatuses(int take)
            => ExactStatusCounts
                .OrderByDescending(x => x.Value)
                .ThenBy(x => x.Key)
                .Take(take)
                .Select(x => new KeyValuePair<string, int>(x.Key.ToString(CultureInfo.InvariantCulture), x.Value))
                .ToList();

        public double AverageTimeTakenMs => TotalRows == 0 ? 0 : (double)TotalTimeTakenMs / TotalRows;

        public void Dispose()
        {
            if (_ownsSqliteWriter)
                _sqliteWriter?.Dispose();
        }

        private void AddBucket(IisIpSummaryRow row)
        {
            var bucket15Utc = FloorToBucketUtc(row.TimestampUtc, 15);
            if (!BucketsBy15SecondUtc.TryGetValue(bucket15Utc, out var quarterMinuteBucket))
            {
                quarterMinuteBucket = new StatusGroupCounts();
                BucketsBy15SecondUtc[bucket15Utc] = quarterMinuteBucket;
            }

            IncrementStatusBucket(quarterMinuteBucket, row.StatusCode);

            var bucketMinuteUtc = FloorToMinuteUtc(row.TimestampUtc);
            if (!BucketsByMinuteUtc.TryGetValue(bucketMinuteUtc, out var minuteBucket))
            {
                minuteBucket = new StatusGroupCounts();
                BucketsByMinuteUtc[bucketMinuteUtc] = minuteBucket;
            }

            IncrementStatusBucket(minuteBucket, row.StatusCode);
        }

        private void IncrementExactStatus(int? statusCode)
        {
            if (!statusCode.HasValue)
                return;

            if (ExactStatusCounts.TryGetValue(statusCode.Value, out var current))
                ExactStatusCounts[statusCode.Value] = current + 1;
            else
                ExactStatusCounts[statusCode.Value] = 1;
        }

        private static void IncrementCount(Dictionary<string, int> counts, string value)
        {
            if (string.IsNullOrWhiteSpace(value) || value == "-")
                return;

            if (counts.TryGetValue(value, out var current))
                counts[value] = current + 1;
            else
                counts[value] = 1;
        }

        private static List<KeyValuePair<string, int>> TopCounts(Dictionary<string, int> counts, int take)
            => counts.OrderByDescending(x => x.Value)
                .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                .Take(take)
                .ToList();
    }

    public sealed class StatusGroupCounts
    {
        public int S2xx { get; set; }
        public int S3xx { get; set; }
        public int S4xx { get; set; }
        public int S5xx { get; set; }
    }

    public sealed record IisIpSummaryRow(
        DateTime TimestampUtc,
        string ClientIp,
        string Method,
        string UriStem,
        string UriQuery,
        string Host,
        int? StatusCode,
        int? SubStatusCode,
        int? Win32StatusCode,
        long? TimeTakenMs,
        long? CsBytes,
        long? ScBytes,
        string UserAgent,
        string Referer);

    public static async Task ScanFileAsync(
        string filePath,
        IReadOnlyDictionary<string, ScanResult> resultsByIp,
        CancellationToken ct)
    {
        if (resultsByIp.Count == 0)
            return;

        var sourceFile = SafeSourceFile(filePath);
        var map = await IisW3cReader.ReadFieldMapAsync(filePath, ct).ConfigureAwait(false);
        if (map is null)
            return;

        if (!map.TryGetIndex("date", out var iDate) ||
            !map.TryGetIndex("time", out var iTime) ||
            !map.TryGetIndex("sc-status", out var iStatus))
        {
            return;
        }

        map.TryGetIndex("OriginalIP", out var iOriginalIp);
        map.TryGetIndex("c-ip", out var iCIp);
        map.TryGetIndex("cs-method", out var iMethod);
        map.TryGetIndex("cs-uri-stem", out var iUriStem);
        map.TryGetIndex("cs-uri-query", out var iUriQuery);
        map.TryGetIndex("cs-host", out var iHost);
        map.TryGetIndex("sc-substatus", out var iSubStatus);
        map.TryGetIndex("sc-win32-status", out var iWin32Status);
        map.TryGetIndex("time-taken", out var iTimeTaken);
        map.TryGetIndex("cs-bytes", out var iCsBytes);
        map.TryGetIndex("sc-bytes", out var iScBytes);
        map.TryGetIndex("cs(User-Agent)", out var iUA);
        map.TryGetIndex("cs(Referer)", out var iReferer);

        await IisW3cReader.ForEachDataLineAsync(filePath, ct, (_, tokens) =>
        {
            if (!TryParseDateTimeUtc(tokens.Get(iDate), tokens.Get(iTime), out var timestampUtc))
                return;

            var ip = IisClientIpResolver.ResolveClientIpPreferOriginal(tokens, iOriginalIp, iCIp);
            if (ip is null || !resultsByIp.TryGetValue(ip, out var result))
                return;

            var row = new IisIpSummaryRow(
                TimestampUtc: timestampUtc,
                ClientIp: ip,
                Method: NormalizeToken(tokens.Get(iMethod)),
                UriStem: NormalizeToken(tokens.Get(iUriStem)),
                UriQuery: NormalizeToken(tokens.Get(iUriQuery)),
                Host: NormalizeToken(tokens.Get(iHost)),
                StatusCode: ParseNullableInt(tokens.Get(iStatus)),
                SubStatusCode: ParseNullableInt(tokens.Get(iSubStatus)),
                Win32StatusCode: ParseNullableInt(tokens.Get(iWin32Status)),
                TimeTakenMs: ParseNullableLong(tokens.Get(iTimeTaken)),
                CsBytes: ParseNullableLong(tokens.Get(iCsBytes)),
                ScBytes: ParseNullableLong(tokens.Get(iScBytes)),
                UserAgent: NormalizeToken(tokens.Get(iUA)),
                Referer: NormalizeToken(tokens.Get(iReferer)));

            result.AddRow(row, sourceFile);
        }).ConfigureAwait(false);
    }

    private static string SafeSourceFile(string filePath)
    {
        try
        {
            return Path.GetRelativePath(AppFolders.IIS, filePath);
        }
        catch
        {
            return Path.GetFileName(filePath);
        }
    }

    private static DateTime FloorToMinuteUtc(DateTime dtUtc)
        => new(dtUtc.Year, dtUtc.Month, dtUtc.Day, dtUtc.Hour, dtUtc.Minute, 0, DateTimeKind.Utc);

    private static DateTime FloorToBucketUtc(DateTime dtUtc, int bucketSeconds)
    {
        if (bucketSeconds <= 0)
            bucketSeconds = 60;

        dtUtc = dtUtc.Kind == DateTimeKind.Utc ? dtUtc : dtUtc.ToUniversalTime();
        var flooredSecond = (dtUtc.Second / bucketSeconds) * bucketSeconds;
        return new DateTime(dtUtc.Year, dtUtc.Month, dtUtc.Day, dtUtc.Hour, dtUtc.Minute, flooredSecond, DateTimeKind.Utc);
    }

    private static void IncrementStatusBucket(StatusGroupCounts counts, int? statusCode)
    {
        if (!statusCode.HasValue)
            return;

        if (statusCode.Value >= 200 && statusCode.Value <= 299)
            counts.S2xx++;
        else if (statusCode.Value >= 300 && statusCode.Value <= 399)
            counts.S3xx++;
        else if (statusCode.Value >= 400 && statusCode.Value <= 499)
            counts.S4xx++;
        else if (statusCode.Value >= 500 && statusCode.Value <= 599)
            counts.S5xx++;
    }

    private static bool TryParseDateTimeUtc(ReadOnlySpan<char> date, ReadOnlySpan<char> time, out DateTime dtUtc)
    {
        dtUtc = default;
        if (date.Length != 10 || time.Length < 8)
            return false;

        if (!int.TryParse(date[..4], NumberStyles.Integer, CultureInfo.InvariantCulture, out var yyyy)) return false;
        if (!int.TryParse(date.Slice(5, 2), NumberStyles.Integer, CultureInfo.InvariantCulture, out var mm)) return false;
        if (!int.TryParse(date.Slice(8, 2), NumberStyles.Integer, CultureInfo.InvariantCulture, out var dd)) return false;
        if (!int.TryParse(time[..2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var hh)) return false;
        if (!int.TryParse(time.Slice(3, 2), NumberStyles.Integer, CultureInfo.InvariantCulture, out var mi)) return false;
        if (!int.TryParse(time.Slice(6, 2), NumberStyles.Integer, CultureInfo.InvariantCulture, out var ss)) return false;

        try
        {
            dtUtc = new DateTime(yyyy, mm, dd, hh, mi, ss, DateTimeKind.Utc);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string NormalizeToken(ReadOnlySpan<char> token)
    {
        if (token.Length == 0)
            return "-";

        var text = token.ToString().Trim();
        return string.IsNullOrWhiteSpace(text) ? "-" : text;
    }

    private static int? ParseNullableInt(ReadOnlySpan<char> token)
    {
        if (token.Length == 0 || token.SequenceEqual("-".AsSpan()))
            return null;

        return int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;
    }

    private static long? ParseNullableLong(ReadOnlySpan<char> token)
    {
        if (token.Length == 0 || token.SequenceEqual("-".AsSpan()))
            return null;

        return long.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;
    }
}
