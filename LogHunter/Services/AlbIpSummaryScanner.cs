using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace LogHunter.Services;

public static class AlbIpSummaryScanner
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
        private AlbIpSummaryExportSqlite.Writer? _sqliteWriter;
        private bool _ownsSqliteWriter;

        public ScanResult(string requestedIp, string sqlitePath)
        {
            RequestedIp = requestedIp;
            _sqlitePath = sqlitePath;
        }

        public string RequestedIp { get; }
        public bool HasRetainedRows => Rows.Count > 0;
        public List<AlbIpSummaryRow> Rows { get; } = new();
        public SortedDictionary<DateTime, BucketCounts> BucketsByMinuteUtc { get; } = new();
        public HashSet<string> SourceFiles { get; } = new(StringComparer.OrdinalIgnoreCase);
        public StatusGroupCounts ElbResponseTotals { get; } = new();
        public StatusGroupCounts FeResponseTotals { get; } = new();
        public Dictionary<string, int> TargetEndpointCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public long Fe5xxWhileElb2xx3xx { get; private set; }
        public long Fe4xxWhileElb2xx3xx { get; private set; }
        public long Elb5xxWhileFe2xx3xx { get; private set; }
        public long Elb4xxWhileFe2xx3xx { get; private set; }

        public long TotalRows { get; private set; }
        public DateTime? FirstHitUtc { get; private set; }
        public DateTime? LastHitUtc { get; private set; }
        public bool UsesSqliteDetailExport => _sqliteWriter is not null;
        public bool ThresholdReached { get; private set; }
        public bool ThresholdPromptPending { get; private set; }
        public DetailRetentionMode DetailMode { get; private set; } = DetailRetentionMode.BelowThreshold;
        public string SqlitePath => _sqlitePath;

        public void AddRow(AlbIpSummaryRow row, string sourceFile)
        {
            TotalRows++;

            if (!FirstHitUtc.HasValue || row.TimestampUtc < FirstHitUtc.Value)
                FirstHitUtc = row.TimestampUtc;

            if (!LastHitUtc.HasValue || row.TimestampUtc > LastHitUtc.Value)
                LastHitUtc = row.TimestampUtc;

            SourceFiles.Add(sourceFile);
            AddBucket(row);
            IncrementStatusBucket(ElbResponseTotals, row.ElbStatusCode);
            IncrementStatusBucket(FeResponseTotals, row.FeStatusCode);
            IncrementCount(TargetEndpointCounts, row.TargetEndpoint);
            UpdateMismatchCounts(row);

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

        public List<KeyValuePair<string, int>> TopTargetEndpoints(int take) => TopCounts(TargetEndpointCounts, take);

        public void Dispose()
        {
            if (_ownsSqliteWriter)
                _sqliteWriter?.Dispose();
        }

        public void ApplyThresholdDecision(DetailRetentionMode mode, AlbIpSummaryExportSqlite.Writer? sharedWriter = null, string? sharedSqlitePath = null)
        {
            if (!ThresholdPromptPending || DetailMode != DetailRetentionMode.BelowThreshold)
                return;

            ApplyDetailMode(mode, sharedWriter, sharedSqlitePath);
        }

        public void ApplyGlobalDetailMode(DetailRetentionMode mode, AlbIpSummaryExportSqlite.Writer? sharedWriter = null, string? sharedSqlitePath = null)
        {
            if (DetailMode != DetailRetentionMode.BelowThreshold)
                return;

            ApplyDetailMode(mode, sharedWriter, sharedSqlitePath);
        }

        private void ApplyDetailMode(DetailRetentionMode mode, AlbIpSummaryExportSqlite.Writer? sharedWriter, string? sharedSqlitePath)
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
                    _sqliteWriter = AlbIpSummaryExportSqlite.Open(_sqlitePath);
                    _ownsSqliteWriter = true;
                }

                _sqliteWriter.WriteRows(Rows);
            }

            Rows.Clear();
            Rows.TrimExcess();
        }

        private void AddBucket(AlbIpSummaryRow row)
        {
            var bucketUtc = FloorToMinuteUtc(row.TimestampUtc);
            if (!BucketsByMinuteUtc.TryGetValue(bucketUtc, out var bucket))
            {
                bucket = new BucketCounts();
                BucketsByMinuteUtc[bucketUtc] = bucket;
            }

            IncrementStatusBucket(bucket.Elb, row.ElbStatusCode);
            IncrementStatusBucket(bucket.Fe, row.FeStatusCode);
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

        private void UpdateMismatchCounts(AlbIpSummaryRow row)
        {
            var elbIs2xx3xx = Is2xx3xx(row.ElbStatusCode);
            var feIs2xx3xx = Is2xx3xx(row.FeStatusCode);
            var elbIs4xx = Is4xx(row.ElbStatusCode);
            var elbIs5xx = Is5xx(row.ElbStatusCode);
            var feIs4xx = Is4xx(row.FeStatusCode);
            var feIs5xx = Is5xx(row.FeStatusCode);

            if (feIs5xx && elbIs2xx3xx)
                Fe5xxWhileElb2xx3xx++;

            if (feIs4xx && elbIs2xx3xx)
                Fe4xxWhileElb2xx3xx++;

            if (elbIs5xx && feIs2xx3xx)
                Elb5xxWhileFe2xx3xx++;

            if (elbIs4xx && feIs2xx3xx)
                Elb4xxWhileFe2xx3xx++;
        }
    }

    public sealed class BucketCounts
    {
        public StatusGroupCounts Elb { get; } = new();
        public StatusGroupCounts Fe { get; } = new();
    }

    public sealed class StatusGroupCounts
    {
        public int S2xx { get; set; }
        public int S3xx { get; set; }
        public int S4xx { get; set; }
        public int S5xx { get; set; }
    }

    public sealed record AlbIpSummaryRow(
        DateTime TimestampUtc,
        string ClientIp,
        string Method,
        string RawRequest,
        int? ElbStatusCode,
        int? FeStatusCode,
        string TargetEndpoint,
        double? TargetProcessingTimeSeconds,
        double? RequestProcessingTimeSeconds,
        double? ResponseProcessingTimeSeconds,
        string ActionsExecuted,
        string UserAgent);

    public static async Task ScanFileAsync(
        string filePath,
        IPAddress requestedIp,
        ScanResult result,
        Action<long> reportBytesDelta)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

        long lastReportedPos = 0;
        const long chunk = 64L * 1024 * 1024;
        var sourceFile = SafeSourceFile(filePath);

        while (true)
        {
            var line = await sr.ReadLineAsync().ConfigureAwait(false);
            if (line is null)
                break;

            if (line.Length == 0)
                continue;

            if (!TryParseMatchedRow(line, requestedIp, out var row))
                continue;

            result.AddRow(row!, sourceFile);

            var pos = fs.Position;
            if (pos - lastReportedPos >= chunk)
            {
                reportBytesDelta(pos - lastReportedPos);
                lastReportedPos = pos;
            }
        }

        var remaining = fs.Length - lastReportedPos;
        if (remaining > 0)
            reportBytesDelta(remaining);
    }

    public static async Task ScanFileAsync(
        string filePath,
        IReadOnlyDictionary<string, ScanResult> resultsByIp,
        Action<long> reportBytesDelta)
    {
        if (resultsByIp.Count == 0)
            return;

        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

        long lastReportedPos = 0;
        const long chunk = 64L * 1024 * 1024;
        var sourceFile = SafeSourceFile(filePath);

        while (true)
        {
            var line = await sr.ReadLineAsync().ConfigureAwait(false);
            if (line is null)
                break;

            if (line.Length == 0)
                continue;

            if (!TryParseMatchedRow(line, resultsByIp, out var result, out var row))
                continue;

            result!.AddRow(row!, sourceFile);

            var pos = fs.Position;
            if (pos - lastReportedPos >= chunk)
            {
                reportBytesDelta(pos - lastReportedPos);
                lastReportedPos = pos;
            }
        }

        var remaining = fs.Length - lastReportedPos;
        if (remaining > 0)
            reportBytesDelta(remaining);
    }

    private static bool TryParseMatchedRow(string line, IPAddress requestedIp, out AlbIpSummaryRow? row)
    {
        row = null;

        var span = line.AsSpan();
        Span<(int start, int length)> slots = stackalloc (int, int)[24];
        int n = TokenizeAlbLine(span, slots);

        if (1 >= n) return false;
        var timestampToken = span.Slice(slots[1].start, slots[1].length);

        if (!DateTime.TryParse(timestampToken, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var timestampUtc))
        {
            return false;
        }

        if (3 >= n) return false;
        var clientToken = span.Slice(slots[3].start, slots[3].length);

        SplitEndpoint(clientToken, out var clientIpToken, out _);
        if (clientIpToken.Length == 0)
            return false;

        if (!IPAddress.TryParse(clientIpToken, out var clientIp) || !clientIp.Equals(requestedIp))
            return false;

        var targetToken = 4 < n ? span.Slice(slots[4].start, slots[4].length) : default;
        var requestProcToken = 5 < n ? span.Slice(slots[5].start, slots[5].length) : default;
        var targetProcToken = 6 < n ? span.Slice(slots[6].start, slots[6].length) : default;
        var responseProcToken = 7 < n ? span.Slice(slots[7].start, slots[7].length) : default;
        var elbStatusToken = 8 < n ? span.Slice(slots[8].start, slots[8].length) : default;
        var targetStatusToken = 9 < n ? span.Slice(slots[9].start, slots[9].length) : default;
        var requestToken = 12 < n ? span.Slice(slots[12].start, slots[12].length) : default;
        var userAgentToken = 13 < n ? span.Slice(slots[13].start, slots[13].length) : default;
        var actionsToken = 22 < n ? span.Slice(slots[22].start, slots[22].length) : default;

        ParseRequest(requestToken,
            out var method,
            out var rawRequest);

        row = new AlbIpSummaryRow(
            TimestampUtc: DateTime.SpecifyKind(timestampUtc, DateTimeKind.Utc),
            ClientIp: clientIp.ToString(),
            Method: method,
            RawRequest: rawRequest,
            ElbStatusCode: ParseNullableInt(elbStatusToken),
            FeStatusCode: ParseNullableInt(targetStatusToken),
            TargetEndpoint: NormalizeToken(targetToken),
            TargetProcessingTimeSeconds: ParseNullableDouble(targetProcToken),
            RequestProcessingTimeSeconds: ParseNullableDouble(requestProcToken),
            ResponseProcessingTimeSeconds: ParseNullableDouble(responseProcToken),
            ActionsExecuted: NormalizeToken(actionsToken),
            UserAgent: NormalizeToken(userAgentToken));

        return true;
    }

    private static bool TryParseMatchedRow(string line, IReadOnlyDictionary<string, ScanResult> resultsByIp, out ScanResult? result, out AlbIpSummaryRow? row)
    {
        result = null;
        row = null;

        var span = line.AsSpan();
        Span<(int start, int length)> slots = stackalloc (int, int)[24];
        int n = TokenizeAlbLine(span, slots);

        if (1 >= n) return false;
        var timestampToken = span.Slice(slots[1].start, slots[1].length);

        if (!DateTime.TryParse(timestampToken, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var timestampUtc))
        {
            return false;
        }

        if (3 >= n) return false;
        var clientToken = span.Slice(slots[3].start, slots[3].length);

        SplitEndpoint(clientToken, out var clientIpToken, out _);
        if (clientIpToken.Length == 0)
            return false;

        var clientIp = clientIpToken.ToString();
        if (!resultsByIp.TryGetValue(clientIp, out result))
            return false;

        var targetToken = 4 < n ? span.Slice(slots[4].start, slots[4].length) : default;
        var requestProcToken = 5 < n ? span.Slice(slots[5].start, slots[5].length) : default;
        var targetProcToken = 6 < n ? span.Slice(slots[6].start, slots[6].length) : default;
        var responseProcToken = 7 < n ? span.Slice(slots[7].start, slots[7].length) : default;
        var elbStatusToken = 8 < n ? span.Slice(slots[8].start, slots[8].length) : default;
        var targetStatusToken = 9 < n ? span.Slice(slots[9].start, slots[9].length) : default;
        var requestToken = 12 < n ? span.Slice(slots[12].start, slots[12].length) : default;
        var userAgentToken = 13 < n ? span.Slice(slots[13].start, slots[13].length) : default;
        var actionsToken = 22 < n ? span.Slice(slots[22].start, slots[22].length) : default;

        ParseRequest(requestToken, out var method, out var rawRequest);

        row = new AlbIpSummaryRow(
            TimestampUtc: DateTime.SpecifyKind(timestampUtc, DateTimeKind.Utc),
            ClientIp: clientIp,
            Method: method,
            RawRequest: rawRequest,
            ElbStatusCode: ParseNullableInt(elbStatusToken),
            FeStatusCode: ParseNullableInt(targetStatusToken),
            TargetEndpoint: NormalizeToken(targetToken),
            TargetProcessingTimeSeconds: ParseNullableDouble(targetProcToken),
            RequestProcessingTimeSeconds: ParseNullableDouble(requestProcToken),
            ResponseProcessingTimeSeconds: ParseNullableDouble(responseProcToken),
            ActionsExecuted: NormalizeToken(actionsToken),
            UserAgent: NormalizeToken(userAgentToken));

        return true;
    }

    private static string SafeSourceFile(string filePath)
    {
        try
        {
            return Path.GetRelativePath(AppFolders.ALB, filePath);
        }
        catch
        {
            return Path.GetFileName(filePath);
        }
    }

    private static DateTime FloorToMinuteUtc(DateTime dtUtc)
    {
        dtUtc = dtUtc.Kind == DateTimeKind.Utc ? dtUtc : dtUtc.ToUniversalTime();
        return new DateTime(dtUtc.Year, dtUtc.Month, dtUtc.Day, dtUtc.Hour, dtUtc.Minute, 0, DateTimeKind.Utc);
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

    private static bool Is2xx3xx(int? statusCode)
        => statusCode.HasValue && statusCode.Value >= 200 && statusCode.Value <= 399;

    private static bool Is4xx(int? statusCode)
        => statusCode.HasValue && statusCode.Value >= 400 && statusCode.Value <= 499;

    private static bool Is5xx(int? statusCode)
        => statusCode.HasValue && statusCode.Value >= 500 && statusCode.Value <= 599;

    private static void ParseRequest(
        ReadOnlySpan<char> requestToken,
        out string method,
        out string rawRequest)
    {
        method = "-";
        rawRequest = NormalizeToken(requestToken);

        if (requestToken.Length == 0 || requestToken.SequenceEqual("-".AsSpan()))
            return;

        int sp1 = requestToken.IndexOf(' ');
        if (sp1 < 0)
            return;

        method = NormalizeToken(requestToken[..sp1]);

    }

    private static string NormalizeToken(ReadOnlySpan<char> token)
    {
        token = token.Trim();
        if (token.IsEmpty || (token.Length == 1 && token[0] == '-'))
            return "-";
        return token.ToString();
    }

    private static int? ParseNullableInt(ReadOnlySpan<char> token)
    {
        if (token.Length == 0 || token.SequenceEqual("-".AsSpan()))
            return null;

        return int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;
    }

    private static double? ParseNullableDouble(ReadOnlySpan<char> token)
    {
        if (token.Length == 0 || token.SequenceEqual("-".AsSpan()))
            return null;

        return double.TryParse(token, NumberStyles.Float, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;
    }

    private static void SplitEndpoint(ReadOnlySpan<char> endpoint, out ReadOnlySpan<char> host, out ReadOnlySpan<char> port)
    {
        host = endpoint;
        port = default;

        if (endpoint.Length == 0 || endpoint.SequenceEqual("-".AsSpan()))
        {
            host = default;
            return;
        }

        int lastColon = endpoint.LastIndexOf(':');
        if (lastColon <= 0 || lastColon >= endpoint.Length - 1)
            return;

        var portCandidate = endpoint[(lastColon + 1)..];
        for (int i = 0; i < portCandidate.Length; i++)
        {
            if (!char.IsDigit(portCandidate[i]))
                return;
        }

        host = endpoint[..lastColon];
        port = portCandidate;
    }

    private static int TokenizeAlbLine(ReadOnlySpan<char> line, Span<(int start, int length)> slots)
    {
        int idx = 0;
        int count = 0;

        while (idx < line.Length && count < slots.Length)
        {
            while (idx < line.Length && line[idx] == ' ')
                idx++;

            if (idx >= line.Length)
                break;

            bool quoted = line[idx] == '"';
            int start = idx;

            if (quoted)
            {
                start++;
                idx = start;

                while (idx < line.Length && line[idx] != '"')
                    idx++;

                int end = idx;
                idx = Math.Min(idx + 1, line.Length);

                slots[count++] = (start, end - start);
                continue;
            }

            while (idx < line.Length && line[idx] != ' ')
                idx++;

            slots[count++] = (start, idx - start);
        }

        return count;
    }

}
