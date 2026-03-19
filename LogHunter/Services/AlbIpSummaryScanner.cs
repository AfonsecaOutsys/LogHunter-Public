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
    public sealed class ScanResult
    {
        public ScanResult(string requestedIp)
        {
            RequestedIp = requestedIp;
        }

        public string RequestedIp { get; }
        public List<AlbIpSummaryRow> Rows { get; } = new();
        public SortedDictionary<DateTime, BucketCounts> BucketsByMinuteUtc { get; } = new();
        public HashSet<string> SourceFiles { get; } = new(StringComparer.OrdinalIgnoreCase);

        public void AddRow(AlbIpSummaryRow row)
        {
            Rows.Add(row);
            SourceFiles.Add(row.SourceFile);

            var bucketUtc = FloorToMinuteUtc(row.TimestampUtc);
            if (!BucketsByMinuteUtc.TryGetValue(bucketUtc, out var bucket))
            {
                bucket = new BucketCounts();
                BucketsByMinuteUtc[bucketUtc] = bucket;
            }

            IncrementStatusBucket(bucket.Elb, row.ElbStatusCode);
            IncrementStatusBucket(bucket.Target, row.TargetStatusCode);
        }
    }

    public sealed class BucketCounts
    {
        public StatusGroupCounts Elb { get; } = new();
        public StatusGroupCounts Target { get; } = new();
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
        string ClientPort,
        string Method,
        string Host,
        string PathNoQuery,
        string RawRequest,
        int? ElbStatusCode,
        int? TargetStatusCode,
        string TargetEndpoint,
        double? TargetProcessingTimeSeconds,
        double? RequestProcessingTimeSeconds,
        double? ResponseProcessingTimeSeconds,
        string ActionsExecuted,
        string TraceId,
        string UserAgent,
        string SourceFile,
        string RawLine);

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

            if (!TryParseMatchedRow(line, requestedIp, sourceFile, out var row))
                continue;

            result.AddRow(row!);

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

    private static bool TryParseMatchedRow(string line, IPAddress requestedIp, string sourceFile, out AlbIpSummaryRow? row)
    {
        row = null;

        var span = line.AsSpan();
        if (!TryGetToken(span, 1, out var timestampToken))
            return false;

        if (!DateTime.TryParse(timestampToken, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var timestampUtc))
        {
            return false;
        }

        if (!TryGetToken(span, 3, out var clientToken))
            return false;

        SplitEndpoint(clientToken, out var clientIpToken, out var clientPortToken);
        if (clientIpToken.Length == 0)
            return false;

        if (!IPAddress.TryParse(clientIpToken, out var clientIp) || !clientIp.Equals(requestedIp))
            return false;

        TryGetToken(span, 4, out var targetToken);
        TryGetToken(span, 5, out var requestProcToken);
        TryGetToken(span, 6, out var targetProcToken);
        TryGetToken(span, 7, out var responseProcToken);
        TryGetToken(span, 8, out var elbStatusToken);
        TryGetToken(span, 9, out var targetStatusToken);
        TryGetToken(span, 12, out var requestToken);
        TryGetToken(span, 13, out var userAgentToken);
        TryGetToken(span, 17, out var traceIdToken);
        TryGetToken(span, 22, out var actionsToken);

        ParseRequest(requestToken,
            out var method,
            out var host,
            out var pathNoQuery,
            out var rawRequest);

        row = new AlbIpSummaryRow(
            TimestampUtc: DateTime.SpecifyKind(timestampUtc, DateTimeKind.Utc),
            ClientIp: clientIp.ToString(),
            ClientPort: NormalizeToken(clientPortToken),
            Method: method,
            Host: host,
            PathNoQuery: pathNoQuery,
            RawRequest: rawRequest,
            ElbStatusCode: ParseNullableInt(elbStatusToken),
            TargetStatusCode: ParseNullableInt(targetStatusToken),
            TargetEndpoint: NormalizeToken(targetToken),
            TargetProcessingTimeSeconds: ParseNullableDouble(targetProcToken),
            RequestProcessingTimeSeconds: ParseNullableDouble(requestProcToken),
            ResponseProcessingTimeSeconds: ParseNullableDouble(responseProcToken),
            ActionsExecuted: NormalizeToken(actionsToken),
            TraceId: NormalizeToken(traceIdToken),
            UserAgent: NormalizeToken(userAgentToken),
            SourceFile: sourceFile,
            RawLine: line);

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

    private static void ParseRequest(
        ReadOnlySpan<char> requestToken,
        out string method,
        out string host,
        out string pathNoQuery,
        out string rawRequest)
    {
        method = "-";
        host = "-";
        pathNoQuery = "-";
        rawRequest = NormalizeToken(requestToken);

        if (requestToken.Length == 0 || requestToken.SequenceEqual("-".AsSpan()))
            return;

        int sp1 = requestToken.IndexOf(' ');
        if (sp1 < 0)
            return;

        method = NormalizeToken(requestToken[..sp1]);

        var rest = requestToken[(sp1 + 1)..];
        int sp2 = rest.IndexOf(' ');
        var urlToken = sp2 >= 0 ? rest[..sp2] : rest;

        if (urlToken.Length == 0)
            return;

        var urlText = urlToken.ToString();
        if (Uri.TryCreate(urlText, UriKind.Absolute, out var absolute))
        {
            host = string.IsNullOrWhiteSpace(absolute.Host) ? "-" : absolute.Host;
            pathNoQuery = string.IsNullOrWhiteSpace(absolute.AbsolutePath) ? "/" : absolute.AbsolutePath;
            return;
        }

        int q = urlToken.IndexOf('?');
        if (q >= 0)
            urlToken = urlToken[..q];

        pathNoQuery = urlToken.Length == 0 ? "-" : urlToken.ToString();
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

    private static bool TryGetToken(ReadOnlySpan<char> line, int tokenIndex, out ReadOnlySpan<char> token)
    {
        token = default;

        int idx = 0;
        int current = 0;

        while (idx < line.Length)
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

                if (current == tokenIndex)
                {
                    token = line.Slice(start, end - start);
                    return true;
                }

                current++;
                continue;
            }

            while (idx < line.Length && line[idx] != ' ')
                idx++;

            int endUnquoted = idx;
            if (current == tokenIndex)
            {
                token = line.Slice(start, endUnquoted - start);
                return true;
            }

            current++;
        }

        return false;
    }
}
