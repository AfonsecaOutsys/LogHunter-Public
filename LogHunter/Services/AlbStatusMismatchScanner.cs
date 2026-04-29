using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LogHunter.Services;

public static class AlbStatusMismatchScanner
{
    public sealed class ScanResult
    {
        public List<MatchRow> Rows { get; } = new();
        public Dictionary<string, int> UriCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> TargetEndpointCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> ClientIpCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> StatusPairCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<int, int> ElbStatusCounts { get; } = new();
        public Dictionary<int, int> TargetStatusCounts { get; } = new();
        public HashSet<string> SourceFiles { get; } = new(StringComparer.OrdinalIgnoreCase);

        public long TotalRows { get; private set; }
        public DateTime? FirstHitUtc { get; private set; }
        public DateTime? LastHitUtc { get; private set; }

        public void AddRow(MatchRow row, string sourceFile)
        {
            Rows.Add(row);
            TotalRows++;
            SourceFiles.Add(sourceFile);

            if (!FirstHitUtc.HasValue || row.TimestampUtc < FirstHitUtc.Value)
                FirstHitUtc = row.TimestampUtc;

            if (!LastHitUtc.HasValue || row.TimestampUtc > LastHitUtc.Value)
                LastHitUtc = row.TimestampUtc;

            Increment(UriCounts, row.UriNoQuery);
            Increment(TargetEndpointCounts, row.TargetEndpoint);
            Increment(ClientIpCounts, row.ClientIp);
            Increment(StatusPairCounts, $"{row.ElbStatusCode}->{row.TargetStatusCode}");
            Increment(ElbStatusCounts, row.ElbStatusCode);
            Increment(TargetStatusCounts, row.TargetStatusCode);
        }

        public List<KeyValuePair<string, int>> TopUris(int take) => TopCounts(UriCounts, take);
        public List<KeyValuePair<string, int>> TopTargetEndpoints(int take) => TopCounts(TargetEndpointCounts, take);
        public List<KeyValuePair<string, int>> TopClientIps(int take) => TopCounts(ClientIpCounts, take);
        public List<KeyValuePair<string, int>> TopStatusPairs(int take) => TopCounts(StatusPairCounts, take);
        public List<KeyValuePair<int, int>> TopElbStatuses() => TopIntCounts(ElbStatusCounts);
        public List<KeyValuePair<int, int>> TopTargetStatuses() => TopIntCounts(TargetStatusCounts);

        private static void Increment(Dictionary<string, int> counts, string value)
        {
            value = string.IsNullOrWhiteSpace(value) ? "-" : value;
            if (counts.TryGetValue(value, out var current))
                counts[value] = current + 1;
            else
                counts[value] = 1;
        }

        private static void Increment(Dictionary<int, int> counts, int value)
        {
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

        private static List<KeyValuePair<int, int>> TopIntCounts(Dictionary<int, int> counts)
            => counts.OrderByDescending(x => x.Value)
                .ThenBy(x => x.Key)
                .ToList();
    }

    public sealed record MatchRow(
        DateTime TimestampUtc,
        string ClientIp,
        string Method,
        string UriNoQuery,
        string RawRequest,
        int ElbStatusCode,
        int TargetStatusCode,
        string TargetEndpoint,
        double? TargetProcessingTimeSeconds,
        double? RequestProcessingTimeSeconds,
        double? ResponseProcessingTimeSeconds,
        string ActionsExecuted,
        string UserAgent,
        string SourceFile);

    public static async Task ScanFileAsync(string filePath, ScanResult result, Action<long> reportBytesDelta)
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

            if (!TryParseMatch(line, sourceFile, out var row))
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

    private static bool TryParseMatch(string line, string sourceFile, out MatchRow? row)
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

        var targetToken = 4 < n ? span.Slice(slots[4].start, slots[4].length) : default;
        var requestProcToken = 5 < n ? span.Slice(slots[5].start, slots[5].length) : default;
        var targetProcToken = 6 < n ? span.Slice(slots[6].start, slots[6].length) : default;
        var responseProcToken = 7 < n ? span.Slice(slots[7].start, slots[7].length) : default;
        var elbStatusToken = 8 < n ? span.Slice(slots[8].start, slots[8].length) : default;
        var targetStatusToken = 9 < n ? span.Slice(slots[9].start, slots[9].length) : default;
        var requestToken = 12 < n ? span.Slice(slots[12].start, slots[12].length) : default;
        var userAgentToken = 13 < n ? span.Slice(slots[13].start, slots[13].length) : default;
        var actionsToken = 22 < n ? span.Slice(slots[22].start, slots[22].length) : default;

        var elbStatus = ParseNullableInt(elbStatusToken);
        var targetStatus = ParseNullableInt(targetStatusToken);
        if (!elbStatus.HasValue || !targetStatus.HasValue)
            return false;

        if (!Is5xx(elbStatus.Value) || !Is2xx3xx(targetStatus.Value))
            return false;

        ParseRequest(requestToken, out var method, out var rawRequest, out var uriNoQuery);

        row = new MatchRow(
            TimestampUtc: DateTime.SpecifyKind(timestampUtc, DateTimeKind.Utc),
            ClientIp: clientIpToken.ToString(),
            Method: method,
            UriNoQuery: uriNoQuery,
            RawRequest: rawRequest,
            ElbStatusCode: elbStatus.Value,
            TargetStatusCode: targetStatus.Value,
            TargetEndpoint: NormalizeToken(targetToken),
            TargetProcessingTimeSeconds: ParseNullableDouble(targetProcToken),
            RequestProcessingTimeSeconds: ParseNullableDouble(requestProcToken),
            ResponseProcessingTimeSeconds: ParseNullableDouble(responseProcToken),
            ActionsExecuted: NormalizeToken(actionsToken),
            UserAgent: NormalizeToken(userAgentToken),
            SourceFile: sourceFile);

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

    private static bool Is2xx3xx(int statusCode) => statusCode >= 200 && statusCode <= 399;
    private static bool Is5xx(int statusCode) => statusCode >= 500 && statusCode <= 599;

    private static void ParseRequest(
        ReadOnlySpan<char> requestToken,
        out string method,
        out string rawRequest,
        out string uriNoQuery)
    {
        method = "-";
        rawRequest = NormalizeToken(requestToken);
        uriNoQuery = ExtractUriNoQueryFromRequest(requestToken);

        if (requestToken.Length == 0 || requestToken.SequenceEqual("-".AsSpan()))
            return;

        int sp1 = requestToken.IndexOf(' ');
        if (sp1 < 0)
            return;

        method = NormalizeToken(requestToken[..sp1]);
    }

    private static string ExtractUriNoQueryFromRequest(ReadOnlySpan<char> request)
    {
        if (request.Length == 0)
            return "-";

        int sp1 = request.IndexOf(' ');
        if (sp1 < 0 || sp1 + 1 >= request.Length)
            return "-";

        var rest = request[(sp1 + 1)..];
        int sp2 = rest.IndexOf(' ');
        ReadOnlySpan<char> url = sp2 >= 0 ? rest[..sp2] : rest;

        int q = url.IndexOf('?');
        if (q >= 0)
            url = url[..q];

        int scheme = url.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0)
        {
            int afterScheme = scheme + 3;
            var after = url[afterScheme..];
            int slash = after.IndexOf('/');
            if (slash >= 0)
            {
                var path = url[(afterScheme + slash)..];
                return path.Length == 0 ? "/" : path.ToString();
            }

            return "/";
        }

        var pathOnly = url.ToString();
        return string.IsNullOrWhiteSpace(pathOnly) ? "-" : pathOnly;
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
