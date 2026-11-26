// Services/PlatformScanner.cs
using ExcelDataReader;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

// Only import what we need from Microsoft.VisualBasic.FileIO to avoid SearchOption ambiguity
using TextFieldParser = Microsoft.VisualBasic.FileIO.TextFieldParser;
using FieldType = Microsoft.VisualBasic.FileIO.FieldType;

namespace LogHunter.Services;

public static class PlatformScanner
{
    private static readonly Regex RxClientIp = new(
        @"ClientIp:\s*(?<ip>[0-9a-fA-F\.:]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex RxXff = new(
        @"X-Forwarded-For:\s*(?<ip>[0-9a-fA-F\.:, ]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static Task<PlatformSuspiciousScanResult> ScanSuspiciousRequestsAsync(
        string platformLogsDir,
        CancellationToken ct = default)
        => Task.Run(() => Scan(platformLogsDir, ct), ct);

    private static PlatformSuspiciousScanResult Scan(string dir, CancellationToken ct)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

        var files = Directory.EnumerateFiles(dir, "*.*", System.IO.SearchOption.AllDirectories)
            .Where(p => p.EndsWith(".csv", StringComparison.OrdinalIgnoreCase) ||
                        p.EndsWith(".xlsx", StringComparison.OrdinalIgnoreCase))
            .ToList();

        var res = new PlatformSuspiciousScanResult
        {
            FilesScanned = files.Count
        };

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                var matchedThisFile = file.EndsWith(".csv", StringComparison.OrdinalIgnoreCase)
                    ? ScanCsv(file, res, ct)
                    : ScanXlsx(file, res, ct);

                if (matchedThisFile)
                    res.FilesMatched++;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Exports can be messy: keep scanning, but report the file instead of dropping it silently.
                res.SkipFile(file, $"unreadable ({ex.GetType().Name})");
            }
        }

        res.FinalizeAggregates();
        return res;
    }

    private static bool ScanCsv(string path, PlatformSuspiciousScanResult res, CancellationToken ct)
    {
        var firstLine = File.ReadLines(path).FirstOrDefault() ?? "";
        var comma = firstLine.Count(c => c == ',');
        var semi = firstLine.Count(c => c == ';');
        var tab = firstLine.Count(c => c == '\t');

        var delimiter =
            tab > comma && tab > semi ? "\t" :
            semi > comma ? ";" : ",";

        using var parser = new TextFieldParser(path)
        {
            TextFieldType = FieldType.Delimited,
            HasFieldsEnclosedInQuotes = true,
            TrimWhiteSpace = false
        };
        parser.SetDelimiters(delimiter);

        var header = parser.ReadFields();
        if (header is null || header.Length == 0)
        {
            res.SkipFile(path, "empty file");
            return false;
        }

        if (!TryResolveColumns(header, out var messageIdx, out var envIdx))
        {
            res.SkipFile(path, "message or environment info column not found");
            return false;
        }

        var anyMatch = false;

        while (!parser.EndOfData)
        {
            ct.ThrowIfCancellationRequested();

            string[]? fields;
            try { fields = parser.ReadFields(); }
            catch (Microsoft.VisualBasic.FileIO.MalformedLineException)
            {
                res.RowsUnparsed++;
                continue;
            }

            if (fields is null || fields.Length == 0)
                continue;

            if (messageIdx >= fields.Length || envIdx >= fields.Length)
            {
                res.RowsUnparsed++;
                continue;
            }

            var msg = fields[messageIdx] ?? "";
            var type = MatchSuspiciousType(msg);
            if (type is null)
                continue;

            var env = fields[envIdx] ?? "";
            if (!TryExtractEffectiveIp(env, out var effectiveIp, out var clientIp, out var xffIp))
            {
                res.AddMatchWithoutIp(path);
                continue;
            }

            anyMatch = true;
            res.AddHit(type, effectiveIp!, clientIp, xffIp);
        }

        return anyMatch;
    }

    private static bool ScanXlsx(string path, PlatformSuspiciousScanResult res, CancellationToken ct)
    {
        using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = ExcelReaderFactory.CreateReader(stream);

        var anyMatch = false;
        var anySheetResolved = false;

        do
        {
            ct.ThrowIfCancellationRequested();

            if (!reader.Read())
                continue;

            var headers = new string[reader.FieldCount];
            for (int i = 0; i < reader.FieldCount; i++)
                headers[i] = reader.GetValue(i)?.ToString() ?? "";

            if (!TryResolveColumns(headers, out var messageIdx, out var envIdx))
                continue;

            anySheetResolved = true;
            while (reader.Read())
            {
                ct.ThrowIfCancellationRequested();

                var msg = reader.GetValue(messageIdx)?.ToString() ?? "";
                var type = MatchSuspiciousType(msg);
                if (type is null)
                    continue;

                var env = reader.GetValue(envIdx)?.ToString() ?? "";
                if (!TryExtractEffectiveIp(env, out var effectiveIp, out var clientIp, out var xffIp))
                {
                    res.AddMatchWithoutIp(path);
                    continue;
                }

                anyMatch = true;
                res.AddHit(type, effectiveIp!, clientIp, xffIp);
            }

        } while (reader.NextResult());

        if (!anySheetResolved)
            res.SkipFile(path, "message or environment info column not found");

        return anyMatch;
    }

    private static string? MatchSuspiciousType(string msg)
    {
        foreach (var def in PlatformSuspiciousErrorDefinitions.All)
            if (def.IsMatch(msg))
                return def.Name;

        return null;
    }

    private static bool TryResolveColumns(IReadOnlyList<string> headers, out int messageIdx, out int envIdx)
    {
        messageIdx = -1;
        envIdx = -1;

        for (int i = 0; i < headers.Count; i++)
        {
            var n = Norm(headers[i]);

            if (messageIdx < 0 && (n == "message" || n == "logbody"))
                messageIdx = i;

            if (envIdx < 0 && n.EndsWith("environmentinformation", StringComparison.OrdinalIgnoreCase))
                envIdx = i;
        }

        return messageIdx >= 0 && envIdx >= 0;
    }

    private static bool TryExtractEffectiveIp(string env, out string? effectiveIp, out string? clientIp, out string? xffIp)
    {
        effectiveIp = null;
        clientIp = null;
        xffIp = null;

        if (string.IsNullOrWhiteSpace(env))
            return false;

        var mClient = RxClientIp.Match(env);
        if (mClient.Success)
            clientIp = mClient.Groups["ip"].Value.Trim();

        var mXff = RxXff.Match(env);
        if (mXff.Success)
        {
            var raw = mXff.Groups["ip"].Value.Trim();
            var first = raw.Split(',')[0].Trim();
            xffIp = string.IsNullOrWhiteSpace(first) ? null : first;
        }

        effectiveIp = !string.IsNullOrWhiteSpace(xffIp) ? xffIp : clientIp;
        return !string.IsNullOrWhiteSpace(effectiveIp);
    }

    private static string Norm(string s)
    {
        if (string.IsNullOrWhiteSpace(s))
            return "";

        Span<char> buffer = stackalloc char[s.Length];
        int p = 0;

        foreach (var ch in s)
        {
            if (char.IsLetterOrDigit(ch))
                buffer[p++] = char.ToLowerInvariant(ch);
        }

        return new string(buffer[..p]);
    }
}

public sealed class PlatformSuspiciousScanResult
{
    public int FilesScanned { get; set; }
    public int FilesMatched { get; set; }
    public int MatchedRows { get; private set; }
    public int RowsWithXff { get; private set; }
    public int RowsWithoutXff { get; private set; }

    public int DistinctEffectiveIps { get; private set; }

    /// <summary>Rows that matched a suspicious pattern but had no client IP in the environment info.</summary>
    public int MatchedRowsWithoutIp { get; private set; }
    public Dictionary<string, int> MatchedRowsWithoutIpByFile { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Files that could not be scanned, with the reason (file name only).</summary>
    public List<(string File, string Reason)> FilesSkipped { get; } = new();

    /// <summary>Rows the CSV parser could not read or that were shorter than the header.</summary>
    public int RowsUnparsed { get; set; }

    public void AddMatchWithoutIp(string path)
    {
        MatchedRowsWithoutIp++;
        var name = Path.GetFileName(path);
        MatchedRowsWithoutIpByFile.TryGetValue(name, out var n);
        MatchedRowsWithoutIpByFile[name] = n + 1;
    }

    public void SkipFile(string path, string reason) => FilesSkipped.Add((Path.GetFileName(path), reason));

    public Dictionary<string, Dictionary<string, int>> EffectiveIpCountsByErrorType { get; } =
        new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, (int Rows, int DistinctEffectiveIps)> ByErrorType { get; } =
        new(StringComparer.OrdinalIgnoreCase);

    public List<(string Ip, int Hits)> TopEffectiveIpsOverall { get; private set; } = new();
    public Dictionary<string, List<(string Ip, int Hits)>> TopEffectiveIpsByErrorType { get; } =
        new(StringComparer.OrdinalIgnoreCase);

    public void AddHit(string typeName, string effectiveIp, string? clientIp, string? xffIp)
    {
        MatchedRows++;

        if (!string.IsNullOrWhiteSpace(xffIp))
            RowsWithXff++;
        else
            RowsWithoutXff++;

        if (!EffectiveIpCountsByErrorType.TryGetValue(typeName, out var map))
        {
            map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            EffectiveIpCountsByErrorType[typeName] = map;
        }

        map.TryGetValue(effectiveIp, out var hits);
        map[effectiveIp] = hits + 1;
    }

    public void FinalizeAggregates()
    {
        var all = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var (type, map) in EffectiveIpCountsByErrorType)
        {
            var rows = map.Values.Sum();
            var distinct = map.Count;

            ByErrorType[type] = (rows, distinct);

            var top = map
                .OrderByDescending(kvp => kvp.Value)
                .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
                .Select(kvp => (kvp.Key, kvp.Value))
                .ToList();

            TopEffectiveIpsByErrorType[type] = top;

            foreach (var kvp in map)
            {
                all.TryGetValue(kvp.Key, out var hits);
                all[kvp.Key] = hits + kvp.Value;
            }
        }

        DistinctEffectiveIps = all.Count;

        TopEffectiveIpsOverall = all
            .OrderByDescending(kvp => kvp.Value)
            .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
            .Select(kvp => (kvp.Key, kvp.Value))
            .ToList();
    }
}