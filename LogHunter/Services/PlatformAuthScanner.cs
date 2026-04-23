// Services/PlatformAuthScanner.cs
using ExcelDataReader;
using Microsoft.VisualBasic.FileIO;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Services;

public static class PlatformAuthScanner
{
    private static readonly Regex RxXff = new(
        @"X-Forwarded-For:\s*(?<ip>[0-9a-fA-F\.:, ]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex RxClientIpFromEnv = new(
        @"ClientIp:\s*(?<ip>[0-9a-fA-F\.:]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex RxXffFromEnv = new(
        @"X-Forwarded-For:\s*(?<ip>[0-9a-fA-F\.:, ]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static Task<PlatformAuthScanResult> ScanAuthenticatedActivityAsync(
        string platformLogsDir,
        IReadOnlyCollection<string> suspiciousIps,
        CancellationToken ct = default)
        => Task.Run(() => Scan(platformLogsDir, suspiciousIps, ct), ct);

    private static PlatformAuthScanResult Scan(string dir, IReadOnlyCollection<string> suspiciousIps, CancellationToken ct)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

        var suspicious = new HashSet<string>(
            suspiciousIps.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()),
            StringComparer.OrdinalIgnoreCase);

        var files = Directory.EnumerateFiles(dir, "*.*", System.IO.SearchOption.AllDirectories)
            .Where(p => p.EndsWith(".csv", StringComparison.OrdinalIgnoreCase) ||
                        p.EndsWith(".xlsx", StringComparison.OrdinalIgnoreCase))
            .ToList();

        var res = new PlatformAuthScanResult
        {
            FilesScanned = files.Count,
            SuspiciousIpsInput = suspicious.Count
        };

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                bool anyHit = file.EndsWith(".csv", StringComparison.OrdinalIgnoreCase)
                    ? ScanCsv(file, suspicious, res, ct)
                    : ScanXlsx(file, suspicious, res, ct);

                if (anyHit)
                    res.FilesMatched++;
            }
            catch
            {
                // Ignore broken files.
            }
        }

        res.FinalizeAggregates();
        return res;
    }

    // ---------------- CSV ----------------

    private static bool ScanCsv(string path, HashSet<string> suspicious, PlatformAuthScanResult res, CancellationToken ct)
    {
        // Ignore integrations by filename (cheap + safe)
        if (Path.GetFileName(path).Contains("Integrations", StringComparison.OrdinalIgnoreCase))
            return false;

        // Detect delimiter from header line
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
            return false;

        if (!TryClassify(header, out var kind, out var spec))
            return false;

        bool anyHit = false;
        var fileName = Path.GetFileName(path);

        while (!parser.EndOfData)
        {
            ct.ThrowIfCancellationRequested();

            string[]? fields;
            try { fields = parser.ReadFields(); }
            catch { continue; }

            if (fields is null || fields.Length == 0)
                continue;

            TryGetUserId(fields, spec.UserIdIdx, out var userId);

            if (!TryGetEffectiveIpCsv(kind, fields, spec, out var effectiveIp))
                continue;

            if (!suspicious.Contains(effectiveIp))
                continue;

            bool isAuth = userId != 0;
            res.AddRow(new PlatformAuthScanResult.CollectedRow(effectiveIp, userId, isAuth, kind, fileName));

            if (isAuth)
            {
                anyHit = true;
                res.AddHit(effectiveIp, kind);
            }
        }

        if (anyHit)
            res.AddMatchedFile(kind);

        return anyHit;
    }

    // ---------------- XLSX ----------------

    private static bool ScanXlsx(string path, HashSet<string> suspicious, PlatformAuthScanResult res, CancellationToken ct)
    {
        if (Path.GetFileName(path).Contains("Integrations", StringComparison.OrdinalIgnoreCase))
            return false;

        using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = ExcelReaderFactory.CreateReader(stream);

        bool anyHit = false;
        var kindsHit = new HashSet<PlatformLogKind>();

        do
        {
            ct.ThrowIfCancellationRequested();

            // First row in each sheet is expected to be the header
            if (!reader.Read())
                continue;

            var headers = new string[reader.FieldCount];
            for (int i = 0; i < reader.FieldCount; i++)
                headers[i] = reader.GetValue(i)?.ToString() ?? "";

            if (!TryClassify(headers, out var kind, out var spec))
                continue;

            var fileName = Path.GetFileName(path);

            while (reader.Read())
            {
                ct.ThrowIfCancellationRequested();

                var userVal = reader.GetValue(spec.UserIdIdx);
                TryParseUserId(userVal, out var userId);

                if (!TryGetEffectiveIpXlsx(kind, reader, spec, out var effectiveIp))
                    continue;

                if (!suspicious.Contains(effectiveIp))
                    continue;

                bool isAuth = userId != 0;
                res.AddRow(new PlatformAuthScanResult.CollectedRow(effectiveIp, userId, isAuth, kind, fileName));

                if (isAuth)
                {
                    anyHit = true;
                    kindsHit.Add(kind);
                    res.AddHit(effectiveIp, kind);
                }
            }
        }
        while (reader.NextResult());

        if (anyHit)
        {
            // One file can contain multiple sheets/kinds
            foreach (var k in kindsHit)
                res.AddMatchedFile(k);
        }

        return anyHit;
    }

    // ---------------- Classification ----------------

    private static bool TryClassify(IReadOnlyList<string> headers, out PlatformLogKind kind, out LogSpec spec)
    {
        kind = PlatformLogKind.Unknown;
        spec = default;

        if (TryResolveError(headers, out spec))
        {
            kind = PlatformLogKind.Error;
            return true;
        }

        if (TryResolveScreen(headers, out spec))
        {
            kind = PlatformLogKind.ScreenRequests;
            return true;
        }

        if (TryResolveHttp(headers, out spec, out var isTraditional))
        {
            kind = isTraditional ? PlatformLogKind.TraditionalWebRequests : PlatformLogKind.General;
            return true;
        }

        return false;
    }

    private static bool TryResolveError(IReadOnlyList<string> headers, out LogSpec spec)
    {
        spec = default;

        int envIdx = -1;
        int userIdx = -1;

        for (int i = 0; i < headers.Count; i++)
        {
            var n = Norm(headers[i]);

            if (envIdx < 0 && n.EndsWith("environmentinformation", StringComparison.OrdinalIgnoreCase))
                envIdx = i;

            if (userIdx < 0 && (n == "userid" || n == "logattributesenduserid"))
                userIdx = i;
        }

        if (envIdx >= 0 && userIdx >= 0)
        {
            spec = new LogSpec(UserIdIdx: userIdx, IpIdx: -1, EnvIdx: envIdx);
            return true;
        }

        return false;
    }

    private static bool TryResolveScreen(IReadOnlyList<string> headers, out LogSpec spec)
    {
        spec = default;

        int ipIdx = -1;
        int userIdx = -1;

        for (int i = 0; i < headers.Count; i++)
        {
            var n = Norm(headers[i]);

            if (ipIdx < 0 && (n == "logattributesnethostip" || n == "source"))
                ipIdx = i;

            if (userIdx < 0 && (n == "userid" || n == "logattributesenduserid"))
                userIdx = i;
        }

        if (ipIdx >= 0 && userIdx >= 0)
        {
            spec = new LogSpec(UserIdIdx: userIdx, IpIdx: ipIdx, EnvIdx: -1);
            return true;
        }

        return false;
    }

    private static bool TryResolveHttp(IReadOnlyList<string> headers, out LogSpec spec, out bool isTraditional)
    {
        spec = default;
        isTraditional = false;

        int ipIdx = -1;
        int userIdx = -1;

        bool traditionalHint = false;

        for (int i = 0; i < headers.Count; i++)
        {
            var n = Norm(headers[i]);

            if (ipIdx < 0 && (n == "logattributeshttpclientip" || n == "clientip"))
                ipIdx = i;

            if (userIdx < 0 && (n == "userid" || n == "logattributesenduserid"))
                userIdx = i;

            // Traditional web requests discriminator (based on your exports)
            if (n.Contains("traditionalss") || n == "msisdn" || n == "screentype" || n.Contains("screenaccessmode"))
                traditionalHint = true;
        }

        if (ipIdx >= 0 && userIdx >= 0)
        {
            isTraditional = traditionalHint;
            spec = new LogSpec(UserIdIdx: userIdx, IpIdx: ipIdx, EnvIdx: -1);
            return true;
        }

        return false;
    }

    // ---------------- Extractors ----------------

    private static bool TryGetUserId(string[] fields, int userIdx, out int userId)
    {
        userId = 0;
        if (userIdx < 0 || userIdx >= fields.Length)
            return false;

        return TryParseUserId(fields[userIdx], out userId);
    }

    private static bool TryParseUserId(object? v, out int userId)
    {
        userId = 0;
        if (v is null) return false;

        if (v is int i) { userId = i; return true; }
        if (v is long l) { userId = (int)l; return true; }
        if (v is double d) { userId = (int)d; return true; }

        var s = v.ToString()?.Trim();
        if (string.IsNullOrWhiteSpace(s))
            return false;

        if (s.Contains('.', StringComparison.Ordinal) &&
            double.TryParse(s, NumberStyles.Any, CultureInfo.InvariantCulture, out var dd))
        {
            userId = (int)dd;
            return true;
        }

        return int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out userId);
    }

    private static bool TryGetEffectiveIpCsv(PlatformLogKind kind, string[] fields, LogSpec spec, out string effectiveIp)
    {
        effectiveIp = "";

        if (kind == PlatformLogKind.Error)
        {
            if (spec.EnvIdx < 0 || spec.EnvIdx >= fields.Length) return false;
            var env = fields[spec.EnvIdx] ?? "";
            return TryExtractEffectiveIpFromEnv(env, out effectiveIp);
        }

        if (spec.IpIdx < 0 || spec.IpIdx >= fields.Length) return false;
        var cell = fields[spec.IpIdx] ?? "";
        return TryExtractEffectiveIpFromCell(cell, out effectiveIp);
    }

    private static bool TryGetEffectiveIpXlsx(PlatformLogKind kind, IExcelDataReader reader, LogSpec spec, out string effectiveIp)
    {
        effectiveIp = "";

        if (kind == PlatformLogKind.Error)
        {
            var env = reader.GetValue(spec.EnvIdx)?.ToString() ?? "";
            return TryExtractEffectiveIpFromEnv(env, out effectiveIp);
        }

        var cell = reader.GetValue(spec.IpIdx)?.ToString() ?? "";
        return TryExtractEffectiveIpFromCell(cell, out effectiveIp);
    }

    private static bool TryExtractEffectiveIpFromCell(string s, out string ip)
    {
        ip = "";
        if (string.IsNullOrWhiteSpace(s))
            return false;

        var m = RxXff.Match(s);
        if (m.Success)
        {
            var raw = m.Groups["ip"].Value.Trim();
            var first = raw.Split(',')[0].Trim();
            if (IPAddress.TryParse(first, out _))
            {
                ip = first;
                return true;
            }
        }

        foreach (var token in s.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var t = token.Trim().Trim('"');
            if (IPAddress.TryParse(t, out _))
            {
                ip = t;
                return true;
            }
        }

        return false;
    }

    private static bool TryExtractEffectiveIpFromEnv(string env, out string ip)
    {
        ip = "";
        if (string.IsNullOrWhiteSpace(env))
            return false;

        var mXff = RxXffFromEnv.Match(env);
        if (mXff.Success)
        {
            var raw = mXff.Groups["ip"].Value.Trim();
            var first = raw.Split(',')[0].Trim();
            if (IPAddress.TryParse(first, out _))
            {
                ip = first;
                return true;
            }
        }

        var mClient = RxClientIpFromEnv.Match(env);
        if (mClient.Success)
        {
            var c = mClient.Groups["ip"].Value.Trim();
            if (IPAddress.TryParse(c, out _))
            {
                ip = c;
                return true;
            }
        }

        return false;
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

    private readonly record struct LogSpec(int UserIdIdx, int IpIdx, int EnvIdx);
}

public enum PlatformLogKind
{
    Unknown = 0,
    Error = 1,
    ScreenRequests = 2,
    TraditionalWebRequests = 3,
    General = 4
}

public sealed class PlatformAuthScanResult
{
    public int FilesScanned { get; set; }
    public int FilesMatched { get; set; }
    public int SuspiciousIpsInput { get; set; }

    public Dictionary<PlatformLogKind, int> FilesMatchedByKind { get; } = new();
    public Dictionary<PlatformLogKind, int> RowsMatchedByKind { get; } = new();

    // IP -> hits breakdown
    public Dictionary<string, IpAuthHits> HitsByIp { get; } = new(StringComparer.OrdinalIgnoreCase);

    public int TotalMatchedRows { get; private set; }
    public int DistinctMatchedIps { get; private set; }

    public List<(string Ip, int Hits)> TopIpsOverall { get; private set; } = new();

    public void AddHit(string ip, PlatformLogKind kind)
    {
        TotalMatchedRows++;

        if (RowsMatchedByKind.TryGetValue(kind, out var r))
            RowsMatchedByKind[kind] = r + 1;
        else
            RowsMatchedByKind[kind] = 1;

        if (!HitsByIp.TryGetValue(ip, out var h))
        {
            h = new IpAuthHits();
            HitsByIp[ip] = h;
        }

        h.Total++;

        switch (kind)
        {
            case PlatformLogKind.Error: h.Error++; break;
            case PlatformLogKind.ScreenRequests: h.Screen++; break;
            case PlatformLogKind.TraditionalWebRequests: h.Traditional++; break;
            case PlatformLogKind.General: h.General++; break;
        }
    }

    public void AddMatchedFile(PlatformLogKind kind)
    {
        if (FilesMatchedByKind.TryGetValue(kind, out var v))
            FilesMatchedByKind[kind] = v + 1;
        else
            FilesMatchedByKind[kind] = 1;
    }

    public void FinalizeAggregates()
    {
        DistinctMatchedIps = HitsByIp.Count;

        TopIpsOverall = HitsByIp
            .OrderByDescending(kvp => kvp.Value.Total)
            .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
            .Select(kvp => (kvp.Key, kvp.Value.Total))
            .ToList();
    }

    // Mutable class so we can increment counters safely
    public sealed class IpAuthHits
    {
        public int Total { get; set; }
        public int General { get; set; }
        public int Traditional { get; set; }
        public int Screen { get; set; }
        public int Error { get; set; }
    }

    /// <summary>Row-level data collected for Excel export.</summary>
    public readonly record struct CollectedRow(
        string Ip,
        int UserId,
        bool IsAuthenticated,
        PlatformLogKind LogKind,
        string SourceFile);

    public List<CollectedRow> CollectedRows { get; } = new();

    public void AddRow(CollectedRow row) => CollectedRows.Add(row);
}