using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using ClosedXML.Excel;
using LogHunter.Services;
using LogHunter.Utils;

namespace LogHunter.Web.Orchestration;

internal static class AlbIpExtractorHelper
{
    public static bool TryExtractIps(
        string filePath,
        out string ipColumn,
        out List<IpHit> ips,
        out string error)
    {
        ipColumn = "";
        ips = new List<IpHit>();
        error = "";

        var ext = Path.GetExtension(filePath);
        if (ext.Equals(".csv", StringComparison.OrdinalIgnoreCase))
            return TryExtractFromCsv(filePath, out ipColumn, out ips, out error);
        if (ext.Equals(".xlsx", StringComparison.OrdinalIgnoreCase))
            return TryExtractFromXlsx(filePath, out ipColumn, out ips, out error);

        error = "Only CSV and XLSX files are supported.";
        return false;
    }

    private static bool TryExtractFromCsv(
        string filePath,
        out string ipColumn,
        out List<IpHit> ips,
        out string error)
    {
        ipColumn = "";
        ips = new List<IpHit>();
        error = "";

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var sr = new StreamReader(fs);

            var headerLine = sr.ReadLine();
            if (string.IsNullOrWhiteSpace(headerLine))
            {
                error = "CSV file is empty.";
                return false;
            }

            var delim = headerLine.Contains('\t') ? '\t' : ',';
            var headers = CsvLite.Split(headerLine, delim);
            var ipCol = FindIpColumnIndex(headers);
            if (ipCol < 0)
            {
                error = "No IP-like column found in CSV header.";
                return false;
            }

            ipColumn = headers[ipCol];
            var hitsCol = FindHitsColumnIndex(headers);
            var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            string? line;
            while ((line = sr.ReadLine()) is not null)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var cols = CsvLite.Split(line, delim);
                if (ipCol >= cols.Count) continue;

                var ip = NormalizeIp(cols[ipCol]);
                if (ip is null) continue;

                var hits = 1;
                if (hitsCol >= 0 && hitsCol < cols.Count)
                {
                    var text = cols[hitsCol].Trim();
                    if (int.TryParse(text.Replace(",", "", StringComparison.Ordinal), out var parsed) && parsed > 0)
                        hits = parsed;
                }

                counts[ip] = counts.TryGetValue(ip, out var cur) ? cur + hits : hits;
            }

            if (counts.Count == 0)
            {
                error = $"Detected IP column '{ipColumn}', but no valid IPs were found.";
                return false;
            }

            ips = counts
                .OrderByDescending(kvp => kvp.Value)
                .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
                .Select(kvp => new IpHit(kvp.Key, kvp.Value))
                .ToList();
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool TryExtractFromXlsx(
        string filePath,
        out string ipColumn,
        out List<IpHit> ips,
        out string error)
    {
        ipColumn = "";
        ips = new List<IpHit>();
        error = "";

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var wb = new XLWorkbook(fs);
            var ws = wb.Worksheets.FirstOrDefault();
            if (ws is null)
            {
                error = "XLSX has no worksheets.";
                return false;
            }

            var usedRange = ws.RangeUsed();
            if (usedRange is null)
            {
                error = "XLSX worksheet is empty.";
                return false;
            }

            var firstRow = usedRange.RangeAddress.FirstAddress.RowNumber;
            var lastRow = usedRange.RangeAddress.LastAddress.RowNumber;
            var firstCol = usedRange.RangeAddress.FirstAddress.ColumnNumber;
            var lastCol = usedRange.RangeAddress.LastAddress.ColumnNumber;

            // Try to find headers in the first few rows
            int ipCol = -1;
            int hitsCol = -1;
            int headerRow = -1;

            for (int r = firstRow; r <= Math.Min(lastRow, firstRow + 10); r++)
            {
                var headers = new List<string>();
                for (int c = firstCol; c <= lastCol; c++)
                    headers.Add(ws.Cell(r, c).GetString());

                var idx = FindIpColumnIndex(headers);
                if (idx >= 0)
                {
                    headerRow = r;
                    ipCol = firstCol + idx;
                    ipColumn = headers[idx];
                    var hitsIdx = FindHitsColumnIndex(headers);
                    if (hitsIdx >= 0)
                        hitsCol = firstCol + hitsIdx;
                    break;
                }
            }

            if (headerRow < 0 || ipCol < 0)
            {
                error = "Could not detect an IP column in the XLSX file.";
                return false;
            }

            var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            for (int r = headerRow + 1; r <= lastRow; r++)
            {
                var ip = NormalizeIp(ws.Cell(r, ipCol).GetString());
                if (ip is null) continue;

                var hits = 1;
                if (hitsCol > 0)
                {
                    var text = ws.Cell(r, hitsCol).GetString().Trim();
                    if (int.TryParse(text.Replace(",", "", StringComparison.Ordinal), out var parsed) && parsed > 0)
                        hits = parsed;
                }

                counts[ip] = counts.TryGetValue(ip, out var cur) ? cur + hits : hits;
            }

            if (counts.Count == 0)
            {
                error = $"Detected IP column '{ipColumn}', but no valid IPs were found.";
                return false;
            }

            ips = counts
                .OrderByDescending(kvp => kvp.Value)
                .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
                .Select(kvp => new IpHit(kvp.Key, kvp.Value))
                .ToList();
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static int FindIpColumnIndex(IReadOnlyList<string> headers)
    {
        var preferred = new[] { "ip", "ipaddress", "ip_address", "clientip", "client_ip", "client ip", "sourceip", "source_ip", "source ip" };
        for (var i = 0; i < headers.Count; i++)
        {
            var h = headers[i].Trim().ToLowerInvariant();
            if (preferred.Contains(h))
                return i;
        }

        for (var i = 0; i < headers.Count; i++)
        {
            var h = headers[i].Trim().ToLowerInvariant();
            if (h.Contains("ip") && !h.Contains("zip") && !h.Contains("ship"))
                return i;
        }

        return -1;
    }

    private static int FindHitsColumnIndex(IReadOnlyList<string> headers)
    {
        for (var i = 0; i < headers.Count; i++)
        {
            var h = headers[i].Trim().ToLowerInvariant();
            if (h == "hits" || h == "count" || h == "requests" || h == "totalrequests" || h == "postputcount")
                return i;
        }
        return -1;
    }

    private static string? NormalizeIp(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var s = raw.Trim().Trim('"').Trim();
        if (s.Contains('.') && s.Count(c => c == ':') == 1)
            s = s.Split(':', 2)[0];
        if (s.StartsWith('[') && s.EndsWith(']') && s.Length > 2)
            s = s[1..^1];

        return IPAddress.TryParse(s, out _) ? s : null;
    }

    internal sealed record IpHit(string Ip, int Hits);
}
