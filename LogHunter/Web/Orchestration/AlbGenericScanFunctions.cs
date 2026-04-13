using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using LogHunter.Services;

namespace LogHunter.Web.Orchestration;

/// <summary>
/// Scan functions for ALB options 4-9, each returning an AlbGenericScanResult.
/// These wrap the existing core scanner logic without modifying it.
/// </summary>
internal static class AlbGenericScanFunctions
{
    // ── Option 3: 5xx while backend succeeded ─────────────────────

    public static async Task<AlbGenericScanResult> ScanStatusMismatchAsync(
        List<string> files,
        string outputFolder,
        Action<string, int, int, string> reportProgress)
    {
        var result = new AlbStatusMismatchScanner.ScanResult();

        for (var i = 0; i < files.Count; i++)
        {
            await AlbStatusMismatchScanner.ScanFileAsync(files[i], result, _ => { }).ConfigureAwait(false);
            reportProgress($"Scanning ALB logs: {i + 1} / {files.Count} files.", i + 1, files.Count, "scanning");
        }

        if (result.TotalRows == 0)
        {
            return new AlbGenericScanResult(
                CompletionMessage: "No matches found where ALB returned 5xx and the target/backend returned 2xx/3xx.",
                ExportPath: null,
                Rows: Array.Empty<AlbGenericResultRow>(),
                Columns: new[] { "Rank", "Status Pair", "Hits" },
                TotalMatches: 0,
                FirstHitUtc: null,
                LastHitUtc: null,
                FilesWithHits: 0,
                ChartHtmlPath: null);
        }

        Directory.CreateDirectory(outputFolder);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var excelPath = Path.Combine(outputFolder, $"alb_5xx_while_backend_succeeded_{stamp}.xlsx");
        AlbStatusMismatchExportExcel.Export(excelPath, result);

        var topStatusPairs = result.TopStatusPairs(10);
        var topUris = result.TopUris(15);
        var topIps = result.TopClientIps(15);

        var rows = new List<AlbGenericResultRow>();

        // Section 1: Top status pairs
        foreach (var (kvp, idx) in topStatusPairs.Select((x, i) => (x, i)))
            rows.Add(new AlbGenericResultRow(new[] { (idx + 1).ToString(), kvp.Key, kvp.Value.ToString("N0", CultureInfo.InvariantCulture), "status-pair" }));

        // Section 2: Top URIs
        foreach (var (kvp, idx) in topUris.Select((x, i) => (x, i)))
            rows.Add(new AlbGenericResultRow(new[] { (idx + 1).ToString(), kvp.Key, kvp.Value.ToString("N0", CultureInfo.InvariantCulture), "uri" }));

        // Section 3: Top client IPs
        foreach (var (kvp, idx) in topIps.Select((x, i) => (x, i)))
            rows.Add(new AlbGenericResultRow(new[] { (idx + 1).ToString(), kvp.Key, kvp.Value.ToString("N0", CultureInfo.InvariantCulture), "client-ip" }));

        return new AlbGenericScanResult(
            CompletionMessage: $"Scan complete. {result.TotalRows:N0} matches found across {result.SourceFiles.Count} files.",
            ExportPath: excelPath,
            Rows: rows,
            Columns: new[] { "Rank", "Value", "Hits", "Section" },
            TotalMatches: result.TotalRows,
            FirstHitUtc: result.FirstHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
            LastHitUtc: result.LastHitUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
            FilesWithHits: result.SourceFiles.Count,
            ChartHtmlPath: null);
    }

    // ── Option 4: Top 50 IPs overall ──────────────────────────────

    public static async Task<AlbGenericScanResult> ScanTop50IpsOverallAsync(
        List<string> files,
        string outputFolder,
        Action<string, int, int, string> reportProgress)
    {
        var ipCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        for (var i = 0; i < files.Count; i++)
        {
            await AlbScanner.ScanFileForOverallIpCountsAsync(files[i], ipCounts, _ => { }).ConfigureAwait(false);
            reportProgress($"Scanning ALB logs: {i + 1} / {files.Count} files.", i + 1, files.Count, "scanning");
        }

        if (ipCounts.Count == 0)
        {
            return new AlbGenericScanResult(
                CompletionMessage: "No IPs found.",
                ExportPath: null,
                Rows: Array.Empty<AlbGenericResultRow>(),
                Columns: new[] { "Rank", "IP", "Hits" },
                TotalMatches: 0,
                FirstHitUtc: null,
                LastHitUtc: null,
                FilesWithHits: 0,
                ChartHtmlPath: null);
        }

        var top = ipCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(50)
            .Select((kvp, idx) => new { Rank = idx + 1, IP = kvp.Key, Hits = kvp.Value })
            .ToList();

        Directory.CreateDirectory(outputFolder);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var csvPath = Path.Combine(outputFolder, $"ALB_Top50_IPs_{stamp}.csv");

        using (var sw = new StreamWriter(csvPath, false, Encoding.UTF8))
        {
            sw.WriteLine("Rank,IP,Hits");
            foreach (var row in top)
                sw.WriteLine($"{row.Rank},{row.IP},{row.Hits}");
        }

        var totalHits = top.Sum(x => (long)x.Hits);
        var rows = top.Select(x => new AlbGenericResultRow(
            new[] { x.Rank.ToString(), x.IP, x.Hits.ToString("N0", CultureInfo.InvariantCulture) })).ToList();

        return new AlbGenericScanResult(
            CompletionMessage: $"Scan complete. {ipCounts.Count:N0} unique IPs found. Top 50 exported.",
            ExportPath: csvPath,
            Rows: rows,
            Columns: new[] { "Rank", "IP", "Hits" },
            TotalMatches: totalHits,
            FirstHitUtc: null,
            LastHitUtc: null,
            FilesWithHits: files.Count,
            ChartHtmlPath: null);
    }

    // ── Option 5: Top 50 IPs by URI (no query) ───────────────────

    public static async Task<AlbGenericScanResult> ScanTop50IpUriNoQueryAsync(
        List<string> files,
        string outputFolder,
        Action<string, int, int, string> reportProgress)
    {
        var pairCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        for (var i = 0; i < files.Count; i++)
        {
            await AlbScanner.ScanFileForIpUriCountsAsync(files[i], pairCounts, _ => { }).ConfigureAwait(false);
            reportProgress($"Scanning ALB logs: {i + 1} / {files.Count} files.", i + 1, files.Count, "scanning");
        }

        if (pairCounts.Count == 0)
        {
            return new AlbGenericScanResult(
                CompletionMessage: "No results found.",
                ExportPath: null,
                Rows: Array.Empty<AlbGenericResultRow>(),
                Columns: new[] { "Rank", "IP", "URI", "Hits" },
                TotalMatches: 0,
                FirstHitUtc: null,
                LastHitUtc: null,
                FilesWithHits: 0,
                ChartHtmlPath: null);
        }

        var top = pairCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(50)
            .Select((kvp, idx) =>
            {
                var key = kvp.Key;
                var tab = key.IndexOf('\t');
                var ip = tab > 0 ? key[..tab] : key;
                var uri = (tab > 0 && tab + 1 < key.Length) ? key[(tab + 1)..] : "";
                return new { Rank = idx + 1, IP = ip, URI = uri, Hits = kvp.Value };
            })
            .ToList();

        Directory.CreateDirectory(outputFolder);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var csvPath = Path.Combine(outputFolder, $"ALB_Top50_IPs_NoQuery_URIs_{stamp}.csv");

        using (var sw = new StreamWriter(csvPath, false, Encoding.UTF8))
        {
            sw.WriteLine("Rank,Hits,IP,URI");
            foreach (var row in top)
            {
                var uri = row.URI.Replace("\"", "\"\"");
                sw.WriteLine($"{row.Rank},{row.Hits},{row.IP},\"{uri}\"");
            }
        }

        var totalHits = top.Sum(x => (long)x.Hits);
        var rows = top.Select(x => new AlbGenericResultRow(
            new[] { x.Rank.ToString(), x.IP, x.URI, x.Hits.ToString("N0", CultureInfo.InvariantCulture) })).ToList();

        return new AlbGenericScanResult(
            CompletionMessage: $"Scan complete. {pairCounts.Count:N0} unique IP+URI pairs found. Top 50 exported.",
            ExportPath: csvPath,
            Rows: rows,
            Columns: new[] { "Rank", "IP", "URI", "Hits" },
            TotalMatches: totalHits,
            FirstHitUtc: null,
            LastHitUtc: null,
            FilesWithHits: files.Count,
            ChartHtmlPath: null);
    }

    // ── Option 6: Top 50 requests by AVG duration ─────────────────

    private struct UriAgg
    {
        public long Count;
        public double SumSeconds;
        public double MaxSeconds;
    }

    public static async Task<AlbGenericScanResult> ScanTop50AvgDurationAsync(
        List<string> files,
        string outputFolder,
        Action<string, int, int, string> reportProgress)
    {
        var stats = new Dictionary<string, UriAgg>(StringComparer.Ordinal);

        for (var i = 0; i < files.Count; i++)
        {
            await ScanFileForDurationStatsAsync(files[i], stats).ConfigureAwait(false);
            reportProgress($"Scanning ALB logs: {i + 1} / {files.Count} files.", i + 1, files.Count, "scanning");
        }

        if (stats.Count == 0)
        {
            return new AlbGenericScanResult(
                CompletionMessage: "No request duration data found in parsed logs.",
                ExportPath: null,
                Rows: Array.Empty<AlbGenericResultRow>(),
                Columns: new[] { "Rank", "AVG (s)", "Count", "MAX (s)", "URI" },
                TotalMatches: 0,
                FirstHitUtc: null,
                LastHitUtc: null,
                FilesWithHits: 0,
                ChartHtmlPath: null);
        }

        var results = stats
            .Select(kvp =>
            {
                var agg = kvp.Value;
                var avg = agg.Count > 0 ? agg.SumSeconds / agg.Count : 0.0;
                return new { AvgSeconds = avg, Count = agg.Count, MaxSeconds = agg.MaxSeconds, URI = kvp.Key };
            })
            .OrderByDescending(x => x.AvgSeconds)
            .Take(50)
            .Select((x, idx) => new { Rank = idx + 1, x.AvgSeconds, x.Count, x.MaxSeconds, x.URI })
            .ToList();

        Directory.CreateDirectory(outputFolder);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var csvPath = Path.Combine(outputFolder, $"ALB_Top50_Requests_AvgDuration_{stamp}.csv");

        using (var sw = new StreamWriter(csvPath, false, Encoding.UTF8))
        {
            sw.WriteLine("AvgSeconds,Count,MaxSeconds,URI");
            foreach (var r in results)
            {
                var uriEsc = r.URI.Replace("\"", "\"\"");
                sw.WriteLine($"{r.AvgSeconds:0.000},{r.Count},{r.MaxSeconds:0.000},\"{uriEsc}\"");
            }
        }

        var totalCount = results.Sum(x => x.Count);
        var rows = results.Select(x => new AlbGenericResultRow(
            new[]
            {
                x.Rank.ToString(),
                x.AvgSeconds.ToString("0.000", CultureInfo.InvariantCulture),
                x.Count.ToString("N0", CultureInfo.InvariantCulture),
                x.MaxSeconds.ToString("0.000", CultureInfo.InvariantCulture),
                x.URI
            })).ToList();

        return new AlbGenericScanResult(
            CompletionMessage: $"Scan complete. {stats.Count:N0} unique URIs found. Top 50 exported.",
            ExportPath: csvPath,
            Rows: rows,
            Columns: new[] { "Rank", "AVG (s)", "Count", "MAX (s)", "URI" },
            TotalMatches: totalCount,
            FirstHitUtc: null,
            LastHitUtc: null,
            FilesWithHits: files.Count,
            ChartHtmlPath: null);
    }

    private static async Task ScanFileForDurationStatsAsync(string filePath, Dictionary<string, UriAgg> stats)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

        while (true)
        {
            var line = await sr.ReadLineAsync().ConfigureAwait(false);
            if (line is null) break;
            if (line.Length == 0) continue;

            var dur = AlbScanner.ExtractAlbTargetProcessingTimeSeconds(line);
            if (dur is null || dur.Value < 0) continue;

            var uri = AlbScanner.ExtractAlbUriNoQuery(line);
            if (string.IsNullOrEmpty(uri)) continue;

            if (!stats.TryGetValue(uri, out var agg))
                agg = default;

            agg.Count++;
            agg.SumSeconds += dur.Value;
            if (dur.Value > agg.MaxSeconds) agg.MaxSeconds = dur.Value;

            stats[uri] = agg;
        }
    }

    // ── Option 7: ALB requests over time per selected IP (5-minute buckets) ──

    public static Func<List<string>, string, Action<string, int, int, string>, Task<AlbGenericScanResult>>
        CreateRequestsPerIp5MinFunc(List<string> ips, string sourceLabel)
    {
        return async (files, outputFolder, reportProgress) =>
        {
            var bucketsByIp = new Dictionary<string, SortedDictionary<DateTime, long>>(StringComparer.Ordinal);
            foreach (var ip in ips)
                bucketsByIp[ip] = new SortedDictionary<DateTime, long>();

            for (var i = 0; i < files.Count; i++)
            {
                await ScanFileForIpBucketsAsync(files[i], bucketsByIp).ConfigureAwait(false);
                reportProgress($"Scanning ALB logs: {i + 1} / {files.Count} files.", i + 1, files.Count, "scanning");
            }

            var allBuckets = new SortedSet<DateTime>();
            foreach (var ip in ips)
                foreach (var b in bucketsByIp[ip].Keys)
                    allBuckets.Add(b);

            if (allBuckets.Count == 0)
            {
                return new AlbGenericScanResult(
                    CompletionMessage: "No matches found for the selected IPs.",
                    ExportPath: null,
                    Rows: Array.Empty<AlbGenericResultRow>(),
                    Columns: new[] { "BucketStartUtc" }.Concat(ips).ToArray(),
                    TotalMatches: 0,
                    FirstHitUtc: null,
                    LastHitUtc: null,
                    FilesWithHits: 0,
                    ChartHtmlPath: null);
            }

            Directory.CreateDirectory(outputFolder);

            // Build chart
            var times = allBuckets.ToArray();
            var series = new List<Charts.TimeSeriesSeries>(ips.Count);

            foreach (var ip in ips)
            {
                var ys = new double[times.Length];
                var map = bucketsByIp[ip];
                for (int i = 0; i < times.Length; i++)
                {
                    map.TryGetValue(times[i], out var c);
                    ys[i] = c;
                }
                series.Add(new Charts.TimeSeriesSeries(SeriesName: ip, TimesUtc: times, Values: ys));
            }

            var chartPath = Charts.SaveTimeSeriesHtml(
                outputFolder: outputFolder,
                title: "ALB Requests per IP per 5 minutes",
                yLabel: "Requests",
                series: series,
                filePrefix: "ALB_RequestsPer5Min");

            long totalHits = 0;
            foreach (var ip in ips)
                totalHits += bucketsByIp[ip].Values.Sum();

            // Build summary rows (top 20 buckets by total)
            var rows = new List<AlbGenericResultRow>();
            var bucketTotals = allBuckets.Select(b =>
            {
                long total = 0;
                foreach (var ip in ips)
                {
                    bucketsByIp[ip].TryGetValue(b, out var c);
                    total += c;
                }
                return new { Bucket = b, Total = total };
            })
            .OrderByDescending(x => x.Total)
            .Take(20)
            .ToList();

            foreach (var bt in bucketTotals)
            {
                var values = new List<string>
                {
                    bt.Bucket.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)
                };
                foreach (var ip in ips)
                {
                    bucketsByIp[ip].TryGetValue(bt.Bucket, out var c);
                    values.Add(c.ToString("N0", CultureInfo.InvariantCulture));
                }
                rows.Add(new AlbGenericResultRow(values));
            }

            return new AlbGenericScanResult(
                CompletionMessage: $"Scan complete. {totalHits:N0} total hits across {ips.Count} IPs in {allBuckets.Count} time buckets.",
                ExportPath: null,
                Rows: rows,
                Columns: new[] { "BucketStartUtc" }.Concat(ips).ToArray(),
                TotalMatches: totalHits,
                FirstHitUtc: times.First().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                LastHitUtc: times.Last().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                FilesWithHits: files.Count,
                ChartHtmlPath: chartPath);
        };
    }

    private static DateTime FloorTo5MinUtc(DateTime dtUtc)
    {
        dtUtc = dtUtc.Kind == DateTimeKind.Utc ? dtUtc : dtUtc.ToUniversalTime();
        int flooredMinute = (dtUtc.Minute / 5) * 5;
        return new DateTime(dtUtc.Year, dtUtc.Month, dtUtc.Day, dtUtc.Hour, flooredMinute, 0, DateTimeKind.Utc);
    }

    private static async Task ScanFileForIpBucketsAsync(string filePath, Dictionary<string, SortedDictionary<DateTime, long>> bucketsByIp)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

        while (true)
        {
            var line = await sr.ReadLineAsync().ConfigureAwait(false);
            if (line is null) break;
            if (line.Length == 0) continue;

            var ip = AlbScanner.ExtractAlbClientIp(line);
            if (ip is null) continue;

            if (!bucketsByIp.TryGetValue(ip, out var map))
                continue;

            var tsUtc = AlbScanner.ExtractAlbTimestampUtc(line);
            if (tsUtc is null) continue;

            var bucket = FloorTo5MinUtc(tsUtc.Value);

            if (map.TryGetValue(bucket, out var cur))
                map[bucket] = cur + 1;
            else
                map[bucket] = 1;
        }
    }

    // ── Option 8: WAF blocked summary ─────────────────────────────

    public static async Task<AlbGenericScanResult> ScanWafBlockedSummaryAsync(
        List<string> files,
        string outputFolder,
        Action<string, int, int, string> reportProgress)
    {
        var counters = new WafCounters();
        var blockedCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        for (var i = 0; i < files.Count; i++)
        {
            await ScanFileForWafBlockedAsync(files[i], counters, blockedCounts).ConfigureAwait(false);
            reportProgress($"Scanning ALB logs: {i + 1} / {files.Count} files.", i + 1, files.Count, "scanning");
        }

        long total = counters.Total;
        long blocked = counters.Blocked;

        if (blockedCounts.Count == 0)
        {
            return new AlbGenericScanResult(
                CompletionMessage: $"No blocked requests found. {total:N0} total entries parsed.",
                ExportPath: null,
                Rows: Array.Empty<AlbGenericResultRow>(),
                Columns: new[] { "Rank", "IP", "URI", "Hits" },
                TotalMatches: blocked,
                FirstHitUtc: null,
                LastHitUtc: null,
                FilesWithHits: 0,
                ChartHtmlPath: null);
        }

        var top = blockedCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(50)
            .Select((kvp, idx) =>
            {
                var key = kvp.Key;
                var tab = key.IndexOf('\t');
                var ip = tab > 0 ? key[..tab] : key;
                var uri = (tab > 0 && tab + 1 < key.Length) ? key[(tab + 1)..] : "";
                return new { Rank = idx + 1, IP = ip, URI = uri, Hits = kvp.Value };
            })
            .ToList();

        Directory.CreateDirectory(outputFolder);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var csvPath = Path.Combine(outputFolder, $"ALB_WAF_Blocked_Top50_{stamp}.csv");

        using (var sw = new StreamWriter(csvPath, false, Encoding.UTF8))
        {
            sw.WriteLine("Rank,Hits,IP,URI");
            foreach (var row in top)
            {
                var uri = row.URI.Replace("\"", "\"\"");
                sw.WriteLine($"{row.Rank},{row.Hits},{row.IP},\"{uri}\"");
            }
        }

        var rows = top.Select(x => new AlbGenericResultRow(
            new[] { x.Rank.ToString(), x.IP, x.URI, x.Hits.ToString("N0", CultureInfo.InvariantCulture) })).ToList();

        return new AlbGenericScanResult(
            CompletionMessage: $"Scan complete. {blocked:N0} blocked out of {total:N0} total entries. Top 50 exported.",
            ExportPath: csvPath,
            Rows: rows,
            Columns: new[] { "Rank", "IP", "URI", "Hits" },
            TotalMatches: blocked,
            FirstHitUtc: null,
            LastHitUtc: null,
            FilesWithHits: files.Count,
            ChartHtmlPath: null);
    }

    private sealed class WafCounters
    {
        public long Total;
        public long Blocked;
    }

    private static async Task ScanFileForWafBlockedAsync(
        string filePath, WafCounters counters, Dictionary<string, int> blockedCounts)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

        while (true)
        {
            var line = await sr.ReadLineAsync().ConfigureAwait(false);
            if (line is null) break;
            if (line.Length == 0) continue;

            counters.Total++;

            if (!line.Contains("waf,forward", StringComparison.OrdinalIgnoreCase))
            {
                counters.Blocked++;

                var ip = AlbScanner.ExtractAlbClientIp(line);
                if (ip is not null)
                {
                    var uri = AlbScanner.ExtractAlbUriNoQuery(line) ?? "";
                    var key = $"{ip}\t{uri}";

                    if (blockedCounts.TryGetValue(key, out var cur))
                        blockedCounts[key] = cur + 1;
                    else
                        blockedCounts[key] = 1;
                }
            }
        }
    }

    // ── Option 9: WAF blocks over time (per minute) (chart) ───────

    public static async Task<AlbGenericScanResult> ScanWafBlockedPerMinuteChartAsync(
        List<string> files,
        string outputFolder,
        Action<string, int, int, string> reportProgress)
    {
        var buckets = new SortedDictionary<DateTime, long>();

        for (var i = 0; i < files.Count; i++)
        {
            await ScanFileForWafBlockedBucketsAsync(files[i], buckets).ConfigureAwait(false);
            reportProgress($"Scanning ALB logs: {i + 1} / {files.Count} files.", i + 1, files.Count, "scanning");
        }

        if (buckets.Count == 0)
        {
            return new AlbGenericScanResult(
                CompletionMessage: "No blocked entries found (per current definition).",
                ExportPath: null,
                Rows: Array.Empty<AlbGenericResultRow>(),
                Columns: new[] { "MinuteUtc", "Blocked" },
                TotalMatches: 0,
                FirstHitUtc: null,
                LastHitUtc: null,
                FilesWithHits: 0,
                ChartHtmlPath: null);
        }

        Directory.CreateDirectory(outputFolder);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);

        var times = buckets.Keys.ToArray();
        var ys = new double[times.Length];
        for (int i = 0; i < times.Length; i++)
            ys[i] = buckets[times[i]];

        var series = new List<Charts.TimeSeriesSeries>(1)
        {
            new("Blocked/min", times, ys)
        };

        var chartPath = Charts.SaveTimeSeriesHtml(
            outputFolder: outputFolder,
            title: "ALB WAF blocks over time (per minute)",
            yLabel: "Blocked requests",
            series: series,
            filePrefix: "ALB_WAF_BlockedPerMin");

        // Build CSV export
        var csvPath = Path.Combine(outputFolder, $"ALB_WAF_BlockedPerMin_{stamp}.csv");
        using (var sw = new StreamWriter(csvPath, false, Encoding.UTF8))
        {
            sw.WriteLine("MinuteUtc,Blocked");
            foreach (var b in buckets)
                sw.WriteLine($"{b.Key:yyyy-MM-dd HH:mm:ss},{b.Value}");
        }

        long totalBlocked = buckets.Values.Sum();

        // Top 20 busiest minutes as summary rows
        var topBuckets = buckets
            .OrderByDescending(b => b.Value)
            .Take(20)
            .Select((b, idx) => new AlbGenericResultRow(
                new[] { b.Key.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture), b.Value.ToString("N0", CultureInfo.InvariantCulture) }))
            .ToList();

        return new AlbGenericScanResult(
            CompletionMessage: $"Scan complete. {totalBlocked:N0} blocked entries across {buckets.Count} minutes.",
            ExportPath: csvPath,
            Rows: topBuckets,
            Columns: new[] { "MinuteUtc", "Blocked" },
            TotalMatches: totalBlocked,
            FirstHitUtc: times.First().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
            LastHitUtc: times.Last().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
            FilesWithHits: files.Count,
            ChartHtmlPath: chartPath);
    }

    private static async Task ScanFileForWafBlockedBucketsAsync(string filePath, SortedDictionary<DateTime, long> buckets)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

        while (true)
        {
            var line = await sr.ReadLineAsync().ConfigureAwait(false);
            if (line is null) break;
            if (line.Length == 0) continue;

            if (!line.Contains("waf,forward", StringComparison.OrdinalIgnoreCase))
            {
                var tsUtc = AlbScanner.ExtractAlbTimestampUtc(line);
                if (tsUtc is not null)
                {
                    var t = tsUtc.Value.Kind == DateTimeKind.Utc ? tsUtc.Value : tsUtc.Value.ToUniversalTime();
                    var minute = new DateTime(t.Year, t.Month, t.Day, t.Hour, t.Minute, 0, DateTimeKind.Utc);

                    if (buckets.TryGetValue(minute, out var cur))
                        buckets[minute] = cur + 1;
                    else
                        buckets[minute] = 1;
                }
            }
        }
    }
}
