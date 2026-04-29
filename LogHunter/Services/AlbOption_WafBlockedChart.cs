using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static partial class AlbOptions
{
    // ---------- OPTION 9 ----------

    public static async Task WafBlockedPerMinuteChartAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: WAF blocks over time (per minute)",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        // Minute bucket -> blocked count. Plain dict + sort once at end (cheaper than SortedDictionary).
        var buckets = new Dictionary<DateTime, long>();

        await RunScanWithProgressParallelAsync(
            title: "Scanning ALB logs",
            files: files,
            createLocal: () => new Dictionary<DateTime, long>(),
            scanFileAsync: ScanFileForWafBlockedBucketsAsync,
            mergeLocal: local =>
            {
                foreach (var kvp in local)
                {
                    if (buckets.TryGetValue(kvp.Key, out var cur))
                        buckets[kvp.Key] = cur + kvp.Value;
                    else
                        buckets[kvp.Key] = kvp.Value;
                }
            }).ConfigureAwait(false);

        if (buckets.Count == 0)
        {
            ConsoleEx.Warn("No blocked entries found (per current definition).");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        Directory.CreateDirectory(outputFolder);

        var times = buckets.Keys.OrderBy(t => t).ToArray();
        var ys = new double[times.Length];
        for (int i = 0; i < times.Length; i++)
            ys[i] = buckets[times[i]];

        var series = new List<(string SeriesName, DateTime[] TimesUtc, double[] Values)>(1)
        {
            ("Blocked/min", times, ys)
        };

        var html = Charts.SaveTimeSeriesHtmlAndOpen(
            outputFolder: outputFolder,
            title: "ALB WAF blocks over time (per minute)",
            yLabel: "Blocked requests",
            series: series,
            filePrefix: "ALB_WAF_BlockedPerMin");

        ConsoleEx.Success($"Chart (offline HTML): {html}");
        ConsoleEx.Pause("Press Enter to return...");
    }

    private static async Task ScanFileForWafBlockedBucketsAsync(
        string filePath,
        Dictionary<DateTime, long> local,
        Action<long> reportBytesDelta,
        CancellationToken ct)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

        long lastReportedPos = 0;
        const long chunk = 64L * 1024 * 1024;
        int lineCount = 0;

        while (true)
        {
            if ((++lineCount & 0xFFFF) == 0)
                ct.ThrowIfCancellationRequested();

            var line = await sr.ReadLineAsync().ConfigureAwait(false);
            if (line is null) break;
            if (line.Length == 0) continue;

            // Same blocked definition as the summary view.
            if (!line.Contains("waf,forward", StringComparison.OrdinalIgnoreCase))
            {
                var tsUtc = AlbScanner.ExtractAlbTimestampUtc(line);
                if (tsUtc is not null)
                {
                    var t = tsUtc.Value.Kind == DateTimeKind.Utc ? tsUtc.Value : tsUtc.Value.ToUniversalTime();
                    var minute = new DateTime(t.Year, t.Month, t.Day, t.Hour, t.Minute, 0, DateTimeKind.Utc);

                    if (local.TryGetValue(minute, out var cur))
                        local[minute] = cur + 1;
                    else
                        local[minute] = 1;
                }
            }

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
}
