using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Utils;

/// <summary>
/// Minimal W3C (IIS) log reader:
/// - reads #Fields mapping per file
/// - iterates data lines
/// - provides TokenReader for fast token access (no Split allocations)
/// - supports .log and .log.gz
///
/// PERF NOTE:
/// TokenReader returned by ForEachDataLineAsync uses an internal reusable offsets buffer.
/// It is safe to use inside the callback. Do not store TokenReader for later use.
/// </summary>
public static class IisW3cReader
{
    private const int IoBufferSize = 1 << 20;

    public sealed class FieldMap
    {
        public required string FieldsLine { get; init; }
        public required List<string> HeaderLines { get; init; }
        public required Dictionary<string, int> Index { get; init; }

        public bool TryGetIndex(string field, out int index)
        {
            if (Index.TryGetValue(field, out index))
                return true;

            index = -1;
            return false;
        }
    }

    /// <summary>
    /// Token accessor for a single log line (space-delimited W3C tokens).
    /// Fast path uses cached token offsets (start,len pairs) built once per line.
    /// </summary>
    public readonly struct TokenReader
    {
        private readonly string _line;
        private readonly int[]? _offsets; // [start0,len0,start1,len1,...]
        private readonly int _count;

        // Compatibility constructor (slow path). Prefer ForEachDataLineAsync.
        public TokenReader(string line)
        {
            _line = line;
            _offsets = null;
            _count = 0;
        }

        internal TokenReader(string line, int[] offsets, int count)
        {
            _line = line;
            _offsets = offsets;
            _count = count;
        }

        public ReadOnlySpan<char> Get(int targetIndex)
        {
            if (targetIndex < 0)
                return ReadOnlySpan<char>.Empty;

            // Fast path
            if (_offsets is not null)
            {
                if (targetIndex >= _count)
                    return ReadOnlySpan<char>.Empty;

                int p = targetIndex * 2;
                int start = _offsets[p];
                int len = _offsets[p + 1];
                return _line.AsSpan(start, len);
            }

            // Slow fallback (kept for compatibility)
            int idx = 0;
            int i = 0;

            while (i < _line.Length)
            {
                while (i < _line.Length && IsDelimiter(_line[i])) i++;
                if (i >= _line.Length) break;

                int start = i;
                while (i < _line.Length && !IsDelimiter(_line[i])) i++;

                if (idx == targetIndex)
                    return _line.AsSpan(start, i - start);

                idx++;
            }

            return ReadOnlySpan<char>.Empty;
        }
    }

    public static List<string> EnumerateLogFiles(string rootDir)
    {
        var list = new List<string>();

        list.AddRange(Directory.EnumerateFiles(rootDir, "*.log", SearchOption.AllDirectories));
        list.AddRange(Directory.EnumerateFiles(rootDir, "*.log.gz", SearchOption.AllDirectories));

        list.Sort(StringComparer.OrdinalIgnoreCase);
        return list;
    }

    public static async Task<FieldMap?> ReadFieldMapAsync(string filePath, CancellationToken ct = default)
    {
        await using var stream = OpenPossiblyGz(filePath);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: IoBufferSize);

        var header = new List<string>();
        string? fieldsLine = null;
        Dictionary<string, int>? idx = null;

        while (true)
        {
            ct.ThrowIfCancellationRequested();

            var line = await reader.ReadLineAsync().ConfigureAwait(false);
            if (line is null) break;

            if (!line.StartsWith("#", StringComparison.Ordinal))
                break;

            if (line.StartsWith("#Fields:", StringComparison.OrdinalIgnoreCase))
            {
                fieldsLine = line;

                idx = ParseFieldIndex(line);

                continue;
            }

            header.Add(line);
        }

        if (fieldsLine is null || idx is null)
            return null;

        // Keep a basic header so exported files remain readable even if the source lacked one.
        if (header.Count == 0)
        {
            header.Add("#Software: Microsoft Internet Information Services");
            header.Add("#Version: 1.0");
            header.Add($"#Date: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
        }

        return new FieldMap
        {
            FieldsLine = fieldsLine,
            HeaderLines = header,
            Index = idx
        };
    }

    /// <summary>
    /// Iterates each data line (non-header) and provides:
    /// - rawLine: original line (good for export)
    /// - tokens: TokenReader for fast token access
    /// </summary>
    public static async Task ForEachDataLineAsync(
        string filePath,
        CancellationToken ct,
        Action<string, TokenReader> onLine)
    {
        await using var stream = OpenPossiblyGz(filePath);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: IoBufferSize);

        // Reused token offsets buffer for this file (start,len pairs).
        // Start with 64 tokens worth of space (128 ints). Grow only if needed.
        int[] offsets = ArrayPool<int>.Shared.Rent(128);

        try
        {
            string? line;
            while ((line = await reader.ReadLineAsync().ConfigureAwait(false)) is not null)
            {
                ct.ThrowIfCancellationRequested();

                if (line.Length == 0) continue;
                if (line[0] == '#') continue;

                int count = TokenizeIntoOffsets(line, ref offsets);
                onLine(line, new TokenReader(line, offsets, count));
            }
        }
        finally
        {
            ArrayPool<int>.Shared.Return(offsets, clearArray: false);
        }
    }

    private static int TokenizeIntoOffsets(string line, ref int[] offsets)
    {
        while (true)
        {
            int tokenCount = 0;
            int i = 0;

            while (i < line.Length)
            {
                while (i < line.Length && IsDelimiter(line[i])) i++;
                if (i >= line.Length) break;

                int start = i;
                while (i < line.Length && !IsDelimiter(line[i])) i++;
                int len = i - start;

                int p = tokenCount * 2;
                if (p + 1 >= offsets.Length)
                {
                    var bigger = ArrayPool<int>.Shared.Rent(offsets.Length * 2);
                    Array.Copy(offsets, bigger, offsets.Length);
                    ArrayPool<int>.Shared.Return(offsets, clearArray: false);
                    offsets = bigger;
                    goto Retry;
                }

                offsets[p] = start;
                offsets[p + 1] = len;
                tokenCount++;
            }

            return tokenCount;

        Retry:
            continue;
        }
    }

    internal static Stream OpenPossiblyGz(string filePath)
    {
        // Big buffer + SequentialScan makes Windows much happier on multi-GB log scans.
        var fs = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite,
            bufferSize: IoBufferSize,
            options: FileOptions.SequentialScan);

        if (filePath.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            return new GZipStream(fs, CompressionMode.Decompress);

        return fs;
    }

    private static Dictionary<string, int> ParseFieldIndex(string fieldsLine)
    {
        var payload = fieldsLine.AsSpan("#Fields:".Length);
        var idx = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        int i = 0;
        int logicalIndex = 0;

        while (i < payload.Length)
        {
            while (i < payload.Length && IsDelimiter(payload[i])) i++;
            if (i >= payload.Length) break;

            int start = i;
            while (i < payload.Length && !IsDelimiter(payload[i])) i++;

            var token = payload.Slice(start, i - start).ToString();
            idx[token] = logicalIndex;
            logicalIndex++;
        }

        return idx;
    }

    private static bool IsDelimiter(char c) => c == ' ' || c == '\t';
}
