using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace LogHunter.Utils;

/// <summary>
/// Immutable IP lookup table for single IPs, CIDR blocks and ranges, IPv4 and IPv6.
/// Overlapping entries are allowed: a lookup returns every label whose range contains the IP
/// (an IOC list can hold 203.0.113.7 and 203.0.113.0/24; a hit must count for both).
/// Internally the ranges are cut into sorted, non-overlapping segments, each carrying the set
/// of labels active there, so a lookup is one binary search.
/// Shared by the IOC sweep (targets) and the CDN intelligence layer (provider ranges).
/// </summary>
internal sealed class IpRangeSet<TLabel> where TLabel : notnull
{
    private static readonly IReadOnlyList<TLabel> NoMatch = Array.Empty<TLabel>();

    private readonly SegmentTable _v4;
    private readonly SegmentTable _v6;
    private readonly TLabel[] _labels;

    private IpRangeSet(SegmentTable v4, SegmentTable v6, TLabel[] labels)
    {
        _v4 = v4;
        _v6 = v6;
        _labels = labels;
    }

    public static IpRangeSet<TLabel> Empty { get; } = new Builder().Build();

    public int SegmentCount => _v4.Count + _v6.Count;

    public IReadOnlyList<TLabel> Labels => _labels;

    public IReadOnlyList<TLabel> Match(string? ip)
    {
        if (!IpTargetParser.TryParseAddress(ip, out var family, out var value))
            return NoMatch;
        return Match(family, value);
    }

    public IReadOnlyList<TLabel> Match(IPAddress ip)
    {
        if (!IpTargetParser.TryToNumber(ip, out var family, out var value))
            return NoMatch;
        return Match(family, value);
    }

    public IReadOnlyList<TLabel> Match(AddressFamily family, UInt128 value)
    {
        var table = family == AddressFamily.InterNetwork ? _v4 : _v6;
        var ids = table.Find(value);
        if (ids is null)
            return NoMatch;

        var result = new TLabel[ids.Length];
        for (var i = 0; i < ids.Length; i++)
            result[i] = _labels[ids[i]];
        return result;
    }

    public bool Contains(string? ip) => Match(ip).Count > 0;

    public sealed class Builder
    {
        private readonly List<TLabel> _labels = new();
        private readonly Dictionary<TLabel, int> _labelIds = new();
        private readonly List<(UInt128 Start, UInt128 End, int Id)> _v4 = new();
        private readonly List<(UInt128 Start, UInt128 End, int Id)> _v6 = new();

        public int Count => _v4.Count + _v6.Count;

        /// <summary>
        /// Adds a parsed target. Equal labels share one id, so adjacent ranges of the same
        /// provider collapse into one segment. Returns the label id.
        /// </summary>
        public int Add(IpTarget target, TLabel label)
        {
            if (!_labelIds.TryGetValue(label, out var id))
            {
                id = _labels.Count;
                _labels.Add(label);
                _labelIds[label] = id;
            }

            var list = target.Family == AddressFamily.InterNetwork ? _v4 : _v6;
            list.Add((target.Start, target.End, id));
            return id;
        }

        public bool TryAdd(string text, TLabel label)
        {
            if (!IpTargetParser.TryParse(text, out var target))
                return false;
            Add(target, label);
            return true;
        }

        public IpRangeSet<TLabel> Build()
            => new(SegmentTable.Build(_v4, MaxValue(32)), SegmentTable.Build(_v6, MaxValue(128)), _labels.ToArray());

        private static UInt128 MaxValue(int bits) => bits == 128 ? UInt128.MaxValue : (UInt128.One << bits) - 1;
    }

    private sealed class SegmentTable
    {
        private readonly UInt128[] _starts;
        private readonly UInt128[] _ends;
        private readonly int[][] _ids;

        private SegmentTable(UInt128[] starts, UInt128[] ends, int[][] ids)
        {
            _starts = starts;
            _ends = ends;
            _ids = ids;
        }

        public int Count => _starts.Length;

        public int[]? Find(UInt128 value)
        {
            int lo = 0, hi = _starts.Length - 1;
            while (lo <= hi)
            {
                var mid = lo + ((hi - lo) >> 1);
                if (_starts[mid] > value)
                    hi = mid - 1;
                else if (_ends[mid] < value)
                    lo = mid + 1;
                else
                    return _ids[mid];
            }

            return null;
        }

        // Sweep line over range boundaries: +id at Start, -id just past End.
        public static SegmentTable Build(List<(UInt128 Start, UInt128 End, int Id)> ranges, UInt128 maxValue)
        {
            var events = new List<(UInt128 Pos, int Id, bool Open)>(ranges.Count * 2);
            foreach (var (start, end, id) in ranges)
            {
                events.Add((start, id, true));
                if (end < maxValue)
                    events.Add((end + 1, id, false));
            }

            events.Sort((a, b) => a.Pos.CompareTo(b.Pos));

            var starts = new List<UInt128>();
            var ends = new List<UInt128>();
            var ids = new List<int[]>();
            var active = new SortedDictionary<int, int>();

            var i = 0;
            while (i < events.Count)
            {
                var pos = events[i].Pos;
                while (i < events.Count && events[i].Pos == pos)
                {
                    Apply(active, events[i].Id, events[i].Open);
                    i++;
                }

                if (active.Count == 0)
                    continue;

                var segEnd = i < events.Count ? events[i].Pos - 1 : maxValue;
                AppendSegment(starts, ends, ids, pos, segEnd, active.Keys.ToArray());
            }

            return new SegmentTable(starts.ToArray(), ends.ToArray(), ids.ToArray());
        }

        private static void Apply(SortedDictionary<int, int> active, int id, bool open)
        {
            active.TryGetValue(id, out var n);
            n += open ? 1 : -1;
            if (n == 0)
                active.Remove(id);
            else
                active[id] = n;
        }

        // Adjacent segments with the same labels collapse into one (keeps CDN tables small).
        private static void AppendSegment(List<UInt128> starts, List<UInt128> ends, List<int[]> ids,
            UInt128 start, UInt128 end, int[] segIds)
        {
            var last = starts.Count - 1;
            if (last >= 0 && ends[last] + 1 == start && ids[last].AsSpan().SequenceEqual(segIds))
            {
                ends[last] = end;
                return;
            }

            starts.Add(start);
            ends.Add(end);
            ids.Add(segIds);
        }
    }
}
