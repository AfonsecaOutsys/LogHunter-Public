using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace LogHunter.Utils;

/// <summary>One parsed target: a single IP, a CIDR block or a start-end range.</summary>
internal readonly record struct IpTarget(string Text, AddressFamily Family, UInt128 Start, UInt128 End)
{
    public bool IsSingle => Start == End;
    public UInt128 Size => End - Start + 1;
}

/// <summary>
/// Parses IOC lists as operators paste them: one target per line (commas, semicolons and
/// whitespace also separate), '#' starts a comment. Accepts IPv4/IPv6 addresses, CIDR
/// (203.0.113.0/24, 2001:db8::/32) and ranges (203.0.113.10-203.0.113.20).
/// </summary>
internal static class IpTargetParser
{
    private static readonly char[] Separators = { ',', ';', ' ', '\t', '\r', '\n' };

    public static (List<IpTarget> Targets, List<string> Invalid) ParseList(string? text)
    {
        var targets = new List<IpTarget>();
        var invalid = new List<string>();
        if (string.IsNullOrWhiteSpace(text))
            return (targets, invalid);

        foreach (var rawLine in text.Split('\n'))
        {
            var line = StripComment(rawLine);
            foreach (var token in SplitTokens(line))
            {
                if (TryParse(token, out var target))
                    targets.Add(target);
                else
                    invalid.Add(token);
            }
        }

        return (targets, invalid);
    }

    public static bool TryParse(string? text, out IpTarget target)
    {
        target = default;
        if (string.IsNullOrWhiteSpace(text))
            return false;

        var s = text.Trim();
        var slash = s.IndexOf('/');
        if (slash > 0)
            return TryParseCidr(s, slash, out target);

        var dash = FindRangeDash(s);
        if (dash > 0)
            return TryParseRange(s, dash, out target);

        if (!TryParseAddress(s, out var family, out var value))
            return false;

        target = new IpTarget(s, family, value, value);
        return true;
    }

    public static bool TryParseAddress(string? text, out AddressFamily family, out UInt128 value)
    {
        family = AddressFamily.Unknown;
        value = default;
        if (string.IsNullOrWhiteSpace(text))
            return false;

        // IPAddress.TryParse accepts legacy forms ("12345" -> 0.0.48.57, "10.1" -> 10.0.0.1):
        // a typo must not become a target, so IPv4 has to be a full dotted quad.
        var s = text.Trim();
        if (!s.Contains(':') && s.Count(c => c == '.') != 3)
            return false;
        if (!IPAddress.TryParse(s, out var addr))
            return false;

        return TryToNumber(addr, out family, out value);
    }

    public static bool TryToNumber(IPAddress addr, out AddressFamily family, out UInt128 value)
    {
        if (addr.IsIPv4MappedToIPv6)
            addr = addr.MapToIPv4();

        family = addr.AddressFamily;
        var bytes = addr.GetAddressBytes();
        value = default;
        if (family != AddressFamily.InterNetwork && family != AddressFamily.InterNetworkV6)
            return false;

        foreach (var b in bytes)
            value = (value << 8) | b;
        return true;
    }

    public static int MaxPrefix(AddressFamily family) => family == AddressFamily.InterNetwork ? 32 : 128;

    private static bool TryParseCidr(string s, int slash, out IpTarget target)
    {
        target = default;
        if (!TryParseAddress(s[..slash], out var family, out var value))
            return false;
        if (!int.TryParse(s[(slash + 1)..], out var prefix) || prefix < 0 || prefix > MaxPrefix(family))
            return false;

        var hostBits = MaxPrefix(family) - prefix;
        // Shifts are taken mod 128, so a /0 on IPv6 needs the explicit full mask.
        var hostMask = hostBits switch
        {
            0 => UInt128.Zero,
            128 => UInt128.MaxValue,
            _ => (UInt128.One << hostBits) - 1,
        };
        var start = value & ~hostMask;
        target = new IpTarget(s, family, start, start | hostMask);
        return true;
    }

    private static bool TryParseRange(string s, int dash, out IpTarget target)
    {
        target = default;
        if (!TryParseAddress(s[..dash], out var f1, out var start)
            || !TryParseAddress(s[(dash + 1)..], out var f2, out var end))
            return false;
        if (f1 != f2 || end < start)
            return false;

        target = new IpTarget(s, f1, start, end);
        return true;
    }

    // IPv6 never contains '-', so the first dash separates a range.
    private static int FindRangeDash(string s) => s.IndexOf('-');

    private static string StripComment(string line)
    {
        var hash = line.IndexOf('#');
        return hash >= 0 ? line[..hash] : line;
    }

    // "a - b" is one range token, so re-join tokens around a lone dash.
    private static IEnumerable<string> SplitTokens(string line)
    {
        var parts = line.Split(Separators, StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i < parts.Length; i++)
        {
            if (i + 2 < parts.Length && parts[i + 1] == "-")
            {
                yield return $"{parts[i]}-{parts[i + 2]}";
                i += 2;
                continue;
            }

            yield return parts[i];
        }
    }
}
