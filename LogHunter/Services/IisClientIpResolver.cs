using System;
using System.Collections.Generic;
using System.Net;
using LogHunter.Utils;

namespace LogHunter.Services;

internal static class IisClientIpResolver
{
    public static string? ResolveClientIpPreferOriginal(IisW3cReader.TokenReader tokens, int iOriginalIp, int iCIp)
    {
        ReadOnlySpan<char> raw = default;

        if (iOriginalIp >= 0)
            raw = tokens.Get(iOriginalIp);

        var resolved = ResolvePreferredClientIp(raw);
        if (!string.IsNullOrWhiteSpace(resolved))
            return resolved;

        if (iCIp >= 0)
            raw = tokens.Get(iCIp);

        return ResolvePreferredClientIp(raw);
    }

    public static string? ResolvePreferredClientIp(ReadOnlySpan<char> raw)
        => ResolvePreferredClientIp(raw, IsKnownCdnEdge);

    /// <summary>
    /// Picks the client from an X-Forwarded-For chain, walking right to left. The rightmost entry is
    /// appended by the OutSystems ALB and cannot be forged; entries to its left come from the client
    /// or from proxies. Private/loopback hops are skipped, and so are known CDN edges, so a request
    /// "client, cloudflare-edge" resolves to the client while a forged "victim, attacker" resolves to
    /// the attacker. If every public hop is a CDN edge, the leftmost edge is returned.
    /// </summary>
    public static string? ResolvePreferredClientIp(ReadOnlySpan<char> raw, Func<string, bool> isCdnEdge)
    {
        if (raw.IsEmpty)
            return null;

        raw = raw.Trim();
        if (raw.IsEmpty || raw[0] == '-')
            return null;

        var hops = SplitHops(raw);
        string? firstParseable = null;
        var publicHops = new List<string>(hops.Count);
        foreach (var hop in hops)
        {
            if (hop is null) continue;
            firstParseable ??= hop;
            if (!IsPrivateOrLoopback(hop)) publicHops.Add(hop);
        }

        if (publicHops.Count == 0)
            return firstParseable;
        if (publicHops.Count == 1)
            return publicHops[0];

        for (var i = publicHops.Count - 1; i >= 0; i--)
        {
            if (!isCdnEdge(publicHops[i]))
                return publicHops[i];
        }

        return publicHops[0];
    }

    private static bool IsKnownCdnEdge(string ip) => IpIntelStore.Lookup(ip)?.Category == IpIntelCategory.Cdn;

    /// <summary>
    /// The leftmost public hop of an X-Forwarded-For chain when it differs from the resolved client:
    /// what the request claims to come from. It can be the genuine user behind a corporate proxy or a
    /// forged value, so it is shown as unverified next to the resolved client. Null when there is
    /// nothing to show.
    /// </summary>
    public static string? GetClaimedClient(ReadOnlySpan<char> raw, string? resolved)
    {
        raw = raw.Trim();
        if (raw.IsEmpty || raw[0] == '-' || raw.IndexOf(',') < 0)
            return null;

        foreach (var hop in SplitHops(raw))
        {
            if (hop is null || IsPrivateOrLoopback(hop)) continue;
            return string.Equals(hop, resolved, StringComparison.OrdinalIgnoreCase) ? null : hop;
        }

        return null;
    }

    // Unparseable tokens are kept as null so the order of the remaining hops is preserved.
    private static List<string?> SplitHops(ReadOnlySpan<char> raw)
    {
        var hops = new List<string?>(4);
        int start = 0;
        while (start < raw.Length)
        {
            int comma = raw[start..].IndexOf(',');
            ReadOnlySpan<char> part;
            if (comma < 0)
            {
                part = raw[start..];
                start = raw.Length;
            }
            else
            {
                part = raw.Slice(start, comma);
                start += comma + 1;
            }

            hops.Add(NormalizeSingleIpToken(part));
        }

        return hops;
    }

    // "Private" here means "never a real internet client": RFC 1918, loopback, link-local,
    // unspecified (0.0.0.0/8, ::), CGNAT (100.64/10) and IPv6 ULA (fc00::/7). Attackers forge
    // these values into X-Forwarded-For, so they must never be reported as the client.
    public static bool IsPrivateOrLoopback(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr))
            return false;

        if (addr.IsIPv4MappedToIPv6)
            addr = addr.MapToIPv4();

        if (IPAddress.IsLoopback(addr))
            return true;

        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            return IsNonPublicIpv4(addr.GetAddressBytes());

        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            return IsNonPublicIpv6(addr);

        return false;
    }

    private static bool IsNonPublicIpv4(byte[] b)
    {
        if (b[0] == 0) return true;                                // 0.0.0.0/8
        if (b[0] == 10) return true;                               // 10/8
        if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true; // 100.64/10 CGNAT
        if (b[0] == 127) return true;                              // 127/8
        if (b[0] == 169 && b[1] == 254) return true;               // 169.254/16
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;  // 172.16/12
        if (b[0] == 192 && b[1] == 168) return true;               // 192.168/16
        return false;
    }

    private static bool IsNonPublicIpv6(IPAddress addr)
    {
        if (addr.Equals(IPAddress.IPv6None)) return true;          // ::
        if (addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal) return true;
        var first = addr.GetAddressBytes()[0];
        return (first & 0xFE) == 0xFC;                             // fc00::/7 ULA
    }

    public static bool IsPublicIp(string ip, Dictionary<string, IpClass> cache)
    {
        if (cache.TryGetValue(ip, out var cls))
            return cls == IpClass.Public;

        if (!IPAddress.TryParse(ip, out _))
        {
            cache[ip] = IpClass.Invalid;
            return false;
        }

        if (IsPrivateOrLoopback(ip))
        {
            cache[ip] = IpClass.PrivateOrLoopback;
            return false;
        }

        cache[ip] = IpClass.Public;
        return true;
    }

    private static string? NormalizeSingleIpToken(ReadOnlySpan<char> raw)
    {
        raw = raw.Trim();
        while (!raw.IsEmpty && (raw[0] == '+' || raw[0] == '"'))
            raw = raw[1..].TrimStart();
        while (!raw.IsEmpty && (raw[^1] == '"' || raw[^1] == '+'))
            raw = raw[..^1].TrimEnd();

        if (raw.IsEmpty || raw[0] == '-')
            return null;

        if (raw.Length > 0 && raw[0] == '[')
        {
            var end = raw.IndexOf(']');
            if (end > 1)
                raw = raw.Slice(1, end - 1);
        }
        else
        {
            var colon = raw.IndexOf(':');
            if (colon > 0 && raw[(colon + 1)..].IndexOf(':') < 0)
                raw = raw[..colon];
        }

        var s = raw.ToString().Trim();
        return IPAddress.TryParse(s, out _) ? s : null;
    }
}

internal enum IpClass
{
    Invalid = 0,
    PrivateOrLoopback = 1,
    Public = 2
}
