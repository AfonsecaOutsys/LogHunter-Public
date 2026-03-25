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
    {
        if (raw.IsEmpty)
            return null;

        raw = raw.Trim();
        if (raw.IsEmpty || raw[0] == '-')
            return null;

        string? firstParseable = null;
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

            var normalized = NormalizeSingleIpToken(part);
            if (normalized is null)
                continue;

            firstParseable ??= normalized;
            if (!IsPrivateOrLoopback(normalized))
                return normalized;
        }

        return firstParseable;
    }

    public static bool IsPrivateOrLoopback(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr))
            return false;

        if (IPAddress.IsLoopback(addr))
            return true;

        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = addr.GetAddressBytes();
            if (b[0] == 10) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 169 && b[1] == 254) return true;
            if (b[0] == 127) return true;
        }

        return false;
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
