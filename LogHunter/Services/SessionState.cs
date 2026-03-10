using LogHunter.Models;
using System;
using System.Collections.Generic;

namespace LogHunter.Services;

public sealed class SessionState
{
    public string Root { get; }

    public List<SavedSelection> SavedSelections { get; } = new();

    // IIS burst tracking (shared across IIS options during a run)
    public HashSet<string> IisBurstIps { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, int>? IisBurstIpHits { get; private set; }
    public DateTime? IisBurstIpsUpdatedUtc { get; private set; }

    // Platform scanners (cached results during a run)
    public Dictionary<string, int>? PlatformSuspiciousIpHits { get; set; }
    public DateTime? PlatformSuspiciousIpHitsUpdatedUtc { get; set; }
    public Dictionary<string, int>? PlatformAuthedIpHits { get; set; }
    public DateTime? PlatformAuthedIpHitsUpdatedUtc { get; set; }

    public SessionState(string root)
    {
        Root = root;
    }

    public void ReplaceIisBurstIps(IEnumerable<string> ips)
        => ReplaceIisBurstIps(ips, null);

    public void ReplaceIisBurstIps(IEnumerable<string> ips, Dictionary<string, int>? ipHits)
    {
        IisBurstIps.Clear();

        foreach (var ip in ips)
        {
            if (string.IsNullOrWhiteSpace(ip))
                continue;

            IisBurstIps.Add(ip.Trim());
        }

        IisBurstIpHits = ipHits is null
            ? null
            : new Dictionary<string, int>(ipHits, StringComparer.OrdinalIgnoreCase);

        IisBurstIpsUpdatedUtc = DateTime.UtcNow;
    }
}
