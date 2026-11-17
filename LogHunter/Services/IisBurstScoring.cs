using System;
using System.Collections.Generic;
using System.Linq;

namespace LogHunter.Services;

/// <summary>
/// Shared IIS burst-pattern detection: threshold derivation, per-bucket aggregation,
/// candidate scoring, flag derivation and severity labeling.
///
/// Consumed by BOTH the console option (<see cref="IisOption_FindBurstPatterns"/>) and the
/// web job manager (IisBurstPatternsJobManager) so the two surfaces can never drift. Any
/// change to detection behavior belongs here and here only.
/// </summary>
internal static class IisBurstScoring
{
    public static BurstAssessment Assess(BurstAgg a, BurstThresholds t)
    {
        var isRate = a.TotalDynamic >= t.RateThreshold;
        var isStrongRate = a.TotalDynamic >= t.StrongRateThreshold;

        // Enumeration = many DISTINCT URIs relative to total (a scanner hits each path
        // ~once, so unique/total approaches 1.0). A busy app repeats a bounded set of
        // endpoints, so its ratio stays low even at high volume. The ratio is the
        // discriminator; it is kept honest by a unique cap high enough that legitimate
        // apps don't saturate it (see BurstThresholds.ForBucket).
        var isEnum = a.TotalDynamic >= t.EnumThreshold
            && a.UniqueDynamicUris >= t.EnumThreshold
            && a.UniqueDynamicRatio >= 0.45;

        var isStrongEnum = a.TotalDynamic >= t.StrongEnumThreshold
            && a.UniqueDynamicUris >= t.StrongEnumThreshold
            && a.UniqueDynamicRatio >= 0.65;

        var isError = a.Dynamic4xx >= t.ErrorThreshold
            || (a.DynamicFourxxRatio >= 0.70
                && a.Dynamic4xx >= Math.Max(8, t.ErrorThreshold / 2)
                && a.TotalDynamic >= Math.Max(15, t.RateThreshold / 3));

        var isFocused = a.TopDynamicUriHits >= t.FocusThreshold
            && a.FocusedUriRatio >= 0.70;

        var isPostHeavy = a.Post >= t.PostThreshold && a.PostRatio >= 0.35;
        var isHeadHeavy = a.Head >= t.HeadThreshold && a.HeadRatio >= 0.35;

        // A burst is a candidate only when it shows a genuinely suspicious signal:
        // strong enumeration, or errors (probing / brute force) at volume or while
        // enumerating. Volume, POST/HEAD-heaviness and single-endpoint FOCUS are NOT
        // threat signals on their own — in an OutSystems estate a busy legitimate app
        // is naturally high-rate, POST-heavy, and often hammers one DataAction (e.g.
        // loading an image grid), all returning 200. A real brute-force/credential
        // attack still surfaces here because its failures (401/403) count as 4xx and
        // trip isError. RATE / POST / HEAD / FOCUS remain descriptive flags only.
        var isCandidate =
            isStrongEnum
            || (isError && (isRate || isEnum || isFocused));

        var score = Score(a, t, isRate, isStrongRate, isEnum, isStrongEnum, isError, isFocused);

        return new BurstAssessment(
            a,
            score,
            isCandidate,
            isRate,
            isStrongRate,
            isEnum,
            isStrongEnum,
            isError,
            isFocused,
            isPostHeavy,
            isHeadHeavy);
    }

    private static int Score(
        BurstAgg a,
        BurstThresholds t,
        bool isRate,
        bool isStrongRate,
        bool isEnum,
        bool isStrongEnum,
        bool isError,
        bool isFocused)
    {
        int score = 0;

        if (isStrongRate) score += 65 + Math.Min(50, a.TotalDynamic - t.StrongRateThreshold);
        else if (isRate) score += 30 + Math.Min(35, a.TotalDynamic - t.RateThreshold);

        if (isStrongEnum) score += 70 + Math.Min(40, (a.UniqueDynamicUris - t.StrongEnumThreshold) * 2);
        else if (isEnum) score += 35 + Math.Min(30, (a.UniqueDynamicUris - t.EnumThreshold) * 2);

        if (isError)
        {
            score += 50 + Math.Min(35, (a.Dynamic4xx - t.ErrorThreshold) * 2);
            if (a.DynamicFourxxRatio >= 0.85) score += 10;
        }

        if (isFocused) score += 35 + Math.Min(15, (int)Math.Round((a.FocusedUriRatio - 0.70) * 100));

        // POST/HEAD intentionally contribute nothing to severity: method mix is
        // descriptive context (shown in the flags), not a measure of how dangerous a
        // burst is, and it no longer gates candidacy either (see Assess).

        return score;
    }

    public static string BuildFlags(BurstAssessment burst)
    {
        var flags = new List<string>();

        if (burst.IsStrongRate) flags.Add("RATE+");
        else if (burst.IsRate) flags.Add("RATE");

        if (burst.IsStrongEnum) flags.Add("ENUM+");
        else if (burst.IsEnum) flags.Add("ENUM");

        if (burst.IsError) flags.Add("4XX");
        if (burst.IsFocused) flags.Add("FOCUS");
        if (burst.IsPostHeavy) flags.Add("POST");
        if (burst.IsHeadHeavy) flags.Add("HEAD");

        return flags.Count == 0 ? "-" : string.Join("+", flags);
    }

    public static string SeverityLabel(int score)
        => score >= 140 ? "CRIT" : score >= 95 ? "HIGH" : score >= 60 ? "MED" : "LOW";

    // ---- Universal (client-agnostic) scanner signatures ----
    // Attackers reuse the same probe paths and tools against every target, so these fixed
    // patterns recognize scanners on ANY client without knowing that client's real
    // endpoints. They never reference the customer's own app paths.

    private static readonly string[] ProbeNeedles =
    {
        "/.env", ".env.", "/.git", "/.svn", "/.hg", "/.aws", "/.ssh", "id_rsa", "sftp-config",
        ".npmrc", ".dockercfg", "/.vscode", "credentials.json", "/.well-known/security",
        "eval-stdin", "phpunit", "/vendor/phpunit", "phpinfo", "phpmyadmin", "/adminer",
        "xmlrpc.php", "wp-login", "wp-admin", "wp-content", "wp-includes", "/wordpress",
        "/containers/json", "/actuator", "/manager/html", "/_profiler", "/cgi-bin",
        "/solr/", "/jenkins", "/struts", "/boaform", "/hudson",
    };

    /// <summary>True if a URI stem matches a universal vuln/secret probe pattern.</summary>
    public static bool IsProbePath(string? uriStem)
    {
        if (string.IsNullOrEmpty(uriStem)) return false;
        var s = uriStem.ToLowerInvariant();
        if (s.EndsWith(".env")) return true;
        foreach (var n in ProbeNeedles)
            if (s.Contains(n)) return true;
        return false;
    }

    private static readonly string[] ScannerUaNeedles =
    {
        "libredtail", "zgrab", "masscan", "zmap", "nuclei", "nikto", "sqlmap", "wpscan",
        "dirbuster", "gobuster", "feroxbuster", "ffuf", "httpx", "python-requests",
        "python-urllib", "go-http-client", "aiohttp", "libwww-perl", "nmap", "censys",
        "internet-measurement", "expanse", "l9explore", "l9tcpid", "custom-asynchttpclient",
    };

    /// <summary>True if a user-agent matches a known mass-scan / automation client.</summary>
    public static bool IsScannerUserAgent(string? ua)
    {
        if (string.IsNullOrEmpty(ua)) return false;
        var s = ua.ToLowerInvariant();
        foreach (var n in ScannerUaNeedles)
            if (s.Contains(n)) return true;
        return false;
    }

    /// <summary>
    /// Deterministic 64-bit FNV-1a hash (case-insensitive). Used to fingerprint path sets
    /// — must be stable, unlike string.GetHashCode which is randomized per process.
    /// </summary>
    public static long StableHash(string s)
    {
        unchecked
        {
            ulong hash = 1469598103934665603UL; // FNV-1a offset basis
            foreach (var ch in s)
            {
                var lc = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
                hash ^= lc;
                hash *= 1099511628211UL; // FNV-1a prime
            }
            return (long)hash;
        }
    }
}

/// <summary>
/// Bucket-size-derived detection thresholds. Computed once per scan via
/// <see cref="ForBucket"/> and passed to <see cref="IisBurstScoring.Assess"/>.
/// </summary>
internal readonly record struct BurstThresholds(
    int BucketSeconds,
    int RateThreshold,
    int StrongRateThreshold,
    int EnumThreshold,
    int StrongEnumThreshold,
    int ErrorThreshold,
    int FocusThreshold,
    int PostThreshold,
    int HeadThreshold,
    int UniqueCap,
    int UriCap)
{
    public static BurstThresholds ForBucket(int bucketSeconds)
    {
        var rate = (int)Math.Ceiling(2.5 * bucketSeconds);
        var strongRate = (int)Math.Ceiling(4.0 * bucketSeconds);
        var enumTh = Math.Max(12, (int)Math.Ceiling(0.60 * bucketSeconds));
        var strongEnum = Math.Max(enumTh + 8, (int)Math.Ceiling(0.90 * bucketSeconds));
        var error = Math.Max(12, (int)Math.Ceiling((30.0 / 60.0) * bucketSeconds));
        var focus = Math.Max(12, (int)Math.Ceiling(1.2 * bucketSeconds));
        var post = Math.Max(10, (int)Math.Ceiling(0.30 * bucketSeconds));
        var head = Math.Max(8, (int)Math.Ceiling(0.25 * bucketSeconds));

        // The unique-URI cap bounds memory but must stay high enough that the
        // unique/total ratio (the enumeration signal) is honest for real traffic. The
        // old floor of 64 was saturated by any busy app touching dozens of endpoints,
        // making legitimate high-volume usage indistinguishable from a scanner. A 512
        // floor keeps the ratio accurate for apps (which repeat a bounded endpoint set)
        // while still tracking a scanner whose distinct count climbs with its volume.
        // The strong-enum+1 term also keeps isStrongEnum reachable at the 300s bucket.
        var uniqueCap = Math.Max(strongEnum + 1, 512);
        var uriCap = 40;

        return new BurstThresholds(
            bucketSeconds, rate, strongRate, enumTh, strongEnum,
            error, focus, post, head, uniqueCap, uriCap);
    }
}

/// <summary>Outcome of assessing one (IP, time-bucket) aggregate against the heuristics.</summary>
internal sealed record BurstAssessment(
    BurstAgg Agg,
    int SeverityScore,
    bool IsCandidate,
    bool IsRate,
    bool IsStrongRate,
    bool IsEnum,
    bool IsStrongEnum,
    bool IsError,
    bool IsFocused,
    bool IsPostHeavy,
    bool IsHeadHeavy);

/// <summary>
/// Per-(IP, time-bucket) request aggregate. Bounded memory: the distinct-URI set and the
/// top-URI counter dictionary are both capped so a single bucket can't grow without limit.
/// </summary>
internal sealed class BurstAgg
{
    public required string Ip { get; init; }
    public required DateTime StartUtc { get; init; }
    public int BucketSeconds { get; init; }

    public int TotalDynamic { get; set; }
    public int TotalAll { get; set; }

    public int C2xx { get; set; }
    public int C3xx { get; set; }
    public int C4xx { get; set; }
    public int C5xx { get; set; }
    public int Dynamic4xx { get; set; }
    public int Dynamic5xx { get; set; }

    public int Get { get; set; }
    public int Post { get; set; }
    public int Head { get; set; }

    public long TimeTakenTotalMs { get; set; }
    public int TimeTakenMaxMs { get; set; }

    public string? Ua { get; set; }
    public bool UaMixed { get; set; }

    public int UniqueDynamicUris { get; set; }
    private HashSet<string>? _uniqueDyn;
    private readonly int _uniqueCap;

    // Order-independent fingerprint of the DISTINCT dynamic path set (XOR of per-path
    // hashes) plus a tally of paths matching universal probe signatures. Both feed the
    // coordinated-campaign grouping and are client-agnostic by construction.
    public long PathSetHash { get; private set; }
    public int ProbeHits { get; private set; }

    private Dictionary<string, int>? _uriCounts;
    private readonly int _uriCap;
    public int TopDynamicUriHits { get; private set; }

    public BurstAgg(int uniqueCap, int uriCap)
    {
        _uniqueCap = uniqueCap;
        _uriCap = uriCap;
    }

    public void AddDynamicUri(string uriStem)
    {
        if (UniqueDynamicUris < _uniqueCap)
        {
            _uniqueDyn ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (_uniqueDyn.Add(uriStem))
            {
                UniqueDynamicUris++;
                PathSetHash ^= IisBurstScoring.StableHash(uriStem);
                if (IisBurstScoring.IsProbePath(uriStem)) ProbeHits++;
            }
        }
        else
        {
            // Distinct-URI set is full; stop counting new distinct URIs to bound memory.
            UniqueDynamicUris = _uniqueCap;
        }

        _uriCounts ??= new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        int currentCount = 0;
        if (_uriCounts.TryGetValue(uriStem, out var v))
        {
            // Always keep counting hits on URIs we already track, even once the
            // dictionary is full — otherwise TopDynamicUriHits (and the FOCUS
            // signal) freezes the moment a bucket exceeds the cap.
            currentCount = v + 1;
            _uriCounts[uriStem] = currentCount;
        }
        else if (_uriCounts.Count < _uriCap)
        {
            currentCount = 1;
            _uriCounts[uriStem] = currentCount;
        }
        // else: a new URI beyond the cap — leave it untracked to bound memory.

        if (currentCount > TopDynamicUriHits)
            TopDynamicUriHits = currentCount;
    }

    public List<(string Uri, int Count)> TopUris(int take)
    {
        if (_uriCounts is null || _uriCounts.Count == 0) return new();
        return _uriCounts
            .OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .Take(take)
            .Select(kv => (kv.Key, kv.Value))
            .ToList();
    }

    public string UaDisplay => UaMixed ? "(mixed)" : (Ua ?? "-");
    public int AvgTimeMs => TotalAll == 0 ? 0 : (int)(TimeTakenTotalMs / TotalAll);
    public double DynamicFourxxRatio => TotalDynamic == 0 ? 0 : (double)Dynamic4xx / TotalDynamic;
    public double UniqueDynamicRatio => TotalDynamic == 0 ? 0 : (double)UniqueDynamicUris / TotalDynamic;
    public double FocusedUriRatio => TotalDynamic == 0 ? 0 : (double)TopDynamicUriHits / TotalDynamic;
    public double HeadRatio => TotalAll == 0 ? 0 : (double)Head / TotalAll;
    public double PostRatio => TotalAll == 0 ? 0 : (double)Post / TotalAll;
    public double ProbeRatio => UniqueDynamicUris == 0 ? 0 : (double)ProbeHits / UniqueDynamicUris;

    // Stable fingerprint key: same user-agent + same distinct path set => same campaign.
    public string FingerprintKey => (UaMixed ? "(mixed)" : (Ua ?? "-")) + "|" + PathSetHash.ToString("x", System.Globalization.CultureInfo.InvariantCulture);
}
