using System.Collections.Generic;

namespace LogHunter.Services;

/// <summary>
/// Workflow keys sent to the usage API (FeatureUse). The server accepts ^[a-z0-9.-]{1,50}$;
/// a unit test checks every constant against it.
/// </summary>
internal static class UsageFeature
{
    public const string AlbDownload = "alb.download";
    public const string AlbTopIpsEndpoint = "alb.top-ips-endpoint";
    public const string AlbIpSummary = "alb.ip-summary";
    public const string AlbIpSweep = "alb.ip-sweep";
    public const string Alb5xxMismatch = "alb.5xx-mismatch";
    public const string AlbTop50Ips = "alb.top50-ips";
    public const string AlbTop50IpsByUri = "alb.top50-ips-by-uri";
    public const string AlbTop50AvgDuration = "alb.top50-avg-duration";
    public const string AlbRequestsOverTime = "alb.requests-over-time";
    public const string AlbWafBlockedSummary = "alb.waf-blocked-summary";
    public const string AlbWafBlocksOverTime = "alb.waf-blocks-over-time";

    public const string IisIpSummary = "iis.ip-summary";
    public const string IisIpSweep = "iis.ip-sweep";
    public const string IisStatusPivot = "iis.status-pivot";
    public const string IisBurstPatterns = "iis.burst-patterns";
    public const string IisTopBandwidth = "iis.top-bandwidth";
    public const string IisUploadsPayloads = "iis.uploads-payloads";

    public const string PlatformSuspiciousIps = "platform.suspicious-ips";
    public const string PlatformAuthActivity = "platform.auth-activity";

    public const string AbuseIpDbCheck = "abuseipdb.check";
    public const string IpRangesRefresh = "ipranges.refresh";
    public const string IpRangesCustomRanges = "ipranges.custom-ranges";
    public const string ToolsSqliteViewer = "tools.sqlite-viewer";

    public static readonly IReadOnlyList<string> All = new[]
    {
        AlbDownload, AlbTopIpsEndpoint, AlbIpSummary, AlbIpSweep, Alb5xxMismatch, AlbTop50Ips, AlbTop50IpsByUri,
        AlbTop50AvgDuration, AlbRequestsOverTime, AlbWafBlockedSummary, AlbWafBlocksOverTime,
        IisIpSummary, IisIpSweep, IisStatusPivot, IisBurstPatterns, IisTopBandwidth, IisUploadsPayloads,
        PlatformSuspiciousIps, PlatformAuthActivity,
        AbuseIpDbCheck, IpRangesRefresh, IpRangesCustomRanges, ToolsSqliteViewer,
    };
}
