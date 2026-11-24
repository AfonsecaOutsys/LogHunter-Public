using LogHunter.Services;
using Xunit;

namespace LogHunter.Tests.Services;

public class IpIntelFeedsTests
{
    [Fact]
    public void ParseAws_KeepsOnlyCdnAndHealthCheckServices()
    {
        // Arrange
        const string body = """
        {"syncToken":"1","createDate":"2026-11-23-07-37-05","prefixes":[
          {"ip_prefix":"13.32.0.0/15","region":"GLOBAL","service":"CLOUDFRONT"},
          {"ip_prefix":"3.172.64.0/18","region":"GLOBAL","service":"CLOUDFRONT_ORIGIN_FACING"},
          {"ip_prefix":"54.239.0.0/16","region":"GLOBAL","service":"AMAZON"},
          {"ip_prefix":"3.5.0.0/16","region":"us-east-1","service":"EC2"},
          {"ip_prefix":"54.243.31.192/26","region":"us-east-1","service":"ROUTE53_HEALTHCHECKS"}],
         "ipv6_prefixes":[{"ipv6_prefix":"2600:9000::/28","region":"GLOBAL","service":"CLOUDFRONT"}]}
        """;

        // Act
        var entries = IpIntelFeeds.ParseAws(body).ToList();

        // Assert
        Assert.Equal(4, entries.Count);
        Assert.DoesNotContain(entries, e => e.Cidr == "54.239.0.0/16" || e.Cidr == "3.5.0.0/16");
        Assert.Equal(IpIntelCategory.HealthCheck, entries.Single(e => e.Cidr == "54.243.31.192/26").Label.Category);
    }

    [Fact]
    public void ParseF5_UsesRegionalEdgesAndCdnOnly()
    {
        // Arrange
        const string body = """
        {"services":{
          "regional_edges":{"regions":{"americas":{"ipv4_cidrs":["5.182.215.0/25"]},"emea":{"ipv4_cidrs":["84.54.61.0/25"]}}},
          "cdn":{"ipv4_cidrs":["159.60.188.0/24"]},
          "dnslb_health_checks":{"ipv4_ips":["18.142.173.13"]}}}
        """;

        // Act
        var cidrs = IpIntelFeeds.ParseF5(body).Select(e => e.Cidr).ToList();

        // Assert
        Assert.Equal(new[] { "5.182.215.0/25", "84.54.61.0/25", "159.60.188.0/24" }, cidrs);
    }

    [Fact]
    public void ParseZscaler_CollectsNestedRangesAsCorporateProxy()
    {
        // Arrange
        const string body = """
        {"zscaler.net":{"continent : EMEA":{"city : Abu Dhabi II":[{"range":"159.254.250.0/23","vpn":""}]},
                        "continent : APAC":{"city : Tokyo":[{"range":"136.226.0.0/23"},{"range":"2400:7aa0::/32"}]}}}
        """;

        // Act
        var entries = IpIntelFeeds.ParseZscaler(body).ToList();

        // Assert
        Assert.Equal(3, entries.Count);
        Assert.All(entries, e => Assert.Equal(IpIntelCategory.CorporateProxy, e.Label.Category));
    }

    [Fact]
    public void LinesAndJsonArrays_ParseTextAndJsonFeeds()
    {
        // Arrange
        var label = new IpIntelLabel("X", "edge", IpIntelCategory.Cdn, "x");

        // Act
        var akamai = IpIntelFeeds.Lines("2.16.0.0/13   23.0.0.0/12\n# comment\n184.24.0.0/13\n", label).Select(e => e.Cidr).ToList();
        var imperva = IpIntelFeeds.JsonArrays("""{"ipRanges":["199.83.128.0/21"],"ipv6Ranges":["2a02:e980::/29"],"res":0}""", label, "ipRanges", "ipv6Ranges").Count();

        // Assert
        Assert.Equal(new[] { "2.16.0.0/13", "23.0.0.0/12", "184.24.0.0/13" }, akamai);
        Assert.Equal(2, imperva);
    }

    [Fact]
    public void Label_PriorityPrefersOriginFacingOverEdge()
    {
        // Arrange
        var edge = new IpIntelLabel("CloudFront", "CLOUDFRONT", IpIntelCategory.Cdn, "aws");
        var origin = new IpIntelLabel("CloudFront", "CLOUDFRONT_ORIGIN_FACING", IpIntelCategory.Cdn, "aws");

        // Act
        var best = IpIntelStore.Best(new[] { edge, origin });

        // Assert
        Assert.Same(origin, best);
        Assert.Equal("CloudFront edge", best!.Badge);
    }
}
