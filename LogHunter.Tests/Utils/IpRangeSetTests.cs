using LogHunter.Utils;
using Xunit;

namespace LogHunter.Tests.Utils;

public class IpRangeSetTests
{
    private static IpRangeSet<string> BuildSet(params string[] targets)
    {
        var builder = new IpRangeSet<string>.Builder();
        foreach (var t in targets)
            Assert.True(builder.TryAdd(t, t));
        return builder.Build();
    }

    [Fact]
    public void Match_IpInsideCidr_ReturnsCidrLabel()
    {
        // Arrange
        var set = BuildSet("172.64.0.0/13");

        // Act
        var labels = set.Match("172.70.243.250");

        // Assert
        Assert.Equal(new[] { "172.64.0.0/13" }, labels);
    }

    [Fact]
    public void Match_OverlappingTargets_ReturnsAllLabels()
    {
        // Arrange
        var set = BuildSet("203.0.113.0/24", "203.0.113.7", "203.0.113.5-203.0.113.9");

        // Act
        var inAll = set.Match("203.0.113.7");
        var inTwo = set.Match("203.0.113.9");
        var inOne = set.Match("203.0.113.200");

        // Assert
        Assert.Equal(3, inAll.Count);
        Assert.Equal(new[] { "203.0.113.0/24", "203.0.113.5-203.0.113.9" }, inTwo);
        Assert.Equal(new[] { "203.0.113.0/24" }, inOne);
    }

    [Theory]
    [InlineData("203.0.112.255")]
    [InlineData("203.0.114.0")]
    [InlineData("2001:db8::1")]
    [InlineData("garbage")]
    [InlineData(null)]
    public void Match_OutsideOrInvalid_ReturnsEmpty(string? ip)
    {
        // Arrange
        var set = BuildSet("203.0.113.0/24");

        // Act
        var labels = set.Match(ip);

        // Assert
        Assert.Empty(labels);
    }

    [Fact]
    public void Match_Ipv6AndMappedIpv4_UseTheRightFamily()
    {
        // Arrange
        var set = BuildSet("2a06:98c0::/29", "82.158.196.58");

        // Act
        var v6 = set.Match("2a06:98c0:3600::103");
        var mapped = set.Match("::ffff:82.158.196.58");

        // Assert
        Assert.Equal(new[] { "2a06:98c0::/29" }, v6);
        Assert.Equal(new[] { "82.158.196.58" }, mapped);
    }

    [Fact]
    public void Build_AdjacentRangesWithSameLabel_CollapseIntoOneSegment()
    {
        // Arrange
        var builder = new IpRangeSet<string>.Builder();
        builder.TryAdd("10.0.0.0/25", "cdn");
        builder.TryAdd("10.0.0.128/25", "cdn");

        // Act
        var set = builder.Build();

        // Assert
        Assert.Single(set.Labels);
        Assert.Equal(1, set.SegmentCount);
        Assert.Equal(new[] { "cdn" }, set.Match("10.0.0.200"));
    }

    [Fact]
    public void Match_FullAddressSpace_CoversMaxAddress()
    {
        // Arrange
        var set = BuildSet("0.0.0.0/0", "::/0");

        // Act
        var maxV4 = set.Match("255.255.255.255");
        var maxV6 = set.Match("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");

        // Assert
        Assert.Single(maxV4);
        Assert.Single(maxV6);
    }

    [Fact]
    public void Match_ManyTargets_StaysCorrectAcrossSegments()
    {
        // Arrange
        var builder = new IpRangeSet<int>.Builder();
        for (var i = 0; i < 1000; i++)
            builder.TryAdd($"10.{i / 256}.{i % 256}.0/24", i);
        var set = builder.Build();

        // Act
        var hit = set.Match("10.3.231.77");
        var miss = set.Match("10.4.0.1");

        // Assert
        Assert.Equal(new[] { 3 * 256 + 231 }, hit);
        Assert.Empty(miss);
    }
}
