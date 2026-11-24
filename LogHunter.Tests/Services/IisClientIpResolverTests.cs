using LogHunter.Services;
using Xunit;

namespace LogHunter.Tests.Services;

public class IisClientIpResolverTests
{
    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("0.12.34.56")]
    [InlineData("100.64.0.1")]
    [InlineData("100.127.255.254")]
    [InlineData("10.15.109.65")]
    [InlineData("172.16.0.1")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.10.10")]
    [InlineData("127.0.0.1")]
    [InlineData("::")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fc00::1")]
    [InlineData("fd12:3456::1")]
    [InlineData("::ffff:10.0.0.1")]
    public void IsPrivateOrLoopback_NonPublicAddresses_ReturnsTrue(string ip)
    {
        // Arrange
        // (input supplied by InlineData)

        // Act
        var result = IisClientIpResolver.IsPrivateOrLoopback(ip);

        // Assert
        Assert.True(result);
    }

    [Theory]
    [InlineData("82.158.196.58")]
    [InlineData("100.63.255.255")]
    [InlineData("100.128.0.1")]
    [InlineData("172.70.243.250")]
    [InlineData("2a06:98c0:3600::103")]
    [InlineData("::ffff:82.158.196.58")]
    public void IsPrivateOrLoopback_PublicAddresses_ReturnsFalse(string ip)
    {
        // Arrange
        // (input supplied by InlineData)

        // Act
        var result = IisClientIpResolver.IsPrivateOrLoopback(ip);

        // Assert
        Assert.False(result);
    }

    [Theory]
    // Forged first hops seen in ticket 3522405: the ALB appended the real attacker on the right.
    [InlineData("0.0.0.0,+82.158.196.58", "82.158.196.58")]
    [InlineData("127.0.0.1:80,+82.158.196.58", "82.158.196.58")]
    [InlineData("10.15.109.65,+140.238.32.108", "140.238.32.108")]
    [InlineData("100.64.1.2,+82.158.196.58", "82.158.196.58")]
    // Platform loopback hops appended after the real client.
    [InlineData("114.141.126.89,+127.0.0.1,+127.0.0.1:56384", "114.141.126.89")]
    [InlineData("82.158.196.58", "82.158.196.58")]
    [InlineData("82.158.196.58:443", "82.158.196.58")]
    public void ResolvePreferredClientIp_ForgedOrInternalHops_ReturnsPublicClient(string originalIp, string expected)
    {
        // Arrange
        var raw = originalIp.AsSpan();

        // Act
        var result = IisClientIpResolver.ResolvePreferredClientIp(raw);

        // Assert
        Assert.Equal(expected, result);
    }

    private static readonly Func<string, bool> CloudflareOnly = ip =>
        ip.StartsWith("172.70.", StringComparison.Ordinal) || ip.StartsWith("2a06:98c0:", StringComparison.Ordinal) || ip.StartsWith("172.68.", StringComparison.Ordinal);

    [Theory]
    // Forged public first hop (ticket 3367120): the ALB-appended rightmost hop is the real client.
    [InlineData("106.106.198.131,+219.153.113.105", "219.153.113.105")]
    // Client behind a CDN edge: skip the edge, keep walking left.
    [InlineData("198.51.100.5,+172.70.243.250", "198.51.100.5")]
    [InlineData("198.51.100.5,+172.70.243.250,+127.0.0.1", "198.51.100.5")]
    // Forged hop to the left of a CDN-appended client: the forged value is ignored.
    [InlineData("1.1.1.1,+198.51.100.5,+172.70.243.250", "198.51.100.5")]
    // Only CDN hops: report the leftmost edge (the badge will say which CDN).
    [InlineData("2a06:98c0:3600::103,+172.68.102.9", "2a06:98c0:3600::103")]
    public void ResolvePreferredClientIp_MultipleHops_WalksRightToLeftSkippingCdnEdges(string originalIp, string expected)
    {
        // Arrange
        var raw = originalIp.AsSpan();

        // Act
        var result = IisClientIpResolver.ResolvePreferredClientIp(raw, CloudflareOnly);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ResolvePreferredClientIp_SinglePublicHop_DoesNotConsultCdnRanges()
    {
        // Arrange
        var calls = 0;
        bool Counting(string ip) { calls++; return true; }

        // Act
        var result = IisClientIpResolver.ResolvePreferredClientIp("172.70.243.250,+127.0.0.1".AsSpan(), Counting);

        // Assert
        Assert.Equal("172.70.243.250", result);
        Assert.Equal(0, calls);
    }

    [Theory]
    [InlineData("-")]
    [InlineData("")]
    public void ResolvePreferredClientIp_EmptyOrDash_ReturnsNull(string originalIp)
    {
        // Arrange
        var raw = originalIp.AsSpan();

        // Act
        var result = IisClientIpResolver.ResolvePreferredClientIp(raw);

        // Assert
        Assert.Null(result);
    }
}
