using System.Net.Sockets;
using LogHunter.Utils;
using Xunit;

namespace LogHunter.Tests.Utils;

public class IpTargetParserTests
{
    [Theory]
    [InlineData("203.0.113.7", 1)]
    [InlineData("203.0.113.0/24", 256)]
    [InlineData("203.0.113.5/24", 256)]
    [InlineData("203.0.113.10-203.0.113.20", 11)]
    [InlineData("10.0.0.0/32", 1)]
    [InlineData("0.0.0.0/0", 4294967296)]
    public void TryParse_Ipv4Targets_ReturnsExpectedSize(string text, long expectedSize)
    {
        // Arrange
        // (input supplied by InlineData)

        // Act
        var ok = IpTargetParser.TryParse(text, out var target);

        // Assert
        Assert.True(ok);
        Assert.Equal(AddressFamily.InterNetwork, target.Family);
        Assert.Equal((UInt128)expectedSize, target.Size);
    }

    [Fact]
    public void TryParse_Ipv6Cidr_NormalizesHostBits()
    {
        // Arrange
        const string text = "2a06:98c0:3600::103/29";

        // Act
        var ok = IpTargetParser.TryParse(text, out var target);
        IpTargetParser.TryParseAddress("2a06:98c0::", out _, out var expectedStart);

        // Assert
        Assert.True(ok);
        Assert.Equal(AddressFamily.InterNetworkV6, target.Family);
        Assert.Equal(expectedStart, target.Start);
        Assert.Equal(UInt128.One << 99, target.Size);
    }

    [Theory]
    [InlineData("not-an-ip")]
    [InlineData("203.0.113.0/33")]
    [InlineData("203.0.113.20-203.0.113.10")]
    [InlineData("203.0.113.1-2001:db8::1")]
    [InlineData("2001:db8::/129")]
    [InlineData("12345")]
    [InlineData("10.1")]
    [InlineData("10.1.2")]
    [InlineData("10.1/16")]
    [InlineData("")]
    public void TryParse_InvalidTargets_ReturnsFalse(string text)
    {
        // Arrange
        // (input supplied by InlineData)

        // Act
        var ok = IpTargetParser.TryParse(text, out _);

        // Assert
        Assert.False(ok);
    }

    [Fact]
    public void ParseList_MixedPaste_SplitsTokensAndReportsInvalid()
    {
        // Arrange
        const string pasted = "1.33.62.91\n157.22.124.0/24, 106.72.171.226 # from customer\n"
                              + "203.0.113.10 - 203.0.113.20\r\nbogus\n# comment only\n2001:db8::1";

        // Act
        var (targets, invalid) = IpTargetParser.ParseList(pasted);

        // Assert
        Assert.Equal(5, targets.Count);
        Assert.Equal("203.0.113.10-203.0.113.20", targets[3].Text);
        Assert.Equal(new[] { "bogus" }, invalid);
    }
}
