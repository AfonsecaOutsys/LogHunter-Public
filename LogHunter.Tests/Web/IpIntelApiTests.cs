using System.Text.Json;
using LogHunter.Services;
using LogHunter.Web.Api;
using Xunit;

namespace LogHunter.Tests.Web;

public class IpIntelApiTests
{
    // Uses the built-in static ranges (Google Cloud LB 35.191.0.0/16), so no network is needed.
    private static JsonElement Lookup(params string[] ips)
        => JsonSerializer.SerializeToElement(IpIntelApi.BuildLookup(ips), new JsonSerializerOptions(JsonSerializerDefaults.Web));

    [Fact]
    public void BuildLookup_MostlyOneCdn_ReturnsConfirmedVerdict()
    {
        // Arrange
        var ips = new[] { "35.191.1.1", "35.191.1.2", "35.191.1.3", "35.191.1.4", "82.158.196.58" };

        // Act
        var result = Lookup(ips);

        // Assert
        var fronted = result.GetProperty("fronted");
        Assert.Equal("confirmed", fronted.GetProperty("level").GetString());
        Assert.Equal("Google Cloud LB", fronted.GetProperty("provider").GetString());
        Assert.Equal(4, result.GetProperty("results").GetArrayLength());
    }

    [Fact]
    public void BuildLookup_HalfCdn_ReturnsLikely()
    {
        // Arrange
        var ips = new[] { "35.191.1.1", "35.191.1.2", "82.158.196.58", "140.238.32.108" };

        // Act
        var level = Lookup(ips).GetProperty("fronted").GetProperty("level").GetString();

        // Assert
        Assert.Equal("likely", level);
    }

    [Fact]
    public void BuildLookup_CorporateProxyOnly_IsNotReportedAsFronted()
    {
        // Arrange
        var ips = new[] { "163.116.130.1", "163.116.130.2" };

        // Act
        var result = Lookup(ips);

        // Assert
        Assert.Equal("none", result.GetProperty("fronted").GetProperty("level").GetString());
        Assert.Equal("CorporateProxy", result.GetProperty("results")[0].GetProperty("category").GetString());
    }

    [Fact]
    public void PillLabel_NeverDownloaded_SaysNotLoaded()
    {
        // Arrange
        var status = new IpIntelStatus(null, 3, 10, false, new[] { new IpIntelFeedState("aws", "AWS", null, null, 0, null, null) });

        // Act
        var label = IpIntelApi.PillLabel(status);

        // Assert
        Assert.Equal("not loaded", label);
        Assert.Equal("missing", status.Level);
    }

    [Fact]
    public void PillLabel_FeedFromThreeHoursAgo_SaysHours()
    {
        // Arrange
        var when = DateTime.UtcNow.AddHours(-3).AddMinutes(-5);
        var status = new IpIntelStatus(when, 3, 10, false, new[] { new IpIntelFeedState("aws", "AWS", when, when, 10, null, null) });

        // Act
        var label = IpIntelApi.PillLabel(status);

        // Assert
        Assert.Equal("3 h", label);
        Assert.Equal("ok", status.Level);
    }
}
