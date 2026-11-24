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
    public void BuildLookup_ProviderKnownOnlyFromNetwork_IsCappedAtLikely()
    {
        // Arrange
        var label = new IpIntelLabel("Akamai", "AS20940", IpIntelCategory.Cdn, "akamai-as20940", Likely: true);
        IpIntelStore.UseTestSnapshot(IpIntelStore.BuildSnapshot(new[] { ("23.192.0.0/11", label) }));

        try
        {
            // Act
            var level = Lookup("23.192.1.1", "23.192.1.2", "23.192.1.3").GetProperty("fronted").GetProperty("level").GetString();

            // Assert
            Assert.Equal("likely", level);
        }
        finally
        {
            IpIntelStore.UseTestSnapshot(IpIntelStore.BuildSnapshot(IpIntelFeeds.Static));
        }
    }

    [Fact]
    public void SaveCustomRanges_LabelsPastedRangesAndClearRemovesThem()
    {
        // Arrange
        const string pasted = "198.18.0.0/24\n10.0.0.0/8\nbogus";

        try
        {
            // Act
            var (saved, invalid) = IpIntelStore.SaveCustomRanges("Acme Akamai Site Shield", pasted);
            var hit = IpIntelStore.Lookup("198.18.0.77");
            var (provider, text) = IpIntelStore.GetCustomRanges();

            // Assert
            Assert.Equal(1, saved);
            Assert.Equal(new[] { "bogus", "10.0.0.0/8" }, invalid);
            Assert.Equal("Acme Akamai Site Shield edge", hit!.Badge);
            Assert.Equal(("Acme Akamai Site Shield", "198.18.0.0/24"), (provider, text));
        }
        finally
        {
            IpIntelStore.SaveCustomRanges(null, "");
        }

        Assert.Null(IpIntelStore.Lookup("198.18.0.77"));
    }

    [Fact]
    public void ParseCustomFile_ReadsProviderHeaderAndRanges()
    {
        // Arrange
        const string content = "# provider: Acme WAF\n203.0.113.0/24\n# note\n198.51.100.7\n";

        // Act
        var (provider, text) = IpIntelStore.ParseCustomFile(content);

        // Assert
        Assert.Equal("Acme WAF", provider);
        Assert.Equal("203.0.113.0/24\n198.51.100.7", text);
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
