using System.Net;
using LogHunter.Services;
using Xunit;

namespace LogHunter.Tests.Services;

public class IpIntelStoreTests
{
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;
        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) => _respond = respond;
        public List<HttpRequestMessage> Requests { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            var response = _respond(request);
            response.RequestMessage ??= request;
            return Task.FromResult(response);
        }
    }

    private static readonly IpIntelFeed CloudflareFeed = IpIntelFeeds.All.Single(f => f.Id == "cloudflare-v4");

    private static HttpResponseMessage Ok(string body, string? etag = null)
    {
        var r = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) };
        if (etag is not null) r.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue(etag);
        return r;
    }

    [Theory]
    [InlineData("172.64.0.0/13", true)]
    [InlineData("2a06:98c0::/29", true)]
    [InlineData("172.31.0.24/32", false)]
    [InlineData("10.0.0.0/8", false)]
    [InlineData("0.0.0.0/0", false)]
    [InlineData("::/0", false)]
    [InlineData("1.0.0.0/7", false)]
    [InlineData("not-a-cidr", false)]
    public void IsUsableRange_FiltersPrivateAndTooWideRanges(string cidr, bool expected)
    {
        // Arrange
        // (input supplied by InlineData)

        // Act
        var usable = IpIntelStore.IsUsableRange(cidr);

        // Assert
        Assert.Equal(expected, usable);
    }

    [Fact]
    public void Validate_FeedThatShrinksByHalf_IsRejected()
    {
        // Arrange
        var body = string.Join("\n", Enumerable.Range(1, 5).Select(i => $"104.{i}.0.0/16"));

        // Act
        var (count, error) = IpIntelStore.Validate(CloudflareFeed, body, previousCount: 15);

        // Assert
        Assert.Equal(5, count);
        Assert.StartsWith("Range count dropped from 15 to 5", error);
    }

    [Fact]
    public void Validate_ChangedJsonFormat_ReportsFormatChanged()
    {
        // Arrange
        var awsFeed = IpIntelFeeds.All.Single(f => f.Id == "aws");

        // Act
        var (_, error) = IpIntelStore.Validate(awsFeed, "<html>maintenance</html>", previousCount: 0);

        // Assert
        Assert.StartsWith("Format changed", error);
    }

    [Fact]
    public async Task RefreshFeedAsync_GoodBody_ReturnsStateWithCountAndEtag()
    {
        // Arrange
        using var http = new HttpClient(new StubHandler(_ => Ok("173.245.48.0/20\n172.64.0.0/13\n", "\"v1\"")));

        // Act
        var state = await IpIntelStore.RefreshFeedAsync(http, CloudflareFeed, null, CancellationToken.None);

        // Assert
        Assert.Null(state.LastError);
        Assert.Equal(2, state.RangeCount);
        Assert.Equal("\"v1\"", state.ETag);
        Assert.NotNull(state.LastSuccessUtc);
    }

    [Fact]
    public async Task RefreshFeedAsync_ServerError_KeepsPreviousSuccess()
    {
        // Arrange
        var previous = new IpIntelFeedState("cloudflare-v4", "Cloudflare", new DateTime(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc), null, 15, null, null);
        using var http = new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.BadGateway)));

        // Act
        var state = await IpIntelStore.RefreshFeedAsync(http, CloudflareFeed, previous, CancellationToken.None);

        // Assert
        Assert.Equal("HTTP 502", state.LastError);
        Assert.Equal(previous.LastSuccessUtc, state.LastSuccessUtc);
        Assert.Equal(15, state.RangeCount);
    }

    [Fact]
    public async Task RefreshFeedAsync_RedirectToOtherHost_IsRejected()
    {
        // Arrange
        using var http = new HttpClient(new StubHandler(_ =>
        {
            var r = Ok("1.2.3.0/24");
            r.RequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://evil.example/ips");
            return r;
        }));

        // Act
        var state = await IpIntelStore.RefreshFeedAsync(http, CloudflareFeed, null, CancellationToken.None);

        // Assert
        Assert.Equal("Redirected to an unexpected host", state.LastError);
        Assert.Null(state.LastSuccessUtc);
    }

    [Fact]
    public void BuildSnapshot_StaticLists_LabelGoogleLbAndNetskope()
    {
        // Arrange
        var snapshot = IpIntelStore.BuildSnapshot(IpIntelFeeds.Static);

        // Act
        var google = IpIntelStore.Best(snapshot.Match("35.191.10.10"));
        var netskope = IpIntelStore.Best(snapshot.Match("163.116.130.1"));
        var none = snapshot.Match("82.158.196.58");

        // Assert
        Assert.Equal(IpIntelCategory.Cdn, google!.Category);
        Assert.Equal(IpIntelCategory.CorporateProxy, netskope!.Category);
        Assert.Empty(none);
    }
}
