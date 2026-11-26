using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using LogHunter.Services;
using Xunit;

namespace LogHunter.Tests.Services;

// UsageReporter is static: keep these tests in one class so they run serially. Never hits the live API.
public sealed class UsageReporterTests : IDisposable
{
    private const string Endpoint = "https://usage.example/LogHunterUsage_IS/rest/Usage";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lh-usage-" + Guid.NewGuid().ToString("N"));

    public UsageReporterTests()
    {
        Directory.CreateDirectory(_dir);
        UsageReporter.Reset();
    }

    public void Dispose()
    {
        UsageReporter.Reset();
        Directory.Delete(_dir, recursive: true);
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;
        public RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage>? respond = null)
            => _respond = respond ?? (_ => new HttpResponseMessage(HttpStatusCode.OK));
        public List<(HttpRequestMessage Request, string Body)> Calls { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
            lock (Calls) Calls.Add((request, body));
            return _respond(request);
        }
    }

    [Theory]
    [InlineData(null, "key", null)]
    [InlineData("", "key", null)]
    [InlineData(Endpoint, "", null)]
    [InlineData(Endpoint, "key", "1")]
    public void Start_DisabledConfigurations_SendNothing(string? endpoint, string? key, string? optOut)
    {
        // Arrange
        var handler = new RecordingHandler();

        // Act
        var task = UsageReporter.Start("2.0.0.4", "web", endpoint, key, _dir, optOut, handler);
        var track = UsageReporter.TrackAsync(UsageFeature.AlbDownload);

        // Assert
        Assert.Null(task);
        Assert.Null(track);
        Assert.Empty(handler.Calls);
        Assert.False(UsageReporter.IsEnabled);
    }

    [Fact]
    public async Task Start_ThenTrack_SendsContractBodiesWithKeyHeader()
    {
        // Arrange
        var handler = new RecordingHandler();

        // Act
        await UsageReporter.Start("2.0.0.4", "console", Endpoint + "/", "secret-key", _dir, null, handler)!;
        await UsageReporter.TrackAsync(UsageFeature.IisIpSweep)!;

        // Assert
        Assert.Equal(2, handler.Calls.Count);
        var (startReq, startBody) = handler.Calls[0];
        var (featureReq, featureBody) = handler.Calls[1];
        Assert.Equal(HttpMethod.Post, startReq.Method);
        Assert.Equal($"{Endpoint}/AppStart", startReq.RequestUri!.ToString());
        Assert.Equal($"{Endpoint}/FeatureUse", featureReq.RequestUri!.ToString());
        Assert.Equal("secret-key", startReq.Headers.GetValues("X-LogHunter-Key").Single());
        Assert.Equal("application/json", startReq.Content!.Headers.ContentType!.MediaType);

        using var start = JsonDocument.Parse(startBody);
        Assert.Equal(new[] { "InstallId", "SessionId", "Version", "Mode" }, start.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal("console", start.RootElement.GetProperty("Mode").GetString());
        Assert.Matches(@"^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$", start.RootElement.GetProperty("InstallId").GetString()!);

        using var feature = JsonDocument.Parse(featureBody);
        Assert.Equal("iis.ip-sweep", feature.RootElement.GetProperty("Feature").GetString());
        Assert.Equal(start.RootElement.GetProperty("SessionId").GetString(), feature.RootElement.GetProperty("SessionId").GetString());
    }

    [Fact]
    public void Start_SavedSettingOff_SendsNothingButStaysAvailable()
    {
        // Arrange
        File.WriteAllText(Path.Combine(_dir, "usage-settings.json"), """{"enabled":false}""");
        var handler = new RecordingHandler();

        // Act
        var start = UsageReporter.Start("2.0.0.5", "web", Endpoint, "k", _dir, null, handler);
        var track = UsageReporter.TrackAsync(UsageFeature.AlbDownload);

        // Assert
        Assert.Null(start);
        Assert.Null(track);
        Assert.Empty(handler.Calls);
        Assert.True(UsageReporter.IsAvailable);
        Assert.False(UsageReporter.IsEnabled);
    }

    [Fact]
    public async Task SetUserEnabled_TogglesSendingAndPersistsTheChoice()
    {
        // Arrange
        var handler = new RecordingHandler();
        await UsageReporter.Start("2.0.0.5", "web", Endpoint, "k", _dir, null, handler)!;

        // Act
        UsageReporter.SetUserEnabled(false);
        var whileOff = UsageReporter.TrackAsync(UsageFeature.AlbIpSummary);
        var savedOff = UsageReporter.LoadUserEnabled(_dir);
        UsageReporter.SetUserEnabled(true);
        await UsageReporter.TrackAsync(UsageFeature.AlbIpSweep)!;

        // Assert
        Assert.Null(whileOff);
        Assert.False(savedOff);
        Assert.True(UsageReporter.LoadUserEnabled(_dir));
        Assert.Equal(new[] { "AppStart", "FeatureUse" }, handler.Calls.Select(c => c.Request.RequestUri!.Segments.Last()));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not json")]
    [InlineData("""{"enabled":true}""")]
    [InlineData("""{}""")]
    public void LoadUserEnabled_MissingCorruptOrOn_DefaultsToOn(string? content)
    {
        // Arrange
        if (content is not null)
            File.WriteAllText(Path.Combine(_dir, "usage-settings.json"), content);

        // Act
        var enabled = UsageReporter.LoadUserEnabled(_dir);

        // Assert
        Assert.True(enabled);
    }

    [Fact]
    public async Task Send_HandlerThrows_NeverSurfacesAnException()
    {
        // Arrange
        var handler = new RecordingHandler(_ => throw new HttpRequestException("proxy said no"));

        // Act
        var exception = await Record.ExceptionAsync(async () =>
        {
            await UsageReporter.Start("2.0.0.4", "web", Endpoint, "k", _dir, null, handler)!;
            await UsageReporter.TrackAsync(UsageFeature.AlbIpSummary)!;
        });

        // Assert
        Assert.Null(exception);
    }

    [Fact]
    public void LoadOrCreateInstallId_ReusesValidIdAndReplacesCorruptFile()
    {
        // Arrange
        var first = UsageReporter.LoadOrCreateInstallId(_dir);

        // Act
        var second = UsageReporter.LoadOrCreateInstallId(_dir);
        File.WriteAllText(Path.Combine(_dir, "install-id"), "{not-a-guid}");
        var replaced = UsageReporter.LoadOrCreateInstallId(_dir);

        // Assert
        Assert.Equal(first, second);
        Assert.NotEqual(first, replaced);
        Assert.Equal(replaced, File.ReadAllText(Path.Combine(_dir, "install-id")));
    }

    [Theory]
    [InlineData("alb/5xx-mismatch", "alb.5xx-mismatch")]
    [InlineData("alb/top-50-ips", "alb.top50-ips")]
    [InlineData("alb/top-50-ips-by-uri", "alb.top50-ips-by-uri")]
    [InlineData("alb/top-50-avg-duration", "alb.top50-avg-duration")]
    [InlineData("alb/waf-blocked-summary", "alb.waf-blocked-summary")]
    [InlineData("alb/waf-blocks-over-time", "alb.waf-blocks-over-time")]
    public void GenericScanFeature_EveryRegisteredScanHasAKey(string slug, string expected)
    {
        // Arrange
        // (input supplied by InlineData)

        // Act
        var key = LogHunter.Web.Api.AlbApi.GenericScanFeature(slug);

        // Assert
        Assert.Equal(expected, key);
    }

    [Fact]
    public void UsageFeature_AllKeysMatchServerPatternAndAreUnique()
    {
        // Arrange
        var pattern = new Regex("^[a-z0-9.-]{1,50}$");

        // Act
        var invalid = UsageFeature.All.Where(k => !pattern.IsMatch(k)).ToList();

        // Assert
        Assert.Empty(invalid);
        Assert.Equal(23, UsageFeature.All.Count);
        Assert.Equal(UsageFeature.All.Count, UsageFeature.All.Distinct().Count());
    }
}
