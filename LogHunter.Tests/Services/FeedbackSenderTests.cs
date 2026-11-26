using System.Net;
using System.Text.Json;
using LogHunter.Services;
using Xunit;

namespace LogHunter.Tests.Services;

// FeedbackSender is static: keep these tests in one class so they run serially. Never hits the live API.
public sealed class FeedbackSenderTests : IDisposable
{
    private const string Endpoint = "https://usage.example/LogHunterUsage_IS/rest/Usage/";
    private const string ValidText = "  The ALB download hangs at 90%.  ";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lh-feedback-" + Guid.NewGuid().ToString("N"));

    public FeedbackSenderTests()
    {
        Directory.CreateDirectory(_dir);
        FeedbackSender.Reset();
    }

    public void Dispose()
    {
        FeedbackSender.Reset();
        Directory.Delete(_dir, recursive: true);
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpResponseMessage> _respond;
        public StubHandler(Func<HttpResponseMessage> respond) => _respond = respond;
        public List<(HttpRequestMessage Request, string Body)> Calls { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
            Calls.Add((request, body));
            return _respond();
        }
    }

    private StubHandler StartWith(Func<HttpResponseMessage> respond)
    {
        var handler = new StubHandler(respond);
        FeedbackSender.Start("2.0.0.4", "web", Endpoint, "secret", _dir, handler);
        return handler;
    }

    [Theory]
    [InlineData(HttpStatusCode.OK, true, FeedbackSender.SentMessage)]
    [InlineData(HttpStatusCode.TooManyRequests, false, FeedbackSender.RateLimitedMessage)]
    [InlineData(HttpStatusCode.BadRequest, false, FeedbackSender.RejectedMessage)]
    [InlineData(HttpStatusCode.Unauthorized, false, FeedbackSender.UnreachableMessage)]
    [InlineData(HttpStatusCode.InternalServerError, false, FeedbackSender.UnreachableMessage)]
    public async Task SendAsync_MapsStatusToUserMessage(HttpStatusCode status, bool expectedOk, string expectedMessage)
    {
        // Arrange
        StartWith(() => new HttpResponseMessage(status));

        // Act
        var result = await FeedbackSender.SendAsync("alb", ValidText);

        // Assert
        Assert.Equal(expectedOk, result.Ok);
        Assert.Equal(expectedMessage, result.Message);
    }

    [Fact]
    public async Task SendAsync_HandlerThrows_ReportsConnectionProblem()
    {
        // Arrange
        StartWith(() => throw new HttpRequestException("offline"));

        // Act
        var result = await FeedbackSender.SendAsync("iis", ValidText);

        // Assert
        Assert.False(result.Ok);
        Assert.Equal(FeedbackSender.UnreachableMessage, result.Message);
    }

    [Fact]
    public async Task SendAsync_PostsContractBodyAndHeaders()
    {
        // Arrange
        var handler = StartWith(() => new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        await FeedbackSender.SendAsync("platform", ValidText);

        // Assert
        var (request, body) = Assert.Single(handler.Calls);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("https://usage.example/LogHunterUsage_IS/rest/Usage/Feedback", request.RequestUri!.ToString());
        Assert.Equal("secret", Assert.Single(request.Headers.GetValues("X-LogHunter-Key")));
        Assert.Equal("application/json", request.Content!.Headers.ContentType!.MediaType);

        using var json = JsonDocument.Parse(body);
        var root = json.RootElement;
        Assert.Equal(File.ReadAllText(Path.Combine(_dir, "install-id")), root.GetProperty("InstallId").GetString());
        Assert.Equal("2.0.0.4", root.GetProperty("Version").GetString());
        Assert.Equal("web", root.GetProperty("Mode").GetString());
        Assert.Equal("platform", root.GetProperty("Area").GetString());
        Assert.Equal(ValidText.Trim(), root.GetProperty("Description").GetString());
    }

    [Theory]
    [InlineData(null, ValidText)]
    [InlineData("ALB", ValidText)]
    [InlineData("unknown", ValidText)]
    [InlineData("alb", "   short    ")]
    [InlineData("alb", null)]
    public async Task SendAsync_InvalidInput_SendsNothing(string? area, string? text)
    {
        // Arrange
        var handler = StartWith(() => new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        var result = await FeedbackSender.SendAsync(area, text);

        // Assert
        Assert.False(result.Ok);
        Assert.Empty(handler.Calls);
    }

    [Fact]
    public void Validate_LengthBounds()
    {
        Assert.Null(FeedbackSender.Validate("other", new string('x', FeedbackSender.MinLength)));
        Assert.Null(FeedbackSender.Validate("other", new string('x', FeedbackSender.MaxLength)));
        Assert.NotNull(FeedbackSender.Validate("other", new string('x', FeedbackSender.MinLength - 1)));
        Assert.NotNull(FeedbackSender.Validate("other", new string('x', FeedbackSender.MaxLength + 1)));
    }

    [Theory]
    [InlineData(null, "key")]
    [InlineData(Endpoint, "")]
    public async Task Start_WithoutEndpointOrKey_IsUnavailable(string? endpoint, string? key)
    {
        // Act
        FeedbackSender.Start("2.0.0.4", "web", endpoint, key, _dir, new StubHandler(() => new HttpResponseMessage(HttpStatusCode.OK)));
        var result = await FeedbackSender.SendAsync("alb", ValidText);

        // Assert
        Assert.False(FeedbackSender.IsAvailable);
        Assert.False(result.Ok);
    }
}
