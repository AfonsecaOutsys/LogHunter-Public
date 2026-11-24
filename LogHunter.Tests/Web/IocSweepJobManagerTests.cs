using LogHunter.Web.Orchestration;
using Xunit;

namespace LogHunter.Tests.Web;

public sealed class IocSweepJobManagerTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lh-ioc-job-" + Guid.NewGuid().ToString("N"));

    public IocSweepJobManagerTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string MakeFolder(string name, bool withLog)
    {
        var path = Path.Combine(_dir, name);
        Directory.CreateDirectory(path);
        if (withLog) File.WriteAllText(Path.Combine(path, "a.log"), "x");
        return path;
    }

    [Fact]
    public void ResolveSources_NoFolders_ReturnsError()
    {
        // Arrange
        var requests = Array.Empty<IocSweepSourceRequest>();

        // Act
        IocSweepJobManager.ResolveSources(requests, out var error);

        // Assert
        Assert.Equal("Add at least one log folder.", error);
    }

    [Fact]
    public void ResolveSources_FolderWithoutLogs_ReturnsError()
    {
        // Arrange
        var empty = MakeFolder("empty", withLog: false);

        // Act
        IocSweepJobManager.ResolveSources(new[] { new IocSweepSourceRequest("x", empty) }, out var error);

        // Assert
        Assert.StartsWith("No .log or .log.gz files in:", error);
    }

    [Fact]
    public void ResolveSources_MissingFolder_ReturnsError()
    {
        // Arrange
        var missing = Path.Combine(_dir, "nope");

        // Act
        IocSweepJobManager.ResolveSources(new[] { new IocSweepSourceRequest("x", missing) }, out var error);

        // Assert
        Assert.StartsWith("Folder not found:", error);
    }

    [Fact]
    public void ResolveSources_DuplicateAndBlankLabels_AreMadeUnique()
    {
        // Arrange
        var a = MakeFolder("prod-alb", withLog: true);
        var b = MakeFolder("dev-alb", withLog: true);
        var c = MakeFolder("lt-alb", withLog: true);
        var requests = new[]
        {
            new IocSweepSourceRequest("ALB", a),
            new IocSweepSourceRequest("alb", b),
            new IocSweepSourceRequest(" ", c),
        };

        // Act
        var sources = IocSweepJobManager.ResolveSources(requests, out var error);

        // Assert
        Assert.Null(error);
        Assert.Equal(new[] { "ALB", "alb (2)", "lt-alb" }, sources.Select(s => s.Label));
    }

    [Fact]
    public void TryStart_NoValidTargets_ReturnsErrorListingIgnoredInput()
    {
        // Arrange
        var folder = MakeFolder("alb", withLog: true);
        var manager = new IocSweepJobManager();

        // Act
        var started = manager.TryStart("bogus, alsobad", new[] { new IocSweepSourceRequest("ALB", folder) }, out _, out var error);

        // Assert
        Assert.False(started);
        Assert.Contains("bogus", error);
        Assert.Equal("idle", manager.GetSnapshot().State);
    }
}
