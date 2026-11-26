using LogHunter.Web.Orchestration;
using Xunit;

namespace LogHunter.Tests.Web;

public sealed class IisSourceFilesTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lh-iis-src-" + Guid.NewGuid().ToString("N"));

    public IisSourceFilesTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Touch(string name)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, "#Fields: date time\n");
        return path;
    }

    [Fact]
    public void Resolve_SelectedFiles_KeepsOnlyExistingFiles()
    {
        // Arrange
        var real = Touch("u_ex1.log");
        var missing = Path.Combine(_dir, "gone.log");

        // Act
        var files = IisSourceFiles.Resolve(new[] { real, missing }, customFolderPath: _dir);

        // Assert
        Assert.Equal(new[] { real }, files);
    }

    [Fact]
    public void Resolve_SelectedFolder_ReturnsItsLogFiles()
    {
        // Arrange
        Touch("u_ex1.log");
        Touch("u_ex2.log");
        Touch("notes.txt");

        // Act
        var files = IisSourceFiles.Resolve(null, _dir);

        // Assert
        Assert.Equal(2, files.Count);
        Assert.All(files, f => Assert.EndsWith(".log", f));
    }
}
