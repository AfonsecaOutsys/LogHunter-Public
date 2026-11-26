using LogHunter.Services;
using Xunit;

namespace LogHunter.Tests.Services;

/// <summary>AppFolders is process-wide: run alone so no parallel test reads a moved workspace.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class AppFoldersState
{
    public const string Name = "AppFolders workspace root";
}

[Collection(AppFoldersState.Name)]
public sealed class AppFoldersTests : IDisposable
{
    private readonly string _original = AppFolders.Base;

    public void Dispose() => AppFolders.UseRoot(_original);

    [Fact]
    public void UseRoot_MovesEveryWorkspaceFolder()
    {
        // Arrange
        var root = Path.Combine(Path.GetTempPath(), "lh-root-" + Guid.NewGuid().ToString("N"));

        // Act
        AppFolders.UseRoot(root);

        // Assert
        var expected = Path.GetFullPath(root);
        Assert.Equal(expected, AppFolders.Base);
        Assert.Equal(Path.Combine(expected, "ALB"), AppFolders.ALB);
        Assert.Equal(Path.Combine(expected, "IIS"), AppFolders.IIS);
        Assert.Equal(Path.Combine(expected, "PlatformLogs"), AppFolders.PlatformLogs);
        Assert.Equal(Path.Combine(expected, "output"), AppFolders.Output);
        Assert.Equal(Path.Combine(expected, "config"), AppFolders.Config);
        Assert.Equal(Path.Combine(expected, "logs"), AppFolders.Logs);
        Assert.Equal(Path.Combine(expected, "ALB", "configs", "_assets"), AppFolders.Assets);
    }

    [Fact]
    public void Base_DefaultsToTheExeFolder()
    {
        // Arrange
        var exeFolder = Path.GetFullPath(AppContext.BaseDirectory);

        // Act
        AppFolders.UseRoot(AppContext.BaseDirectory);

        // Assert
        Assert.Equal(exeFolder, AppFolders.Base);
        Assert.Equal(Path.Combine(exeFolder, "IIS"), AppFolders.IIS);
    }
}
