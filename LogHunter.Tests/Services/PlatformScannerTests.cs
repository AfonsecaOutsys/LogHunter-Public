using LogHunter.Services;
using LogHunter.Web.Orchestration;
using Xunit;

namespace LogHunter.Tests.Services;

public sealed class PlatformScannerTests : IDisposable
{
    private const string Dangerous = "A potentially dangerous Request.Form value was detected";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lh-platform-" + Guid.NewGuid().ToString("N"));

    public PlatformScannerTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private void Write(string name, params string[] lines) => File.WriteAllLines(Path.Combine(_dir, name), lines);

    [Fact]
    public async Task Scan_MatchingRowWithoutClientIp_IsCountedNotDropped()
    {
        // Arrange
        Write("errors.csv",
            "Id,Message,EnvironmentInformation",
            $"1,\"{Dangerous}\",\"ClientIp: 203.0.113.7\"",
            $"2,\"{Dangerous}\",\"\"",
            $"3,\"{Dangerous}\",\"7\"");

        // Act
        var result = await PlatformScanner.ScanSuspiciousRequestsAsync(_dir);

        // Assert
        Assert.Equal(1, result.MatchedRows);
        Assert.Equal(2, result.MatchedRowsWithoutIp);
        Assert.Equal(2, result.MatchedRowsWithoutIpByFile["errors.csv"]);
    }

    [Fact]
    public async Task Scan_FileWithoutMessageOrEnvColumns_IsReportedAsSkipped()
    {
        // Arrange
        Write("other.csv", "Id,Text,When", "1,hello,today");

        // Act
        var result = await PlatformScanner.ScanSuspiciousRequestsAsync(_dir);

        // Assert
        var skipped = Assert.Single(result.FilesSkipped);
        Assert.Equal("other.csv", skipped.File);
        Assert.Contains("column not found", skipped.Reason);
    }

    [Fact]
    public async Task Scan_TabDelimitedFile_IsParsed()
    {
        // Arrange
        Write("errors.tsv.csv",
            "Id\tMessage\tEnvironmentInformation",
            $"1\t{Dangerous}\tClientIp: 198.51.100.4");

        // Act
        var result = await PlatformScanner.ScanSuspiciousRequestsAsync(_dir);

        // Assert
        Assert.Equal(1, result.MatchedRows);
        Assert.Equal("198.51.100.4", result.TopEffectiveIpsOverall.Single().Ip);
    }

    [Fact]
    public async Task CompletionMessage_NoIpsButMatchedRows_DoesNotSayNoMatches()
    {
        // Arrange
        Write("errors2.csv",
            "Id,Message,EnvironmentInformation",
            $"1,\"{Dangerous}\",\"7\"");
        Write("other.csv", "Id,Text", "1,x");
        var result = await PlatformScanner.ScanSuspiciousRequestsAsync(_dir);

        // Act
        var message = PlatformSuspiciousJobManager.BuildCompletionMessage(result);

        // Assert
        Assert.DoesNotContain("No matching", message);
        Assert.Contains("0 IPs extracted", message);
        Assert.Contains("1 row matched but had no client IP (errors2.csv: 1)", message);
        Assert.Contains("1 file skipped (message or environment info column not found): other.csv.", message);
    }

    [Fact]
    public async Task CompletionMessage_PluralisesAndGroupsSkippedFilesByReason()
    {
        // Arrange
        Write("errors.csv",
            "Id,Message,EnvironmentInformation",
            $"1,\"{Dangerous}\",\"ClientIp: 203.0.113.7\"",
            $"2,\"{Dangerous}\",\"ClientIp: 203.0.113.7\"");
        Write("General.csv", "Id,Text", "1,x");
        Write("Integrations.csv", "Id,Text", "1,x");
        var result = await PlatformScanner.ScanSuspiciousRequestsAsync(_dir);

        // Act
        var message = PlatformSuspiciousJobManager.BuildCompletionMessage(result);

        // Assert
        Assert.StartsWith("Found 2 suspicious rows in 1 file: 1 distinct IP.", message);
        Assert.Contains("2 files skipped (message or environment info column not found): ", message);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(message, "column not found"));
    }
}
