using LogHunter.Services;
using Xunit;

namespace LogHunter.Tests.Services;

public sealed class PlatformAuthScannerTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lh-platform-auth-" + Guid.NewGuid().ToString("N"));

    public PlatformAuthScannerTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private void Write(string name, params string[] lines) => File.WriteAllLines(Path.Combine(_dir, name), lines);

    [Fact]
    public async Task Scan_NetHostIpIsTheServerNotTheClient_FileIsSkipped()
    {
        // Arrange: an ODC Service Actions export, where net.host.ip is the server's own loopback.
        Write("Service_Actions.csv",
            "@timestamp,log.attributes.enduser.id,log.attributes.net.host.ip,log.body",
            "2026-10-29T12:00:00Z,177,127.0.0.1,GetOpenWorkItems",
            "2026-10-29T12:00:01Z,178,127.0.0.1,GetOpenWorkItems");

        // Act
        var result = await PlatformAuthScanner.ScanAuthenticatedActivityAsync(_dir, new[] { "127.0.0.1" });

        // Assert
        Assert.Equal(0, result.TotalMatchedRows);
        Assert.Contains("Service_Actions.csv", result.FilesSkippedNoClientIp);
    }

    [Fact]
    public async Task Scan_HttpClientIpColumn_CountsAuthenticatedRows()
    {
        // Arrange: an ODC General export with the real client in http.client_ip.
        Write("General.csv",
            "@timestamp,log.attributes.enduser.id,log.attributes.http.client_ip,log.body",
            "2026-10-29T12:00:00Z,177,10.98.3.19,GetOpenWorkItems",
            "2026-10-29T12:00:01Z,0,10.98.3.19,Anonymous call",
            "2026-10-29T12:00:02Z,178,10.98.4.230,GetOpenWorkItems");

        // Act
        var result = await PlatformAuthScanner.ScanAuthenticatedActivityAsync(_dir, new[] { "10.98.3.19" });

        // Assert
        Assert.Equal(1, result.TotalMatchedRows);
        Assert.Empty(result.FilesSkippedNoClientIp);
    }
}
