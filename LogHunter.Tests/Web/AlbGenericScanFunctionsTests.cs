using LogHunter.Web.Orchestration;
using Xunit;

namespace LogHunter.Tests.Web;

public sealed class AlbGenericScanFunctionsTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lh-generic-" + Guid.NewGuid().ToString("N"));

    public AlbGenericScanFunctionsTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string AlbLine(string client, string url) =>
        $"https 2026-11-09T10:00:00Z app/lb/1 {client} 10.0.0.1:80 0.1 0.2 0.1 200 200 0 57 \"GET {url} HTTP/1.1\" \"curl/7\" - - arn \"Root=1\" \"h\" \"-\" 1 2026-11-09T10:00:00Z \"forward\" \"-\" \"-\" \"10.0.0.1:80\" \"200\" \"-\" \"-\"";

    [Fact]
    public async Task ScanTop50IpsOverall_TotalMatchesIsUniqueIpCountNotHitSum()
    {
        // Arrange: 3 unique IPs, 6 hits in total.
        var file = Path.Combine(_dir, "a.log");
        File.WriteAllLines(file, new[]
        {
            AlbLine("203.0.113.7:1000", "https://h:443/A"),
            AlbLine("203.0.113.7:1001", "https://h:443/A"),
            AlbLine("203.0.113.7:1002", "https://h:443/B"),
            AlbLine("198.51.100.1:1000", "https://h:443/A"),
            AlbLine("198.51.100.1:1001", "https://h:443/C"),
            AlbLine("192.0.2.5:1000", "https://h:443/A"),
        });

        // Act
        var ips = await AlbGenericScanFunctions.ScanTop50IpsOverallAsync(new List<string> { file }, _dir, (_, _, _, _) => { });
        var pairs = await AlbGenericScanFunctions.ScanTop50IpUriNoQueryAsync(new List<string> { file }, _dir, (_, _, _, _) => { });

        // Assert
        Assert.Equal(3, ips.TotalMatches);
        Assert.Equal(5, pairs.TotalMatches);
        Assert.Equal("203.0.113.7", ips.Rows[0].Values[1]);
    }
}
