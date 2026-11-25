using System.IO.Compression;
using System.Text;
using LogHunter.Services;
using LogHunter.Utils;
using Xunit;

namespace LogHunter.Tests.Services;

public sealed class IocSweepScannerTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lh-ioc-" + Guid.NewGuid().ToString("N"));

    public IocSweepScannerTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string AlbLine(string ts, string client, int status, string url) =>
        $"https {ts} app/my-lb/50dc6c495c0c9188 {client} 10.0.0.1:80 0.086 0.048 0.037 {status} {status} 0 57 "
        + $"\"GET {url} HTTP/1.1\" \"curl/7.46.0\" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 "
        + "arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/t/73e2d6bc24d8a067 "
        + "\"Root=1-58337281-1d84f3d73c47ec4e58577259\" \"www.example.com\" \"-\" 1 2026-11-09T22:22:48.364000Z "
        + "\"forward\" \"-\" \"-\" \"10.0.0.1:80\" \"200\" \"-\" \"-\"";

    private const string IisHeader =
        "#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n"
        + "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken OriginalIP\n";

    private static string IisLine(string date, string time, string uri, int status, string originalIp) =>
        $"{date} {time} 10.15.109.65 POST {uri} - 443 - 10.13.37.5 curl/7.88.1 {status} 0 0 15 {originalIp}";

    private string WriteFile(string name, string content)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void TryReadAlbRecord_AwsSampleLine_ParsesClientTimestampStatusAndUri()
    {
        // Arrange
        var line = AlbLine("2026-11-09T23:55:06.415134Z", "203.0.113.7:2817", 403, "https://www.example.com:443/Login/Users?x=1");

        // Act
        var ok = IocSweepScanner.TryReadAlbRecord(line, out var rec);

        // Assert
        Assert.True(ok);
        Assert.Equal("203.0.113.7", rec.ClientIp);
        Assert.Equal(new DateTime(2026, 11, 9, 23, 55, 6, 415, DateTimeKind.Utc).AddTicks(1340), rec.TimestampUtc);
        Assert.Equal("403", rec.Status);
        Assert.Equal("/Login/Users", rec.Uri);
    }

    [Theory]
    [InlineData("[2001:db8::1]:443", "2001:db8::1")]
    [InlineData("2001:db8::1:443", "2001:db8::1")]
    public void TryReadAlbRecord_Ipv6Client_StripsPort(string client, string expected)
    {
        // Arrange
        var line = AlbLine("2026-11-09T23:55:06Z", client, 200, "https://h:443/");

        // Act
        var ok = IocSweepScanner.TryReadAlbRecord(line, out var rec);

        // Assert
        Assert.True(ok);
        Assert.Equal(expected, rec.ClientIp);
    }

    [Fact]
    public void TryReadAlbRecord_Garbage_ReturnsFalse()
    {
        // Arrange
        const string line = "this is not an alb line";

        // Act
        var ok = IocSweepScanner.TryReadAlbRecord(line, out _);

        // Assert
        Assert.False(ok);
    }

    [Fact]
    public async Task RunAsync_AlbAndIisSources_CountsPerTargetAndScope()
    {
        // Arrange
        var alb = WriteFile("alb.log", string.Join("\n",
            AlbLine("2026-11-09T10:00:00Z", "203.0.113.7:1000", 200, "https://h:443/A"),
            AlbLine("2026-11-09T11:00:00Z", "203.0.113.9:1000", 403, "https://h:443/B"),
            AlbLine("2026-11-09T12:00:00Z", "198.51.100.1:1000", 200, "https://h:443/C"),
            "garbage line"));
        var iis = WriteFile("u_ex261109.log", IisHeader + string.Join("\n",
            IisLine("2026-11-08", "09:00:00", "/App/screenservices/X", 500, "0.0.0.0,+203.0.113.7"),
            IisLine("2026-11-08", "09:05:00", "/App/Home", 200, "198.51.100.1")));
        var (targets, invalid) = IpTargetParser.ParseList("203.0.113.7\n203.0.113.0/24\n192.0.2.1\nnope");
        var sources = new[]
        {
            new IocSweepSource("Prod ALB", new[] { alb }),
            new IocSweepSource("Prod IIS", new[] { iis }),
        };

        // Act
        var result = await IocSweepScanner.RunAsync(sources, targets, invalid, null, CancellationToken.None);

        // Assert
        var single = result.Targets[0];
        var cidr = result.Targets[1];
        var zero = result.Targets[2];
        Assert.Equal(2, single.Hits);
        Assert.Equal(1, single.HitsBySource["Prod ALB"]);
        Assert.Equal(1, single.HitsBySource["Prod IIS"]);
        Assert.Equal(new DateTime(2026, 11, 8, 9, 0, 0, DateTimeKind.Utc), single.FirstSeenUtc);
        Assert.Equal(3, cidr.Hits);
        Assert.Equal(2, cidr.MatchedIps.Count);
        Assert.Equal(0, zero.Hits);
        Assert.Equal(new[] { "nope" }, result.InvalidTokens);
        Assert.Equal(4, result.Scopes[0].LinesRead);
        Assert.Equal(1, result.Scopes[0].ParseFailures);
        Assert.Equal(1, result.Scopes[0].AlbFiles);
        Assert.Equal(1, result.Scopes[1].IisFiles);
        Assert.Equal(new DateTime(2026, 11, 9, 12, 0, 0, DateTimeKind.Utc), result.Scopes[0].MaxUtc);
    }

    [Fact]
    public async Task RunAsync_GzAndCorruptFiles_ReadsGzAndReportsCorrupt()
    {
        // Arrange
        var gzPath = Path.Combine(_dir, "alb.log.gz");
        await using (var fs = File.Create(gzPath))
        await using (var gz = new GZipStream(fs, CompressionLevel.Fastest))
        {
            var bytes = Encoding.UTF8.GetBytes(AlbLine("2026-11-09T10:00:00Z", "203.0.113.7:1000", 200, "https://h:443/A"));
            await gz.WriteAsync(bytes);
        }

        var corrupt = Path.Combine(_dir, "broken.log.gz");
        await File.WriteAllBytesAsync(corrupt, new byte[] { 1, 2, 3, 4, 5 });
        var (targets, _) = IpTargetParser.ParseList("203.0.113.7");
        var sources = new[] { new IocSweepSource("ALB", new[] { gzPath, corrupt }) };

        // Act
        var result = await IocSweepScanner.RunAsync(sources, targets, Array.Empty<string>(), null, CancellationToken.None);

        // Assert
        Assert.Equal(1, result.Targets[0].Hits);
        Assert.Single(result.Scopes[0].UnreadableFiles);
        Assert.Contains("broken.log.gz", result.Scopes[0].UnreadableFiles[0]);
    }
}
