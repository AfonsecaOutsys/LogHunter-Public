using ClosedXML.Excel;
using LogHunter.Services;
using LogHunter.Utils;
using Xunit;

namespace LogHunter.Tests.Services;

public sealed class IocSweepReportTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lh-ioc-report-" + Guid.NewGuid().ToString("N"));

    public IocSweepReportTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static IocSweepResult BuildResult()
    {
        IpTargetParser.TryParse("203.0.113.0/24", out var cidr);
        IpTargetParser.TryParse("192.0.2.1", out var single);
        var hit = new IocSweepTargetResult(cidr);
        hit.Record("203.0.113.7", new DateTime(2026, 11, 9, 10, 0, 0, DateTimeKind.Utc), "/<script>alert(1)</script>", "403", "Prod ALB");
        hit.Record("203.0.113.8", new DateTime(2026, 11, 9, 11, 0, 0, DateTimeKind.Utc), "=cmd|' /C calc'!A0", "200", "Prod ALB");
        var miss = new IocSweepTargetResult(single);
        var scope = new IocSweepSourceScope("Prod ALB") { FilesRead = 2, AlbFiles = 2, LinesRead = 10, RecordsParsed = 9, ParseFailures = 1 };
        scope.UnreadableFiles.Add(@"C:\secret\customer\broken.log.gz (InvalidDataException: bad)");
        return new IocSweepResult(new[] { hit, miss }, new[] { scope }, new[] { "bogus" }, DateTime.UtcNow, DateTime.UtcNow);
    }

    [Fact]
    public void WriteHtml_Result_EncodesLogContentAndOmitsFilePaths()
    {
        // Arrange
        var path = Path.Combine(_dir, "r.html");

        // Act
        IocSweepReport.WriteHtml(BuildResult(), path);
        var html = File.ReadAllText(path);

        // Assert
        Assert.Contains("203.0.113.0/24", html);
        Assert.Contains("192.0.2.1", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.DoesNotContain("<script>alert", html);
        Assert.DoesNotContain(@"C:\secret", html);
        Assert.Contains("bogus", html);
        Assert.Contains("connecting IP", html);
    }

    [Fact]
    public void WriteExcel_Result_WritesSheetsAndFormulaTextAsLiteral()
    {
        // Arrange
        var path = Path.Combine(_dir, "r.xlsx");

        // Act
        IocSweepReport.WriteExcel(BuildResult(), path);
        using var wb = new XLWorkbook(path);

        // Assert
        Assert.Equal(new[] { "Targets", "Matched IPs", "Paths", "Scope", "Notes" }, wb.Worksheets.Select(w => w.Name));
        var paths = wb.Worksheet("Paths");
        var formulaCell = paths.CellsUsed().First(c => c.GetString().StartsWith("=cmd"));
        Assert.False(formulaCell.HasFormula);
        Assert.Equal("broken.log.gz (InvalidDataException: bad)", wb.Worksheet("Scope").Cell(2, 9).GetString());
        Assert.Equal(2, wb.Worksheet("Targets").Cell(2, 4).GetValue<long>());
    }

    [Fact]
    public void Reports_CdnEdgeHit_CarriesNetworkLabel()
    {
        // Arrange: 35.191.0.0/16 is a built-in Google Cloud load balancer range.
        IpTargetParser.TryParse("35.191.0.0/24", out var cidr);
        var hit = new IocSweepTargetResult(cidr);
        hit.Record("35.191.0.9", DateTime.UtcNow, "/", "200", "Prod ALB");
        var result = new IocSweepResult(new[] { hit }, new[] { new IocSweepSourceScope("Prod ALB") }, Array.Empty<string>(), DateTime.UtcNow, DateTime.UtcNow);
        var html = Path.Combine(_dir, "cdn.html");
        var xlsx = Path.Combine(_dir, "cdn.xlsx");

        // Act
        IocSweepReport.WriteHtml(result, html);
        IocSweepReport.WriteExcel(result, xlsx);
        using var wb = new XLWorkbook(xlsx);

        // Assert
        Assert.Contains("35.191.0.9 [Google Cloud LB edge]", File.ReadAllText(html));
        Assert.Equal("Google Cloud LB edge", wb.Worksheet("Targets").Cell(2, 3).GetString());
        Assert.Equal("Google Cloud LB edge", wb.Worksheet("Matched IPs").Cell(2, 3).GetString());
    }

    [Theory]
    [InlineData("203.0.113.7", "IP")]
    [InlineData("203.0.113.0/24", "CIDR")]
    [InlineData("203.0.113.1-203.0.113.9", "Range")]
    public void TargetKind_Targets_ReturnsKind(string text, string expected)
    {
        // Arrange
        IpTargetParser.TryParse(text, out var target);

        // Act
        var kind = IocSweepReport.TargetKind(target);

        // Assert
        Assert.Equal(expected, kind);
    }
}
