using System;
using LogHunter.Services;
using LogHunter.Web.Orchestration;

namespace LogHunter.Web.Hosting;

internal sealed class WebAppContext
{
    public WebAppContext(string appName, string version, string rootPath, SessionState session)
    {
        AppName = appName;
        Version = version;
        RootPath = rootPath;
        Session = session;
        StartedUtc = DateTime.UtcNow;
        AlbDownloads = new AlbDownloadJobManager(rootPath, Directory.GetCurrentDirectory());
        AlbTopIps = new AlbTopIpsJobManager(rootPath);
        AlbTopIpsStaging = new AlbTopIpsStagingManager(AppFolders.WebAlbOption2Staging);
        AlbIpSummary = new AlbIpSummaryJobManager();
        Alb5xxMismatch = new AlbGenericScanJobManager();
        AlbTop50Ips = new AlbGenericScanJobManager();
        AlbTop50IpUri = new AlbGenericScanJobManager();
        AlbTop50AvgDuration = new AlbGenericScanJobManager();
        AlbRequestsPerIp5Min = new AlbGenericScanJobManager();
        AlbWafBlockedSummary = new AlbGenericScanJobManager();
        AlbWafBlockedChart = new AlbGenericScanJobManager();
        IisIpSummary = new IisIpSummaryJobManager();
        IisStatusPivot = new IisStatusPivotJobManager();
        IisBurstPatterns = new IisBurstPatternsJobManager();
        IisBytesIntel = new IisBytesIntelJobManager();
    }

    public string AppName { get; }

    public string Version { get; }

    public string RootPath { get; }

    public SessionState Session { get; }

    public DateTime StartedUtc { get; }

    public AlbDownloadJobManager AlbDownloads { get; }
    public AlbTopIpsJobManager AlbTopIps { get; }
    public AlbTopIpsStagingManager AlbTopIpsStaging { get; }
    public AlbIpSummaryJobManager AlbIpSummary { get; }
    public AlbGenericScanJobManager Alb5xxMismatch { get; }
    public AlbGenericScanJobManager AlbTop50Ips { get; }
    public AlbGenericScanJobManager AlbTop50IpUri { get; }
    public AlbGenericScanJobManager AlbTop50AvgDuration { get; }
    public AlbGenericScanJobManager AlbRequestsPerIp5Min { get; }
    public AlbGenericScanJobManager AlbWafBlockedSummary { get; }
    public AlbGenericScanJobManager AlbWafBlockedChart { get; }
    public IisIpSummaryJobManager IisIpSummary { get; }
    public IisStatusPivotJobManager IisStatusPivot { get; }
    public IisBurstPatternsJobManager IisBurstPatterns { get; }
    public IisBytesIntelJobManager IisBytesIntel { get; }
}
