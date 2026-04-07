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
    public IisIpSummaryJobManager IisIpSummary { get; }
    public IisStatusPivotJobManager IisStatusPivot { get; }
    public IisBurstPatternsJobManager IisBurstPatterns { get; }
    public IisBytesIntelJobManager IisBytesIntel { get; }
}
