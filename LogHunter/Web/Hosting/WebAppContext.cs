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
    }

    public string AppName { get; }

    public string Version { get; }

    public string RootPath { get; }

    public SessionState Session { get; }

    public DateTime StartedUtc { get; }

    public AlbDownloadJobManager AlbDownloads { get; }
}
