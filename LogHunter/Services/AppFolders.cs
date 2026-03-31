using System;
using System.IO;

namespace LogHunter.Services;

public static class AppFolders
{
    // Next to the running EXE (stable for Debug/Release/publish/single-file).
    public static readonly string Base = Path.GetFullPath(AppContext.BaseDirectory);
    public static readonly string Config = Path.Combine(Base, "config");

    public static readonly string ALB = Path.Combine(Base, "ALB");
    public static readonly string ALBConfigs = Path.Combine(ALB, "configs");

    public static readonly string IIS = Path.Combine(Base, "IIS");
    public static readonly string PlatformLogs = Path.Combine(Base, "PlatformLogs");
    public static readonly string Output = Path.Combine(Base, "output");

    // Shared static assets (JS/CSS/etc) used by HTML reports.
    // Now under: ALB\configs\_assets
    public static readonly string Assets = Path.Combine(ALBConfigs, "_assets");

    public static void Ensure()
    {
        Directory.CreateDirectory(Config);
        Directory.CreateDirectory(ALB);
        Directory.CreateDirectory(ALBConfigs);

        Directory.CreateDirectory(IIS);
        Directory.CreateDirectory(PlatformLogs);
        Directory.CreateDirectory(Output);

        Directory.CreateDirectory(Assets);
    }
}
