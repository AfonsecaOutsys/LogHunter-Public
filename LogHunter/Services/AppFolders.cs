using System;
using System.IO;

namespace LogHunter.Services;

public static class AppFolders
{
    // Next to the running EXE (stable for Debug/Release/publish/single-file) unless --root moves the
    // workspace. Properties, not readonly fields: fields froze on first touch and ignored --root.
    private static string s_base = Path.GetFullPath(AppContext.BaseDirectory);

    public static string Base => s_base;
    public static string Config => Path.Combine(Base, "config");

    public static string ALB => Path.Combine(Base, "ALB");
    public static string ALBConfigs => Path.Combine(ALB, "configs");

    public static string IIS => Path.Combine(Base, "IIS");
    public static string PlatformLogs => Path.Combine(Base, "PlatformLogs");
    public static string Output => Path.Combine(Base, "output");
    public static string WebTemp => Path.Combine(Base, "web-temp");
    public static string WebAlbOption2Staging => Path.Combine(WebTemp, "alb-option2");
    public static string Logs => Path.Combine(Base, "logs");

    // Shared static assets (JS/CSS/etc) used by HTML reports.
    // Now under: ALB\configs\_assets
    public static string Assets => Path.Combine(ALBConfigs, "_assets");

    /// <summary>Moves the workspace to <paramref name="root"/>. Program calls this before any folder is used.</summary>
    public static void UseRoot(string root) => s_base = Path.GetFullPath(root);

    public static void Ensure()
    {
        Directory.CreateDirectory(Config);
        Directory.CreateDirectory(ALB);
        Directory.CreateDirectory(ALBConfigs);

        Directory.CreateDirectory(IIS);
        Directory.CreateDirectory(PlatformLogs);
        Directory.CreateDirectory(Output);
        Directory.CreateDirectory(WebTemp);
        Directory.CreateDirectory(WebAlbOption2Staging);

        Directory.CreateDirectory(Assets);
    }
}
