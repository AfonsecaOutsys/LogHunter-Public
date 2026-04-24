using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LogHunter.Services;

[SupportedOSPlatform("windows")]
internal static class StartupModeDialog
{
    private const string ConfigFileName = "startup-mode.json";

    public enum Mode { Web, Console }

    public static bool TrySavedMode(out Mode mode)
    {
        mode = Mode.Web;
        var path = GetConfigPath();
        try
        {
            if (!File.Exists(path))
                return false;

            var json = File.ReadAllText(path);
            var cfg = JsonSerializer.Deserialize<StartupModeConfig>(json);
            if (cfg is null || string.IsNullOrWhiteSpace(cfg.Mode))
                return false;

            mode = string.Equals(cfg.Mode, "console", StringComparison.OrdinalIgnoreCase)
                ? Mode.Console
                : Mode.Web;
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static void SaveMode(Mode mode)
    {
        var path = GetConfigPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var json = JsonSerializer.Serialize(new StartupModeConfig(mode == Mode.Console ? "console" : "web"),
            new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, json);
    }

    public static void ClearSavedMode()
    {
        var path = GetConfigPath();
        if (File.Exists(path))
            File.Delete(path);
    }

    public static Mode ShowDialog()
    {
        const int IDWEB = 1000;
        const int IDCONSOLE = 1001;
        return ShowTaskDialog(IDWEB, IDCONSOLE);
    }

    private static Mode ShowTaskDialog(int IDWEB, int IDCONSOLE)
    {
        var buttonSize = Marshal.SizeOf<TASKDIALOG_BUTTON>();
        var buttonsPtr = Marshal.AllocHGlobal(buttonSize * 2);
        var strWeb = Marshal.StringToHGlobalUni("Web Mode\nOpen the browser-based UI on 127.0.0.1");
        var strConsole = Marshal.StringToHGlobalUni("Console Mode\nClassic console menu in the terminal");
        try
        {
            var btn1 = new TASKDIALOG_BUTTON { nButtonID = IDWEB, pszButtonText = strWeb };
            var btn2 = new TASKDIALOG_BUTTON { nButtonID = IDCONSOLE, pszButtonText = strConsole };
            Marshal.StructureToPtr(btn1, buttonsPtr, false);
            Marshal.StructureToPtr(btn2, buttonsPtr + buttonSize, false);

            var config = new TASKDIALOGCONFIG
            {
                cbSize = (uint)Marshal.SizeOf<TASKDIALOGCONFIG>(),
                dwFlags = TDF_USE_COMMAND_LINKS | TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT,
                pszWindowTitle = "LogHunter",
                pszMainInstruction = "Choose startup mode",
                pszContent = "How would you like to run LogHunter?",
                pButtons = buttonsPtr,
                cButtons = 2,
                pszVerificationText = "Remember my choice",
                nDefaultButton = IDWEB
            };

            var hr = TaskDialogIndirect(ref config, out var buttonPressed, out _, out var verificationChecked);
            if (hr != 0 || (buttonPressed != IDWEB && buttonPressed != IDCONSOLE))
                return Mode.Web;

            var selected = buttonPressed == IDCONSOLE ? Mode.Console : Mode.Web;

            if (verificationChecked)
                SaveMode(selected);

            return selected;
        }
        finally
        {
            Marshal.FreeHGlobal(strWeb);
            Marshal.FreeHGlobal(strConsole);
            Marshal.FreeHGlobal(buttonsPtr);
        }
    }

    private static string GetConfigPath()
        => Path.Combine(AppFolders.Config, ConfigFileName);

    // --- TaskDialog P/Invoke ---

    private const uint TDF_USE_COMMAND_LINKS = 0x0010;
    private const uint TDF_ALLOW_DIALOG_CANCELLATION = 0x0008;
    private const uint TDF_SIZE_TO_CONTENT = 0x01000000;

    [DllImport("comctl32.dll", CharSet = CharSet.Unicode)]
    private static extern int TaskDialogIndirect(
        ref TASKDIALOGCONFIG pTaskConfig,
        out int pnButton,
        out int pnRadioButton,
        [MarshalAs(UnmanagedType.Bool)] out bool pfVerificationFlagChecked);

    // --- TaskDialog structs (Pack=1 matches native pshpack1.h) ---

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    private struct TASKDIALOGCONFIG
    {
        public uint cbSize;
        public IntPtr hwndParent;
        public IntPtr hInstance;
        public uint dwFlags;
        public uint dwCommonButtons;
        [MarshalAs(UnmanagedType.LPWStr)] public string pszWindowTitle;
        public IntPtr hMainIcon;
        [MarshalAs(UnmanagedType.LPWStr)] public string pszMainInstruction;
        [MarshalAs(UnmanagedType.LPWStr)] public string pszContent;
        public uint cButtons;
        public IntPtr pButtons;
        public int nDefaultButton;
        public uint cRadioButtons;
        public IntPtr pRadioButtons;
        public int nDefaultRadioButton;
        [MarshalAs(UnmanagedType.LPWStr)] public string pszVerificationText;
        [MarshalAs(UnmanagedType.LPWStr)] public string pszExpandedInformation;
        [MarshalAs(UnmanagedType.LPWStr)] public string pszExpandedControlText;
        [MarshalAs(UnmanagedType.LPWStr)] public string pszCollapsedControlText;
        public IntPtr hFooterIcon;
        [MarshalAs(UnmanagedType.LPWStr)] public string pszFooter;
        public IntPtr pfCallback;
        public IntPtr lpCallbackData;
        public uint cxWidth;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct TASKDIALOG_BUTTON
    {
        public int nButtonID;
        public IntPtr pszButtonText;
    }

    private sealed record StartupModeConfig(
        [property: JsonPropertyName("mode")] string? Mode);
}
