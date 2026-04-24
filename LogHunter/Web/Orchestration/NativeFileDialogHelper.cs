using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Web.Orchestration;

[SupportedOSPlatform("windows")]
internal static class NativeFileDialogHelper
{
    public static Task<string?> BrowseFolderAsync(string? initialDirectory = null)
    {
        var tcs = new TaskCompletionSource<string?>();
        var thread = new Thread(() =>
        {
            try
            {
                tcs.SetResult(ShowFolderDialog(initialDirectory));
            }
            catch (Exception ex)
            {
                tcs.SetException(ex);
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return tcs.Task;
    }

    public static Task<string?> BrowseSingleFileAsync(string? initialDirectory = null, string? filterName = null, string? filterSpec = null)
    {
        var tcs = new TaskCompletionSource<string?>();
        var thread = new Thread(() =>
        {
            try
            {
                tcs.SetResult(ShowSingleFileDialog(initialDirectory, filterName, filterSpec));
            }
            catch (Exception ex)
            {
                tcs.SetException(ex);
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return tcs.Task;
    }

    public static Task<IReadOnlyList<string>> BrowseFilesAsync(string? initialDirectory = null)
    {
        var tcs = new TaskCompletionSource<IReadOnlyList<string>>();
        var thread = new Thread(() =>
        {
            try
            {
                tcs.SetResult(ShowFilesDialog(initialDirectory));
            }
            catch (Exception ex)
            {
                tcs.SetException(ex);
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return tcs.Task;
    }

    private static string? ShowFolderDialog(string? initialDirectory)
    {
        var owner = GetForegroundWindow();
        var dialog = (IFileOpenDialog)new FileOpenDialogCoClass();
        try
        {
            dialog.GetOptions(out var options);
            dialog.SetOptions(options | FOS.FOS_PICKFOLDERS | FOS.FOS_FORCEFILESYSTEM);
            dialog.SetTitle("Select a folder containing ALB log files");

            if (!string.IsNullOrWhiteSpace(initialDirectory))
                SetInitialDirectory(dialog, initialDirectory);

            var hr = dialog.Show(owner);
            if (hr != 0)
                return null;

            dialog.GetResult(out var item);
            item.GetDisplayName(SIGDN.SIGDN_FILESYSPATH, out var path);
            return path;
        }
        finally
        {
            Marshal.ReleaseComObject(dialog);
        }
    }

    private static string? ShowSingleFileDialog(string? initialDirectory, string? filterName, string? filterSpec)
    {
        var owner = GetForegroundWindow();
        var dialog = (IFileOpenDialog)new FileOpenDialogCoClass();
        try
        {
            dialog.GetOptions(out var options);
            dialog.SetOptions(options | FOS.FOS_FORCEFILESYSTEM);
            dialog.SetTitle("Select a file");

            if (!string.IsNullOrWhiteSpace(filterName) && !string.IsNullOrWhiteSpace(filterSpec))
            {
                var filter = new COMDLG_FILTERSPEC { pszName = filterName, pszSpec = filterSpec };
                dialog.SetFileTypes(1, new[] { filter });
            }

            if (!string.IsNullOrWhiteSpace(initialDirectory))
                SetInitialDirectory(dialog, initialDirectory);

            var hr = dialog.Show(owner);
            if (hr != 0)
                return null;

            dialog.GetResult(out var item);
            item.GetDisplayName(SIGDN.SIGDN_FILESYSPATH, out var path);
            return path;
        }
        finally
        {
            Marshal.ReleaseComObject(dialog);
        }
    }

    private static IReadOnlyList<string> ShowFilesDialog(string? initialDirectory)
    {
        var owner = GetForegroundWindow();
        var dialog = (IFileOpenDialog)new FileOpenDialogCoClass();
        try
        {
            dialog.GetOptions(out var options);
            dialog.SetOptions(options | FOS.FOS_ALLOWMULTISELECT | FOS.FOS_FORCEFILESYSTEM);
            dialog.SetTitle("Select ALB log files");

            var filter = new COMDLG_FILTERSPEC
            {
                pszName = "Log files (*.log)",
                pszSpec = "*.log"
            };
            dialog.SetFileTypes(1, new[] { filter });

            if (!string.IsNullOrWhiteSpace(initialDirectory))
                SetInitialDirectory(dialog, initialDirectory);

            var hr = dialog.Show(owner);
            if (hr != 0)
                return Array.Empty<string>();

            dialog.GetResults(out var items);
            items.GetCount(out var count);
            var result = new List<string>((int)count);
            for (uint i = 0; i < count; i++)
            {
                items.GetItemAt(i, out var item);
                item.GetDisplayName(SIGDN.SIGDN_FILESYSPATH, out var path);
                if (!string.IsNullOrWhiteSpace(path))
                    result.Add(path);
            }
            return result;
        }
        finally
        {
            Marshal.ReleaseComObject(dialog);
        }
    }

    private static void SetInitialDirectory(IFileOpenDialog dialog, string path)
    {
        var hr = SHCreateItemFromParsingName(path, IntPtr.Zero, typeof(IShellItem).GUID, out var item);
        if (hr == 0 && item != null)
            dialog.SetFolder(item);
    }

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    private static extern int SHCreateItemFromParsingName(
        string pszPath, IntPtr pbc, [MarshalAs(UnmanagedType.LPStruct)] Guid riid, out IShellItem ppv);

    [ComImport, Guid("DC1C5A9C-E88A-4dde-A5A1-60F82A20AEF7")]
    private class FileOpenDialogCoClass { }

    [ComImport, Guid("d57c7288-d4ad-4768-be02-9d969532d960"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IFileOpenDialog
    {
        [PreserveSig] int Show(IntPtr hwndOwner);
        void SetFileTypes(uint cFileTypes, [MarshalAs(UnmanagedType.LPArray)] COMDLG_FILTERSPEC[] rgFilterSpec);
        void SetFileTypeIndex(uint iFileType);
        void GetFileTypeIndex(out uint piFileType);
        void Advise(IntPtr pfde, out uint pdwCookie);
        void Unadvise(uint dwCookie);
        void SetOptions(FOS fos);
        void GetOptions(out FOS pfos);
        void SetDefaultFolder(IShellItem psi);
        void SetFolder(IShellItem psi);
        void GetFolder(out IShellItem ppsi);
        void GetCurrentSelection(out IShellItem ppsi);
        void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string pszName);
        void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string pszTitle);
        void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string pszText);
        void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string pszLabel);
        void GetResult(out IShellItem ppsi);
        void AddPlace(IShellItem psi, int fdap);
        void SetDefaultExtension([MarshalAs(UnmanagedType.LPWStr)] string pszDefaultExtension);
        void Close(int hr);
        void SetClientGuid([MarshalAs(UnmanagedType.LPStruct)] Guid guid);
        void ClearClientData();
        void SetFilter(IntPtr pFilter);
        void GetResults(out IShellItemArray ppenum);
        void GetSelectedItems(out IShellItemArray ppsai);
    }

    [ComImport, Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItem
    {
        void BindToHandler(IntPtr pbc, [MarshalAs(UnmanagedType.LPStruct)] Guid bhid, [MarshalAs(UnmanagedType.LPStruct)] Guid riid, out IntPtr ppv);
        void GetParent(out IShellItem ppsi);
        void GetDisplayName(SIGDN sigdnName, [MarshalAs(UnmanagedType.LPWStr)] out string ppszName);
        void GetAttributes(uint sfgaoMask, out uint psfgaoAttribs);
        void Compare(IShellItem psi, uint hint, out int piOrder);
    }

    [ComImport, Guid("b63ea76d-1f85-456f-a19c-48159efa858b"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItemArray
    {
        void BindToHandler(IntPtr pbc, [MarshalAs(UnmanagedType.LPStruct)] Guid bhid, [MarshalAs(UnmanagedType.LPStruct)] Guid riid, out IntPtr ppv);
        void GetPropertyStore(int flags, [MarshalAs(UnmanagedType.LPStruct)] Guid riid, out IntPtr ppv);
        void GetPropertyDescriptionList([MarshalAs(UnmanagedType.LPStruct)] Guid keyType, [MarshalAs(UnmanagedType.LPStruct)] Guid riid, out IntPtr ppv);
        void GetAttributes(int dwAttribFlags, uint sfgaoMask, out uint psfgaoAttribs);
        void GetCount(out uint pdwNumItems);
        void GetItemAt(uint dwIndex, out IShellItem ppsi);
        void EnumItems(out IntPtr ppenumShellItems);
    }

    [Flags]
    private enum FOS : uint
    {
        FOS_OVERWRITEPROMPT = 0x2,
        FOS_FORCEFILESYSTEM = 0x40,
        FOS_ALLOWMULTISELECT = 0x200,
        FOS_PICKFOLDERS = 0x20,
        FOS_NOCHANGEDIR = 0x8
    }

    private enum SIGDN : uint
    {
        SIGDN_FILESYSPATH = 0x80058000
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct COMDLG_FILTERSPEC
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string pszName;
        [MarshalAs(UnmanagedType.LPWStr)] public string pszSpec;
    }
}
