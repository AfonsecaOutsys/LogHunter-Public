using LogHunter.Menus;
using LogHunter.Services;
using LogHunter.Viewer;
using LogHunter.Web.Hosting;
using Microsoft.Data.Sqlite;
using Spectre.Console;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Json;

namespace LogHunter;

sealed class BellDetectingWriter : TextWriter
{
    private readonly TextWriter _inner;
    public BellDetectingWriter(TextWriter inner) => _inner = inner;

    public override Encoding Encoding => _inner.Encoding;

    public override void Write(char value)
    {
        if (value == '\a') Debugger.Break();
        _inner.Write(value);
    }

    public override void Write(string? value)
    {
        if (value is not null && value.IndexOf('\a') >= 0) Debugger.Break();
        _inner.Write(value);
    }

    public override void WriteLine(string? value)
    {
        if (value is not null && value.IndexOf('\a') >= 0) Debugger.Break();
        _inner.WriteLine(value);
    }
}

internal static class Program
{
    private static volatile bool _ctrlCRequested;
    private const bool DefaultToWebMode = false;

    private static async Task Main(string[] args)
    {
        var version = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion
            ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString()
            ?? "unknown";

        string? rootOverride = null;
        string? viewerSqlitePath = null;
        string? viewerIp = null;
        string? albDownloadJobPath = null;
        var consoleMode = !DefaultToWebMode;
        var launchBrowser = true;

        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];

            if (a is "--version" or "-v")
            {
                Console.WriteLine(version);
                return;
            }

            if (a is "--help" or "-h" or "/?")
            {
                ShowHelp(version);
                return;
            }

            if (a == "--root")
            {
                if (i + 1 >= args.Length)
                {
                    Console.WriteLine("Missing value for --root");
                    Console.WriteLine();
                    ShowHelp(version);
                    return;
                }

                rootOverride = args[++i];
                continue;
            }

            if (a == "--web")
            {
                consoleMode = false;
                continue;
            }

            if (a == "--console")
            {
                consoleMode = true;
                continue;
            }

            if (a == "--no-browser")
            {
                launchBrowser = false;
                continue;
            }

            if (a == "--viewer-sqlite")
            {
                if (i + 1 >= args.Length)
                {
                    Console.WriteLine("Missing value for --viewer-sqlite");
                    Console.WriteLine();
                    ShowHelp(version);
                    return;
                }

                viewerSqlitePath = args[++i];
                continue;
            }

            if (a == "--viewer-ip")
            {
                if (i + 1 >= args.Length)
                {
                    Console.WriteLine("Missing value for --viewer-ip");
                    Console.WriteLine();
                    ShowHelp(version);
                    return;
                }

                viewerIp = args[++i];
                continue;
            }

            if (a == "--run-alb-download-job")
            {
                if (i + 1 >= args.Length)
                {
                    Console.WriteLine("Missing value for --run-alb-download-job");
                    return;
                }

                albDownloadJobPath = args[++i];
                continue;
            }

            Console.WriteLine($"Unknown argument: {a}");
            Console.WriteLine();
            ShowHelp(version);
            return;
        }

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            _ctrlCRequested = true;
        };

        try
        {
            Console.SetOut(new BellDetectingWriter(Console.Out));
            Console.SetError(new BellDetectingWriter(Console.Error));

            var root = string.IsNullOrWhiteSpace(rootOverride)
                ? AppContext.BaseDirectory
                : Path.GetFullPath(rootOverride);

            if (!string.IsNullOrWhiteSpace(albDownloadJobPath))
            {
                await RunAlbDownloadJobAsync(albDownloadJobPath).ConfigureAwait(false);
                return;
            }

            if (!string.IsNullOrWhiteSpace(viewerSqlitePath))
            {
                if (TryDetectViewerKind(viewerSqlitePath, out var viewerKind))
                {
                    if (viewerKind == "iis")
                    {
                        using var viewerHost = new IisIpSummarySqliteViewerHost(viewerSqlitePath, viewerIp);
                        await viewerHost.RunAsync(() => _ctrlCRequested).ConfigureAwait(false);
                    }
                    else
                    {
                        using var viewerHost = new AlbIpSummarySqliteViewerHost(viewerSqlitePath, viewerIp);
                        await viewerHost.RunAsync(() => _ctrlCRequested).ConfigureAwait(false);
                    }
                }
                else
                {
                    Console.WriteLine("Unable to determine viewer type for the SQLite file.");
                }

                return;
            }

            AppFolders.Ensure();
            EmbeddedAssets.EnsureTabulatorAssets(root);

            var session = new SessionState(root);

            if (!consoleMode)
            {
                using var webHost = new WebAppHost(new WebAppContext("LogHunter", version, root, session));
                await webHost.RunAsync(() => _ctrlCRequested, launchBrowser).ConfigureAwait(false);
                return;
            }

            var asm = Assembly.GetExecutingAssembly();
            var all = asm.GetManifestResourceNames();

            AnsiConsole.MarkupLine("[yellow]Embedded resources containing 'tabulator':[/]");
            var hits = all.Where(n => n.Contains("tabulator", StringComparison.OrdinalIgnoreCase)).ToList();
            if (hits.Count == 0)
            {
                AnsiConsole.MarkupLine("  [red](none found)[/]");
            }
            else
            {
                foreach (var n in hits)
                    AnsiConsole.MarkupLine("  [dim]" + Markup.Escape(n) + "[/]");
            }
            AnsiConsole.WriteLine();

            AnsiConsole.MarkupLine($"[bold]LogHunter[/] [dim]{version}[/]");
            AnsiConsole.MarkupLine($"[dim]Workspace:[/] {Markup.Escape(root)}");
            AnsiConsole.MarkupLine("[dim]Tip:[/] Ctrl+C to exit");

            IMenu? menu = new MainMenu(session);
            while (menu is not null && !_ctrlCRequested)
                menu = await menu.ShowAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            try
            {
                AnsiConsole.MarkupLine("[red]Unhandled error[/]");
                AnsiConsole.WriteException(ex, ExceptionFormats.ShortenEverything);
            }
            catch
            {
                Console.WriteLine("Unhandled error:");
                Console.WriteLine(ex);
            }
        }
    }

    private static void ShowHelp(string version)
    {
        Console.WriteLine($"LogHunter {version}");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  LogHunter [--root <path>] [--web] [--console] [--no-browser] [--viewer-sqlite <path> --viewer-ip <ip>] [--version] [--help]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --root <path>           Workspace path (defaults to the exe folder)");
        Console.WriteLine("  --console               Start the legacy console menu");
        Console.WriteLine("  --web                   Explicitly start the local web shell on 127.0.0.1");
        Console.WriteLine("  --no-browser            In web mode, do not auto-open the default browser");
        Console.WriteLine("  --viewer-sqlite <path>  Start the SQLite viewer for the specified database");
        Console.WriteLine("  --viewer-ip <ip>        Optional selected IP shown in viewer metadata");
        Console.WriteLine("  --version, -v           Print version and exit");
        Console.WriteLine("  --help, -h              Show this help");
    }

    private static bool TryDetectViewerKind(string dbPath, out string kind)
    {
        kind = "alb";

        try
        {
            using var connection = new SqliteConnection($"Data Source={Path.GetFullPath(dbPath)};Mode=ReadOnly");
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "PRAGMA table_info(Hits);";
            using var reader = cmd.ExecuteReader();

            var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            while (reader.Read())
            {
                if (!reader.IsDBNull(1))
                    columns.Add(reader.GetString(1));
            }

            if (columns.Contains("ScStatusCode"))
            {
                kind = "iis";
                return true;
            }

            if (columns.Contains("ElbResponseCode"))
            {
                kind = "alb";
                return true;
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    private static async Task RunAlbDownloadJobAsync(string requestFilePath)
    {
        try
        {
            if (!File.Exists(requestFilePath))
            {
                Console.Error.WriteLine($"ALB download job request file was not found: {requestFilePath}");
                Environment.ExitCode = 1;
                return;
            }

            var json = await File.ReadAllTextAsync(requestFilePath).ConfigureAwait(false);
            var request = JsonSerializer.Deserialize<AlbDownloadRequest>(json);
            if (request is null)
            {
                Console.Error.WriteLine("ALB download job request file was invalid.");
                Environment.ExitCode = 1;
                return;
            }

            var result = await AlbDownload.RunDownloadAsync(
                request,
                progress =>
                {
                    Console.WriteLine("__LHJOB_PROGRESS__" + JsonSerializer.Serialize(progress));
                }).ConfigureAwait(false);

            Console.WriteLine(result.Success ? "ALB download completed." : $"ALB download failed: {result.Message}");
            Console.WriteLine("__LHJOB_RESULT__" + JsonSerializer.Serialize(result));
            Environment.ExitCode = result.Success ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.ToString());
            Environment.ExitCode = 1;
        }
    }
}
