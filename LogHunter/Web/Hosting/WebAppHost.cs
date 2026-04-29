using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Services;
using LogHunter.Web.Api;
using LogHunter.Web.Orchestration;
using LogHunter.Web.Pages;
using Microsoft.Data.Sqlite;

namespace LogHunter.Web.Hosting;

internal sealed class WebAppHost : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static readonly (string Path, string Suffix, string ContentType)[] AssetMap = new[]
    {
        ("/assets/site.css",     ".Web.Assets.site.css",     "text/css; charset=utf-8"),
        ("/assets/site.js",      ".Web.Assets.site.js",      "application/javascript; charset=utf-8"),
        ("/assets/alb.js",       ".Web.Assets.alb.js",       "application/javascript; charset=utf-8"),
        ("/assets/iis.js",       ".Web.Assets.iis.js",       "application/javascript; charset=utf-8"),
        ("/assets/platform.js",  ".Web.Assets.platform.js",  "application/javascript; charset=utf-8"),
        ("/assets/abuseip.js",   ".Web.Assets.abuseip.js",   "application/javascript; charset=utf-8"),
    };

    private static Dictionary<string, (byte[] Body, string ContentType, string ETag)>? s_assetCache;
    private static object? s_assetCacheLock = new();

    private readonly WebAppContext _context;
    private readonly HttpListener _listener = new();
    private readonly int _port;
    private readonly string _baseUrl;

    public WebAppHost(WebAppContext context)
    {
        _context = context;
        _port = GetFreePort();
        _baseUrl = $"http://127.0.0.1:{_port}/";
        _listener.Prefixes.Add(_baseUrl);
    }

    public async Task RunAsync(Func<bool> stopRequested, bool launchBrowser)
    {
        _listener.Start();

        Console.WriteLine($"{_context.AppName} web shell ready");
        Console.WriteLine($"URL: {_baseUrl}");
        Console.WriteLine("Press Ctrl+C to stop the local web server.");

        if (launchBrowser)
        {
            TryOpenBrowser(_baseUrl);
        }

        // Background watcher: when stopRequested flips to true, stop the listener so any
        // in-flight GetContextAsync() awaits unblock with HttpListenerException/ObjectDisposedException.
        using var stopWatcherCts = new CancellationTokenSource();
        var stopWatcher = Task.Run(async () =>
        {
            while (!stopWatcherCts.IsCancellationRequested)
            {
                if (stopRequested())
                {
                    try { _listener.Stop(); } catch { /* listener already stopped/disposed */ }
                    return;
                }
                try
                {
                    await Task.Delay(100, stopWatcherCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        });

        try
        {
            while (!stopRequested())
            {
                HttpListenerContext context;
                try
                {
                    context = await _listener.GetContextAsync().ConfigureAwait(false);
                }
                catch (HttpListenerException) when (stopRequested())
                {
                    break;
                }
                catch (ObjectDisposedException) when (stopRequested())
                {
                    break;
                }

                // Dispatch handling on the thread pool so the accept loop is never blocked
                // by a slow request. Each request is fully isolated.
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await HandleAsync(context).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        try
                        {
                            await WriteTextAsync(context.Response, HttpStatusCode.InternalServerError, ex.ToString(), "text/plain; charset=utf-8").ConfigureAwait(false);
                        }
                        catch
                        {
                            // Response already closed or unwritable; swallow to keep the loop alive.
                        }
                    }
                });
            }
        }
        finally
        {
            stopWatcherCts.Cancel();
            try { await stopWatcher.ConfigureAwait(false); } catch { /* ignore watcher shutdown errors */ }
        }
    }

    public void Dispose()
    {
        if (_listener.IsListening)
        {
            _listener.Stop();
        }

        _listener.Close();
    }

    private async Task HandleAsync(HttpListenerContext context)
    {
        var path = context.Request.Url?.AbsolutePath ?? "/";

        if (string.Equals(path, "/api/app/info", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, BuildAppInfo()).ConfigureAwait(false);
            return;
        }

        if (await AlbApi.TryHandleAsync(_context, context).ConfigureAwait(false))
        {
            return;
        }

        if (await IisApi.TryHandleAsync(_context, context).ConfigureAwait(false))
        {
            return;
        }

        if (await PlatformApi.TryHandleAsync(_context, context).ConfigureAwait(false))
        {
            return;
        }

        if (await AbuseIpApi.TryHandleAsync(_context, context).ConfigureAwait(false))
        {
            return;
        }

        if (string.Equals(path, "/api/viewer/browse-and-launch", StringComparison.OrdinalIgnoreCase))
        {
            await HandleViewerBrowseAndLaunchAsync(context).ConfigureAwait(false);
            return;
        }

        if (await TryServeAssetAsync(path, context.Request, context.Response).ConfigureAwait(false))
        {
            return;
        }

        if (WebShellPageBuilder.TryBuildPage(_context, path, out var html))
        {
            await WriteTextAsync(context.Response, HttpStatusCode.OK, html, "text/html; charset=utf-8").ConfigureAwait(false);
            return;
        }

        if (string.Equals(path, "/favicon.ico", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = (int)HttpStatusCode.NoContent;
            context.Response.Close();
            return;
        }

        await WriteTextAsync(context.Response, HttpStatusCode.NotFound, "Not found", "text/plain; charset=utf-8").ConfigureAwait(false);
    }

    private async Task HandleViewerBrowseAndLaunchAsync(HttpListenerContext context)
    {
        if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
        {
            await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
            return;
        }

        var dbPath = await NativeFileDialogHelper.BrowseSingleFileAsync(null, "SQLite databases (*.db)", "*.db").ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(dbPath))
        {
            await WriteJsonAsync(context.Response, new { ok = false, message = "No file selected." }).ConfigureAwait(false);
            return;
        }

        if (!TryDetectViewerKind(dbPath, out var kind))
        {
            await WriteJsonAsync(context.Response, new { ok = false, message = "Could not detect database type (ALB or IIS)." }).ConfigureAwait(false);
            return;
        }

        var launched = kind == "iis"
            ? IisIpSummarySqliteViewerLauncher.Launch(dbPath, null)
            : AlbIpSummarySqliteViewerLauncher.Launch(dbPath, null);

        if (launched)
            await WriteJsonAsync(context.Response, new { ok = true, message = $"Opened {kind.ToUpperInvariant()} viewer." }).ConfigureAwait(false);
        else
            await WriteJsonAsync(context.Response, new { ok = false, message = "Failed to launch the viewer process." }).ConfigureAwait(false);
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

            if (columns.Contains("ScStatusCode")) { kind = "iis"; return true; }
            if (columns.Contains("ElbResponseCode")) { kind = "alb"; return true; }
        }
        catch { return false; }
        return false;
    }

    private object BuildAppInfo()
    {
        var uptime = DateTime.UtcNow - _context.StartedUtc;
        return new
        {
            appName = _context.AppName,
            version = _context.Version,
            rootPath = _context.RootPath,
            baseUrl = _baseUrl,
            mode = "web",
            status = "ready",
            startedUtc = _context.StartedUtc.ToString("u", CultureInfo.InvariantCulture),
            uptime = uptime.ToString("g", CultureInfo.InvariantCulture),
            savedSelectionsCount = _context.Session.SavedSelections.Count,
            processId = Environment.ProcessId,
            machineName = Environment.MachineName
        };
    }

    private static async Task<bool> TryServeAssetAsync(string path, HttpListenerRequest request, HttpListenerResponse response)
    {
        var cache = LazyInitializer.EnsureInitialized(ref s_assetCache, ref s_assetCacheLock, BuildAssetCache)!;

        if (!cache.TryGetValue(path, out var entry))
        {
            return false;
        }

        response.Headers["Cache-Control"] = "public, max-age=86400, immutable";
        response.Headers["ETag"] = entry.ETag;

        var ifNoneMatch = request.Headers["If-None-Match"];
        if (!string.IsNullOrEmpty(ifNoneMatch) && ifNoneMatch == entry.ETag)
        {
            response.StatusCode = (int)HttpStatusCode.NotModified;
            response.ContentLength64 = 0;
            response.Close();
            return true;
        }

        response.StatusCode = (int)HttpStatusCode.OK;
        response.ContentType = entry.ContentType;
        response.ContentLength64 = entry.Body.Length;
        await response.OutputStream.WriteAsync(entry.Body, 0, entry.Body.Length).ConfigureAwait(false);
        response.Close();
        return true;
    }

    private static Dictionary<string, (byte[] Body, string ContentType, string ETag)> BuildAssetCache()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceNames = assembly.GetManifestResourceNames();
        var dict = new Dictionary<string, (byte[] Body, string ContentType, string ETag)>(StringComparer.OrdinalIgnoreCase);

        foreach (var (path, suffix, contentType) in AssetMap)
        {
            var resourceName = resourceNames.FirstOrDefault(n => n.EndsWith(suffix, StringComparison.OrdinalIgnoreCase));
            if (resourceName is null)
            {
                continue;
            }

            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream is null)
            {
                continue;
            }

            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            var body = ms.ToArray();
            var etag = ComputeETag(body);
            dict[path] = (body, contentType, etag);
        }

        return dict;
    }

    private static string ComputeETag(byte[] body)
    {
        var hash = SHA1.HashData(body);
        var sb = new StringBuilder(2 + 16);
        sb.Append('"');
        for (var i = 0; i < 8 && i < hash.Length; i++)
        {
            sb.Append(hash[i].ToString("x2", CultureInfo.InvariantCulture));
        }
        sb.Append('"');
        return sb.ToString();
    }

    private static async Task WriteJsonAsync(HttpListenerResponse response, object payload)
    {
        var json = JsonSerializer.Serialize(payload, JsonOptions);
        await WriteTextAsync(response, HttpStatusCode.OK, json, "application/json; charset=utf-8").ConfigureAwait(false);
    }

    private static async Task WriteTextAsync(HttpListenerResponse response, HttpStatusCode statusCode, string body, string contentType)
    {
        var data = Encoding.UTF8.GetBytes(body);
        response.StatusCode = (int)statusCode;
        response.ContentType = contentType;
        response.ContentLength64 = data.Length;
        await using var stream = response.OutputStream;
        await stream.WriteAsync(data).ConfigureAwait(false);
    }

    private static bool TryOpenBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static int GetFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}
