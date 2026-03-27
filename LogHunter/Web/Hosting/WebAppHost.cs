using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using LogHunter.Web.Api;
using LogHunter.Web.Pages;

namespace LogHunter.Web.Hosting;

internal sealed class WebAppHost : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

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

        var getContextTask = _listener.GetContextAsync();
        while (!stopRequested())
        {
            HttpListenerContext? context = null;
            try
            {
                var completed = await Task.WhenAny(getContextTask, Task.Delay(500)).ConfigureAwait(false);
                if (completed != getContextTask)
                {
                    continue;
                }

                context = await getContextTask.ConfigureAwait(false);
                getContextTask = _listener.GetContextAsync();
                await HandleAsync(context).ConfigureAwait(false);
            }
            catch (HttpListenerException) when (stopRequested())
            {
                break;
            }
            catch (ObjectDisposedException) when (stopRequested())
            {
                break;
            }
            catch (Exception ex) when (context is not null)
            {
                await WriteTextAsync(context.Response, HttpStatusCode.InternalServerError, ex.ToString(), "text/plain; charset=utf-8").ConfigureAwait(false);
            }
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

        if (TryServeAsset(path, context.Response))
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

    private static bool TryServeAsset(string path, HttpListenerResponse response)
    {
        string? suffix;
        string? contentType;

        if (string.Equals(path, "/assets/site.css", StringComparison.OrdinalIgnoreCase))
        {
            suffix = ".Web.Assets.site.css";
            contentType = "text/css; charset=utf-8";
        }
        else if (string.Equals(path, "/assets/site.js", StringComparison.OrdinalIgnoreCase))
        {
            suffix = ".Web.Assets.site.js";
            contentType = "application/javascript; charset=utf-8";
        }
        else if (string.Equals(path, "/assets/alb.js", StringComparison.OrdinalIgnoreCase))
        {
            suffix = ".Web.Assets.alb.js";
            contentType = "application/javascript; charset=utf-8";
        }
        else
        {
            return false;
        }

        var body = ReadEmbeddedTextBySuffix(suffix);
        if (body is null)
        {
            return false;
        }

        WriteTextAsync(response, HttpStatusCode.OK, body, contentType).GetAwaiter().GetResult();
        return true;
    }

    private static string? ReadEmbeddedTextBySuffix(string suffix)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = assembly.GetManifestResourceNames()
            .FirstOrDefault(name => name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase));

        if (resourceName is null)
        {
            return null;
        }

        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            return null;
        }

        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
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
