using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using LogHunter.Services;
using LogHunter.Utils;
using LogHunter.Web.Hosting;
using LogHunter.Web.Orchestration;

namespace LogHunter.Web.Api;

internal static class IocSweepApi
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static async Task<bool> TryHandleAsync(WebAppContext app, HttpListenerContext context)
    {
        var path = context.Request.Url?.AbsolutePath ?? "/";
        if (!path.StartsWith("/api/ip-sweep/", StringComparison.OrdinalIgnoreCase))
            return false;

        var action = path["/api/ip-sweep/".Length..].ToLowerInvariant();
        if (action == "job")
        {
            await WriteJsonAsync(context.Response, app.IocSweep.GetSnapshot()).ConfigureAwait(false);
            return true;
        }

        if (action == "meta")
        {
            await WriteJsonAsync(context.Response, new
            {
                defaultSources = DefaultSources(),
                maxSources = IocSweepJobManager.MaxSources,
                currentJob = app.IocSweep.GetSnapshot()
            }).ConfigureAwait(false);
            return true;
        }

        if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
        {
            await WriteTextAsync(context.Response, HttpStatusCode.MethodNotAllowed, "Method not allowed", "text/plain; charset=utf-8").ConfigureAwait(false);
            return true;
        }

        switch (action)
        {
            case "run":
                await HandleRunAsync(app, context).ConfigureAwait(false);
                return true;
            case "browse-folder":
                await HandleBrowseFolderAsync(context).ConfigureAwait(false);
                return true;
            case "open-report":
                await WriteOpenResultAsync(context, app.IocSweep.TryOpenReport(out var reportMessage), reportMessage).ConfigureAwait(false);
                return true;
            case "open-export":
                await WriteOpenResultAsync(context, app.IocSweep.TryOpenExport(out var exportMessage), exportMessage).ConfigureAwait(false);
                return true;
            default:
                await WriteJsonAsync(context.Response, new { ok = false, error = "Unknown action." }, HttpStatusCode.NotFound).ConfigureAwait(false);
                return true;
        }
    }

    // Workspace ALB and IIS folders are offered when they contain logs.
    private static object[] DefaultSources()
    {
        var list = new List<object>();
        foreach (var (label, folder) in new[] { ("ALB", AppFolders.ALB), ("IIS", AppFolders.IIS) })
        {
            if (!Directory.Exists(folder)) continue;
            var count = IisW3cReader.EnumerateLogFiles(folder).Count;
            if (count > 0) list.Add(new { label, path = folder, files = count });
        }

        return list.ToArray();
    }

    private static async Task HandleRunAsync(WebAppContext app, HttpListenerContext context)
    {
        IocSweepRunRequest? body;
        try
        {
            body = await ReadJsonAsync<IocSweepRunRequest>(context.Request).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await WriteJsonAsync(context.Response, new { ok = false, error = ex.Message }, HttpStatusCode.BadRequest).ConfigureAwait(false);
            return;
        }

        var sources = (body?.Sources ?? Array.Empty<IocSweepSourceRequest>()).ToList();
        if (!app.IocSweep.TryStart(body?.Targets, sources, out var snapshot, out var error))
        {
            await WriteJsonAsync(context.Response, new { ok = false, error, snapshot }, HttpStatusCode.BadRequest).ConfigureAwait(false);
            return;
        }

        await WriteJsonAsync(context.Response, new { ok = true, snapshot }).ConfigureAwait(false);
    }

    private static async Task HandleBrowseFolderAsync(HttpListenerContext context)
    {
        var folderPath = await NativeFileDialogHelper.BrowseFolderAsync(AppFolders.ALB).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(folderPath))
        {
            await WriteJsonAsync(context.Response, new { ok = false, cancelled = true }).ConfigureAwait(false);
            return;
        }

        var files = IisW3cReader.EnumerateLogFiles(folderPath).Count;
        var label = Path.GetFileName(folderPath.TrimEnd('\\', '/'));
        await WriteJsonAsync(context.Response, new { ok = true, source = new { label, path = folderPath, files } }).ConfigureAwait(false);
    }

    private static Task WriteOpenResultAsync(HttpListenerContext context, bool ok, string message)
        => WriteJsonAsync(context.Response, new { ok, message }, ok ? HttpStatusCode.OK : HttpStatusCode.BadRequest);

    private static async Task<T?> ReadJsonAsync<T>(HttpListenerRequest request)
    {
        using var reader = new StreamReader(request.InputStream, request.ContentEncoding ?? Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: false);
        var json = await reader.ReadToEndAsync().ConfigureAwait(false);
        TraceLog.WriteBody("http", "request-body", json);
        return string.IsNullOrWhiteSpace(json) ? default : JsonSerializer.Deserialize<T>(json, JsonOptions);
    }

    private static async Task WriteJsonAsync(HttpListenerResponse response, object payload, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        var json = JsonSerializer.Serialize(payload, JsonOptions);
        TraceLog.WriteBody("http", "response-body", json, new { status = (int)statusCode });
        await WriteTextAsync(response, statusCode, json, "application/json; charset=utf-8").ConfigureAwait(false);
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

    private sealed record IocSweepRunRequest(string? Targets, IReadOnlyList<IocSweepSourceRequest>? Sources);
}
