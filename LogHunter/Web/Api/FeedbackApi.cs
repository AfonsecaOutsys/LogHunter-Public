using System;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using LogHunter.Services;

namespace LogHunter.Web.Api;

/// <summary>POST /api/feedback { area, description }. Bodies are not traced: the description is free text.</summary>
internal static class FeedbackApi
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static async Task<bool> TryHandleAsync(HttpListenerContext context)
    {
        var path = context.Request.Url?.AbsolutePath ?? "/";
        if (!string.Equals(path, "/api/feedback", StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(context.Response, new { ok = false, message = "Method not allowed" }, HttpStatusCode.MethodNotAllowed).ConfigureAwait(false);
            return true;
        }

        FeedbackRequest? body;
        try
        {
            using var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding ?? Encoding.UTF8);
            body = JsonSerializer.Deserialize<FeedbackRequest>(await reader.ReadToEndAsync().ConfigureAwait(false), JsonOptions);
        }
        catch (JsonException)
        {
            body = null;
        }

        var result = await FeedbackSender.SendAsync(body?.Area, body?.Description).ConfigureAwait(false);
        await WriteJsonAsync(context.Response, new { ok = result.Ok, message = result.Message }, HttpStatusCode.OK).ConfigureAwait(false);
        return true;
    }

    private static async Task WriteJsonAsync(HttpListenerResponse response, object payload, HttpStatusCode statusCode)
    {
        var data = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload, JsonOptions));
        response.StatusCode = (int)statusCode;
        response.ContentType = "application/json; charset=utf-8";
        response.ContentLength64 = data.Length;
        await using var stream = response.OutputStream;
        await stream.WriteAsync(data).ConfigureAwait(false);
    }

    private sealed record FeedbackRequest(string? Area, string? Description);
}
