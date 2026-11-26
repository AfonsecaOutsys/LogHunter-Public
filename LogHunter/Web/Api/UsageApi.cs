using System;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using LogHunter.Services;

namespace LogHunter.Web.Api;

/// <summary>GET / POST /api/usage/settings { enabled }: the usage-counts toggle on the Feedback page.</summary>
internal static class UsageApi
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static async Task<bool> TryHandleAsync(HttpListenerContext context)
    {
        var path = context.Request.Url?.AbsolutePath ?? "/";
        if (!string.Equals(path, "/api/usage/settings", StringComparison.OrdinalIgnoreCase))
            return false;

        if (string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
        {
            UsageSettingsRequest? body = null;
            try
            {
                using var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding ?? Encoding.UTF8);
                body = JsonSerializer.Deserialize<UsageSettingsRequest>(await reader.ReadToEndAsync().ConfigureAwait(false), JsonOptions);
            }
            catch (JsonException)
            {
                // Treated as a bad request below.
            }

            if (body?.Enabled is not { } enabled)
            {
                await WriteJsonAsync(context.Response, new { ok = false }, HttpStatusCode.BadRequest).ConfigureAwait(false);
                return true;
            }

            UsageReporter.SetUserEnabled(enabled);
        }

        await WriteJsonAsync(context.Response, new { available = UsageReporter.IsAvailable, enabled = UsageReporter.IsEnabled }, HttpStatusCode.OK).ConfigureAwait(false);
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

    private sealed record UsageSettingsRequest(bool? Enabled);
}
