using System;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;

namespace LogHunter.Services;

/// <summary>
/// Opt-in trace log (--trace / --debug). Writes one JSON object per line so a session can be replayed afterwards.
/// Every call is a no-op until <see cref="Start"/> runs, and tracing failures never surface to the caller.
/// </summary>
internal static class TraceLog
{
    private const int MaxStringLength = 4000;
    private const int MaxArrayItems = 10;
    private const int ArrayHeadItems = 3;
    private const int ArrayTailItems = 5;
    private const int MaxClientEventsPerBatch = 500;

    private static readonly object Gate = new();
    private static readonly AsyncLocal<long?> CurrentRequestId = new();

    private static readonly JsonSerializerOptions DataOptions = new(JsonSerializerDefaults.Web);
    private static readonly JsonSerializerOptions LineOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static readonly Regex AwsCredentialAssignmentRegex = new(
        @"(AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|SECURITY_TOKEN)[""']?\s*[=:]\s*)\S+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex AwsAccessKeyIdRegex = new(
        @"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static StreamWriter? _writer;
    private static long _sequence;
    private static long _requestSequence;

    public static bool IsEnabled => _writer is not null;

    public static string? FilePath { get; private set; }

    public static void Start(string folder, string version, string[] args)
    {
        Directory.CreateDirectory(folder);
        var path = Path.Combine(folder, $"trace-{DateTime.Now:yyyyMMdd-HHmmss}-{Environment.ProcessId}.jsonl");
        var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);

        lock (Gate)
        {
            _writer = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true };
            FilePath = path;
        }

        Write("app", "start", new
        {
            version,
            args = string.Join(" ", args),
            pid = Environment.ProcessId,
            os = Environment.OSVersion.VersionString,
            machine = Environment.MachineName,
            baseDirectory = AppContext.BaseDirectory,
            traceFile = path
        });
    }

    public static void Stop()
    {
        Write("app", "exit");

        lock (Gate)
        {
            _writer?.Dispose();
            _writer = null;
        }
    }

    public static void Write(string category, string action, object? data = null)
    {
        if (_writer is null)
            return;

        try
        {
            var entry = new JsonObject
            {
                ["ts"] = DateTime.UtcNow.ToString("O"),
                ["seq"] = 0,
                ["cat"] = category,
                ["act"] = action,
                ["tid"] = Environment.CurrentManagedThreadId
            };

            if (CurrentRequestId.Value is long requestId)
                entry["req"] = requestId;

            if (data is not null)
            {
                var node = data as JsonNode ?? JsonSerializer.SerializeToNode(data, DataOptions);
                entry["data"] = Sanitize(node);
            }

            lock (Gate)
            {
                if (_writer is null)
                    return;

                entry["seq"] = ++_sequence;
                _writer.WriteLine(entry.ToJsonString(LineOptions));
            }
        }
        catch
        {
            // Tracing is diagnostic only; it must never break the traced action.
        }
    }

    /// <summary>Writes a JSON (or plain text) request/response body, structured, redacted and size-bounded.</summary>
    public static void WriteBody(string category, string action, string? body, object? meta = null)
    {
        if (_writer is null)
            return;

        try
        {
            var data = meta is null
                ? new JsonObject()
                : JsonSerializer.SerializeToNode(meta, DataOptions) as JsonObject ?? new JsonObject();

            data["body"] = ParseBody(body);
            Write(category, action, data);
        }
        catch
        {
            // Tracing is diagnostic only; it must never break the traced action.
        }
    }

    /// <summary>Starts a traced HTTP request and tags later entries in the same async flow with its id. Returns 0 when not traced.</summary>
    public static long BeginRequest(HttpListenerRequest request)
    {
        if (_writer is null)
            return 0;

        var path = request.Url?.AbsolutePath ?? "/";
        if (string.Equals(path, "/api/trace", StringComparison.OrdinalIgnoreCase))
            return 0;

        var requestId = Interlocked.Increment(ref _requestSequence);
        CurrentRequestId.Value = requestId;
        Write("http", "begin", new { method = request.HttpMethod, path, query = request.Url?.Query });
        return requestId;
    }

    public static void EndRequest(long requestId, HttpListenerResponse response, long elapsedMilliseconds)
    {
        if (requestId == 0)
            return;

        int status;
        try { status = response.StatusCode; }
        catch { status = 0; }

        Write("http", "end", new { status, ms = elapsedMilliseconds });
    }

    /// <summary>Stops tagging entries with the current request id, for work that outlives the request (background jobs).</summary>
    public static void DetachRequest() => CurrentRequestId.Value = null;

    /// <summary>Writes a batch of browser events posted to /api/trace as { events: [{ event, ts, page, data }] }.</summary>
    public static void WriteClientEvents(string? body)
    {
        if (_writer is null || string.IsNullOrWhiteSpace(body))
            return;

        try
        {
            if (JsonNode.Parse(body)?["events"] is not JsonArray events)
                return;

            var count = 0;
            foreach (var item in events)
            {
                if (item is not JsonObject clientEvent || ++count > MaxClientEventsPerBatch)
                    break;

                var name = clientEvent["event"]?.GetValue<string>() ?? "event";
                Write("client", name, new JsonObject
                {
                    ["clientTs"] = clientEvent["ts"]?.DeepClone(),
                    ["page"] = clientEvent["page"]?.DeepClone(),
                    ["data"] = clientEvent["data"]?.DeepClone()
                });
            }
        }
        catch
        {
            // Tracing is diagnostic only; malformed client batches are dropped.
        }
    }

    public static string RedactText(string text)
    {
        var redacted = AwsCredentialAssignmentRegex.Replace(text, "$1[redacted]");
        return AwsAccessKeyIdRegex.Replace(redacted, "[redacted-key-id]");
    }

    private static JsonNode? ParseBody(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return null;

        try
        {
            return JsonNode.Parse(body);
        }
        catch (JsonException)
        {
            return JsonValue.Create(body);
        }
    }

    private static JsonNode? Sanitize(JsonNode? node)
    {
        switch (node)
        {
            case null:
                return null;

            case JsonObject obj:
            {
                var copy = new JsonObject();
                foreach (var (key, value) in obj)
                    copy[key] = IsSensitiveName(key) && value is not null ? "[redacted]" : Sanitize(value);

                return copy;
            }

            case JsonArray array:
            {
                var copy = new JsonArray();
                for (var i = 0; i < array.Count; i++)
                {
                    if (array.Count > MaxArrayItems && i == ArrayHeadItems)
                    {
                        var skipped = array.Count - ArrayHeadItems - ArrayTailItems;
                        copy.Add($"(+{skipped} more)");
                        i += skipped - 1;
                        continue;
                    }

                    copy.Add(Sanitize(array[i]));
                }

                return copy;
            }

            case JsonValue value when value.TryGetValue<string>(out var text):
                return JsonValue.Create(Truncate(RedactText(text)));

            default:
                return node.DeepClone();
        }
    }

    private static bool IsSensitiveName(string name)
    {
        var lower = name.ToLowerInvariant();
        return lower.Contains("secret")
            || lower.Contains("token")
            || lower.Contains("password")
            || lower.Contains("apikey")
            || lower.Contains("api_key")
            || lower.Contains("credential")
            || lower.Contains("awsenvironment");
    }

    private static string Truncate(string text)
        => text.Length <= MaxStringLength
            ? text
            : $"{text[..MaxStringLength]}...(+{text.Length - MaxStringLength} chars)";
}
