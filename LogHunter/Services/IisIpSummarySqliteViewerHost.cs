using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LogHunter.Viewer;
using Microsoft.Data.Sqlite;

namespace LogHunter.Services;

internal sealed class IisIpSummarySqliteViewerHost : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = false };

    private readonly string _dbPath;
    private readonly string? _requestedIp;
    private readonly HttpListener _listener = new();
    private readonly string _connectionString;
    private readonly int _port;
    private readonly string _baseUrl;

    public IisIpSummarySqliteViewerHost(string dbPath, string? requestedIp, int? port = null)
    {
        _dbPath = Path.GetFullPath(dbPath);
        _requestedIp = string.IsNullOrWhiteSpace(requestedIp) ? null : requestedIp.Trim();
        if (!File.Exists(_dbPath))
            throw new FileNotFoundException("SQLite database was not found.", _dbPath);

        _connectionString = $"Data Source={_dbPath};Mode=ReadOnly";
        _port = port is > 0 ? port.Value : GetFreePort();
        _baseUrl = $"http://127.0.0.1:{_port}/";
        _listener.Prefixes.Add(_baseUrl);
    }

    private SqliteConnection OpenConnection()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using (var pragma = conn.CreateCommand())
        {
            pragma.CommandText = "PRAGMA query_only = 1; PRAGMA mmap_size = 268435456; PRAGMA cache_size = -65536; PRAGMA temp_store = MEMORY;";
            pragma.ExecuteNonQuery();
        }
        return conn;
    }

    public async Task RunAsync(Func<bool> stopRequested)
    {
        var metadata = LoadMetadata();

        _listener.Start();
        Console.WriteLine($"IIS SQLite deep analysis viewer ready for {metadata.DatabaseName}");
        Console.WriteLine($"Viewer URL: {_baseUrl}");
        Console.WriteLine("Press Ctrl+C in this viewer process to stop the local server.");

        await Task.Delay(350).ConfigureAwait(false);
        TryOpenBrowser(_baseUrl);

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
                        await HandleAsync(context, metadata).ConfigureAwait(false);
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
            _listener.Stop();
        _listener.Close();
    }

    private async Task HandleAsync(HttpListenerContext context, ViewerMetadata metadata)
    {
        var path = context.Request.Url?.AbsolutePath ?? "/";
        if (path.Equals("/", StringComparison.Ordinal))
        {
            await WriteTextAsync(context.Response, HttpStatusCode.OK, IisIpSummarySqliteViewerPage.BuildHtml(), "text/html; charset=utf-8").ConfigureAwait(false);
            return;
        }
        if (path.Equals("/api/metadata", StringComparison.Ordinal))
        {
            await WriteJsonAsync(context.Response, metadata).ConfigureAwait(false);
            return;
        }
        if (path.Equals("/api/presets", StringComparison.Ordinal))
        {
            await WriteJsonAsync(context.Response, PresetDefinitions.All.Select(x => new { x.Id, x.Label }).ToArray()).ConfigureAwait(false);
            return;
        }
        if (path.Equals("/api/rows", StringComparison.Ordinal))
        {
            await WriteJsonAsync(context.Response, QueryRows(ViewerQueryRequest.From(context.Request.QueryString))).ConfigureAwait(false);
            return;
        }
        if (path.Equals("/api/export.csv", StringComparison.Ordinal))
        {
            await WriteCsvAsync(context.Response, ViewerQueryRequest.From(context.Request.QueryString)).ConfigureAwait(false);
            return;
        }

        await WriteTextAsync(context.Response, HttpStatusCode.NotFound, "Not found", "text/plain; charset=utf-8").ConfigureAwait(false);
    }

    private ViewerMetadata LoadMetadata()
    {
        using var connection = OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*), MIN(TimestampUtc), MAX(TimestampUtc), MIN(ClientIp), COUNT(DISTINCT ClientIp) FROM Hits;";
        using var reader = cmd.ExecuteReader();
        reader.Read();

        var totalRows = reader.IsDBNull(0) ? 0L : reader.GetInt64(0);
        var startUtc = reader.IsDBNull(1) ? null : reader.GetString(1);
        var endUtc = reader.IsDBNull(2) ? null : reader.GetString(2);
        var fallbackIp = reader.IsDBNull(3) ? null : reader.GetString(3);
        var distinctIps = reader.IsDBNull(4) ? 0 : reader.GetInt32(4);
        var clientIp = _requestedIp ?? (distinctIps > 1 ? $"Multiple ({distinctIps})" : fallbackIp);

        return new ViewerMetadata(
            SelectedIp: clientIp ?? string.Empty,
            DatabaseName: Path.GetFileName(_dbPath),
            DatabasePath: _dbPath,
            TotalRows: totalRows,
            StartUtc: startUtc,
            EndUtc: endUtc,
            TimeRangeUtc: string.IsNullOrWhiteSpace(startUtc) || string.IsNullOrWhiteSpace(endUtc) ? string.Empty : $"{startUtc} -> {endUtc}",
            ViewerUrl: _baseUrl,
            Methods: LoadMethods());
    }

    private string[] LoadMethods()
    {
        using var connection = OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT DISTINCT Method FROM Hits WHERE Method IS NOT NULL AND Method <> '-' AND Method <> '' ORDER BY Method COLLATE NOCASE;";
        using var reader = cmd.ExecuteReader();
        var values = new List<string>();
        while (reader.Read())
            values.Add(reader.GetString(0));
        return values.ToArray();
    }

    private ViewerRowsResponse QueryRows(ViewerQueryRequest request)
    {
        var where = new List<string>();
        using var connection = OpenConnection();
        using var countCmd = connection.CreateCommand();
        using var rowsCmd = connection.CreateCommand();

        AddPreset(where, request.Preset);
        ApplyFilters(where, countCmd, request);
        foreach (SqliteParameter parameter in countCmd.Parameters)
            rowsCmd.Parameters.AddWithValue(parameter.ParameterName, parameter.Value ?? DBNull.Value);

        var whereClause = where.Count == 0 ? string.Empty : " WHERE " + string.Join(" AND ", where);
        countCmd.CommandText = "SELECT COUNT(*) FROM Hits" + whereClause + ";";
        var totalFiltered = Convert.ToInt64(countCmd.ExecuteScalar(), CultureInfo.InvariantCulture);

        rowsCmd.CommandText = $@"
SELECT TimestampUtc, ClientIp, Method, UriStem, UriQuery, Host, ScStatusCode, ScSubStatusCode, ScWin32StatusCode, TimeTakenMs, CsBytes, ScBytes, UserAgent, Referer
FROM Hits{whereClause}
ORDER BY {MapSortField(request.SortField)} {MapSortDirection(request.SortDirection)}, Id DESC
LIMIT $limit OFFSET $offset;";
        rowsCmd.Parameters.AddWithValue("$limit", request.PageSize);
        rowsCmd.Parameters.AddWithValue("$offset", (request.Page - 1) * request.PageSize);

        var rows = new List<ViewerRow>();
        using var reader = rowsCmd.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new ViewerRow(
                GetString(reader, 0), GetString(reader, 1), GetString(reader, 2), GetString(reader, 3), GetString(reader, 4), GetString(reader, 5),
                GetNullableInt(reader, 6), GetNullableInt(reader, 7), GetNullableInt(reader, 8), GetNullableLong(reader, 9), GetNullableLong(reader, 10), GetNullableLong(reader, 11), GetString(reader, 12), GetString(reader, 13)));
        }

        return new ViewerRowsResponse(totalFiltered, request.Page, request.PageSize, rows);
    }

    private async Task WriteCsvAsync(HttpListenerResponse response, ViewerQueryRequest request)
    {
        var where = new List<string>();
        using var connection = OpenConnection();
        using var cmd = connection.CreateCommand();
        AddPreset(where, request.Preset);
        ApplyFilters(where, cmd, request);
        var whereClause = where.Count == 0 ? string.Empty : " WHERE " + string.Join(" AND ", where);

        cmd.CommandText = $@"
SELECT TimestampUtc, ClientIp, Method, UriStem, UriQuery, Host, ScStatusCode, ScSubStatusCode, ScWin32StatusCode, TimeTakenMs, CsBytes, ScBytes, UserAgent, Referer
FROM Hits{whereClause}
ORDER BY {MapSortField(request.SortField)} {MapSortDirection(request.SortDirection)}, Id DESC;";

        response.StatusCode = (int)HttpStatusCode.OK;
        response.ContentType = "text/csv; charset=utf-8";
        response.Headers["Content-Disposition"] = $"attachment; filename=iis-ip-summary-{DateTime.UtcNow:yyyyMMdd_HHmmss}.csv";

        await using var writer = new StreamWriter(response.OutputStream, new UTF8Encoding(false), 16 * 1024, false);
        await writer.WriteLineAsync("TimestampUtc,ClientIp,Method,UriStem,UriQuery,Host,ScStatusCode,ScSubStatusCode,ScWin32StatusCode,TimeTakenMs,CsBytes,ScBytes,UserAgent,Referer").ConfigureAwait(false);

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var values = new[]
            {
                GetString(reader, 0), GetString(reader, 1), GetString(reader, 2), GetString(reader, 3), GetString(reader, 4), GetString(reader, 5),
                GetNullableInt(reader, 6)?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                GetNullableInt(reader, 7)?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                GetNullableInt(reader, 8)?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                GetNullableLong(reader, 9)?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                GetNullableLong(reader, 10)?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                GetNullableLong(reader, 11)?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                GetString(reader, 12), GetString(reader, 13)
            };

            await writer.WriteLineAsync(string.Join(',', values.Select(EscapeCsv))).ConfigureAwait(false);
        }
    }

    private static void AddPreset(List<string> where, string preset)
    {
        var definition = PresetDefinitions.All.FirstOrDefault(x => x.Id.Equals(preset, StringComparison.OrdinalIgnoreCase)) ?? PresetDefinitions.All[0];
        if (!string.IsNullOrWhiteSpace(definition.WhereClause))
            where.Add(definition.WhereClause);
    }

    private static void ApplyFilters(List<string> where, SqliteCommand cmd, ViewerQueryRequest request)
    {
        AddContains(where, cmd, "ClientIp", "$clientIpContains", request.ClientIpContains);
        if (!string.IsNullOrWhiteSpace(request.Method))
        {
            where.Add("Method = $method");
            cmd.Parameters.AddWithValue("$method", request.Method);
        }
        if (TryParseUtcBound(request.StartUtc, false, out var startUtc))
        {
            where.Add("TimestampUtc >= $startUtc");
            cmd.Parameters.AddWithValue("$startUtc", startUtc);
        }
        if (TryParseUtcBound(request.EndUtc, true, out var endUtc))
        {
            where.Add("TimestampUtc <= $endUtc");
            cmd.Parameters.AddWithValue("$endUtc", endUtc);
        }
        if (int.TryParse(request.StatusCode, NumberStyles.Integer, CultureInfo.InvariantCulture, out var code))
        {
            where.Add("ScStatusCode = $statusCode");
            cmd.Parameters.AddWithValue("$statusCode", code);
        }
        if (!string.IsNullOrWhiteSpace(request.StatusClass))
        {
            var clause = request.StatusClass switch
            {
                "2xx3xx" => "ScStatusCode BETWEEN 200 AND 399",
                "4xx" => "ScStatusCode BETWEEN 400 AND 499",
                "5xx" => "ScStatusCode BETWEEN 500 AND 599",
                _ => string.Empty
            };
            if (!string.IsNullOrWhiteSpace(clause))
                where.Add(clause);
        }
        AddContains(where, cmd, "UriStem", "$uriContains", request.UriContains);
        AddContains(where, cmd, "UriQuery", "$queryContains", request.QueryContains);
        AddContains(where, cmd, "Host", "$hostContains", request.HostContains);
        AddContains(where, cmd, "UserAgent", "$userAgentContains", request.UserAgentContains);
        AddContains(where, cmd, "Referer", "$refererContains", request.RefererContains);
    }

    private static void AddContains(List<string> where, SqliteCommand cmd, string column, string parameter, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return;
        where.Add($"{column} LIKE {parameter}");
        cmd.Parameters.AddWithValue(parameter, $"%{value.Trim()}%");
    }

    private static bool TryParseUtcBound(string? value, bool endOfMinute, out string timestampUtc)
    {
        timestampUtc = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
            return false;
        if (!DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
            return false;
        parsed = DateTime.SpecifyKind(parsed, DateTimeKind.Utc);
        if (endOfMinute)
            parsed = parsed.AddSeconds(59 - parsed.Second);
        timestampUtc = parsed.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
        return true;
    }

    private static string MapSortField(string? sortField)
        => sortField?.Trim().ToLowerInvariant() switch
        {
            "clientip" => "ClientIp",
            "method" => "Method COLLATE NOCASE",
            "uristem" => "UriStem COLLATE NOCASE",
            "uriquery" => "UriQuery COLLATE NOCASE",
            "host" => "Host COLLATE NOCASE",
            "scstatuscode" => "ScStatusCode",
            "scsubstatuscode" => "ScSubStatusCode",
            "scwin32statuscode" => "ScWin32StatusCode",
            "timetakenms" => "TimeTakenMs",
            "csbytes" => "CsBytes",
            "scbytes" => "ScBytes",
            "useragent" => "UserAgent COLLATE NOCASE",
            "referer" => "Referer COLLATE NOCASE",
            _ => "TimestampUtc"
        };

    private static string MapSortDirection(string? sortDirection)
        => string.Equals(sortDirection, "asc", StringComparison.OrdinalIgnoreCase) ? "ASC" : "DESC";

    private static async Task WriteJsonAsync(HttpListenerResponse response, object payload)
        => await WriteTextAsync(response, HttpStatusCode.OK, JsonSerializer.Serialize(payload, JsonOptions), "application/json; charset=utf-8").ConfigureAwait(false);

    private static async Task WriteTextAsync(HttpListenerResponse response, HttpStatusCode statusCode, string body, string contentType)
    {
        var data = Encoding.UTF8.GetBytes(body);
        response.StatusCode = (int)statusCode;
        response.ContentType = contentType;
        response.ContentLength64 = data.Length;
        await using var stream = response.OutputStream;
        await stream.WriteAsync(data).ConfigureAwait(false);
    }

    private static string GetString(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);
    private static int? GetNullableInt(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);
    private static long? GetNullableLong(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetInt64(ordinal);

    private static bool TryOpenBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
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

    private static string EscapeCsv(string value)
    {
        if (value.Contains('"', StringComparison.Ordinal))
            value = value.Replace("\"", "\"\"", StringComparison.Ordinal);
        return value.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? $"\"{value}\"" : value;
    }

    private sealed record ViewerMetadata(string SelectedIp, string DatabaseName, string DatabasePath, long TotalRows, string? StartUtc, string? EndUtc, string TimeRangeUtc, string ViewerUrl, string[] Methods);
    private sealed record ViewerRowsResponse(long TotalFiltered, int Page, int PageSize, IReadOnlyList<ViewerRow> Rows);
    private sealed record ViewerRow(string TimestampUtc, string ClientIp, string Method, string UriStem, string UriQuery, string Host, int? ScStatusCode, int? ScSubStatusCode, int? ScWin32StatusCode, long? TimeTakenMs, long? CsBytes, long? ScBytes, string UserAgent, string Referer);
    private sealed record ViewerQueryRequest(int Page, int PageSize, string SortField, string SortDirection, string Preset, string? ClientIpContains, string? Method, string? StartUtc, string? EndUtc, string? StatusCode, string? StatusClass, string? UriContains, string? QueryContains, string? HostContains, string? UserAgentContains, string? RefererContains)
    {
        public static ViewerQueryRequest From(NameValueCollection query)
        {
            var page = Math.Max(1, ParseInt(query["page"], 1));
            var pageSize = Math.Clamp(ParseInt(query["pageSize"], 100), 1, 500);
            return new ViewerQueryRequest(page, pageSize, query["sortField"] ?? "timestampUtc", query["sortDirection"] ?? "desc", query["preset"] ?? "all", query["clientIpContains"], query["method"], query["startUtc"], query["endUtc"], query["statusCode"], query["statusClass"], query["uriContains"], query["queryContains"], query["hostContains"], query["userAgentContains"], query["refererContains"]);
        }

        private static int ParseInt(string? value, int fallback)
            => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed : fallback;
    }

    private sealed record PresetDefinition(string Id, string Label, string WhereClause);

    private static class PresetDefinitions
    {
        public static IReadOnlyList<PresetDefinition> All { get; } =
        [
            new("all", "All rows", string.Empty),
            new("latest", "Latest rows", string.Empty),
            new("errors", "4xx and 5xx only", "ScStatusCode >= 400"),
            new("success", "2xx and 3xx only", "ScStatusCode BETWEEN 200 AND 399"),
            new("slow", "Slow requests (>= 2000 ms)", "TimeTakenMs >= 2000")
        ];
    }
}
