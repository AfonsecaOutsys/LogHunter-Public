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
using System.Threading.Tasks;
using LogHunter.Services;
using Microsoft.Data.Sqlite;

namespace LogHunter.Viewer;

internal sealed class AlbIpSummarySqliteViewerHost : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false
    };

    private readonly string _dbPath;
    private readonly string? _requestedIp;
    private readonly HttpListener _listener = new();
    private readonly SqliteConnection _connection;
    private readonly int _port;
    private readonly string _baseUrl;

    public AlbIpSummarySqliteViewerHost(string dbPath, string? requestedIp)
    {
        _dbPath = Path.GetFullPath(dbPath);
        _requestedIp = string.IsNullOrWhiteSpace(requestedIp) ? null : requestedIp.Trim();

        if (!File.Exists(_dbPath))
            throw new FileNotFoundException("SQLite database was not found.", _dbPath);

        _connection = new SqliteConnection($"Data Source={_dbPath};Mode=ReadOnly");
        _connection.Open();
        _port = GetFreePort();
        _baseUrl = $"http://127.0.0.1:{_port}/";
        _listener.Prefixes.Add(_baseUrl);
    }

    public async Task RunAsync(Func<bool> stopRequested)
    {
        var metadata = LoadMetadata();

        _listener.Start();
        Console.WriteLine($"SQLite deep analysis viewer ready for {metadata.DatabaseName}");
        Console.WriteLine($"Viewer URL: {_baseUrl}");
        Console.WriteLine("Press Ctrl+C in this viewer process to stop the local server.");
        TryOpenBrowser(_baseUrl);

        var getContextTask = _listener.GetContextAsync();
        while (!stopRequested())
        {
            HttpListenerContext? context = null;
            try
            {
                var completed = await Task.WhenAny(getContextTask, Task.Delay(500)).ConfigureAwait(false);
                if (completed != getContextTask)
                    continue;

                context = await getContextTask.ConfigureAwait(false);
                getContextTask = _listener.GetContextAsync();
                await HandleAsync(context, metadata).ConfigureAwait(false);
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
            _listener.Stop();

        _listener.Close();
        _connection.Dispose();
    }

    private async Task HandleAsync(HttpListenerContext context, ViewerMetadata metadata)
    {
        var path = context.Request.Url?.AbsolutePath ?? "/";
        if (path.Equals("/", StringComparison.Ordinal))
        {
            await WriteTextAsync(context.Response, HttpStatusCode.OK, AlbIpSummarySqliteViewerPage.BuildHtml(), "text/html; charset=utf-8").ConfigureAwait(false);
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
            var request = ViewerQueryRequest.From(context.Request.QueryString);
            var payload = QueryRows(request);
            await WriteJsonAsync(context.Response, payload).ConfigureAwait(false);
            return;
        }

        if (path.Equals("/api/export.csv", StringComparison.Ordinal))
        {
            var request = ViewerQueryRequest.From(context.Request.QueryString);
            await WriteCsvAsync(context.Response, request).ConfigureAwait(false);
            return;
        }

        await WriteTextAsync(context.Response, HttpStatusCode.NotFound, "Not found", "text/plain; charset=utf-8").ConfigureAwait(false);
    }

    private ViewerMetadata LoadMetadata()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
SELECT
    COUNT(*),
    MIN(TimestampUtc),
    MAX(TimestampUtc),
    MIN(ClientIp)
FROM Hits;";

        using var reader = cmd.ExecuteReader();
        reader.Read();

        var totalRows = reader.IsDBNull(0) ? 0L : reader.GetInt64(0);
        var startUtc = reader.IsDBNull(1) ? null : reader.GetString(1);
        var endUtc = reader.IsDBNull(2) ? null : reader.GetString(2);
        var clientIp = _requestedIp ?? (reader.IsDBNull(3) ? null : reader.GetString(3));
        var methods = LoadMethods();

        return new ViewerMetadata(
            SelectedIp: clientIp ?? string.Empty,
            DatabaseName: Path.GetFileName(_dbPath),
            DatabasePath: _dbPath,
            TotalRows: totalRows,
            StartUtc: startUtc,
            EndUtc: endUtc,
            TimeRangeUtc: BuildTimeRange(startUtc, endUtc),
            ViewerUrl: _baseUrl,
            Methods: methods);
    }

    private string[] LoadMethods()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
SELECT DISTINCT Method
FROM Hits
WHERE Method IS NOT NULL AND Method <> '-' AND Method <> ''
ORDER BY Method COLLATE NOCASE;";

        using var reader = cmd.ExecuteReader();
        var values = new List<string>();
        while (reader.Read())
            values.Add(reader.GetString(0));

        return values.ToArray();
    }

    private ViewerRowsResponse QueryRows(ViewerQueryRequest request)
    {
        var where = new List<string>();
        using var countCmd = _connection.CreateCommand();
        using var rowsCmd = _connection.CreateCommand();

        AddPreset(where, countCmd, request.Preset);
        ApplyFilters(where, countCmd, request);

        foreach (SqliteParameter parameter in countCmd.Parameters)
            rowsCmd.Parameters.AddWithValue(parameter.ParameterName, parameter.Value ?? DBNull.Value);

        var whereClause = where.Count == 0 ? string.Empty : " WHERE " + string.Join(" AND ", where);

        countCmd.CommandText = "SELECT COUNT(*) FROM Hits" + whereClause + ";";
        var totalFiltered = Convert.ToInt64(countCmd.ExecuteScalar(), CultureInfo.InvariantCulture);

        rowsCmd.CommandText = $@"
SELECT
    TimestampUtc,
    ClientIp,
    Method,
    RawRequest,
    ElbResponseCode,
    FeResponseCode,
    TargetEndpoint,
    TargetProcessingTimeSeconds,
    RequestProcessingTimeSeconds,
    ResponseProcessingTimeSeconds,
    ActionsExecuted,
    UserAgent
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
                TimestampUtc: GetString(reader, 0),
                ClientIp: GetString(reader, 1),
                Method: GetString(reader, 2),
                RawRequest: GetString(reader, 3),
                ElbResponseCode: GetNullableInt(reader, 4),
                FeResponseCode: GetNullableInt(reader, 5),
                TargetEndpoint: GetString(reader, 6),
                TargetProcessingTimeSeconds: GetNullableDouble(reader, 7),
                RequestProcessingTimeSeconds: GetNullableDouble(reader, 8),
                ResponseProcessingTimeSeconds: GetNullableDouble(reader, 9),
                ActionsExecuted: GetString(reader, 10),
                UserAgent: GetString(reader, 11)));
        }

        return new ViewerRowsResponse(totalFiltered, request.Page, request.PageSize, rows);
    }

    private async Task WriteCsvAsync(HttpListenerResponse response, ViewerQueryRequest request)
    {
        var where = new List<string>();
        using var cmd = _connection.CreateCommand();
        AddPreset(where, cmd, request.Preset);
        ApplyFilters(where, cmd, request);
        var whereClause = where.Count == 0 ? string.Empty : " WHERE " + string.Join(" AND ", where);

        cmd.CommandText = $@"
SELECT
    TimestampUtc,
    ClientIp,
    Method,
    RawRequest,
    ElbResponseCode,
    FeResponseCode,
    TargetEndpoint,
    TargetProcessingTimeSeconds,
    RequestProcessingTimeSeconds,
    ResponseProcessingTimeSeconds,
    ActionsExecuted,
    UserAgent
FROM Hits{whereClause}
ORDER BY {MapSortField(request.SortField)} {MapSortDirection(request.SortDirection)}, Id DESC;";

        response.StatusCode = (int)HttpStatusCode.OK;
        response.ContentType = "text/csv; charset=utf-8";
        response.Headers["Content-Disposition"] = $"attachment; filename=alb-ip-summary-{DateTime.UtcNow:yyyyMMdd_HHmmss}.csv";

        await using var writer = new StreamWriter(response.OutputStream, new UTF8Encoding(false), bufferSize: 16 * 1024, leaveOpen: false);
        await writer.WriteLineAsync("TimestampUtc,ClientIp,Method,RawRequest,ELB Response Code,FE Response Code,TargetEndpoint,TargetProcessingTimeSeconds,RequestProcessingTimeSeconds,ResponseProcessingTimeSeconds,ActionsExecuted,UserAgent").ConfigureAwait(false);

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var values = new[]
            {
                GetString(reader, 0),
                GetString(reader, 1),
                GetString(reader, 2),
                GetString(reader, 3),
                GetNullableInt(reader, 4)?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                GetNullableInt(reader, 5)?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                GetString(reader, 6),
                GetNullableDouble(reader, 7)?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                GetNullableDouble(reader, 8)?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                GetNullableDouble(reader, 9)?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                GetString(reader, 10),
                GetString(reader, 11)
            };

            await writer.WriteLineAsync(string.Join(',', values.Select(EscapeCsv))).ConfigureAwait(false);
        }
    }

    private static void AddPreset(List<string> where, SqliteCommand cmd, string preset)
    {
        var definition = PresetDefinitions.All.FirstOrDefault(x => x.Id.Equals(preset, StringComparison.OrdinalIgnoreCase))
            ?? PresetDefinitions.All[0];

        if (string.IsNullOrWhiteSpace(definition.WhereClause))
            return;

        where.Add(definition.WhereClause);
    }

    private static void ApplyFilters(List<string> where, SqliteCommand cmd, ViewerQueryRequest request)
    {
        if (!string.IsNullOrWhiteSpace(request.Method))
        {
            where.Add("Method = $method");
            cmd.Parameters.AddWithValue("$method", request.Method);
        }

        if (TryParseUtcBound(request.StartUtc, endOfMinute: false, out var startUtc))
        {
            where.Add("TimestampUtc >= $startUtc");
            cmd.Parameters.AddWithValue("$startUtc", startUtc);
        }

        if (TryParseUtcBound(request.EndUtc, endOfMinute: true, out var endUtc))
        {
            where.Add("TimestampUtc <= $endUtc");
            cmd.Parameters.AddWithValue("$endUtc", endUtc);
        }

        AddStatusFilter(where, cmd, "ElbResponseCode", "$elbCode", request.ElbCode, request.ElbClass);
        AddStatusFilter(where, cmd, "FeResponseCode", "$feCode", request.FeCode, request.FeClass);
        AddContains(where, cmd, "TargetEndpoint", "$targetContains", request.TargetContains);
        AddContains(where, cmd, "RawRequest", "$rawRequestContains", request.RawRequestContains);
        AddContains(where, cmd, "UserAgent", "$userAgentContains", request.UserAgentContains);
        AddContains(where, cmd, "ActionsExecuted", "$actionsContains", request.ActionsContains);
    }

    private static void AddContains(List<string> where, SqliteCommand cmd, string columnName, string parameterName, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return;

        where.Add($"{columnName} LIKE {parameterName}");
        cmd.Parameters.AddWithValue(parameterName, $"%{value.Trim()}%");
    }

    private static void AddStatusFilter(List<string> where, SqliteCommand cmd, string columnName, string parameterName, string? exactCode, string? statusClass)
    {
        if (int.TryParse(exactCode, NumberStyles.Integer, CultureInfo.InvariantCulture, out var code))
        {
            where.Add($"{columnName} = {parameterName}");
            cmd.Parameters.AddWithValue(parameterName, code);
        }

        if (string.IsNullOrWhiteSpace(statusClass))
            return;

        var clause = statusClass.Trim() switch
        {
            "2xx3xx" => $"{columnName} BETWEEN 200 AND 399",
            "4xx" => $"{columnName} BETWEEN 400 AND 499",
            "5xx" => $"{columnName} BETWEEN 500 AND 599",
            _ => null
        };

        if (!string.IsNullOrWhiteSpace(clause))
            where.Add(clause);
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
            "rawrequest" => "RawRequest COLLATE NOCASE",
            "elbresponsecode" => "ElbResponseCode",
            "feresponsecode" => "FeResponseCode",
            "targetendpoint" => "TargetEndpoint COLLATE NOCASE",
            "actionsexecuted" => "ActionsExecuted COLLATE NOCASE",
            "useragent" => "UserAgent COLLATE NOCASE",
            "requestprocessingtimeseconds" => "RequestProcessingTimeSeconds",
            "targetprocessingtimeseconds" => "TargetProcessingTimeSeconds",
            "responseprocessingtimeseconds" => "ResponseProcessingTimeSeconds",
            _ => "TimestampUtc"
        };

    private static string MapSortDirection(string? sortDirection)
        => string.Equals(sortDirection, "asc", StringComparison.OrdinalIgnoreCase) ? "ASC" : "DESC";

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

    private static string GetString(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);

    private static int? GetNullableInt(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);

    private static double? GetNullableDouble(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? null : reader.GetDouble(ordinal);

    private static string BuildTimeRange(string? startUtc, string? endUtc)
        => string.IsNullOrWhiteSpace(startUtc) || string.IsNullOrWhiteSpace(endUtc)
            ? string.Empty
            : $"{startUtc} → {endUtc}";

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

    private static string EscapeCsv(string value)
    {
        if (value.Contains('"', StringComparison.Ordinal))
            value = value.Replace("\"", "\"\"", StringComparison.Ordinal);

        return value.IndexOfAny([',', '"', '\n', '\r']) >= 0
            ? $"\"{value}\""
            : value;
    }

    private sealed record ViewerMetadata(
        string SelectedIp,
        string DatabaseName,
        string DatabasePath,
        long TotalRows,
        string? StartUtc,
        string? EndUtc,
        string TimeRangeUtc,
        string ViewerUrl,
        string[] Methods);

    private sealed record ViewerRowsResponse(long TotalFiltered, int Page, int PageSize, IReadOnlyList<ViewerRow> Rows);

    private sealed record ViewerRow(
        string TimestampUtc,
        string ClientIp,
        string Method,
        string RawRequest,
        int? ElbResponseCode,
        int? FeResponseCode,
        string TargetEndpoint,
        double? TargetProcessingTimeSeconds,
        double? RequestProcessingTimeSeconds,
        double? ResponseProcessingTimeSeconds,
        string ActionsExecuted,
        string UserAgent);

    private sealed record ViewerQueryRequest(
        int Page,
        int PageSize,
        string SortField,
        string SortDirection,
        string Preset,
        string? Method,
        string? StartUtc,
        string? EndUtc,
        string? ElbCode,
        string? ElbClass,
        string? FeCode,
        string? FeClass,
        string? TargetContains,
        string? RawRequestContains,
        string? UserAgentContains,
        string? ActionsContains)
    {
        public static ViewerQueryRequest From(NameValueCollection query)
        {
            var page = Math.Max(1, ParseInt(query["page"], 1));
            var pageSize = Math.Clamp(ParseInt(query["pageSize"], 100), 1, 500);
            return new ViewerQueryRequest(
                Page: page,
                PageSize: pageSize,
                SortField: query["sortField"] ?? "timestampUtc",
                SortDirection: query["sortDirection"] ?? "desc",
                Preset: query["preset"] ?? "all",
                Method: query["method"],
                StartUtc: query["startUtc"],
                EndUtc: query["endUtc"],
                ElbCode: query["elbCode"],
                ElbClass: query["elbClass"],
                FeCode: query["feCode"],
                FeClass: query["feClass"],
                TargetContains: query["targetContains"],
                RawRequestContains: query["rawRequestContains"],
                UserAgentContains: query["userAgentContains"],
                ActionsContains: query["actionsContains"]);
        }

        private static int ParseInt(string? value, int fallback)
            => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
                ? parsed
                : fallback;
    }

    private sealed record PresetDefinition(string Id, string Label, string WhereClause);

    private static class PresetDefinitions
    {
        public static IReadOnlyList<PresetDefinition> All { get; } =
        [
            new("all", "All rows", string.Empty),
            new("latest", "Latest rows", string.Empty),
            new("fe5xx_elb2xx3xx", "FE Response 5xx while ELB Response is 2xx/3xx", "FeResponseCode BETWEEN 500 AND 599 AND ElbResponseCode BETWEEN 200 AND 399"),
            new("fe4xx_elb2xx3xx", "FE Response 4xx while ELB Response is 2xx/3xx", "FeResponseCode BETWEEN 400 AND 499 AND ElbResponseCode BETWEEN 200 AND 399"),
            new("elb5xx_fe2xx3xx", "ELB Response 5xx while FE Response is 2xx/3xx", "ElbResponseCode BETWEEN 500 AND 599 AND FeResponseCode BETWEEN 200 AND 399"),
            new("elb4xx_fe2xx3xx", "ELB Response 4xx while FE Response is 2xx/3xx", "ElbResponseCode BETWEEN 400 AND 499 AND FeResponseCode BETWEEN 200 AND 399")
        ];
    }
}
