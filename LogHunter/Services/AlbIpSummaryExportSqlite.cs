using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using Microsoft.Data.Sqlite;

namespace LogHunter.Services;

public static class AlbIpSummaryExportSqlite
{
    public static Writer Open(string dbPath) => new(dbPath);

    public sealed class Writer : IDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly SqliteTransaction _transaction;
        private readonly SqliteCommand _insert;
        private bool _completed;

        public Writer(string dbPath)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(dbPath)!);
            if (File.Exists(dbPath))
                File.Delete(dbPath);

            _connection = new SqliteConnection($"Data Source={dbPath}");
            _connection.Open();

            using (var pragma = _connection.CreateCommand())
            {
                pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;";
                pragma.ExecuteNonQuery();
            }

            using (var create = _connection.CreateCommand())
            {
                create.CommandText = @"
CREATE TABLE Hits (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    TimestampUtc TEXT NOT NULL,
    ClientIp TEXT NOT NULL,
    ClientPort TEXT,
    Method TEXT,
    Host TEXT,
    PathNoQuery TEXT,
    RawRequest TEXT,
    FeStatusCode INTEGER,
    CfStatusCode INTEGER,
    CfEndpoint TEXT,
    TargetProcessingTimeSeconds REAL,
    RequestProcessingTimeSeconds REAL,
    ResponseProcessingTimeSeconds REAL,
    ActionsExecuted TEXT,
    TraceId TEXT,
    UserAgent TEXT,
    SourceFile TEXT,
    RawLine TEXT
);";
                create.ExecuteNonQuery();
            }

            _transaction = _connection.BeginTransaction();
            _insert = _connection.CreateCommand();
            _insert.Transaction = _transaction;
            _insert.CommandText = @"
INSERT INTO Hits (
    TimestampUtc,
    ClientIp,
    ClientPort,
    Method,
    Host,
    PathNoQuery,
    RawRequest,
    FeStatusCode,
    CfStatusCode,
    CfEndpoint,
    TargetProcessingTimeSeconds,
    RequestProcessingTimeSeconds,
    ResponseProcessingTimeSeconds,
    ActionsExecuted,
    TraceId,
    UserAgent,
    SourceFile,
    RawLine
) VALUES (
    $TimestampUtc,
    $ClientIp,
    $ClientPort,
    $Method,
    $Host,
    $PathNoQuery,
    $RawRequest,
    $FeStatusCode,
    $CfStatusCode,
    $CfEndpoint,
    $TargetProcessingTimeSeconds,
    $RequestProcessingTimeSeconds,
    $ResponseProcessingTimeSeconds,
    $ActionsExecuted,
    $TraceId,
    $UserAgent,
    $SourceFile,
    $RawLine
);";

            AddParameter("$TimestampUtc");
            AddParameter("$ClientIp");
            AddParameter("$ClientPort");
            AddParameter("$Method");
            AddParameter("$Host");
            AddParameter("$PathNoQuery");
            AddParameter("$RawRequest");
            AddParameter("$FeStatusCode");
            AddParameter("$CfStatusCode");
            AddParameter("$CfEndpoint");
            AddParameter("$TargetProcessingTimeSeconds");
            AddParameter("$RequestProcessingTimeSeconds");
            AddParameter("$ResponseProcessingTimeSeconds");
            AddParameter("$ActionsExecuted");
            AddParameter("$TraceId");
            AddParameter("$UserAgent");
            AddParameter("$SourceFile");
            AddParameter("$RawLine");
        }

        public void WriteRows(IEnumerable<AlbIpSummaryScanner.AlbIpSummaryRow> rows)
        {
            foreach (var row in rows)
                WriteRow(row);
        }

        public void WriteRow(AlbIpSummaryScanner.AlbIpSummaryRow row)
        {
            _insert.Parameters["$TimestampUtc"].Value = row.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
            _insert.Parameters["$ClientIp"].Value = row.ClientIp;
            _insert.Parameters["$ClientPort"].Value = DbValue(row.ClientPort);
            _insert.Parameters["$Method"].Value = DbValue(row.Method);
            _insert.Parameters["$Host"].Value = DbValue(row.Host);
            _insert.Parameters["$PathNoQuery"].Value = DbValue(row.PathNoQuery);
            _insert.Parameters["$RawRequest"].Value = DbValue(row.RawRequest);
            _insert.Parameters["$FeStatusCode"].Value = DbValue(row.ElbStatusCode);
            _insert.Parameters["$CfStatusCode"].Value = DbValue(row.TargetStatusCode);
            _insert.Parameters["$CfEndpoint"].Value = DbValue(row.TargetEndpoint);
            _insert.Parameters["$TargetProcessingTimeSeconds"].Value = DbValue(row.TargetProcessingTimeSeconds);
            _insert.Parameters["$RequestProcessingTimeSeconds"].Value = DbValue(row.RequestProcessingTimeSeconds);
            _insert.Parameters["$ResponseProcessingTimeSeconds"].Value = DbValue(row.ResponseProcessingTimeSeconds);
            _insert.Parameters["$ActionsExecuted"].Value = DbValue(row.ActionsExecuted);
            _insert.Parameters["$TraceId"].Value = DbValue(row.TraceId);
            _insert.Parameters["$UserAgent"].Value = DbValue(row.UserAgent);
            _insert.Parameters["$SourceFile"].Value = DbValue(row.SourceFile);
            _insert.Parameters["$RawLine"].Value = DbValue(row.RawLine);
            _insert.ExecuteNonQuery();
        }

        public void Complete()
        {
            if (_completed)
                return;

            _transaction.Commit();

            using var idx = _connection.CreateCommand();
            idx.CommandText = @"
CREATE INDEX idx_hits_timestamp_utc ON Hits(TimestampUtc);
CREATE INDEX idx_hits_path_no_query ON Hits(PathNoQuery);
CREATE INDEX idx_hits_host ON Hits(Host);
CREATE INDEX idx_hits_fe_status ON Hits(FeStatusCode);
CREATE INDEX idx_hits_cf_status ON Hits(CfStatusCode);
CREATE INDEX idx_hits_cf_endpoint ON Hits(CfEndpoint);";
            idx.ExecuteNonQuery();

            _completed = true;
        }

        public void Dispose()
        {
            if (!_completed)
                Complete();

            _insert.Dispose();
            _transaction.Dispose();
            _connection.Dispose();
        }

        private void AddParameter(string name)
            => _insert.Parameters.AddWithValue(name, DBNull.Value);

        private static object DbValue(string value)
            => string.IsNullOrWhiteSpace(value) || value == "-" ? DBNull.Value : value;

        private static object DbValue(int? value)
            => value.HasValue ? value.Value : DBNull.Value;

        private static object DbValue(double? value)
            => value.HasValue ? value.Value : DBNull.Value;
    }
}
