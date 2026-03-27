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
                pragma.CommandText = @"
PRAGMA journal_mode=MEMORY;
PRAGMA synchronous=OFF;
PRAGMA temp_store=MEMORY;
PRAGMA locking_mode=EXCLUSIVE;";
                pragma.ExecuteNonQuery();
            }

            using (var create = _connection.CreateCommand())
            {
                create.CommandText = @"
CREATE TABLE Hits (
    Id INTEGER PRIMARY KEY,
    TimestampUtc TEXT NOT NULL,
    ClientIp TEXT NOT NULL,
    Method TEXT,
    RawRequest TEXT,
    ElbResponseCode INTEGER,
    FeResponseCode INTEGER,
    TargetEndpoint TEXT,
    TargetProcessingTimeSeconds REAL,
    RequestProcessingTimeSeconds REAL,
    ResponseProcessingTimeSeconds REAL,
    ActionsExecuted TEXT,
    UserAgent TEXT
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
) VALUES (
    $TimestampUtc,
    $ClientIp,
    $Method,
    $RawRequest,
    $ElbResponseCode,
    $FeResponseCode,
    $TargetEndpoint,
    $TargetProcessingTimeSeconds,
    $RequestProcessingTimeSeconds,
    $ResponseProcessingTimeSeconds,
    $ActionsExecuted,
    $UserAgent
);";

            AddParameter("$TimestampUtc");
            AddParameter("$ClientIp");
            AddParameter("$Method");
            AddParameter("$RawRequest");
            AddParameter("$ElbResponseCode");
            AddParameter("$FeResponseCode");
            AddParameter("$TargetEndpoint");
            AddParameter("$TargetProcessingTimeSeconds");
            AddParameter("$RequestProcessingTimeSeconds");
            AddParameter("$ResponseProcessingTimeSeconds");
            AddParameter("$ActionsExecuted");
            AddParameter("$UserAgent");
            _insert.Prepare();
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
            _insert.Parameters["$Method"].Value = DbValue(row.Method);
            _insert.Parameters["$RawRequest"].Value = DbValue(row.RawRequest);
            _insert.Parameters["$ElbResponseCode"].Value = DbValue(row.ElbStatusCode);
            _insert.Parameters["$FeResponseCode"].Value = DbValue(row.FeStatusCode);
            _insert.Parameters["$TargetEndpoint"].Value = DbValue(row.TargetEndpoint);
            _insert.Parameters["$TargetProcessingTimeSeconds"].Value = DbValue(row.TargetProcessingTimeSeconds);
            _insert.Parameters["$RequestProcessingTimeSeconds"].Value = DbValue(row.RequestProcessingTimeSeconds);
            _insert.Parameters["$ResponseProcessingTimeSeconds"].Value = DbValue(row.ResponseProcessingTimeSeconds);
            _insert.Parameters["$ActionsExecuted"].Value = DbValue(row.ActionsExecuted);
            _insert.Parameters["$UserAgent"].Value = DbValue(row.UserAgent);
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
CREATE INDEX idx_hits_elb_response_code ON Hits(ElbResponseCode);
CREATE INDEX idx_hits_fe_response_code ON Hits(FeResponseCode);
CREATE INDEX idx_hits_target_endpoint ON Hits(TargetEndpoint);
CREATE INDEX idx_hits_method ON Hits(Method);
CREATE INDEX idx_hits_timestamp_elb_fe ON Hits(TimestampUtc, ElbResponseCode, FeResponseCode);";
            idx.ExecuteNonQuery();

            using var analyze = _connection.CreateCommand();
            analyze.CommandText = "ANALYZE;";
            analyze.ExecuteNonQuery();

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
