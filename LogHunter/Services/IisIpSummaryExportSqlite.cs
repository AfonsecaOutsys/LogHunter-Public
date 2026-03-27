using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using Microsoft.Data.Sqlite;

namespace LogHunter.Services;

public static class IisIpSummaryExportSqlite
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
    UriStem TEXT,
    UriQuery TEXT,
    Host TEXT,
    ScStatusCode INTEGER,
    ScSubStatusCode INTEGER,
    ScWin32StatusCode INTEGER,
    TimeTakenMs INTEGER,
    CsBytes INTEGER,
    ScBytes INTEGER,
    UserAgent TEXT,
    Referer TEXT
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
    UriStem,
    UriQuery,
    Host,
    ScStatusCode,
    ScSubStatusCode,
    ScWin32StatusCode,
    TimeTakenMs,
    CsBytes,
    ScBytes,
    UserAgent,
    Referer
) VALUES (
    $TimestampUtc,
    $ClientIp,
    $Method,
    $UriStem,
    $UriQuery,
    $Host,
    $ScStatusCode,
    $ScSubStatusCode,
    $ScWin32StatusCode,
    $TimeTakenMs,
    $CsBytes,
    $ScBytes,
    $UserAgent,
    $Referer
);";

            AddParameter("$TimestampUtc");
            AddParameter("$ClientIp");
            AddParameter("$Method");
            AddParameter("$UriStem");
            AddParameter("$UriQuery");
            AddParameter("$Host");
            AddParameter("$ScStatusCode");
            AddParameter("$ScSubStatusCode");
            AddParameter("$ScWin32StatusCode");
            AddParameter("$TimeTakenMs");
            AddParameter("$CsBytes");
            AddParameter("$ScBytes");
            AddParameter("$UserAgent");
            AddParameter("$Referer");
            _insert.Prepare();
        }

        public void WriteRows(IEnumerable<IisIpSummaryScanner.IisIpSummaryRow> rows)
        {
            foreach (var row in rows)
                WriteRow(row);
        }

        public void WriteRow(IisIpSummaryScanner.IisIpSummaryRow row)
        {
            _insert.Parameters["$TimestampUtc"].Value = row.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
            _insert.Parameters["$ClientIp"].Value = row.ClientIp;
            _insert.Parameters["$Method"].Value = DbValue(row.Method);
            _insert.Parameters["$UriStem"].Value = DbValue(row.UriStem);
            _insert.Parameters["$UriQuery"].Value = DbValue(row.UriQuery);
            _insert.Parameters["$Host"].Value = DbValue(row.Host);
            _insert.Parameters["$ScStatusCode"].Value = DbValue(row.StatusCode);
            _insert.Parameters["$ScSubStatusCode"].Value = DbValue(row.SubStatusCode);
            _insert.Parameters["$ScWin32StatusCode"].Value = DbValue(row.Win32StatusCode);
            _insert.Parameters["$TimeTakenMs"].Value = DbValue(row.TimeTakenMs);
            _insert.Parameters["$CsBytes"].Value = DbValue(row.CsBytes);
            _insert.Parameters["$ScBytes"].Value = DbValue(row.ScBytes);
            _insert.Parameters["$UserAgent"].Value = DbValue(row.UserAgent);
            _insert.Parameters["$Referer"].Value = DbValue(row.Referer);
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
CREATE INDEX idx_hits_status_code ON Hits(ScStatusCode);
CREATE INDEX idx_hits_uri_stem ON Hits(UriStem);
CREATE INDEX idx_hits_method ON Hits(Method);
CREATE INDEX idx_hits_timestamp_status ON Hits(TimestampUtc, ScStatusCode);";
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

        private static object DbValue(long? value)
            => value.HasValue ? value.Value : DBNull.Value;
    }
}
