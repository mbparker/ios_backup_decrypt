﻿using System.Collections.Generic;
using System.IO;
using System.Linq;
using Dapper;
using Microsoft.Data.Sqlite;

namespace iOS.Backup.Decrypt.Library.Repositories
{
    public class ManifestRepository
    {
        private readonly string dbFilename;

        public ManifestRepository(string dbFilePath)
        {
            dbFilename = Path.Combine(dbFilePath, "Manifest.db");
        }

        public bool OpenTempDb()
        {
            using (var conn = new SqliteConnection($"Data Source={dbFilename}"))
            {
                conn.Open();
                try
                {
                    var fileCount = conn.Query<int>("select count(*) from files").FirstOrDefault();
                    return fileCount > 0;
                }
                finally
                {
                    SqliteConnection.ClearPool(conn);
                    conn.Close();
                }
            }
        }

        public DBFile GetFile(string path)
        {
            using (var conn = new SqliteConnection($"Data Source={dbFilename}"))
            {
                conn.Open();
                try
                {
                    var file = conn.Query<DBFile>(@"
                    SELECT fileID, file
                    FROM Files
                    WHERE relativePath = @Path
                    ORDER BY domain, relativePath
                    LIMIT 1;", new { Path = path }).FirstOrDefault();
                    return file;
                }
                finally
                {
                    SqliteConnection.ClearPool(conn);
                    conn.Close();
                }
            }
        }
        
        public IEnumerable<DBFile> GetAllFiles()
        {
            using (var conn = new SqliteConnection($"Data Source={dbFilename}"))
            {
                conn.Open();
                try
                {
                    var files = conn.Query<DBFile>(@"
                    SELECT fileID, domain, relativePath
                    FROM Files
                    ORDER BY domain, relativePath");
                    return files;
                }
                finally
                {
                    SqliteConnection.ClearPool(conn);
                    conn.Close();
                }
            }
        }
    }

    public class DBFile
    {
        public string fileID { get; set; }
        public string domain { get; set; }
        public string RelativePath { get; set; }
        public byte[] file { get; set; }
    }

}
