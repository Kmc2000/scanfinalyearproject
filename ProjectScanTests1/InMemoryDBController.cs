
using System;
using System.Data.Common;
using System.Linq;
using System.Runtime.CompilerServices;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ProjectScan.Services;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory.Database;

namespace ProjectScanTests1
{
    internal class InMemoryDBController : IDisposable
    {
        private readonly DbConnection connection;
        private readonly DbContextOptions<MalwareScannerContext> contextOptions;

        private readonly MalwareScannerContext context;

        public InMemoryDBController()
        {
            // Create in-memory connection
            connection = new SqliteConnection("Filename=:memory:");
            connection.Open();

            contextOptions = new DbContextOptionsBuilder<MalwareScannerContext>().UseSqlite(connection).Options;

            // build schema
            context = new MalwareScannerContext(contextOptions);
            if(context.Database.EnsureCreated()) Console.WriteLine("Database successfully created");
        }

        public MalwareScannerContext GetContext()
        { 
            return context; 
        }

        public void Dispose()
        {
            connection.Dispose();
        }
    }
}
