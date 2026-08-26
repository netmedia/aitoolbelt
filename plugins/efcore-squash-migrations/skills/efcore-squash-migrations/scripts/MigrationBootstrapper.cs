// ============================================================================
//  MigrationBootstrapper
//  Netmedia (https://netmedia.agency)
//
//  Safe startup migration for a SQUASHED EF Core migration history.
//
//  Handles all three database states correctly, with no data loss:
//    1. Empty / brand-new database      -> runs the squashed migration (creates schema).
//    2. Existing pre-squash database    -> marks the squashed migration as applied WITHOUT
//                                          running its DDL (fake-apply), then continues.
//    3. Already up-to-date database     -> no-op (only applies genuinely new future migrations).
//
//  Provider-agnostic: uses IHistoryRepository.GetInsertScript(...) so the __EFMigrationsHistory
//  table name and SQL quoting are always correct for the active provider (SQL Server, PostgreSQL,
//  MySQL, SQLite, Oracle). Safe to leave in the codebase permanently and safe to run repeatedly.
//
//  USAGE (e.g. in Program.cs):
//      using (var scope = app.Services.CreateScope())
//      {
//          var db = scope.ServiceProvider.GetRequiredService<MyDbContext>();
//          await MigrationBootstrapper.MigrateSafelyAsync(db);
//      }
//
//  Adjust the namespace to match your project.
// ============================================================================

using System;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage;

namespace Netmedia.Data
{
    public static class MigrationBootstrapper
    {
        /// <summary>
        /// Migrates the database safely after a migration squash. On databases that already contain
        /// the schema but have not recorded the squashed migration, the squashed migration is marked
        /// as applied instead of being executed, so no DDL runs and no data is lost.
        /// </summary>
        public static async Task MigrateSafelyAsync(DbContext db, CancellationToken ct = default)
        {
            if (db is null) throw new ArgumentNullException(nameof(db));

            var creator     = db.GetService<IRelationalDatabaseCreator>();
            var historyRepo = db.GetService<IHistoryRepository>();

            // The single squashed migration is the earliest (first) migration defined in the assembly.
            var squashedId = db.Database.GetMigrations().FirstOrDefault();
            if (squashedId is null)
            {
                // No migrations defined at all - nothing to do.
                return;
            }

            var databaseExists = await creator.ExistsAsync(ct).ConfigureAwait(false);

            // A database that exists AND already has application tables, but has not recorded the
            // squashed migration, is a pre-squash database. Fake-apply the squash: record it in
            // __EFMigrationsHistory without executing its Up() DDL.
            if (databaseExists && await HasTablesAsync(creator, ct).ConfigureAwait(false))
            {
                var applied = (await db.Database.GetAppliedMigrationsAsync(ct).ConfigureAwait(false)).ToList();

                if (!applied.Contains(squashedId))
                {
                    var productVersion = GetEfProductVersion();
                    var insertSql = historyRepo.GetInsertScript(new HistoryRow(squashedId, productVersion));

                    // Respect the configured retry/execution strategy and wrap in a transaction.
                    var strategy = db.Database.CreateExecutionStrategy();
                    await strategy.ExecuteAsync(async () =>
                    {
                        await using var tx = await db.Database.BeginTransactionAsync(ct).ConfigureAwait(false);
                        await db.Database.ExecuteSqlRawAsync(insertSql, ct).ConfigureAwait(false);
                        await tx.CommitAsync(ct).ConfigureAwait(false);
                    }).ConfigureAwait(false);
                }
            }

            // - Fresh DB:        creates the full schema and records the squashed migration.
            // - Pre-squash DB:   squash is now recorded, so this only applies genuinely NEW migrations.
            // - Up-to-date DB:   no-op.
            await db.Database.MigrateAsync(ct).ConfigureAwait(false);
        }

        /// <summary>
        /// Uses HasTablesAsync when available (newer EF Core), falling back to the synchronous
        /// HasTables for older versions.
        /// </summary>
        private static async Task<bool> HasTablesAsync(IRelationalDatabaseCreator creator, CancellationToken ct)
        {
            var asyncMethod = creator.GetType().GetMethod("HasTablesAsync",
                BindingFlags.Public | BindingFlags.Instance,
                binder: null,
                types: new[] { typeof(CancellationToken) },
                modifiers: null);

            if (asyncMethod is not null &&
                asyncMethod.Invoke(creator, new object[] { ct }) is Task<bool> task)
            {
                return await task.ConfigureAwait(false);
            }

            return creator.HasTables();
        }

        /// <summary>
        /// Returns the EF Core product version string stored in the ProductVersion column.
        /// Falls back to the EF assembly version if ProductInfo.GetVersion() is not accessible
        /// on the current EF Core version.
        /// </summary>
        private static string GetEfProductVersion()
        {
            try
            {
                // Available in most EF Core versions (Microsoft.EntityFrameworkCore.Infrastructure).
                return ProductInfo.GetVersion();
            }
            catch
            {
                var version = typeof(DbContext).Assembly.GetName().Version;
                return version?.ToString() ?? "0.0.0";
            }
        }
    }
}
