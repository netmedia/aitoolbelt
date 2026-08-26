-- ============================================================================
--  Fake-apply a squashed EF Core migration on an EXISTING database
--  Netmedia (https://netmedia.agency)
--
--  Run this ONCE against each database that already has the full schema and all
--  the OLD (pre-squash) migrations applied. It records the new squashed migration
--  in __EFMigrationsHistory WITHOUT running any DDL, so no tables are recreated
--  and no data is lost. After this, `dotnet ef database update` / Database.Migrate()
--  treats the database as up to date.
--
--  Use this only if you are NOT using the app-startup MigrationBootstrapper
--  (which does the same thing automatically). Using both is harmless.
--
--  >>> REPLACE the two placeholders before running: <<<
--     @MigrationId     = exact filename prefix of the squashed migration
--                        e.g. 20260808120000_SquashedInitial
--     @ProductVersion  = your EF Core version, e.g. 9.0.0
--
--  Pick the section for your database provider; delete the others.
--  Old (pre-squash) migration rows may be left in place (harmless) or removed
--  after the squash row exists - see the optional cleanup at the bottom.
-- ============================================================================


-- ---------------------------------------------------------------------------
-- SQL Server
-- ---------------------------------------------------------------------------
IF NOT EXISTS (
    SELECT 1 FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260808120000_SquashedInitial'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260808120000_SquashedInitial', N'9.0.0');
END;
GO


-- ---------------------------------------------------------------------------
-- PostgreSQL
-- ---------------------------------------------------------------------------
-- INSERT INTO "__EFMigrationsHistory" ("MigrationId", "ProductVersion")
-- VALUES ('20260808120000_SquashedInitial', '9.0.0')
-- ON CONFLICT ("MigrationId") DO NOTHING;


-- ---------------------------------------------------------------------------
-- MySQL / MariaDB
-- ---------------------------------------------------------------------------
-- INSERT IGNORE INTO `__EFMigrationsHistory` (`MigrationId`, `ProductVersion`)
-- VALUES ('20260808120000_SquashedInitial', '9.0.0');


-- ---------------------------------------------------------------------------
-- SQLite
-- ---------------------------------------------------------------------------
-- INSERT OR IGNORE INTO "__EFMigrationsHistory" ("MigrationId", "ProductVersion")
-- VALUES ('20260808120000_SquashedInitial', '9.0.0');


-- ============================================================================
--  OPTIONAL cleanup: remove old pre-squash migration rows once the squash row
--  exists. Not required (extra rows are ignored by EF), purely for tidiness.
--  Only run AFTER confirming the squashed row above is present.
-- ============================================================================
-- SQL Server:
-- DELETE FROM [__EFMigrationsHistory]
-- WHERE [MigrationId] <> N'20260808120000_SquashedInitial';
--
-- PostgreSQL / SQLite:
-- DELETE FROM "__EFMigrationsHistory"
-- WHERE "MigrationId" <> '20260808120000_SquashedInitial';
--
-- MySQL / MariaDB:
-- DELETE FROM `__EFMigrationsHistory`
-- WHERE `MigrationId` <> '20260808120000_SquashedInitial';
