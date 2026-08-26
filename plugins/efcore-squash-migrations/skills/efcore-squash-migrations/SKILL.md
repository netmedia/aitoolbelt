---
name: efcore-squash-migrations
description: >
  Squashes all existing EF Core migrations into a single "initial" migration, deletes the old
  migration files, and wires up safe startup logic so that EVERY database is upgraded correctly:
  brand-new databases get the full schema created, and existing databases (dev/staging/production)
  that already have every old migration applied are marked as up-to-date WITHOUT re-running any
  DDL and WITHOUT losing any data.

  Use this skill whenever the user wants to:
  - Squash / collapse / consolidate many EF Core migrations into one migration
  - Reset or clean up an EF Core migrations history that has grown too large
  - Rebaseline migrations while keeping existing production/staging databases intact
  - Make an app safely apply a squashed migration on startup against already-migrated databases
  - Regenerate a single InitialCreate migration from the current model without data loss

  ALWAYS use this skill when the user mentions: squashing migrations, collapsing migrations,
  consolidating EF Core migrations, rebaselining migrations, "make all migrations into one",
  or cleaning up the Migrations folder while keeping existing databases working.

metadata:
  author: Netmedia
  homepage: https://netmedia.agency
  email: netmedia@netmedia.hr
---

# EF Core Squash Migrations Skill

You are helping a developer collapse a large EF Core migration history into a **single squashed
migration**, delete the old migration files, and update the project so the application still
migrates every environment correctly on the next run.

The single most important property this skill guarantees: **no existing database loses data and no
existing database re-runs schema DDL.** Squashing changes the migration IDs, so every already-migrated
database must be told "the new squashed migration is already applied" instead of trying to run it.

This skill is generic and works with any EF Core project (EF Core 6/7/8/9+) and any relational
provider (SQL Server, PostgreSQL, MySQL/MariaDB, SQLite, Oracle).

---

## Why this is not just "delete and re-add"

EF Core records applied migrations in the `__EFMigrationsHistory` table, keyed by **MigrationId**
(the `20240101120000_Name` strings). Existing databases contain rows for all the *old* migration IDs.

When you squash, you delete those migrations and create ONE new migration with a **brand-new ID that
no existing database has ever seen**. If the app then calls `Database.Migrate()` on an existing
database, EF sees the new migration is "pending" and runs its `Up()` — which is a full
`CREATE TABLE` for the entire schema. On a database that already has those tables this either errors
out ("There is already an object named ...") or is otherwise wrong.

The fix is to **mark the squashed migration as already applied** on existing databases (insert its
ID into `__EFMigrationsHistory`) WITHOUT executing its DDL. New/empty databases still run the
migration normally. This skill sets both paths up.

Key safety fact used throughout: **extra rows in `__EFMigrationsHistory` are harmless.** EF only
compares the migrations defined in the assembly against history. Leftover old migration IDs are
ignored. So you never need to delete the old history rows — you only need to *add* one row for the
new squashed migration ID. (You may clean up the old rows later for tidiness, but it is optional.)

---

## Overview of the Process

1. **Confirm scope & options** — provider, DbContext, migrations folder, squashed name, strategy
2. **Preflight & safety** — clean git tree, DB backup, verify NO pending model changes
3. **Delete old migrations** — remove the Migrations folder contents (kept recoverable in git)
4. **Create the single squashed migration** — `dotnet ef migrations add <Name>`
5. **Wire up safe startup logic** — bootstrapper that fakes-apply on existing DBs, creates on new DBs
6. **(Optional) one-time SQL** — a fake-apply script for DBs you upgrade out-of-band
7. **Verify** — fresh DB test, production-copy test, "no pending migrations" check

---

## Step 1: Confirm Scope and Options

Before touching anything, establish these. Detect what you can from the repo, then ask the user to
confirm only what is genuinely ambiguous. If the session is unattended, pick the documented defaults,
state them, and proceed.

Determine and confirm:

- **Solution / project layout** — which project holds the DbContext and which holds the migrations
  (often the same, sometimes a separate `*.Infrastructure` / `*.Data` project). Use
  `Glob: pattern=**/*.csproj` and `Glob: pattern=**/Migrations/*ModelSnapshot.cs` to locate them.
- **DbContext name(s)** — grep for `: DbContext` (`Grep: pattern=": DbContext"`). If there are
  multiple DbContexts, each has its OWN migrations history and must be squashed separately; confirm
  which one(s) to squash.
- **Database provider** — inspect the csproj for the provider package:
  - `Microsoft.EntityFrameworkCore.SqlServer` → SQL Server (default assumption)
  - `Npgsql.EntityFrameworkCore.PostgreSQL` → PostgreSQL
  - `Pomelo.EntityFrameworkCore.MySql` / `MySql.EntityFrameworkCore` → MySQL/MariaDB
  - `Microsoft.EntityFrameworkCore.Sqlite` → SQLite
  The provider matters for the `__EFMigrationsHistory` table quoting in any raw SQL.
- **Squashed migration name** — default `InitialCreate`. (If a real `InitialCreate` history row might
  still exist in production and could collide, use a distinct name like `SquashedInitial` so the new
  MigrationId is guaranteed unique. This is the safer default when in doubt.)
- **EF tooling** — verify `dotnet ef` is available: `dotnet ef --version`. If missing, install with
  `dotnet tool install --global dotnet-ef` (or `dotnet tool restore` if the repo uses a tool
  manifest).
- **Strategy** — how existing databases get the fake-apply. Offer both and default to installing the
  startup bootstrapper (Step 5) because it is self-healing:
  - **A. Startup bootstrapper (recommended, default):** the app detects an already-populated DB on
    startup and marks the squashed migration applied automatically. Works for every environment with
    zero manual steps.
  - **B. One-time SQL script (Step 6):** for teams that migrate databases out-of-band (DBA-run
    scripts, no `Migrate()` at startup). Can be used alongside A.

State the confirmed choices back to the user in one short block before proceeding.

---

## Step 2: Preflight and Safety

**Do not skip. These prevent an unrecoverable mistake.**

1. **Clean, committed git tree.** The old migrations must be recoverable. Run `git status`; if there
   are uncommitted changes, ask the user to commit or stash first. The old migration files live in
   git history after deletion, so they are never truly lost.
2. **Back up existing databases.** Remind the user to back up (or snapshot) production and staging
   before deploying the squashed migration. The fake-apply is safe, but a backup is non-negotiable
   for any migration-history surgery.
3. **Verify there are NO pending model changes.** The squashed migration must exactly represent the
   current model, which in turn must match what production already has. Check with:
   ```bash
   dotnet ef migrations has-pending-model-changes --project <MigrationsProject> --startup-project <StartupProject>
   ```
   - EF Core 8+: this command exists and must report no changes.
   - Older EF Core: run `dotnet ef migrations add __VerifyNoChanges`, confirm the generated `Up()`
     and `Down()` are empty, then `dotnet ef migrations remove`. If they are NOT empty, the model and
     the last migration are out of sync — resolve that (add and apply the real pending migration
     everywhere) BEFORE squashing.
4. **Confirm production is fully migrated.** The squash assumes existing databases already have every
   current migration applied. If some environment is behind, migrate it to the latest CURRENT
   migration first (before the squash), otherwise the fake-apply would mark it as having schema it
   does not have.

Only continue once the model is in sync and everyone is on the latest current migration.

---

## Step 3: Delete the Old Migrations

Delete the entire contents of the migrations folder for the target DbContext, **including the
`*ModelSnapshot.cs` file** (this is essential — a stale snapshot makes the new migration come out
empty). Keep the `DbContext` and any non-migration files.

- Locate the folder (commonly `Migrations/`, `Data/Migrations/`, `Infrastructure/Migrations/`).
- Delete every `*.cs` migration file **and** the `*ModelSnapshot.cs`.
- Do NOT remove them one-by-one with `dotnet ef migrations remove` (slow and it would try to revert
  the DB). A plain file delete is correct here because git preserves history.

If this session cannot delete files on the user's machine directly, move them into a `_to_delete/`
folder and tell the user, or instruct the user to delete the folder contents. Confirm the folder is
empty of migration files (only the folder itself, or nothing, should remain) before Step 4.

---

## Step 4: Create the Single Squashed Migration

Generate one migration that recreates the full current schema:

```bash
dotnet ef migrations add <SquashedName> \
  --project <MigrationsProject> \
  --startup-project <StartupProject> \
  --context <DbContextName>
```

(`--context` is only required when the project has more than one DbContext.)

Verify the result:

- Exactly one new migration `*_<SquashedName>.cs` plus a regenerated `*ModelSnapshot.cs` exist.
- Its `Up()` contains `CreateTable(...)` for the whole schema (not empty, not a diff).
- The model snapshot matches the current model — re-run the pending-changes check from Step 2 and
  confirm it reports nothing pending.

Note the exact MigrationId (the filename prefix, e.g. `20260808120000_SquashedInitial`). You'll need
it for the one-time SQL in Step 6; the startup bootstrapper reads it automatically.

**Fresh/empty databases are now fully handled** — `Database.Migrate()` (or `dotnet ef database
update`) will create the entire schema and record the squashed migration. The remaining steps exist
solely to protect databases that already have the schema.

---

## Step 5: Wire Up Safe Startup Logic (recommended default)

Replace any existing startup migration call (typically `db.Database.Migrate()` in `Program.cs` /
`Startup.cs` / a hosted service) with a bootstrapper that handles all three cases:

- **Empty/new database** → run the squashed migration normally (creates the full schema).
- **Existing pre-squash database** (schema present, squashed ID not in history) → insert the squashed
  migration ID into `__EFMigrationsHistory` WITHOUT running its DDL, then continue.
- **Already-squashed / up-to-date database** → do nothing except apply genuinely new future migrations.

Copy `scripts/MigrationBootstrapper.cs` from this skill into the project (adjust the namespace), and
call it where the app currently calls `Migrate()`. It is provider-agnostic: it uses EF's
`IHistoryRepository.GetInsertScript(...)` so the history-table name and SQL quoting are always correct
for the active provider, and `IRelationalDatabaseCreator` to detect whether the database already has
tables.

Core logic (see the script file for the complete, drop-in version):

```csharp
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage;

public static class MigrationBootstrapper
{
    public static async Task MigrateSafelyAsync(DbContext db, CancellationToken ct = default)
    {
        var creator     = db.GetService<IRelationalDatabaseCreator>();
        var historyRepo = db.GetService<IHistoryRepository>();

        // The single squashed migration is the first one defined in the assembly (earliest ID).
        var squashedId = db.Database.GetMigrations().First();

        var databaseExists = await creator.ExistsAsync(ct);

        // An existing database that already has application tables but has NOT recorded the
        // squashed migration is a pre-squash database: mark the squash as applied, don't run it.
        if (databaseExists && creator.HasTables())
        {
            var applied = (await db.Database.GetAppliedMigrationsAsync(ct)).ToList();
            if (!applied.Contains(squashedId))
            {
                var productVersion = ProductInfo.GetVersion();
                var insertSql = historyRepo.GetInsertScript(new HistoryRow(squashedId, productVersion));

                var strategy = db.Database.CreateExecutionStrategy();
                await strategy.ExecuteAsync(async () =>
                {
                    await using var tx = await db.Database.BeginTransactionAsync(ct);
                    await db.Database.ExecuteSqlRawAsync(insertSql, ct);
                    await tx.CommitAsync(ct);
                });
            }
        }

        // Fresh DB → creates schema + records the squash.
        // Pre-squash DB → squash now recorded, so this only applies genuinely NEW future migrations.
        // Up-to-date DB → no-op.
        await db.Database.MigrateAsync(ct);
    }
}
```

Notes and adaptations:

- `ProductInfo.GetVersion()` lives in `Microsoft.EntityFrameworkCore.Infrastructure` (internal in some
  versions). The script file includes a safe fallback that reads the EF assembly version if that API
  is not accessible, so the value stored in the `ProductVersion` column is always populated.
- `HasTables()` is synchronous on `IRelationalDatabaseCreator`; there is also `HasTablesAsync` in
  recent versions — the script picks whichever exists.
- Wrap the call at startup in the app's normal scope, e.g. in `Program.cs`:
  ```csharp
  using (var scope = app.Services.CreateScope())
  {
      var db = scope.ServiceProvider.GetRequiredService<MyDbContext>();
      await MigrationBootstrapper.MigrateSafelyAsync(db);
  }
  ```
- If the app previously called `db.Database.Migrate()`, remove that call — `MigrateSafelyAsync` calls
  `MigrateAsync` itself.
- The bootstrapper is itself idempotent and safe to keep in the codebase permanently: after every
  database has been squash-marked once, the fake-apply branch simply never triggers again.

---

## Step 6: (Optional) One-Time SQL Fake-Apply Script

For teams whose databases are migrated out-of-band (DBAs running scripts, environments where the app
does not call `Migrate()` at startup), provide a one-time script instead of — or in addition to — the
bootstrapper. Copy `scripts/fake-apply-existing-db.sql`, fill in the squashed MigrationId and the EF
product version, and run it once against each already-migrated database:

```sql
-- SQL Server
IF NOT EXISTS (SELECT 1 FROM [__EFMigrationsHistory] WHERE [MigrationId] = N'20260808120000_SquashedInitial')
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260808120000_SquashedInitial', N'9.0.0');
```

```sql
-- PostgreSQL
INSERT INTO "__EFMigrationsHistory" ("MigrationId", "ProductVersion")
VALUES ('20260808120000_SquashedInitial', '9.0.0')
ON CONFLICT ("MigrationId") DO NOTHING;
```

Use the EXACT MigrationId from Step 4 and a `ProductVersion` matching the app's EF Core version. After
this runs, plain `Database.Migrate()` / `dotnet ef database update` treats the database as up to date.
Old migration ID rows can be left in place (harmless) or deleted for tidiness once the squash row
exists.

---

## Step 7: Verify (do not skip)

Prove all three scenarios before considering the job done:

1. **Fresh database:** point the app (or `dotnet ef database update`) at a brand-new empty database
   and confirm the entire schema is created and the squashed migration is the only history row.
2. **Existing-database copy:** restore a COPY of production (or a representative existing DB) and run
   the app / bootstrapper against it. Confirm:
   - No DDL runs, no errors, no data change.
   - `__EFMigrationsHistory` gains the squashed migration row.
   - `dotnet ef migrations list` (or `GetPendingMigrations()`) shows nothing pending afterward.
3. **Idempotency / future migrations:** run the app twice against the same DB (second run must be a
   no-op), then add a trivial throwaway migration, confirm it applies cleanly on top of the squash,
   and remove it.

Report to the user: the squashed MigrationId, the files changed (Migrations folder, snapshot,
`Program.cs`/bootstrapper), the strategy installed, and a short reminder to back up before deploying
and to run the fresh + prod-copy tests in a safe environment first.

---

## Common Pitfalls (call these out if you see them)

- **Deleting only the migration files but not the `*ModelSnapshot.cs`** → the new migration comes out
  empty. Always delete the snapshot too.
- **Squashing while the model has pending changes** → the squashed schema won't match production.
  Always run the pending-changes check first (Step 2).
- **An environment that was behind on migrations** → fake-applying the squash tells EF that database
  has schema it may not actually have. Get every environment to the latest CURRENT migration before
  squashing.
- **Assuming `Database.Migrate()` alone is enough** → on existing databases it will try to recreate
  the schema. The fake-apply (Step 5 or 6) is mandatory, not optional.
- **Multiple DbContexts** → each has its own history table and must be squashed independently.
- **Reusing the exact name `InitialCreate`** when a matching old `InitialCreate` row might linger →
  prefer a distinct name (e.g. `SquashedInitial`) so the new MigrationId cannot collide with anything
  already in `__EFMigrationsHistory`.
