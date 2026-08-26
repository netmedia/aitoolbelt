# efcore-squash-migrations

A Claude Code skill that collapses a large EF Core migration history into a **single squashed
migration**, removes the old migration files, and wires up safe startup logic so every database is
upgraded correctly — **without losing data and without re-running schema DDL on databases that are
already migrated.**

## What It Does

- Confirms scope (provider, DbContext, migrations folder, squashed name) and runs safety preflight
  checks (clean git tree, backup reminder, verifies there are **no pending model changes**)
- Deletes the old migrations, including the model snapshot, so a clean single migration can be built
- Creates one squashed migration (`dotnet ef migrations add <Name>`) representing the current model
- Installs a provider-agnostic **startup bootstrapper** that:
  - creates the full schema on brand-new/empty databases
  - **fake-applies** the squashed migration on existing databases (records it in
    `__EFMigrationsHistory` without running its DDL) so nothing is recreated and no data is lost
  - is a no-op on databases that are already up to date
- Optionally generates a one-time SQL fake-apply script for databases migrated out-of-band
- Verifies all three scenarios (fresh DB, existing-DB copy, future migration on top)

## Why It Matters

Squashing changes the migration IDs. Existing databases have the *old* IDs in
`__EFMigrationsHistory`, so a plain `Database.Migrate()` would treat the new squashed migration as
pending and try to recreate the entire schema. This skill handles that correctly by marking the
squash as already applied on existing databases.

## Included Files

| File | Purpose |
|------|---------|
| `SKILL.md` | The full guided workflow |
| `skills/.../scripts/MigrationBootstrapper.cs` | Drop-in, provider-agnostic safe-migrate helper for app startup |
| `skills/.../scripts/fake-apply-existing-db.sql` | One-time SQL template to mark the squash applied on existing DBs |

## Requirements

- .NET EF Core project (EF Core 6/7/8/9+) with a standard migrations folder
- `dotnet ef` tooling available (`dotnet tool install --global dotnet-ef` if missing)
- Any relational provider (SQL Server, PostgreSQL, MySQL/MariaDB, SQLite, Oracle)

## Usage

Just describe what you want:

```
"Squash all my EF Core migrations into one"
"Consolidate the migrations but keep production working"
"Rebaseline migrations without losing data"
"Make the app apply the squashed migration safely on existing databases"
```

## Author

**Netmedia**
Website: https://netmedia.agency
Email: netmedia@netmedia.hr
