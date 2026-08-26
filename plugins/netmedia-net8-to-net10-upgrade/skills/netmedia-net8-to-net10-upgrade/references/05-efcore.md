# EF Core 8 → EF Core 10

EF Core 10 **requires `net10.0`** — no `net8.0`/`net9.0` asset exists, and no multi-targeting is possible. EF Core 8 support ends 2026-11-10.

Contents: [Packages](#packages-and-version-alignment) · [Breaking: EF 9](#breaking-changes--ef-core-9) · [Breaking: EF 10](#breaking-changes--ef-core-10) · [Migration mechanics](#migration-mechanics) · [Silent behaviour changes](#silent-behaviour-changes) · [Adopt](#what-to-adopt)

## Packages and version alignment

All Microsoft EF packages ship in lockstep and must be pinned to the same `10.0.x` — put a single `EFCoreVersion` property in `Directory.Packages.props`.

```xml
<PackageReference Include="Microsoft.EntityFrameworkCore" />
<PackageReference Include="Microsoft.EntityFrameworkCore.SqlServer" />
<PackageReference Include="Microsoft.EntityFrameworkCore.Design">
  <PrivateAssets>all</PrivateAssets>
  <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
</PackageReference>
<PackageReference Include="Microsoft.EntityFrameworkCore.Tools" />
```

Rules:

1. All `Microsoft.EntityFrameworkCore.*`: identical version, matching TFM.
2. Third-party providers: **major version must equal the EF Core major version**. Providers declare `Relational (>= N.0.0 && <= N.0.999)`; NuGet hard-fails on mismatch.
3. `dotnet-ef` tool version ≥ the runtime version: `dotnet tool update --global dotnet-ef`. EF 10 tooling still works against EF 8/9 runtime projects but needs the .NET 10 SDK.
4. Take the latest patch — verify on nuget.org at upgrade time; these move monthly.

**Provider status (verify before planning):**

| Provider | Status |
|---|---|
| SQL Server / SQLite / Cosmos / InMemory (Microsoft) | 10.x, targets `net10.0` |
| `Npgsql.EntityFrameworkCore.PostgreSQL` | 10.x, GA alongside EF 10, no lag |
| **`Pomelo.EntityFrameworkCore.MySql`** | **BLOCKER** — latest stable 9.0.0 targets `net8.0` and caps `Relational` at `<= 9.0.999`. Track [#2016](https://github.com/PomeloFoundation/Pomelo.EntityFrameworkCore.MySql/issues/2016). Pomelo historically lags each EF major by 6–12 months. Re-check NuGet before committing to a date. |

**SQL Server engine:** provider docs say SQL Server 2019 onwards. There is **no minimum-version bump** in EF 9 or 10. The compatibility-level default went the *other* way — EF 9 **lowered** `UseSqlServer`'s default from 160 to 150 (so `LEAST`/`GREATEST`, which need 160, are off unless you opt in). EF 10: 150 for `UseSqlServer`, **170 for `UseAzureSql`**.

```csharp
optionsBuilder.UseSqlServer(cs, o => o.UseCompatibilityLevel(160));
```

This configures EF's SQL generation only — it does not change the database's own compatibility level.

## Breaking changes — EF Core 9

[Full list](https://learn.microsoft.com/en-us/ef/core/what-is-new/ef-core-9.0/breaking-changes)

### High impact — these fail at first boot

**`Migrate()` throws if the model has pending changes.** Fires whenever the compiled model differs from `<Context>ModelSnapshot.cs`. Non-obvious triggers:

- non-deterministic model building (`DateTime.Now`, `Guid.NewGuid()` inside `HasData`)
- last migration generated for a different provider
- ASP.NET Core Identity where model-affecting options (`Stores.SchemaVersion`, `Stores.MaxLengthForKeys`) are configured in DI but not at design time — fix with an `IDesignTimeDbContextFactory<T>` that builds the same service collection

Escape hatch only if you control drift another way: `options.ConfigureWarnings(w => w.Ignore(RelationalEventId.PendingModelChangesWarning))`.

**`Migrate()` throws inside an explicit transaction.** The common "resilient migration" pattern is now an error:

```csharp
// NO LONGER VALID
await db.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
{
    await using var tx = await db.Database.BeginTransactionAsync(ct);
    await db.Database.MigrateAsync(ct);
    await tx.CommitAsync(ct);
});

// correct on EF 9+
await db.Database.MigrateAsync(ct);
```

EF 9+ starts its own transaction, runs under an `ExecutionStrategy`, and takes a **migration lock** so concurrent instances (multiple pods starting at once) can't collide. **Audit every `Migrate()` / `MigrateAsync()` call site before deploying.**

### Medium / low impact

| Change | Effect |
|---|---|
| `Microsoft.EntityFrameworkCore.Design` not found with SDK ≥ 9.0.200 | Add `<Publish>true</Publish>` to the `.Design` reference. Fixed properly in EF 10. |
| **`ToString()` returns `""` for `null`** | `x.NullableBool.ToString()` previously could yield `null` or `"True"`. |
| **C#-semantics nullable comparisons** | See [silent behaviour changes](#silent-behaviour-changes) — **row counts change**. |
| `EF.Constant()`/`EF.Parameter()` inside compiled queries | Now throws `InvalidCastException`. Remove the call or stop using `EF.CompileQuery`. |
| `AsNoTrackingWithIdentityResolution` + LINQ operators on JSON collection navigations | Now throws instead of silently corrupting materialization. Use `AsTracking()` or plain `AsNoTracking()`. |
| Compiled models reference value-converter methods directly | `private static` converter methods break compilation of the generated model. Make them `public`/`internal`. |
| All pending migrations in one transaction | **Reverted in EF Core 10** — back to one transaction per migration. If you relied on EF 9's all-or-nothing deploy semantics, EF 10 undoes that. |
| EF tools no longer support .NET Framework projects | Startup project must target .NET. |

### Azure Cosmos DB (EF 9) — changes the on-disk JSON

Existing containers break on upgrade unless configured back:

| Change | Old | New | Opt-out |
|---|---|---|---|
| Discriminator property | `Discriminator` | `$type` | `HasDiscriminator<string>("Discriminator")` |
| `id` content | `"Blog\|8"` | `"8"` | `HasDiscriminatorInJsonId()` |
| Key mapped to JSON `id` | shadow `id` + separate key prop | key prop *is* `id` | `HasShadowId()` / `modelBuilder.HasShadowIds()` |
| Sync I/O | blocked | **throws** | `ConfigureWarnings(w => w.Ignore(CosmosEventId.SyncNotSupported))` — removal planned |
| Raw SQL projections | `SELECT c["City"]` | requires `SELECT VALUE c["City"]` | add `VALUE` |
| `undefined` results | surfaced as `null` | filtered out | `EF.Functions.CoalesceUndefined(c.City, null)` |
| `.Take(5).Where(…)` | silently mistranslated | throws | reorder to `.Where(…).Take(5)` |
| `HasIndex` on Cosmos | ignored | throws | remove |

## Breaking changes — EF Core 10

[Full list](https://learn.microsoft.com/en-us/ef/core/what-is-new/ef-core-10.0/breaking-changes) — much shorter than EF 9's.

**`--framework` now required for multi-targeted projects.** CI-breaker for any repo whose DbContext project uses `<TargetFrameworks>`:

```bash
dotnet ef migrations add MyMigration --framework net10.0
```

**`Application Name` injected into the connection string.** EF injects an anonymous `Application Name` (EF + SqlClient versions) if you didn't set one. Consequence: **SqlClient uses a different connection pool** from your non-EF data access (Dapper/ADO.NET) against the same database. Inside a `TransactionScope` this can **escalate to a distributed transaction (MSDTC)**.

> Set `Application Name=MyApp` explicitly in every SQL Server connection string as part of the upgrade. EF will not overwrite it. This is the single most likely production surprise in a mixed EF/Dapper codebase.

**SQL Server native `json` type by default on Azure SQL / compat ≥ 170.** With `UseAzureSql`, upgrading generates a migration altering every `nvarchar(max)` JSON column to `json`. Supported, but a non-trivial database change. On-premises `UseSqlServer` defaults to 150, so this does not fire there. Opt out with `UseCompatibilityLevel(160)` or `HasColumnType("nvarchar(max)")` per property.

**Complex type column names are now uniquified**, and **nested complex type properties use the full path** (`NestedComplex_Property` → `Complex_NestedComplex_Property`). Both **produce migrations**. Preserve the old shape with explicit `HasColumnName(…)` if you don't want the rename.

**`ExecuteUpdateAsync` accepts a non-expression lambda** — source-breaking for code that built `Expression<Func<SetPropertyCalls<T>, …>>` trees by hand. Delete those helpers.

**SQL parameter names simplified**: `@__city_0` → `@city`. Breaks SQL snapshot/approval tests and interceptors parsing `CommandText`. Docs warn to **expect a temporary query-plan compilation spike after deployment** — every cache entry is new text.

**`IRelationalCommandDiagnosticsLogger` methods take a new `logCommandText` parameter**, backing constant redaction in logs. `IDiscriminatorPropertySetConvention.ProcessDiscriminatorPropertySet`'s first parameter changed to `IConventionTypeBaseBuilder`. Update custom loggers, interceptors, and conventions.

**Logging redacts inlined constants by default** (`IN (?, ?)`). Use `EnableSensitiveDataLogging()` to see values. A new analyzer warns on string concatenation into `FromSqlRaw`/`ExecuteSqlRaw`.

**Microsoft.Data.Sqlite time-zone handling** (only matters if you use SQLite, including in tests) — three changes gated by one switch:

```csharp
AppContext.SetSwitch("Microsoft.Data.Sqlite.Pre10TimeZoneHandling", isEnabled: true);
```

`GetDateTimeOffset` on text without an offset now assumes UTC (was local); `DateTimeOffset` → REAL is converted to UTC first; `GetDateTime` on text with an offset returns `DateTimeKind.Utc`. Integration tests asserting on `DateTime` will fail on non-UTC machines. Fix the assertions; treat the switch as a stopgap with an expiry date.

## Migration mechanics

**Existing migration files are not rewritten and not re-executed.** `__EFMigrationsHistory` rows stay valid — EF matches on `MigrationId` only; `ProductVersion` is informational. There is no model-snapshot format break between 8, 9, and 10.

**Will a migration be generated?** Not spuriously, but genuinely non-empty in these enumerable cases: nested complex types (column renames), complex types with colliding column names, `UseAzureSql`/compat ≥ 170 with JSON mappings (`nvarchar(max)` → `json`), and provider-specific convention changes. Parameter naming and parameterized-collection mode are **query-time only** and produce no migration.

**Drift-check procedure — run it, don't assume:**

```bash
# 1. Baseline from HEAD, before touching packages
dotnet ef migrations script 0 --idempotent -o before.sql --framework net8.0

# 2. Upgrade packages + TFM, build.

# 3. Does EF think the model diverged from the snapshot?
dotnet ef migrations has-pending-model-changes --framework net10.0   # exit 0 = clean

# 4. Regenerate under EF 10 and diff
dotnet ef migrations script 0 --idempotent -o after.sql --framework net10.0
diff before.sql after.sql

# 5. Probe migration must be empty
dotnet ef migrations add __Probe --framework net10.0
#    inspect Up()/Down(), then:
dotnet ef migrations remove --framework net10.0
```

Step 4's diff can be noisy-but-harmless if generated DDL text changed; steps 3 and 5 are authoritative. Make it permanent in CI:

```csharp
Assert.False(context.Database.HasPendingModelChanges());
```

**Migration execution semantics moved twice:**

| | EF 8 | EF 9 | EF 10 |
|---|---|---|---|
| Transaction scope | per migration | **all pending in one** | reverted → per migration |
| Concurrency lock | none | DB lock | DB lock |
| External transaction around `Migrate()` | allowed | throws | throws |
| Pending model changes at `Migrate()` | ignored | throws | throws |

## Silent behaviour changes

These change results without erroring. Each deserves a targeted test.

### `Contains` over a collection — three SQL shapes across three versions

```csharp
int[] ids = [1, 2, 3];
var blogs = await db.Blogs.Where(b => ids.Contains(b.Id)).ToListAsync();
```

| Version | SQL |
|---|---|
| EF 7 and earlier | `IN (1, 2, 3)` |
| EF 8 / 9 | `IN (SELECT [i].[value] FROM OPENJSON(@__ids_0) …)` |
| **EF 10** | `IN (@ids1, @ids2, @ids3)` — multiple parameters, padded to bucket sizes |

**Practical risk:** with a large `Contains` list (thousands of ids), EF 10 emits thousands of parameters. SQL Server's hard limit is **2100 parameters** (documented per stored procedure / UDF, which is what parameterized queries hit via `sp_executesql`). Code that relied on `OPENJSON` to carry big lists must opt back:

```csharp
optionsBuilder.UseSqlServer(cs, o => o.UseParameterizedCollectionMode(ParameterTranslationMode.Parameter));
```

Per query: `EF.Constant(ids).Contains(…)` / `EF.Parameter(ids).Contains(…)`. Expect one-time plan-cache churn either way.

### Nullable comparison semantics (EF 9) — row counts change

```csharp
db.Entities.Where(x => !(x.NullableIntOne > x.NullableIntTwo))
// EF 9+: CASE WHEN [e].[One] > [e].[Two] THEN 0 ELSE 1 END
```

When either operand is NULL, EF 8 produced SQL three-valued logic (row excluded); EF 9+ matches C# (`!(null > 5)` is `true`, row **included**). **Any predicate shaped `!(a op b)` over nullable columns can return more rows after the upgrade.** Grep for negated comparisons.

### Split queries — ordering fix (EF 10)

EF ≤ 9 omitted the key column from the inner subquery's `ORDER BY` while the outer query ordered by it, which mis-associates rows when the sort key has ties. EF 10 appends the key. **Existing split queries with non-unique `OrderBy` keys legitimately return different (correct) results.** Tests asserting the old grouping will fail — the new results are right.

### Other

- `AsNoTrackingWithIdentityResolution` + JSON collection navigations now throws (EF 9).
- New translations mean expressions that previously client-evaluated or threw may now go to the server — server-side rounding/precision on `datetime2` can differ.
- SQL Server / Npgsql have **no** breaking `DateTime` change in EF 9 or 10; the UTC changes are Microsoft.Data.Sqlite only.
- Npgsql 10 independently changed `arrayColumn.Contains(element)` from the `@>` containment operator to `element = ANY(array)` — **changes GIN index usage**. Re-benchmark array queries.

## What to adopt

### Complex types

EF 10 makes them broadly usable and they are the intended replacement for `OwnsOne` on non-identity value objects:

- **optional** complex types (require at least one required property on the type)
- **structs** (collections of structs not yet supported)
- **collections**: `ComplexCollection(…)`
- JSON mapping: `ComplexProperty(c => c.ShippingAddress, c => c.ToJson())`
- lambda chaining: `.Property(e => e.Details.Description).HasMaxLength(500)`
- value semantics — assigning copies members, unlike owned entities which alias the instance

**Propose, don't apply:** moving `OwnsOne` → complex types produces migrations and column renames (see EF 10 breaking changes).

### Named query filters (EF 10)

```csharp
modelBuilder.Entity<Blog>()
    .HasQueryFilter("SoftDeletionFilter", b => !b.IsDeleted)
    .HasQueryFilter("TenantFilter",       b => b.TenantId == tenantId);

var all = await db.Blogs.IgnoreQueryFilters(["SoftDeletionFilter"]).ToListAsync();
```

The **unnamed** overload still *replaces* any previous filter — a long-standing footgun. Multitenancy + soft-delete codebases that combined predicates with `&&` should migrate to named filters.

### `LeftJoin` / `RightJoin` (EF 10 + .NET 10 LINQ)

First-class operators replacing the `GroupJoin`/`SelectMany`/`DefaultIfEmpty` incantation:

```csharp
db.Students.LeftJoin(db.Departments,
    s => s.DepartmentID, d => d.ID,
    (s, d) => new { s.FirstName, Department = d.Name ?? "[NONE]" });
```

### `ExecuteUpdateAsync` / `ExecuteDeleteAsync`

Available since EF 7; EF 10 adds the statement-bodied form:

```csharp
await db.Blogs.ExecuteUpdateAsync(s =>
{
    s.SetProperty(b => b.Views, 8);
    if (nameChanged) s.SetProperty(b => b.Name, "foo");
});
```

Limitations (unchanged): no insert, no change-tracker interaction, no automatic optimistic concurrency, executes immediately (not batched with `SaveChanges`), single table, relational only.

### Compiled models

```bash
dotnet ef dbcontext optimize -o Models -n BlogModels -c BlogContext
```

EF 9+ auto-detects the compiled model in the same assembly — no `UseModel(…)` call. MSBuild integration via `Microsoft.EntityFrameworkCore.Tasks` + `<EFOptimizeContext>true</EFOptimizeContext>`. Pays off on large models (hundreds of entity types) at startup only. **Regenerate after the upgrade** — old artifacts are version-specific.

### Free query improvements (no code change)

EF 9: table and projection pruning, inlined uncorrelated subqueries (2 roundtrips → 1), aggregates over subqueries via `OUTER APPLY`, `Count > 0` → `EXISTS`, negation pushdown, `Order()`/`OrderDescending()`, `string.Join` → `CONCAT_WS`, `ToHashSetAsync()`. EF 10: `DateOnly.ToDateTime()`, `DateOnly.DayNumber`, `COALESCE` → `ISNULL` on SQL Server, `MIN`/`MAX` over `DISTINCT`, consecutive `LIMIT` collapsing.

### SQL Server vector search (EF 10)

Requires SQL Server 2025+ / Azure SQL. **Exact search only** in EF 10 — `SqlVector<float>` + `EF.Functions.VectorDistance`. Approximate search with a vector index (`HasVectorIndex`, `VectorSearch()`) is **EF Core 11**, as is SQL Server full-text search and `.config/dotnet-ef.json`. If you already use the community `EFCore.SqlServer.VectorSearch` package, remove it.

## Optional de-risking: take EF Core 9 first, on `net8.0`

**EF Core 9 targets .NET 8.** This is the one place in the whole upgrade where a genuine intermediate stop exists — you can absorb EF 9's behavioural breaks *without* a TFM change, ship that, and only then move to `net10.0` + EF 10.

Worth doing when the codebase has any of: `Migrate()` called at startup, LINQ over nullable columns, Cosmos DB, or compiled queries. Skip it for a small model with a clean migration story.

**Stage A — EF 9 on `net8.0`** (no TFM change, no C# change, no SDK dependency)

1. Bump `Microsoft.EntityFrameworkCore.*` to `9.0.x`; add `<Publish>true</Publish>` to the `.Design` reference.
2. Remove any external transaction / `ExecutionStrategy` wrapper around `Migrate()`.
3. Run `has-pending-model-changes`; fix drift.
4. Audit `!(a op b)` over nullable columns and `.ToString()` on nullables.
5. Remove `EF.Constant`/`EF.Parameter` from `EF.CompileQuery` bodies.
6. Cosmos: decide `$type` / `id` / shadow-id, convert sync calls to async.
7. Note that `UseSqlServer`'s default compat level dropped 160 → 150; add `UseCompatibilityLevel(160)` if you want `LEAST`/`GREATEST`.

Ship and observe. Everything above is a *runtime behaviour* change, and isolating it means a production incident points at EF rather than at the whole platform bump.

**Stage B — `net10.0` + EF 10.** The rest of this document.

> This does **not** generalize to the runtime. There is no useful `net9.0` stop: .NET 9 leaves support the same day as .NET 8, so retargeting to it buys nothing and costs a second full regression pass. Stage the *upgrade axes* instead (SDK → TFM → language → analyzers), which is what `SKILL.md` Phases 2–5 do.

## Checklist

1. Remove any external transaction / `ExecutionStrategy` wrapper around `Migrate()`.
2. Run `has-pending-model-changes`; fix drift (Identity → `IDesignTimeDbContextFactory`, non-deterministic `HasData`).
3. Audit `!(a op b)` over nullable columns and `.ToString()` on nullables.
4. Remove `EF.Constant`/`EF.Parameter` from `EF.CompileQuery` bodies.
5. Make value-converter static methods `public`/`internal` if using compiled models.
6. Verify every third-party provider has a 10.x release.
7. Add `Application Name=<app>` to every SQL Server connection string.
8. Add `--framework net10.0` to `dotnet ef` calls in CI for multi-targeted projects.
9. Decide `ParameterTranslationMode` if you pass large `Contains` lists.
10. Accept or opt out of the `nvarchar(max)` → `json` migration under `UseAzureSql`.
11. Regenerate compiled models.
12. Update SQL snapshot tests for `@__x_0` → `@x` and redacted constants.
13. Review split queries with non-unique `OrderBy` keys.
14. Run the full drift procedure and add `HasPendingModelChanges()` as a permanent CI test.
