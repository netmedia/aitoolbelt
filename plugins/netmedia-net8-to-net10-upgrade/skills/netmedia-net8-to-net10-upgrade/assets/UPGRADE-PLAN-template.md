# .NET 10 upgrade plan — <SOLUTION NAME>

Author: <name> · Date: <date> · Scanner output: `inventory.json`

## 1. Decision summary

| | |
|---|---|
| Target | `net10.0` (LTS, end of support 2028-11-14) |
| Reason | .NET 8 end of support **2026-11-10** |
| Intermediate stop at `net9.0`? | **No** — .NET 9 expires the same day as .NET 8 |
| C# version | 14, adopted in Phase 5 (retarget ships on `LangVersion 12`) |
| Solution file | `.sln` → `.slnx` in Phase 5.1 / stay on `.sln` because <reason> |
| Estimated tiers | libraries → tests → web → EF → functions |

## 2. Blockers

Anything here must be resolved or explicitly accepted before Phase 3 starts.

| Blocker | Projects | Decision | Owner |
|---|---|---|---|
| e.g. Pomelo MySQL has no EF Core 10 release | | | |
| e.g. Functions app X still in-process | | | |
| e.g. Live Durable orchestrations | | | |

## 3. Project inventory and retarget order

| # | Project | Kind | Current TFM | Notes |
|---|---|---|---|---|
| 1 | | library | net8.0 | |
| 2 | | test | net8.0 | |
| 3 | | web | net8.0 | |
| 4 | | functions | net8.0 | in-process → isolated first, on net8.0 |

## 4. Scope: applied vs proposed

**Will apply in this work:**

- [ ] SDK pin, `Directory.Build.props`, Central Package Management
- [ ] TFM bump to `net10.0` across all tiers
- [ ] Breaking-change fixes (list the specific ones from the scan)
- [ ] Mechanical C# 14 sweep: `field`, collection expressions, `Lock`, null-conditional assignment
- [ ] `Startup.cs` → `WebApplication` builder
- [ ] `UseStaticFiles` → `MapStaticAssets`
- [ ] `[LoggerMessage]`, `[GeneratedRegex]`, STJ source generation

**Will propose as diffs, not apply:**

- [ ] Swashbuckle → built-in OpenAPI (downstream client generators may break on 3.1 output)
- [ ] `OwnsOne` → EF complex types (produces migrations / column renames)
- [ ] `params T[]` → `params ReadOnlySpan<T>` on public APIs (binary breaking)
- [ ] Microsoft.Testing.Platform (all-or-nothing per solution, breaks CI invocations)
- [ ] Hosting-plan migration (Linux Consumption → Flex Consumption)
- [ ] Nullable `warnings` → `enable` (separate, ongoing work)

## 5. Phase log

| Phase | Gate | Status | Commit |
|---|---|---|---|
| 0 Inventory | plan agreed | | |
| 1 Baseline hygiene | build + tests green on net8.0 | | |
| 2 SDK-only bump | build green on SDK 10, still net8.0 | | |
| 3a Libraries retargeted | build + tests green | | |
| 3b Tests retargeted | tests green | | |
| 3c Web retargeted | build + smoke test | | |
| 3d EF retargeted | `has-pending-model-changes` clean, script diff reviewed | | |
| 3e Functions retargeted | deployed to slot, swapped | | |
| 4 Breaking-change sweep | non-prod smoke deploy | | |
| 5 Modernization | one commit each | | |
| 6 Verification | see below | | |

## 6. Verification results

- [ ] `dotnet build -warnaserror`
- [ ] Full test suite
- [ ] `dotnet format --verify-no-changes`
- [ ] `dotnet package list --vulnerable --include-transitive`
- [ ] `dotnet ef migrations has-pending-model-changes`
- [ ] Migration script diff before vs after reviewed
- [ ] Verified behind the real reverse proxy / IIS (forwarded headers, cookie auth 401/403)
- [ ] GC / memory re-baselined (DATAS, Kestrel memory-pool eviction)
- [ ] Hot-path benchmark compared (EF parameter mode, JSON, LINQ)
- [ ] Observability checked: handled-exception diagnostics, W3C trace propagation, EF SQL parameter names in log queries

## 7. Residual risk

Every suppression, shim, and deferred item — with an owner and an expiry date.

| Item | Where | Why | Owner | Expires |
|---|---|---|---|---|
| e.g. `EnableUnsafeBinaryFormatterSerialization` | `Legacy.Cache` | Persisted blobs not yet re-serialized | | |
| e.g. `Pre10TimeZoneHandling` switch | test project | SQLite assertions assume local time | | |
| e.g. `NuGetAuditMode=direct` | root props | Transitive CVEs in <package> unfixable today | | |
