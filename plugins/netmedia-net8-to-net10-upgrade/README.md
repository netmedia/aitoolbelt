# Netmedia NET8toNET10 Upgrade

A Claude Code skill that takes a .NET 8 solution to **.NET 10 LTS** — and then modernizes it.
Two jobs, always both, never in the same commit:

1. **Upgrade** — make the solution build, test, and deploy green on `net10.0`.
2. **Modernize** — rewrite the code to the idioms .NET 9/10 introduced, and *propose* the rewrites
   that are too invasive to apply unilaterally.

Covers class libraries, ASP.NET Core Web APIs, MVC/Razor Pages/Blazor websites, Azure Functions,
and EF Core.

## Why Now

| Fact | Date |
|------|------|
| .NET 8 end of support | **2026-11-10** |
| .NET 9 end of support | **2026-11-10** — same day, so stopping at net9.0 buys nothing |
| Azure Functions **in-process** model end of support | **2026-11-10** |
| .NET 10 (LTS) end of support | 2028-11-14 |

.NET 10 is not supported in-process at all, so for Functions apps the isolated-worker migration is
a hard prerequisite, not cleanup. `dotnet upgrade-assistant` is deprecated and there is no
supported deterministic migrator — the phased sequence in this skill is the replacement.

## What It Does

Six phases, each ending in a gate (`dotnet build` clean + tests green) with a commit:

| Phase | What happens |
|-------|--------------|
| **0 Inventory** | `scripts/inventory.py` scans the solution, classifies every project, and greps for ~40 known landmines. Produces `UPGRADE-PLAN.md`. |
| **1 Baseline hygiene** | SDK pin, `Directory.Build.props`, Central Package Management — still on `net8.0`. `AnalysisLevel` and `LangVersion` deliberately pinned low. |
| **2 SDK-only bump** | Build unchanged code on the .NET 10 SDK to surface NU1015 / NU1510 / audit breaks in isolation. |
| **3 Retarget** | In dependency order: libraries → tests → web → EF Core → Functions. Gated per tier. |
| **4 Breaking-change sweep** | The .NET 9 + .NET 10 changes that reach production silently. |
| **5 Modernization** | `.slnx`, C# 14, hosting, OpenAPI, validation, source generators, EF Core — one commit each. |
| **6 Verify** | Build, tests, format, vulnerability audit, EF drift check, GC/hot-path benchmarks, real-proxy verification. |

It distinguishes **apply** from **propose**: anything that changes a public API surface, a database
schema, a serialized wire format, or a deployment topology is proposed as a diff for review rather
than edited.

## Blockers It Catches

- Azure Functions still on the in-process model (and in-flight Durable orchestrations, whose
  **persisted state** is affected by the Newtonsoft → System.Text.Json serializer change)
- `Pomelo.EntityFrameworkCore.MySql` — still no EF Core 10 release
- Functions on Linux Consumption — .NET 10 is unsupported there, forcing a new app on Flex Consumption
- `BinaryFormatter` on persisted data
- Mixed EF Core + Dapper inside `TransactionScope` — EF 10's `Application Name` injection can
  escalate to a distributed transaction
- `Migrate()` inside an explicit transaction — throws since EF Core 9

## Included Files

| File | Purpose |
|------|---------|
| `SKILL.md` | The six-phase workflow, gates, and apply-vs-propose rules |
| `scripts/inventory.py` | Read-only solution scanner → `UPGRADE-PLAN.md` + `inventory.json` (stdlib only) |
| `references/01-solution-hygiene.md` | `.slnx`, CPM, `Directory.Build.props`, analyzers, NuGet audit, CI changes |
| `references/02-breaking-changes.md` | Every .NET 9 + 10 runtime/SDK/BCL break, tiered by impact |
| `references/03-csharp-modernization.md` | C# 13/14 rewrite catalogue + the silent overload-resolution traps |
| `references/04-aspnetcore.md` | Web API and website upgrade + modernization |
| `references/05-efcore.md` | EF Core 8 → 10, breaking changes, schema-drift procedure |
| `references/06-functions.md` | In-process → isolated worker, .NET 10, Durable, hosting plans |
| `references/07-libraries-and-tests.md` | Class libraries, nullable rollout, source generators, test projects |
| `assets/` | `global.json`, `Directory.Build.props`, `Directory.Packages.props`, upgrade-plan template |

## Requirements

- .NET 10 SDK on the machine doing the upgrade
- `dotnet ef` tooling for any project using EF Core
- Python 3 for the inventory scanner (stdlib only, read-only, never writes into the scanned tree)
- Azure Functions Core Tools 4.x (latest) for Functions projects — install both .NET 8 and .NET 10
  SDKs on build agents, as Core Tools has known issues with .NET 10-only agents

## Usage

Just describe what you want:

```
"Upgrade this solution to .NET 10"
"What breaks if we move from net8.0 to net10.0?"
"We need off .NET 8 before support ends — plan it"
"Migrate our Functions apps to the isolated worker model"
"Modernize the Startup.cs and Swagger setup while you're in there"
```

Start with the inventory:

```bash
python3 scripts/inventory.py C:\path\to\solution --out UPGRADE-PLAN.md --json inventory.json
```

## Accuracy

All version numbers, end-of-support dates, error codes, and default-value changes were verified
against Microsoft primary sources (learn.microsoft.com, dotnet.microsoft.com, nuget.org) in
August 2026. Package versions drift monthly — the skill instructs re-verification at upgrade time.

## Author

**Netmedia**
Website: https://netmedia.agency
Email: netmedia@netmedia.hr
