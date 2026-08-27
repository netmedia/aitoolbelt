---
name: netmedia-net8-to-net10-upgrade
description: >
  Upgrades AND modernizes a .NET 8 (or .NET 6/7/9) solution to .NET 10 LTS — class libraries,
  ASP.NET Core Web APIs, MVC/Razor Pages/Blazor websites, Azure Functions, and EF Core — through
  six gated phases, then rewrites the code to current .NET 10 idioms: WebApplication hosting
  instead of Startup.cs, built-in OpenAPI instead of Swashbuckle, MapStaticAssets, HybridCache,
  AddValidation, isolated-worker Functions, EF Core 10 complex types and named query filters,
  C# 14 syntax, .slnx solutions, and Central Package Management.

  Use this skill whenever the user wants to:
  - Upgrade, migrate, retarget, or modernize a .NET / .NET Core solution to a newer version
  - Move projects from net6.0/net7.0/net8.0/net9.0 to net10.0, or bump a TargetFramework
  - Get off an out-of-support .NET before the November 10, 2026 end-of-support date
  - Migrate Azure Functions from the in-process model to the isolated worker model
  - Find out what will break when a C# solution moves to a newer .NET or EF Core version
  - Modernize legacy ASP.NET Core hosting, Swagger setup, or EF Core mappings

  ALWAYS use this skill when the user mentions: upgrading .NET, ".NET 8 to .NET 10",
  "net8.0 to net10.0", retargeting a solution, EF Core 8/9/10 breaking changes, Functions
  in-process to isolated, or asks whether their solution is ready for .NET 10 — even if they
  never say the word "upgrade".

metadata:
  author: Netmedia
  homepage: https://netmedia.agency
  email: netmedia@netmedia.hr
---

# Netmedia .NET 8 → .NET 10 LTS upgrade and modernization

Two jobs, always both:

1. **Upgrade** — make the solution build, test, and deploy green on `net10.0`.
2. **Modernize** — rewrite code to the idioms .NET 9/10 introduced, and *propose* the rewrites that are too invasive to apply unilaterally.

Never mix the two in one commit. The upgrade must be reviewable on its own.

## Facts that drive every decision

| Fact | Value |
|---|---|
| .NET 10 | GA 2025-11-11, **LTS**, end of support **2028-11-14** |
| .NET 8 | end of support **2026-11-10** |
| .NET 9 | end of support **2026-11-10** — same day as .NET 8 |
| Azure Functions in-process model | end of support **2026-11-10** |
| C# version implied by `net10.0` | **C# 14** |
| EF Core 10 | requires `net10.0`; no `net8.0` asset |
| .NET 10 on Azure Functions | GA, **isolated worker only**, not on Linux Consumption |

Consequences to state to the user up front if they don't already know:

- Do **not** retarget to `net9.0` as a stepping stone. It expires the same day as `net8.0`, so it buys nothing and costs a second full regression pass. Stage the *upgrade axes* instead — SDK, then TFM, then language, then analyzers (Phases 2–5). The one real exception is EF Core 9, which targets .NET 8; see Phase 3.
- If any Functions project is still in-process, that migration is a **hard prerequisite**, not cleanup.
- `dotnet upgrade-assistant` is deprecated. There is no supported deterministic migrator. The sequence in this skill is the replacement.

## Workflow

Work through the phases in order. Each phase ends with a **gate**: `dotnet build` clean and tests green. Do not start a phase before the previous gate passes. Commit at every gate.

### Risky changes: commit before/after, and keep a MUST TEST log

Some changes inside a phase are not mechanical — they're a diagnosis ("this is broken, here's the fix") applied without a way to actually run the app and confirm it. That includes anything in Phase 4, most of Phase 5's judgment-based items, and any change you cannot verify beyond "it compiles." For each one:

1. **Before applying it, offer the user a commit checkpoint** if the working tree has uncommitted changes — a clean "before" commit makes the change bisectable and trivially revertible. Don't ask for permission to commit itself if the user has already authorized commits for this session; just do it, and say so.
2. **Land the risky change as its own commit**, separate from mechanical changes in the same phase, so `git diff <before>..<after>` shows exactly the risky part.
3. **Record it in a `## MUST TEST after upgrade` section** in `UPGRADE-PLAN.md` (append one row per item, don't wait until the end — add it right after the commit lands, while the reasoning is fresh). Columns: risk description, files touched, before-commit SHA, after-commit SHA, what to test, how to test. This is what makes the difference between "hope it works" and "here's exactly what to click/run to find out."
4. **Verify your own diagnosis before applying the fix**, not just before shipping it. The single most expensive mistake in this category is fixing a *suspected* breaking change based on the API surface alone (e.g., "this call is obsolete/ignored, so behavior must be broken") without checking how the affected data is *consumed* downstream. Concretely: before changing an auth/claims/serialization default, grep for every place that reads the thing you're about to change the shape of, and confirm your fix's output matches what those readers expect — not just what the framework's default *used to be* or what a migration doc says the "old" behavior was. A change that "fixes" a bug that was never actually happening (because some other default was already compensating) is worse than not fixing it, because it ships with a clean build and a compelling-sounding commit message. If you find you were wrong after already committing the fix, revert immediately, as its own commit, and record the incident in the MUST TEST log the same way (before/after refs spanning the bad window) — don't silently amend history.

### Phase 0 — Inventory

Run the scanner before reading anything else, from the solution root. Use its **absolute path** — the working directory is the user's repo, not the skill folder:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/skills/netmedia-net8-to-net10-upgrade/scripts/inventory.py . --out UPGRADE-PLAN.md --json inventory.json
```

On Windows the interpreter is usually `python`; elsewhere `python3`. Stdlib only, no dependencies, read-only — it never writes into the scanned tree. If neither interpreter is present, fall back to reading the `.csproj` files directly and working the reference checklists by hand.

It classifies every project (library / web / functions / test / worker), extracts TFMs and package versions, and greps for the ~40 known upgrade landmines. Read `UPGRADE-PLAN.md`, then read only the reference files the findings point at.

Fill in `assets/UPGRADE-PLAN-template.md` with:

- project inventory and the order projects will be retargeted
- every blocker found (see **Blockers** below)
- what will be applied vs. what will be proposed for review

Show the plan to the user and get agreement on scope before editing anything. If working unattended, state the chosen scope at the top of the report and proceed.

### Phase 1 — Baseline hygiene (still `net8.0`)

Set the ground rules before any TFM moves. Copy from `assets/`:

- `global.json` — pin SDK `10.0.100`, `rollForward: latestFeature`
- `Directory.Build.props` — shared TFM, `LangVersion`, nullable, analyzer level **pinned to `8.0`**, audit settings
- `Directory.Packages.props` — Central Package Management, transitive pinning

Pinning `AnalysisLevel` to `8.0` and `LangVersion` to `12` here is deliberate: it keeps the analyzer and C# 14 waves out of the retarget commit. They get unpinned in Phase 5.

Gate: builds and tests still green on `net8.0`.

### Phase 2 — SDK-only bump (still `net8.0`)

Build the unchanged solution with the .NET 10 SDK. This surfaces SDK / MSBuild / NuGet breaks in isolation from runtime and language breaks. Expect: `NU1015` (versionless `PackageReference`), `NU1510` (pruned references), transitive vulnerability audit warnings `NU1901`–`NU1904`, terminal-logger output changes, `dotnet` CLI writing to stderr.

Fix these before retargeting. See `references/02-breaking-changes.md` § SDK and NuGet.

Gate: green build on the .NET 10 SDK, `net8.0` target.

### Phase 3 — Retarget, in dependency order

Order matters. Retarget and gate each tier before moving to the next:

1. **Class libraries** → `references/07-libraries-and-tests.md`
2. **Test projects** → `references/07-libraries-and-tests.md` (stay on VSTest; defer Microsoft.Testing.Platform)
3. **Web APIs and websites** → `references/04-aspnetcore.md`
4. **EF Core projects** → `references/05-efcore.md` (run the schema-drift procedure, do not skip it)
5. **Azure Functions** → `references/06-functions.md`

For Functions still on the in-process model, do the model migration **on `net8.0` first**, deploy it, then bump to `net10.0`. Bundling them makes failures undiagnosable.

Gate per tier: build + tests + (for EF) `dotnet ef migrations has-pending-model-changes` clean.

### Phase 4 — Breaking-change sweep

Work `references/02-breaking-changes.md` top to bottom for the items the inventory flagged. The Tier 1 items are the ones that reach production silently:

- `BinaryFormatter` removed (.NET 9)
- SIGTERM / `AppDomain.ProcessExit` no longer fires in plain console apps (.NET 10)
- Configuration binder now preserves `null` — `null` → `int` is silently `0` (.NET 10)
- Cookie auth returns 401/403 instead of 302 on API endpoints (ASP.NET Core 10)
- Forwarded headers from unknown proxies ignored — redirect loops behind reverse proxies
- `Migrate()` throws on pending model changes and inside an external transaction (EF Core 9)
- EF Core 10 injects `Application Name` into connection strings — MSDTC escalation risk in mixed EF/Dapper code
- Durable Functions default serializer Newtonsoft → System.Text.Json, affecting **persisted** orchestration state
- DATAS on by default for Server GC (.NET 9) — benchmark before and after

Gate: green build, green tests, and a smoke deploy to a non-production environment.

### Phase 5 — Modernization

Only now unpin `LangVersion` and raise `AnalysisLevel`. Land each of these as its **own** commit, in this order (cheapest and safest first):

1. `dotnet sln migrate` → `.slnx`, deleting the `.sln` in the same commit — `references/01-solution-hygiene.md`
2. Mechanical C# 14 sweep: `field` keyword, collection expressions, `System.Threading.Lock`, null-conditional assignment — `references/03-csharp-modernization.md` Tier A
3. Hosting: `Startup.cs` → `WebApplication` builder, endpoint/service extension methods — `references/04-aspnetcore.md` § 2
4. `UseStaticFiles` → `MapStaticAssets`, `TypedResults`, route groups — `references/04-aspnetcore.md` § 1
5. Swashbuckle → built-in OpenAPI + Scalar — `references/04-aspnetcore.md` § 1.1
6. `AddValidation()`, `IExceptionHandler` + ProblemDetails, HybridCache — `references/04-aspnetcore.md`
7. Source generators: `[LoggerMessage]`, `[GeneratedRegex]`, STJ source generation — `references/07-libraries-and-tests.md`
8. EF Core: complex types, named query filters, `ExecuteUpdateAsync`, compiled models — `references/05-efcore.md`
9. Nullable reference types, phased `warnings` → `annotations` → `enable` — `references/07-libraries-and-tests.md`. **If the project has EF Core entities, flipping to `enable` is not just a warnings change — it silently changes which properties EF Core's model considers `Required`.** Run the EF-model-drift check in that reference file's "Nullable reference types on a legacy codebase" section immediately after the flip, before moving on. Skipping this can produce a migration that coerces existing `NULL` data to empty strings the next time someone runs `dotnet ef migrations add` without noticing the drift

**Apply vs. propose.** Apply anything mechanical and locally verifiable. *Propose* — as a diff in the report, not as an edit — anything that changes a public API surface, a database schema, a serialized wire format, or a deployment topology. Specifically propose rather than apply:

- Swashbuckle → built-in OpenAPI where custom filters exist (client generators downstream may break on OpenAPI 3.1 output)
- `OwnsOne` → complex types (produces migrations, renames columns)
- `params T[]` → `params ReadOnlySpan<T>` on public APIs (binary breaking)
- extension members, partial constructors, union-shaped refactors
- hosting-plan migrations (Linux Consumption → Flex Consumption)
- Microsoft.Testing.Platform adoption (all-or-nothing per solution, breaks CI invocations)

**Every proposed-not-applied item is a numbered, self-contained backlog entry, not a one-line note.** The upgrade session ends; a *different* session, possibly weeks later with zero memory of this conversation, is what actually executes these. Write each one so that session can act on just the entry — treat it like handing the task to a new hire who has the repo but not your context. For each item in `UPGRADE-PLAN.md`'s `## Follow-up backlog` section, include:

1. **Origin and status** — which phase surfaced it, and why it wasn't applied now (scope larger than expected, needs a design decision, no current usage to convert, etc.) — the *reason*, not just "deferred."
2. **Every current call site**, as a table or list: exact file path, line number(s), and a one-line description of what's there. Get this from a fresh grep at write-time, not from memory of what you saw earlier in the session — code shifts line numbers as you edit.
3. **The actual blocker**, explained concretely enough that someone unfamiliar with the investigation understands *why* this isn't a five-minute mechanical change — an API shape mismatch, a downstream contract risk, a hazard specific to this codebase's architecture (name the exact class/method that creates the hazard).
4. **A concrete step-by-step execution plan** — not "consider doing X" but an ordered list a fresh session can follow: what to add, what to touch first (and why that one first — usually lowest-risk or highest-value), what to check before proceeding to the next file, where the genuinely hard decision point is (and what the options are, if it's a design choice rather than a mechanical one).
5. **A verification section** — what to run or exercise afterward to confirm it worked, specific to this item (not a generic "run the tests").

Numbered so the user can say "tackle #3" in a future session and you can jump straight to it. Do not compress this into a single paragraph per item — under-detailing here just relocates the investigation work you already did back onto a future session that has to redo it from scratch.

### Phase 6 — Verify

- `dotnet build -warnaserror`
- full test suite
- `dotnet format --verify-no-changes`
- `dotnet package list --vulnerable --include-transitive`
- EF: `dotnet ef migrations has-pending-model-changes`, plus a diff of `migrations script 0 --idempotent` before vs after. **If Phase 5 flipped `Nullable` to `enable` on any EF Core project, this is not redundant with Phase 3d's check** — Phase 3d ran before the nullable flip, so it cannot have caught the model drift that flip introduces. Treat a crash (not just "pending changes") here as expected-until-proven-otherwise on a legacy codebase; see `references/07-libraries-and-tests.md`'s EF-model-drift check
- benchmark GC shape and a representative hot path (DATAS, memory-pool eviction, and the EF parameter-mode change all move numbers)
- verify behind the *real* reverse proxy / IIS, not just Kestrel locally
- re-check observability: handled-exception diagnostics, W3C trace propagation, EF SQL parameter names in log queries

Report what changed, what was proposed and not applied, and every residual warning suppression with an owner. Make sure `UPGRADE-PLAN.md`'s `## MUST TEST after upgrade` section (see Workflow above) is complete and current — every risky change from every phase, each with its before/after commit pair, what to test, and how. Make sure `## Follow-up backlog` (see Phase 5's "Apply vs. propose" above) has one fully-detailed, numbered entry per proposed-not-applied item across the whole upgrade, not just Phase 5's. These two sections are the actual handoff artifact when there's no environment in which to run the app yourself, or when the user starts a fresh session later to work the backlog one item at a time — treat both as required output, not optional documentation.

## Blockers to surface immediately

Stop and tell the user if the inventory finds any of these — they change the project's shape:

| Blocker | Why |
|---|---|
| `Pomelo.EntityFrameworkCore.MySql` | No EF Core 10 release; 9.0.0 hard-caps `Relational` at `<= 9.0.999`. Re-check NuGet before planning. |
| Functions on **Linux Consumption** | .NET 10 unsupported there. Forces a new app on Flex Consumption; no in-place plan migration, and Flex has no deployment slots. |
| Live in-flight Durable orchestrations | Serializer change corrupts persisted state. Drain or pin the serializer first. |
| `BinaryFormatter` on persisted data | Removed in .NET 9. Needs a real format migration, not a compat shim. |
| Third-party provider or analyzer with no `net10.0` build | Blocks the whole tier. Check every non-Microsoft package early. |
| Mixed EF Core + Dapper inside `TransactionScope` | EF 10's `Application Name` injection can escalate to a distributed transaction. Set `Application Name` explicitly. |

## Reference files

Read on demand — do not preload.

| File | Read when |
|---|---|
| `references/01-solution-hygiene.md` | Phase 1 and 5.1 — `.slnx`, CPM, `Directory.Build.props`, analyzers, NuGet audit, CI |
| `references/02-breaking-changes.md` | Phase 2 and 4 — every runtime/SDK/BCL/C# break from .NET 9 and 10, tiered by impact |
| `references/03-csharp-modernization.md` | Phase 5.2 — C# 13/14 rewrite catalogue, mechanical vs. judgment, compiler binding breaks |
| `references/04-aspnetcore.md` | Any Web API / MVC / Razor Pages / Blazor project |
| `references/05-efcore.md` | Any project referencing EF Core |
| `references/06-functions.md` | Any Azure Functions project |
| `references/07-libraries-and-tests.md` | Class libraries, nullable rollout, source generators, test projects |

## Assets

`assets/global.json`, `assets/Directory.Build.props`, `assets/Directory.Packages.props`, `assets/UPGRADE-PLAN-template.md` — copy and adapt; do not invent equivalents.

## Ground rules

- Verify every package version against NuGet at upgrade time. Versions in the references were correct in August 2026 and drift monthly.
- Never suppress a warning without recording why and who owns removing the suppression.
- Never carry a compat shim (`EnableUnsafeBinaryFormatterSerialization`, `Pre10TimeZoneHandling`, `LegacyExceptionHandling`) without an expiry date in the report.
- When a doc claim and the shipped assembly disagree, trust the assembly and say so.
