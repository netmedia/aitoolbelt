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

## MUST TEST after upgrade

Every change that altered real runtime behavior (or could have) and was **not** confirmed against
a running instance. Add a row the moment the change lands, not at the end when the reasoning has
gone cold. `before`/`after` are commit SHAs (or short refs) bracketing exactly that change, so
`git diff <before>..<after> -- <files>` shows precisely what to inspect, and `git checkout
<before>` gives a known-good comparison point. If a change turns out to be wrong and gets reverted,
keep the row — mark the range that had the bug live (`broken: <bad-sha>..<fix-sha>`) rather than
deleting the history.

| # | Risk | Files | Before | After | What to test | How to test |
|---|---|---|---|---|---|---|
| 1 | e.g. `MapInboundClaims` changed, alters which claim-type shape downstream code sees | `Program.cs` | `abc123` | `def456` | Role-gated endpoints, claim-based user identification | Log in as each role, call a role-gated endpoint, confirm `User.Id`/`IsInRole` resolve |
| 2 | e.g. Swashbuckle → built-in OpenAPI, doc shape 3.0 → 3.1 | `Program.cs` | `def456` | `ghi789` | Any external API consumer/client generator | Diff the served OpenAPI JSON before/after; load the new UI and exercise an authenticated call |

## Follow-up backlog (post-upgrade)

Every item from `## 4. Scope` marked "propose, don't apply" gets one numbered entry here — written
so a **different, future session with zero memory of this upgrade** can read just this entry and
start executing, without re-reading the rest of this document or re-doing the investigation. Treat
it like a handoff to a new hire: they have the repo, not your context. The user will typically
start a fresh session later and say "let's tackle #3" — that entry needs to be enough on its own.

Each entry needs:

1. **Origin and status** — which phase surfaced it, and *why* it wasn't applied now (scope bigger
   than expected, needs a design decision that isn't yours to make, no current usage to convert,
   etc.) — the reason, not just "deferred."
2. **Every current call site** — file path + line number(s) + one-line description, from a fresh
   grep at write time (line numbers drift as the session edits other things — don't rely on memory
   of what you saw earlier).
3. **The actual blocker**, explained concretely enough for someone unfamiliar with the
   investigation to understand why this isn't a five-minute mechanical change — name the exact
   API-shape mismatch, downstream contract risk, or codebase-specific hazard (cite the class/method
   that creates it).
4. **A concrete step-by-step execution plan** — an ordered list, not "consider doing X." State what
   to touch first and why (usually lowest-risk or highest-value first), what to verify before
   moving to the next file, and where the genuinely hard decision point is if there is one (with
   the actual options, not just "make a decision here").
5. **A verification section** specific to this item — what to run or exercise to confirm it
   actually worked, not a generic "run the tests."

Do not compress an entry into a single paragraph — under-detailing here just relocates the
investigation work back onto the future session that has to redo it from scratch.

### #1 — <short title>

**Origin:** Phase <N> <name>. **Status:** proposed, not applied. **Size:** <small/medium/large — one line on what drives the size>.

**What it is:** <the modernization opportunity, one paragraph>

**Current state — every call site:**
| File | Line(s) | Usage shape |
|---|---|---|
| | | |

**Why deferred:** <the actual blocker, concrete and specific to this codebase>

**How to execute:**
1. ...
2. ...

**Verification:** <specific commands/flows to exercise afterward>

---

### #2 — <short title>

<same structure>

