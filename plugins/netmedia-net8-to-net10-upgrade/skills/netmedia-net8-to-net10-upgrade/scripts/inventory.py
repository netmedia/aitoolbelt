#!/usr/bin/env python3
"""Scan a .NET solution and report everything that matters for a .NET 8 -> 10 upgrade.

Usage:
    python3 inventory.py /path/to/solution [--out UPGRADE-PLAN.md] [--json inventory.json]

Stdlib only. Read-only: never writes into the scanned tree.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

SKIP_DIRS = {"bin", "obj", "node_modules", ".git", ".vs", ".idea", "packages", "TestResults", "artifacts"}
SOURCE_EXT = {".cs", ".razor", ".cshtml", ".vb", ".fs"}
CONFIG_EXT = {".json", ".config", ".props", ".targets", ".csproj", ".yml", ".yaml", ".xml"}

# (id, regex, where, severity, what it means / what to do)
SIGNALS: list[tuple[str, str, str, str, str]] = [
    # --- blockers -------------------------------------------------------
    ("pomelo-mysql", r"Pomelo\.EntityFrameworkCore\.MySql", "config", "blocker",
     "Pomelo MySQL provider has no EF Core 10 release; 9.x caps Relational at <=9.0.999. Verify on NuGet before planning."),
    ("binaryformatter", r"\bBinaryFormatter\b", "source", "blocker",
     "BinaryFormatter removed in .NET 9 (throws at runtime). Persisted data needs a real format migration, not a shim."),
    ("functions-inprocess", r"\[FunctionName\(|Microsoft\.NET\.Sdk\.Functions", "any", "blocker",
     "Azure Functions in-process model. EOS 2026-11-10 and unsupported on .NET 10. Migrate to isolated worker on net8.0 FIRST."),
    ("webjobs-refs", r"Microsoft\.Azure\.WebJobs", "any", "blocker",
     "Microsoft.Azure.WebJobs.* must not remain referenced in an isolated-worker app. See references/06-functions.md."),
    ("durable-inprocess", r"IDurableOrchestrationContext|IDurableOrchestrationClient|CreateEntityProxy", "source", "blocker",
     "In-process Durable Functions. Serializer changes to System.Text.Json and affects PERSISTED orchestration state - drain in-flight instances."),

    # --- high -----------------------------------------------------------
    ("startup-cs", r"class\s+Startup\b|UseStartup<|ConfigureWebHostDefaults|IWebHostBuilder", "source", "high",
     "Legacy Startup.cs / WebHostBuilder hosting. WebHostBuilder/IWebHost/WebHost obsolete in .NET 10 (ASPDEPR004/008)."),
    ("functions-startup", r"FunctionsStartup|IFunctionsHostBuilder", "source", "high",
     "Functions Startup class -> Program.cs with FunctionsApplication.CreateBuilder(args)."),
    ("migrate-in-transaction", r"CreateExecutionStrategy\(\)|BeginTransaction", "source", "high",
     "If a Migrate()/MigrateAsync() call sits inside an explicit transaction or ExecutionStrategy, EF Core 9+ THROWS. Audit every call site."),
    ("db-migrate", r"Database\.Migrate(Async)?\(", "source", "high",
     "Migrate() now throws on pending model changes and inside external transactions (EF Core 9). App can fail on first boot."),
    ("jwt-security-token", r"JwtSecurityToken|DefaultInboundClaimTypeMap", "source", "high",
     "Security token events hand you JsonWebToken, not JwtSecurityToken. Use options.MapInboundClaims=false. Verify claim types."),
    ("forwarded-headers", r"ForwardedHeaders|KnownNetworks|KnownProxies", "source", "high",
     "Forwarded headers from unknown proxies are ignored -> redirect loops / wrong scheme. Populate KnownProxies/KnownIPNetworks. KnownNetworks obsolete (ASPDEPR005)."),
    ("system-linq-async", r"System\.Linq\.Async", "config", "high",
     "System.Linq.AsyncEnumerable moved in-box in .NET 10. Remove the System.Linq.Async package or you get ambiguous extension methods."),
    ("x509-ctor", r"new\s+X509Certificate2?\s*\(", "source", "high",
     "SYSLIB0057: X509Certificate2 constructors obsolete. Use X509CertificateLoader.LoadCertificate/LoadPkcs12."),
    ("use-azure-sql", r"UseAzureSql\(", "source", "high",
     "EF 10 + UseAzureSql defaults to compat level 170 -> generates a migration altering nvarchar(max) JSON columns to the native json type."),
    ("dapper-with-ef", r"\bDapper\b", "any", "high",
     "Mixed EF + Dapper: EF 10 injects Application Name into the connection string -> separate pool, MSDTC escalation risk inside TransactionScope. Set Application Name explicitly."),
    ("razor-runtime-compilation", r"AddRazorRuntimeCompilation", "source", "high",
     "ASPDEPR003: Razor runtime compilation obsolete. Use Hot Reload in dev, build-time compilation in prod."),

    # --- medium ---------------------------------------------------------
    ("swashbuckle", r"AddSwaggerGen|UseSwagger\(|Swashbuckle", "any", "medium",
     "Swashbuckle -> built-in Microsoft.AspNetCore.OpenApi + Scalar. Watch OpenAPI 3.1 output shape breaking downstream client generators. PROPOSE, don't apply blindly."),
    ("with-openapi", r"\.WithOpenApi\(", "source", "medium",
     "ASPDEPR002: .WithOpenApi() deprecated -> .AddOpenApiOperationTransformer(...). Note the signature change."),
    ("openapi-reference", r"<OpenApiReference|Microsoft\.Extensions\.ApiDescription\.Client", "config", "medium",
     "Client generation package deprecated -> NSwag CLI / Kiota / openapi-generator-cli."),
    ("use-static-files", r"UseStaticFiles\(", "source", "medium",
     "Consider MapStaticAssets (.NET 9) for compression + fingerprinting. Keep UseStaticFiles for default docs, uploads, embedded resources."),
    ("action-context-accessor", r"IActionContextAccessor", "source", "medium",
     "ASPDEPR006: obsolete -> IHttpContextAccessor + endpoint metadata."),
    ("memory-distributed-cache", r"IDistributedCache|IMemoryCache", "source", "medium",
     "Candidate for HybridCache: stampede protection, tag invalidation, unified L1/L2."),
    ("query-filter", r"HasQueryFilter\(", "source", "medium",
     "Unnamed HasQueryFilter REPLACES the previous filter. If you combine soft-delete + tenant filters, move to EF 10 named query filters."),
    ("owns-json", r"OwnsOne\(|OwnsMany\(", "source", "medium",
     "Owned types mapped to JSON are candidates for EF 10 complex types - but the move renames columns and produces migrations. PROPOSE."),
    ("ef-compile-query", r"EF\.CompileQuery|EF\.Constant\(|EF\.Parameter\(", "source", "medium",
     "EF.Constant/EF.Parameter no longer work inside compiled queries (EF 9) - throws InvalidCastException."),
    ("negated-nullable-compare", r"!\s*\([A-Za-z_][\w\.]*\s*[<>]=?\s*", "source", "medium",
     "EF 9 changed negated nullable comparisons to C# semantics - !(a > b) can now return MORE rows. Verify against nullable columns."),
    ("array-reverse", r"\.Reverse\(\)", "source", "medium",
     "C# 14: array.Reverse() can bind to the in-place void MemoryExtensions.Reverse instead of LINQ when targeting < net10.0. Use Enumerable.Reverse(x)."),
    ("expression-lambda-linq", r"Expression<Func<", "source", "medium",
     "C# 14 span overload resolution can rebind LINQ calls inside expression trees (Contains -> MemoryExtensions.Contains), throwing at runtime."),
    ("newtonsoft", r"Newtonsoft\.Json|\[JsonProperty", "any", "medium",
     "System.Text.Json ignores [JsonProperty]. Functions moving in-process -> isolated silently change serializer. Port to [JsonPropertyName] or opt back in explicitly."),
    ("assemblyinfo", r"AssemblyInfo\.cs$", "filename", "medium",
     "Legacy AssemblyInfo.cs: move InternalsVisibleTo to MSBuild items and delete generated-attribute duplicates (CS0579)."),
    ("packages-config", r"packages\.config$", "filename", "medium",
     "packages.config predates PackageReference. Migrate before anything else."),
    ("skip-clean-output", r"_FunctionsSkipCleanOutput|FunctionsPreservedDependencies", "config", "medium",
     "In-process-only artifact - delete it, do not carry it forward to the isolated worker."),
    ("write-as-json", r"WriteAsJsonAsync\(", "source", "medium",
     "Functions Worker 2.x: HttpResponseData.WriteAsJsonAsync no longer sets status 200 automatically. Audit every call site."),
    ("lock-object", r"private\s+(static\s+)?readonly\s+object\s+\w*(?i:lock|sync)", "source", "low",
     "Candidate for System.Threading.Lock (C# 13 + .NET 9). Not if used with Monitor.Wait/Pulse/TryEnter."),
    ("logger-interpolation", r"Log(Information|Debug|Warning|Error|Critical|Trace)\(\$\"", "source", "low",
     "Interpolated log messages allocate even when disabled and produce no queryable properties. Use the [LoggerMessage] source generator."),
    ("static-regex", r"static\s+readonly\s+Regex\b", "source", "low",
     "Candidate for [GeneratedRegex] - compile-time, trim/AOT-safe, no RegexOptions.Compiled startup cost."),
    ("process-exit", r"AppDomain\.CurrentDomain\.ProcessExit|AssemblyLoadContext\.Default\.Unloading", "source", "high",
     ".NET 10 no longer installs default SIGTERM handlers - ProcessExit does NOT fire in plain console apps. Use PosixSignalRegistration."),
    ("aspnet-json-options", r"AddJsonOptions\(|ConfigureHttpJsonOptions\(", "source", "low",
     "Minimal APIs and MVC use SEPARATE JSON option objects. Verify both if the app mixes endpoint styles."),
]

PROJECT_KIND_ORDER = ["library", "test", "web", "worker", "functions", "unknown"]


def strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1]


def walk_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            yield Path(dirpath) / name


def parse_project(path: Path) -> dict:
    info = {
        "path": str(path),
        "name": path.stem,
        "sdk": "",
        "tfms": [],
        "kind": "unknown",
        "packages": {},
        "properties": {},
        "project_refs": [],
    }
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        root = ET.fromstring(text)
    except Exception as exc:  # unreadable / malformed csproj
        info["error"] = f"{type(exc).__name__}: {exc}"
        return info

    info["sdk"] = root.attrib.get("Sdk", "")
    for el in root.iter():
        tag = strip_ns(el.tag)
        if tag in ("TargetFramework", "TargetFrameworks"):
            info["tfms"].extend(t.strip() for t in (el.text or "").split(";") if t.strip())
        elif tag in ("AzureFunctionsVersion", "OutputType", "Nullable", "ImplicitUsings", "LangVersion",
                     "AnalysisLevel", "AnalysisMode", "ManagePackageVersionsCentrally", "PublishAot",
                     "PublishTrimmed", "EnforceCodeStyleInBuild", "TreatWarningsAsErrors", "IsPackable"):
            info["properties"][tag] = (el.text or "").strip()
        elif tag == "PackageReference":
            pid = el.attrib.get("Include") or el.attrib.get("Update")
            if pid:
                info["packages"][pid] = el.attrib.get("Version", "")
        elif tag == "ProjectReference":
            inc = el.attrib.get("Include")
            if inc:
                info["project_refs"].append(inc.replace("\\", "/"))
        elif tag == "FrameworkReference":
            info["packages"].setdefault("(framework) " + (el.attrib.get("Include") or ""), "")

    pkgs = " ".join(info["packages"])
    sdk = info["sdk"]
    if "AzureFunctionsVersion" in info["properties"] or "Functions" in pkgs or "Sdk.Functions" in sdk:
        info["kind"] = "functions"
    elif "Microsoft.NET.Test.Sdk" in pkgs or re.search(r"\bxunit|nunit|mstest|TUnit\b", pkgs, re.I):
        info["kind"] = "test"
    elif sdk.startswith("Microsoft.NET.Sdk.Web") or sdk.startswith("Microsoft.NET.Sdk.BlazorWebAssembly"):
        info["kind"] = "web"
    elif sdk.startswith("Microsoft.NET.Sdk.Worker"):
        info["kind"] = "worker"
    elif sdk.startswith("Microsoft.NET.Sdk.Razor"):
        info["kind"] = "web"
    else:
        info["kind"] = "library"
    return info


def scan_signals(root: Path) -> dict[str, list[str]]:
    compiled = [(sid, re.compile(rx), where, sev, note) for sid, rx, where, sev, note in SIGNALS]
    hits: dict[str, list[str]] = defaultdict(list)
    for f in walk_files(root):
        ext = f.suffix.lower()
        is_source = ext in SOURCE_EXT
        is_config = ext in CONFIG_EXT
        if not (is_source or is_config):
            continue
        rel = str(f.relative_to(root))
        text = None
        for sid, rx, where, _sev, _note in compiled:
            if where == "filename":
                if rx.search(f.name):
                    hits[sid].append(rel)
                continue
            if where == "source" and not is_source:
                continue
            if where == "config" and not is_config:
                continue
            if text is None:
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    text = ""
            if rx.search(text):
                hits[sid].append(rel)
    return hits


def outdated_packages(projects: list[dict]) -> list[tuple[str, str, str]]:
    """Microsoft-family packages still pinned below 10.x."""
    # Families whose major version tracks the .NET major version. Microsoft.NET.Test.Sdk
    # is deliberately absent - it versions on its own scheme (17.x / 18.x).
    families = ("Microsoft.AspNetCore.", "Microsoft.Extensions.", "Microsoft.EntityFrameworkCore.",
                "System.Text.Json", "System.Net.Http.Json", "Npgsql.EntityFrameworkCore",
                "Microsoft.Azure.Functions.Worker")
    out = []
    for p in projects:
        for pid, ver in p["packages"].items():
            if not ver or not any(pid.startswith(f) for f in families):
                continue
            m = re.match(r"^\[?(\d+)", ver)
            if m and int(m.group(1)) < 10:
                out.append((p["name"], pid, ver))
    return sorted(out)


def build_report(root: Path, projects: list[dict], hits: dict, sln_files: list[str], cpm: bool) -> str:
    sev_rank = {"blocker": 0, "high": 1, "medium": 2, "low": 3}
    notes = {sid: (sev, note) for sid, _rx, _w, sev, note in SIGNALS}
    tfm_counter = Counter(t for p in projects for t in p["tfms"])
    kinds = Counter(p["kind"] for p in projects)

    L: list[str] = []
    A = L.append
    A(f"# .NET 10 upgrade inventory — `{root}`\n")
    A(f"{len(projects)} projects. Target frameworks in use: "
      + (", ".join(f"`{t}` ×{n}" for t, n in tfm_counter.most_common()) or "none found") + ".\n")

    A("## Blockers and findings\n")
    found = [(sid, files) for sid, files in hits.items() if files]
    found.sort(key=lambda kv: (sev_rank.get(notes[kv[0]][0], 9), kv[0]))
    if not found:
        A("None of the known landmines matched. Still work `references/02-breaking-changes.md` manually.\n")
    else:
        A("| Severity | Finding | Files | What it means |")
        A("|---|---|---|---|")
        for sid, files in found:
            sev, note = notes[sid]
            sample = ", ".join(f"`{f}`" for f in sorted(files)[:3])
            more = f" +{len(files) - 3} more" if len(files) > 3 else ""
            A(f"| **{sev}** | `{sid}` | {sample}{more} | {note} |")
        A("")

    A("## Projects\n")
    A("| Project | Kind | TFM | SDK | Notable properties |")
    A("|---|---|---|---|---|")
    for p in sorted(projects, key=lambda p: (PROJECT_KIND_ORDER.index(p["kind"]), p["name"])):
        props = ", ".join(f"{k}={v}" for k, v in sorted(p["properties"].items()) if v) or "—"
        A(f"| `{p['name']}` | {p['kind']} | {', '.join(p['tfms']) or '—'} | {p['sdk'] or '—'} | {props} |")
    A("")

    stale = outdated_packages(projects)
    if stale:
        A("## Packages pinned below 10.x\n")
        A("Verify the current patch on nuget.org — these move monthly.\n")
        A("| Project | Package | Version |")
        A("|---|---|---|")
        for name, pid, ver in stale[:60]:
            A(f"| `{name}` | `{pid}` | {ver} |")
        if len(stale) > 60:
            A(f"\n_+{len(stale) - 60} more; see `inventory.json`._")
        A("")

    A("## Solution hygiene\n")
    A(f"- Solution files: {', '.join('`' + s + '`' for s in sln_files) or 'none found'}")
    A(f"- Central Package Management: {'**yes**' if cpm else '**no** — adopt it; .NET 10 turns versionless PackageReference into error NU1015'}")
    versionless = [(p['name'], pid) for p in projects for pid, v in p['packages'].items()
                   if not v and not pid.startswith("(framework)")]
    if versionless and not cpm:
        A(f"- **{len(versionless)} versionless `PackageReference` entries without CPM** → NU1015 errors on the .NET 10 SDK")
    A("")

    A("## Suggested retarget order\n")
    for i, kind in enumerate([k for k in PROJECT_KIND_ORDER if kinds.get(k)], start=1):
        names = ", ".join(f"`{p['name']}`" for p in projects if p["kind"] == kind)
        A(f"{i}. **{kind}** ({kinds[kind]}) — {names}")
    A("\nGate each tier on a green build and green tests before starting the next. "
      "Functions still on the in-process model migrate to isolated on `net8.0` first.\n")

    A("## Next steps\n")
    A("1. Read `SKILL.md` Phase 1 and copy the `assets/` baseline files.")
    A("2. Read only the reference files the findings above point at.")
    A("3. Fill in `assets/UPGRADE-PLAN-template.md` and agree scope before editing code.\n")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="Inventory a .NET solution for a .NET 10 upgrade.")
    ap.add_argument("root", help="Solution or repository root")
    ap.add_argument("--out", default="UPGRADE-PLAN.md", help="Markdown report path (default: UPGRADE-PLAN.md)")
    ap.add_argument("--json", dest="json_out", default=None, help="Optional JSON output path")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    projects, sln_files, cpm = [], [], False
    for f in walk_files(root):
        if f.suffix.lower() == ".csproj":
            projects.append(parse_project(f))
        elif f.suffix.lower() in (".sln", ".slnx"):
            sln_files.append(str(f.relative_to(root)))
        elif f.name == "Directory.Packages.props":
            cpm = True

    if not projects:
        print(f"error: no .csproj files found under {root}", file=sys.stderr)
        return 1

    hits = scan_signals(root)
    report = build_report(root, projects, hits, sln_files, cpm)
    Path(args.out).write_text(report, encoding="utf-8")

    if args.json_out:
        payload = {
            "root": str(root),
            "projects": projects,
            "solutionFiles": sln_files,
            "centralPackageManagement": cpm,
            "findings": {k: v for k, v in hits.items() if v},
            "outdatedPackages": [
                {"project": n, "package": p, "version": v} for n, p, v in outdated_packages(projects)
            ],
        }
        Path(args.json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    blockers = sum(1 for sid, files in hits.items() if files
                   and next(s for i, _r, _w, s, _n in SIGNALS if i == sid) == "blocker")
    print(f"{len(projects)} projects scanned. Report: {args.out}"
          + (f", JSON: {args.json_out}" if args.json_out else "")
          + (f". {blockers} blocker(s) found." if blockers else "."))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
