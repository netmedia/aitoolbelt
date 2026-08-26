# Solution hygiene — `.slnx`, CPM, Directory.Build.props, analyzers, CI

Read in Phase 1 (baseline) and Phase 5.1 (solution file migration).

Contents: [SDK pin](#sdk-pin) · [Directory.Build.props](#directorybuildprops) · [Central Package Management](#central-package-management) · [.slnx](#slnx) · [Analyzers](#analyzers) · [NuGet audit](#nuget-and-vulnerability-audit) · [dotnet format](#dotnet-format) · [CI](#ci-changes-you-will-be-forced-into) · [Upgrade tooling](#state-of-upgrade-tooling-2026)

## SDK pin

```bash
dotnet new globaljson --sdk-version 10.0.100 --roll-forward latestFeature
```

Pin before anything else so every developer and agent surfaces the same SDK-level breaks. Note `dnx` scripts bypass `global.json` SDK selection.

## Directory.Build.props

MSBuild walks **upward and stops at the first match**. A nested `Directory.Build.props` must import its parent explicitly:

```xml
<Import Project="$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '$(MSBuildThisFileDirectory)../'))"
        Condition="'' != $([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '$(MSBuildThisFileDirectory)../'))" />
```

**Case-sensitive on Linux.** `Directory.build.props` silently does nothing in a container build — a classic CI-only failure.

`Directory.Build.props` is imported early (defaults); `Directory.Build.targets` is imported late, after NuGet's props/targets (overrides). Also available: `Directory.Build.rsp` (default CLI args, CLI builds only), `Directory.Solution.props` / `.targets`.

Baseline is in `assets/Directory.Build.props`. Two properties there are deliberately conservative during the upgrade and get raised in Phase 5:

```xml
<AnalysisLevel>8.0</AnalysisLevel>   <!-- Phase 5: latest-recommended -->
<LangVersion>12</LangVersion>        <!-- Phase 5: latest -->
```

Docs: [customize-by-directory](https://learn.microsoft.com/en-us/visualstudio/msbuild/customize-by-directory)

## Central Package Management

`Directory.Packages.props` at repo root (`dotnet new packagesprops` scaffolds it):

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
    <CentralPackageTransitivePinningEnabled>true</CentralPackageTransitivePinningEnabled>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Serilog" Version="4.2.0" />
  </ItemGroup>
  <ItemGroup>
    <GlobalPackageReference Include="Nerdbank.GitVersioning" Version="3.7.115" PrivateAssets="All" />
  </ItemGroup>
</Project>
```

Projects then carry versionless `<PackageReference Include="Serilog" />`. Escape hatches: `VersionOverride="3.0.0"` per project; `<ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally>` to opt a project out.

Why it matters for this upgrade specifically:

- **.NET 10 turns versionless `PackageReference` into error `NU1015`** — except under CPM, where it is correct. CPM is effectively the fix.
- `CentralPackageTransitivePinningEnabled` is the lever that forces a patched transitive version, which pairs with .NET 10's new transitive vulnerability audit.
- All `Microsoft.EntityFrameworkCore.*` packages must move in lockstep. One `EFCoreVersion` property in CPM makes drift impossible.

Gotchas: only the **nearest** `Directory.Packages.props` is evaluated; `NU1507` if multiple sources are configured without package source mapping.

Docs: [central-package-management](https://learn.microsoft.com/en-us/nuget/consume-packages/central-package-management)

## .slnx

XML solution format. Introduced in SDK 9.0.200, GA in VS 17.14, default for `dotnet new sln` in .NET 10.

```bash
dotnet sln MySolution.sln migrate      # emits MySolution.slnx
dotnet build ./MySolution.slnx
dotnet sln ./MySolution.slnx add ./src/Lib
dotnet new sln --format sln            # opt back to legacy
```

**It is an error to run `dotnet build` in a directory containing both a `.sln` and a `.slnx`.** So migration must be a single commit that *deletes* the old file, coordinated across the team — not an additive one. Do it in Phase 5, never inside the retarget commit.

Tooling support: .NET CLI full; Visual Studio needs the SLNX persistence setting enabled; C# Dev Kit needs `dotnet.defaultSolution`; Rider preliminary; **slngen not updated**. Check what your team and CI actually use before migrating.

Docs: [dotnet sln](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-sln) · [SLNX blog](https://devblogs.microsoft.com/dotnet/introducing-slnx-support-dotnet-cli/)

## Analyzers

- `AnalysisLevel` defaults to **`latest`** and is **not** pinned to the TFM. Installing SDK 10 turns on new rules by itself, before you retarget anything. This is why Phase 1 pins it to `8.0`.
- `AnalysisMode`: `None` < `Default` < `Minimum` < `Recommended` < `All`. The compound form (`latest-recommended`) takes precedence over a separate `AnalysisMode`.
- `EnableNETAnalyzers` is `true` by default for .NET 5+.
- `EnforceCodeStyleInBuild` is **`false`** on the CLI — IDExxxx rules only fire in the IDE unless you turn it on. Turning it on is usually the single biggest source of new warnings. Stage it separately.
- `CodeAnalysisTreatWarningsAsErrors=false` exempts CA rules while keeping compiler warnings fatal — useful mid-upgrade.

New rules to expect: **.NET 9** CA1514, CA1515, CA1871, CA1872, **CA2022** (inexact `Stream.Read` — a real correctness detector), CA2262, CA2263, CA2264, CA2265. **.NET 10** CA2023, CA2266.

MSBuild BuildChecks (.NET 9): `dotnet build MySolution.slnx /check` — BC0101, BC0102. Cheap CI addition.

Docs: [code-analysis overview](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/overview)

## NuGet and vulnerability audit

NuGet 7.0 ships in SDK 10.0.100.

- `NuGetAuditMode` default flips `direct` → **`all`** for `net10.0+`. Under `-warnaserror`, restore starts failing on transitive CVEs you do not directly control.
- Levers: `<NuGetAuditMode>direct</NuGetAuditMode>`, `<WarningsNotAsErrors>NU1901;NU1902;NU1903;NU1904;$(WarningsNotAsErrors)</WarningsNotAsErrors>`, `<NuGetAuditSuppress Include="https://github.com/advisories/GHSA-..." />`.
- Actually fix instead: `dotnet package update --vulnerable` (new in NuGet 7.0, CPM-aware).
- `dotnet nuget why <solution|project> <PackageId>` traces a transitive path.
- **Package pruning** (net10.0+): direct references duplicating framework assemblies are pruned and warned on (`NU1510`) — `System.Text.Json`, `System.Memory`, `System.Linq.AsyncEnumerable`, various `Microsoft.Extensions.*`. Pruned direct references are also **privatized**, so they stop flowing to consumers of your packages. Disable with `<RestoreEnablePackagePruning>false</RestoreEnablePackagePruning>`; keep them under multi-targeting with a condition:
  ```xml
  <PackageReference Include="System.Text.Json" Version="8.0.5"
      Condition="!$([MSBuild]::IsTargetFrameworkCompatible('$(TargetFramework)','net8.0'))" />
  ```
- HTTP feed warnings are now **errors** in `dotnet package list` / `search`; audit sources no longer allow insecure HTTP. Internal on-prem feeds need `AllowInsecureConnections`.
- `project.json` is no longer supported by `dotnet restore`.

Docs: [NuGet 7.0](https://learn.microsoft.com/en-us/nuget/release-notes/nuget-7.0) · [auditing-packages](https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages)

## dotnet format

In-box since .NET 6, not deprecated. Subcommands `whitespace`, `style`, `analyzers`.

```bash
dotnet format --verify-no-changes          # CI gate
dotnet format style --severity info        # mechanical modernization sweep
dotnet format analyzers --severity info
```

Useful flags: `--diagnostics <IDs>`, `--exclude-diagnostics`, `--include`/`--exclude`, `--report <path>`, `--no-restore`. Driving the Phase 5.2 C# sweep with `--diagnostics IDE0300` etc. keeps each commit reviewable.

## CI changes you will be forced into

- **Terminal Logger is the default** (.NET 9) for build/clean/msbuild/pack/publish/restore/test. Breaks log parsers. `--tl:off` or `MSBUILDTERMINALLOGGER=off`.
- **The `dotnet` CLI writes non-command data to stderr** (.NET 10), and `dotnet watch` logs to stderr. Scripts treating any stderr output as failure will break.
- **`--interactive` defaults to `true`** in user scenarios (.NET 10). It auto-detects CI, but pin it: `dotnet restore --interactive false`.
- **Workload default mode is `workload-set`** (.NET 10). Revert with `dotnet workload config --update-mode manifests`.
- **`dotnet test` changes if Microsoft.Testing.Platform is enabled** — `dotnet test <path>` stops working. See `references/07-libraries-and-tests.md`. Defer MTP.
- **Default container images are Ubuntu, not Debian** (.NET 10) — `mcr.microsoft.com/dotnet/{sdk,runtime,aspnet}:10.0` is Ubuntu 24.04. Debian images are no longer published. Audit every `apt-get` line in your Dockerfiles.
- `dotnet dev-certs https -ep <path>` no longer creates the target folder (.NET 9).

## State of upgrade tooling (2026)

1. **`dotnet upgrade-assistant` — deprecated.** The global tool still installs and runs (Windows-only, SDK 8+), and still does TFM/package bumps. It does none of the API migrations. In VS it sits behind *Tools > Options > Projects and Solutions > Modernization > Enable legacy Upgrade Assistant*.
2. **`dotnet/upgrade-assistant` repo → renamed `dotnet/modernize-dotnet` → also deprecated**, moved to `microsoft/upgrade-agent-plugins`.
3. **Current Microsoft path: the GitHub Copilot modernization / upgrade agent** — VS 2026 or VS 2022 17.14.16+ (`@Modernize`), VS Code (`@upgrade`), Copilot CLI (`@upgrade upgrade my solution to .NET 10`). Requires a Copilot subscription. It writes `.github/upgrades/{scenarioId}/{assessment,plan,tasks}.md`, which are reviewable and committable. Treat it as assistive, not deterministic.

The deterministic path — and what this skill automates — is the phased sequence in `SKILL.md`, driven by `dotnet build`, `dotnet format`, and the breaking-change checklists.
