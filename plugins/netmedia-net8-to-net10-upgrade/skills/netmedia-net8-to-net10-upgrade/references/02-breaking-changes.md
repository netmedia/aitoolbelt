# Breaking changes — .NET 9 and .NET 10

An 8 → 10 jump absorbs **both** releases' breaking changes at once. Read in Phase 2 (SDK section) and Phase 4 (everything).

Contents: [Tier 1](#tier-1--will-break-something) · [Tier 2](#tier-2--check-likely-cheap) · [SDK and NuGet](#sdk-and-nuget) · [Obsoletions](#obsoletions-to-clear) · [ASP.NET Core](#aspnet-core-breaking-changes) · [Where to look things up](#authoritative-lists)

Authoritative lists: [.NET 9](https://learn.microsoft.com/en-us/dotnet/core/compatibility/9.0) · [.NET 10](https://learn.microsoft.com/en-us/dotnet/core/compatibility/10.0) · [ASP.NET Core 9](https://learn.microsoft.com/en-us/aspnet/core/breaking-changes/9/overview) · [ASP.NET Core 10](https://learn.microsoft.com/en-us/aspnet/core/breaking-changes/10/overview)

## Tier 1 — will break something

### BinaryFormatter removed (.NET 9)

The type still exists, but the **in-box implementation throws in all cases** regardless of the old settings. `EnableUnsafeBinaryFormatterSerialization` no longer re-enables it — that switch name was repurposed to gate the **out-of-band compatibility package**.

Hits: legacy session state, cached blobs, WinForms clipboard/drag-drop, `ObjectStateFormatter`-adjacent code.

Bridge only, with an expiry date in the report (both lines are required — the package needs the switch):

```xml
<PackageReference Include="System.Runtime.Serialization.Formatters" Version="10.0.*" />
<EnableUnsafeBinaryFormatterSerialization>true</EnableUnsafeBinaryFormatterSerialization>
```

Officially unsupported and carries every original CVE class. If the data is *persisted*, this is a real format migration, not a shim. [removal](https://learn.microsoft.com/en-us/dotnet/core/compatibility/serialization/9.0/binaryformatter-removal) · [migration guide](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-migration-guide/)

### Termination signal handlers no longer installed (.NET 10)

SIGTERM (Unix) and `CTRL_SHUTDOWN_EVENT`/`CTRL_CLOSE_EVENT` (Windows) are no longer intercepted. `AppDomain.ProcessExit` and `AssemblyLoadContext.Unloading` **do not fire**; the process dies immediately.

- **Safe:** anything on the Generic Host / `UseConsoleLifetime()` — ASP.NET Core, worker services. The hosting layer registers its own handlers.
- **Breaks:** plain console apps, custom daemons, container sidecars relying on `ProcessExit` for flush/cleanup. Kubernetes graceful shutdown is the classic failure.

```csharp
using var term = PosixSignalRegistration.Create(PosixSignal.SIGTERM, _ => Environment.Exit(0));
using var hup  = PosixSignalRegistration.Create(PosixSignal.SIGHUP,  _ => Environment.Exit(0));
```

[sigterm-signal-handler](https://learn.microsoft.com/en-us/dotnet/core/compatibility/core-libraries/10.0/sigterm-signal-handler)

### Configuration binder preserves `null` (.NET 10)

Previously JSON `null` became `""` and was skipped; empty arrays were ignored; `null` → non-nullable value type threw.

Now `null` binds as `null`, empty arrays bind as empty, and **`null` → non-nullable value type silently becomes `default(T)`** — `null` → `int` is `0`, `null` → `DayOfWeek` is `Sunday`. This changes behaviour without throwing.

Audit every options/settings class with non-nullable value-type properties against every `appsettings*.json` that contains `null`. Fix by removing the key, using `""`, or making the property nullable and validating with `.ValidateDataAnnotations().ValidateOnStart()`.

[configuration-null-values-preserved](https://learn.microsoft.com/en-us/dotnet/core/compatibility/extensions/10.0/configuration-null-values-preserved)

### DATAS on by default for Server GC (.NET 9)

Dynamic Adaptation To Application Sizes makes heap size track live-data size. Usually a memory win; for high-throughput services it can cost throughput. This is the most likely source of "the app behaves differently after the upgrade."

Benchmark it. Disable if needed:

```xml
<GarbageCollectionAdaptationMode>0</GarbageCollectionAdaptationMode>
```

[DATAS](https://learn.microsoft.com/en-us/dotnet/standard/garbage-collection/datas)

### Default container images Debian → Ubuntu (.NET 10)

`mcr.microsoft.com/dotnet/{sdk,runtime,aspnet}:10.0` is now Ubuntu 24.04 "Noble". **Debian-based images are no longer published.** Any `apt-get install` of Debian-specific packages, Debian paths, or Debian user assumptions needs review.

[default-images-use-ubuntu](https://learn.microsoft.com/en-us/dotnet/core/compatibility/containers/10.0/default-images-use-ubuntu)

### New exception handling model (.NET 9)

Based on the NativeAOT implementation; 2–4× faster. SEH support removed everywhere except Windows x86. Opt out: `System.Runtime.LegacyExceptionHandling = true` in runtimeconfig, or `DOTNET_LegacyExceptionHandling=1`.

### Saturating float → integer conversions (.NET 9 JIT)

`(int)double.NaN` and out-of-range casts saturate instead of producing platform-dependent garbage. Code that relied on wraparound changes results.

### `IHost.RunAsync` / `StopAsync` throw when a `BackgroundService` fails (.NET 11 note; verify for your version)

Also relevant on 10: **`BackgroundService` runs all of `ExecuteAsync` as a Task** — synchronous prologue code before the first `await` no longer runs on the caller's thread during `StartAsync`.

## Tier 2 — check, likely cheap

**Serialization**

- **System.Text.Json checks for property-name conflicts** (.NET 10). A user property colliding with metadata names (`$type`, `$id`, `$ref`, or a `TypeDiscriminatorPropertyName`) now throws at serializer-creation/first-use. Hits polymorphic hierarchies with a `Type` property. Fix by renaming or `[JsonIgnore]`. [link](https://learn.microsoft.com/en-us/dotnet/core/compatibility/serialization/10/property-name-validation)
- **`XmlSerializer` no longer ignores `[Obsolete]` properties** (.NET 10) — silently adds/changes elements in XML payloads.
- .NET 9 STJ: nullable `JsonDocument` properties deserialize to `JsonValueKind.Null`; metadata reader unescapes metadata property names.

**Networking / HTTP**

- **`HttpClientFactory` uses `SocketsHttpHandler` as primary handler** (.NET 9) — pooled-connection lifetime semantics change; custom handler chains may behave differently.
- **`HttpClientFactory` redacts header values in logs by default** (.NET 9), plus URI query redaction in `HttpClient` EventSource events. Breaks log scraping. Selective re-enable: `RedactLoggedHeaders(Func<string,bool>)`.
- **`Uri` length limits removed** (.NET 10) — code relying on `UriFormatException` as a size guard loses it.
- **HTTP/3 disabled by default when `PublishTrimmed` is set** (.NET 10).
- **Default trace context propagator is W3C** (.NET 10) — changes outgoing correlation headers. Matters if you interop with anything expecting `Request-Id` / B3.

**Cryptography / platform**

- **OpenSSL 1.1.1+ required on Unix** (.NET 10). Env vars renamed: `CLR_OPENSSL_VERSION_OVERRIDE` → **`DOTNET_OPENSSL_VERSION_OVERRIDE`**, ICU override → **`DOTNET_ICU_VERSION_OVERRIDE`**. If you set the old names in Dockerfiles they now silently do nothing.
- **OpenSSL primitives unsupported on macOS** (.NET 10) — dev-machine impact.
- **DSA removed on macOS**; `X500DistinguishedName` and LDAP `DirectoryControl` parsing stricter (.NET 10) — relevant to AD/LDAP and cert auth.
- **CET enabled by default on Windows** (.NET 9) — occasional incompatibility with old native interop.

**Libraries**

- **`System.Linq.AsyncEnumerable` moved into the core libraries** (.NET 10). Conflicts with the `System.Linq.Async` (Rx) package → ambiguous-extension-method compile errors. **Remove that package reference.** Very common in legacy codebases. [link](https://learn.microsoft.com/en-us/dotnet/core/compatibility/core-libraries/10.0/asyncenumerable)
- `BufferedStream.WriteByte` no longer implicitly flushes (.NET 10).
- `ProviderAliasAttribute` moved to `Microsoft.Extensions.Logging.Abstractions` (.NET 10) — binary break for custom logging providers.
- `FilePatternMatch.Stem` non-nullable; `Nullable.GetUnderlyingType` throws for custom `Type` subclasses; ZIP/TAR reads now validate checksums; `MemoryStream` capacity/exception behaviour changed.
- **Single-file apps no longer probe the executable directory for native libraries** (.NET 10); `DllImportSearchPath.AssemblyDirectory` searches only the assembly directory. Retest native-dependency-heavy apps.
- Warnings for .NET Standard 1.x and .NET 7 targets (.NET 9) — noise in multi-targeted libraries.

## SDK and NuGet

These surface in **Phase 2**, before you retarget.

| Change | Effect | Lever |
|---|---|---|
| `PackageReference` without `Version` → **error NU1015** (.NET 10) | Blocks restore. Was warning NU1604. | Adopt CPM (exempt), or add `Version=`, or `<SdkAnalysisLevel>9.0.300</SdkAnalysisLevel>` (blunt) |
| `NuGetAuditMode` default `direct` → **`all`** (net10.0+) | Restore fails on transitive CVEs under `-warnaserror` | `<NuGetAuditMode>direct</NuGetAuditMode>`, `WarningsNotAsErrors`, `NuGetAuditSuppress`, or `dotnet package update --vulnerable` |
| **Package pruning + NU1510** (.NET 10) | Framework-duplicating direct refs pruned and privatized; packages with no runtime assets dropped from `deps.json` (breaks reflection-based plugin loading) | `<RestoreEnablePackagePruning>false</RestoreEnablePackagePruning>` |
| `dotnet new sln` defaults to SLNX | New solutions are `.slnx` | `dotnet new sln --format sln` |
| `dotnet package list` performs a restore; HTTP feed warnings → errors | Internal HTTP feeds fail | `AllowInsecureConnections` |
| Terminal Logger default (.NET 9); CLI logs to stderr (.NET 10) | Breaks CI log parsers | `--tl:off`, `MSBUILDTERMINALLOGGER=off` |
| `--interactive` defaults `true` (.NET 10) | Pipelines may prompt | `--interactive false` |
| `dotnet tool install --local` creates a manifest by default | New `.config/dotnet-tools.json` | — |
| MSBuild custom culture resource handling changed (9 and 10) | Hits `.resx` files whose "culture" segment isn't a real culture (`Strings.legacy.resx`) | Rename or set metadata |
| `MSBUILDCUSTOMBUILDEVENTWARNING` escape hatch removed (.NET 10) | Custom task warnings | — |
| Code coverage `EnableDynamicNativeInstrumentation` defaults `false` | Coverage numbers move | — |

## Obsoletions to clear

`SYSLIBxxxx` IDs are **not** suppressed by `#pragma warning disable CS0618` — you must use the specific ID.

**.NET 9**

| ID | API | Replacement |
|---|---|---|
| **SYSLIB0057** | `X509Certificate2` / `X509Certificate` ctors taking `byte[]`, `string`, `SecureString`, `X509KeyStorageFlags` | `X509CertificateLoader.LoadCertificate` / `LoadPkcs12` / `LoadCertificateFromFile` / `LoadPkcs12FromFile` |
| SYSLIB0014 | `ServicePointManager` | `SocketsHttpHandler` / `SslClientAuthenticationOptions` |
| SYSLIB0054 | `Thread.VolatileRead` / `VolatileWrite` | `Volatile.Read` / `Volatile.Write` |
| SYSLIB0009 | `AuthenticationManager` | — |
| SYSLIB0056 | `Assembly.LoadFrom(string, byte[], AssemblyHashAlgorithm)` | overloads without the hash algorithm |

SYSLIB0057 is the high-frequency one — nearly every solution that loads a `.pfx` or `.cer` hits it.

**.NET 10**

| ID | API | Replacement |
|---|---|---|
| SYSLIB0058 | `SslStream.KeyExchangeAlgorithm/Strength`, `.CipherAlgorithm/Strength`, `.HashAlgorithm/Strength` and the matching enums | `SslStream.NegotiatedCipherSuite` |
| SYSLIB0059 | `SystemEvents.EventsThreadShutdown` | `AppDomain.ProcessExit` |
| SYSLIB0060 | `Rfc2898DeriveBytes` constructors | `Rfc2898DeriveBytes.Pbkdf2` static method |
| SYSLIB0061 | `Queryable.MaxBy`/`MinBy` with `IComparer<TSource>` | overloads with `IComparer<TKey>` |
| SYSLIB0062 | `XsltSettings.EnableScript` | — |

Plus a batch of Windows Forms obsoletions (.NET 10).

## ASP.NET Core breaking changes

Full detail in `references/04-aspnetcore.md` § 4. The two that reach production silently:

- **Cookie login redirects disabled for known API endpoints** (ASP.NET Core 10) — unauthenticated requests to endpoints carrying `IApiEndpointMetadata` (`[ApiController]`, JSON minimal APIs, `TypedResults` endpoints, SignalR) get **401/403 instead of a 302** to the login page. Breaks SPA/MVC hybrids that detect session timeout from the redirect.
- **Forwarded headers from unknown proxies are ignored** (serviced into 8.0.17 / 9.0.6 too) — symptoms are infinite HTTPS redirect loops, auth failures, wrong scheme in generated URLs. Fix by populating `KnownProxies` / `KnownIPNetworks`.

Deprecation diagnostics to expect at build: `ASPDEPR002` (`WithOpenApi`), `ASPDEPR003` (Razor runtime compilation), `ASPDEPR004`/`ASPDEPR008` (`WebHostBuilder`/`IWebHost`/`WebHost`), `ASPDEPR005` (`IPNetwork`/`KnownNetworks`), `ASPDEPR006` (`IActionContextAccessor`), `ASPDEPR007` (OpenAPI analyzers).

## EF Core breaking changes

In `references/05-efcore.md`. The two that fail at first boot: `Migrate()` throwing on pending model changes, and `Migrate()` throwing inside an external transaction (both EF Core 9).

## Authoritative lists

When the inventory flags something not covered here, look it up rather than guessing:

- [.NET breaking changes reference](https://learn.microsoft.com/en-us/dotnet/core/compatibility/breaking-changes)
- [C# compiler breaking changes — .NET 10](https://learn.microsoft.com/en-us/dotnet/csharp/whats-new/breaking-changes/compiler%20breaking%20changes%20-%20dotnet%2010) (also in `references/03-csharp-modernization.md`)
- [ASPDEPR ID index](https://learn.microsoft.com/en-us/aspnet/core/diagnostics/aspdepr-ids?view=aspnetcore-10.0) — work in progress; the individual breaking-change articles are more complete
