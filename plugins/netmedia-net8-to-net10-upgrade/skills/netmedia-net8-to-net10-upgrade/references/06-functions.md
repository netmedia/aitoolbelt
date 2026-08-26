# Azure Functions → .NET 10 isolated worker

Contents: [Support matrix](#support-matrix) · [csproj](#reference-csproj) · [Packages](#binding-extension-packages) · [Config](#hostjson-local-settings-and-app-settings) · [In-process → isolated](#in-process--isolated-migration) · [Durable](#durable-functions) · [Deployment](#deployment-procedure) · [Hosting plans](#hosting-plans)

**.NET 8 and the in-process model both end support on 2026-11-10.** .NET 10 is not supported in-process at all, so the model migration is a hard prerequisite, not cleanup.

**Do the model migration on `net8.0` first, deploy it, then bump to `net10.0`.** Bundling them makes failures undiagnosable — the risky part (bindings, serializer, Durable state) gets mixed with the boring part.

## Support matrix

| Functions runtime | Isolated worker | In-process |
|---|---|---|
| 4.x | **.NET 10**, 9.0, 8.0, .NET Framework 4.8 | .NET 8.0 only |

| .NET version | `Microsoft.Azure.Functions.Worker` | `.Worker.Sdk` |
|---|---|---|
| **.NET 10** | **≥ 2.50.0** | **≥ 2.0.5** |
| .NET 9 | ≥ 2.0.0 | ≥ 2.0.0 |
| .NET 8 | ≥ 1.16.0 | ≥ 1.11.0 |

Verify current versions on NuGet at upgrade time. **Do not mix 1.x and 2.x core packages** — 2.x is required for .NET 10 and changes several defaults.

## Reference csproj

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <AzureFunctionsVersion>v4</AzureFunctionsVersion>
    <OutputType>Exe</OutputType>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <!-- keep even for non-HTTP apps: best cold-start / perf -->
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
    <PackageReference Include="Microsoft.Azure.Functions.Worker" />
    <PackageReference Include="Microsoft.Azure.Functions.Worker.Sdk" />
    <PackageReference Include="Microsoft.Azure.Functions.Worker.Extensions.Http.AspNetCore" />
  </ItemGroup>

  <ItemGroup>
    <None Update="host.json"><CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory></None>
    <None Update="local.settings.json">
      <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
      <CopyToPublishDirectory>Never</CopyToPublishDirectory>
    </None>
  </ItemGroup>

  <!-- only if migrating code that used the Functions ExecutionContext binding -->
  <ItemGroup>
    <Using Include="System.Threading.ExecutionContext" Alias="ExecutionContext" />
  </ItemGroup>
</Project>
```

| Property | Note |
|---|---|
| `OutputType` = `Exe` | **Required** — the isolated worker is a standalone process. Absent in in-process projects; the most commonly forgotten edit. |
| `_FunctionsSkipCleanOutput` | **Delete it.** In-process-only workaround for `Microsoft.NET.Sdk.Functions` stripping assemblies from the output folder. Inert under isolated. Same for `FunctionsPreservedDependencies`. |
| `FUNCTIONS_INPROC_NET8_ENABLED` app setting | **Remove.** In-process-only flag. |
| `FrameworkReference Microsoft.AspNetCore.App` | Keep even for non-HTTP triggers — Microsoft recommends it for performance. |

Optional cold-start optimization: `<RuntimeIdentifier>win-x64</RuntimeIdentifier>` + `<PublishReadyToRun>true</PublishReadyToRun>`.

## Binding extension packages

All extensions live under `Microsoft.Azure.Functions.Worker.Extensions.*`. **No `Microsoft.Azure.WebJobs.*` or `Microsoft.Azure.Functions.Extensions` reference may remain** — Microsoft states this explicitly.

| In-process | Isolated |
|---|---|
| `Microsoft.NET.Sdk.Functions` | `Microsoft.Azure.Functions.Worker` + `.Worker.Sdk` |
| `Microsoft.Azure.WebJobs.Extensions.Storage` | `.Worker.Extensions.Storage.Blobs` + `.Storage.Queues` + `.Tables` |
| `…WebJobs.Extensions.CosmosDB` / `.DocumentDB` | `…Worker.Extensions.CosmosDB` |
| `…WebJobs.Extensions.ServiceBus` / `.EventHubs` / `.EventGrid` | `…Worker.Extensions.{ServiceBus,EventHubs,EventGrid}` |
| `…WebJobs.Extensions.SignalRService` | `…Worker.Extensions.SignalRService` |
| `…WebJobs.Extensions.DurableTask` | `…Worker.Extensions.DurableTask` |
| `Microsoft.DurableTask.SqlServer.AzureFunctions` | `…Worker.Extensions.DurableTask.SqlServer` |
| `…WebJobs.Extensions.{SendGrid,Kafka,RabbitMQ}` | `…Worker.Extensions.{SendGrid,Kafka,RabbitMQ}` |
| timer trigger (was built in) | **add** `…Worker.Extensions.Timer` |
| `Microsoft.Azure.Functions.Extensions` (DI) | **remove** — DI is built in |

Watch for extension-level breaking changes when a major version jumps (e.g. the Service Bus extension 4.x → 5.x changed `host.json` structure). Read each extension's release notes.

## host.json, local settings, and app settings

`host.json` schema stays `"2.0"`; no .NET 10-specific change. Useful entries:

```json
{
  "version": "2.0",
  "telemetryMode": "OpenTelemetry",
  "SendCanceledInvocationsToWorker": "false",
  "retry": { "strategy": "fixedDelay", "maxRetryCount": 4, "delayInterval": "00:00:10" }
}
```

`host.json` configures the **host runtime** only. In the isolated model most logs originate in *your* process — configure those in `Program.cs` / `appsettings.json`.

`local.settings.json` — the only mandatory edit vs in-process:

```json
{ "Values": { "FUNCTIONS_WORKER_RUNTIME": "dotnet-isolated" } }
```

Azure app settings / site config (Premium, Dedicated, Consumption — **not** Flex, see below):

| Setting | Value |
|---|---|
| `FUNCTIONS_WORKER_RUNTIME` | `dotnet-isolated` |
| `FUNCTIONS_EXTENSION_VERSION` | `~4` |
| `netFrameworkVersion` (Windows site config) | `v10.0` |
| `linuxFxVersion` (Linux Dedicated/Premium) | `DOTNET-ISOLATED\|10.0` — confirm the exact token with `az functionapp config show` |
| `WEBSITE_USE_PLACEHOLDER_DOTNETISOLATED` | `1` (cold-start optimization; needs 64-bit worker) |

```bash
az functionapp config appsettings set -g <rg> -n <app> \
  --settings FUNCTIONS_WORKER_RUNTIME=dotnet-isolated FUNCTIONS_EXTENSION_VERSION=~4
az functionapp config set -g <rg> -n <app> --net-framework-version v10.0 --use-32bit-worker-process false
```

## In-process → isolated migration

[Official guide](https://learn.microsoft.com/en-us/azure/azure-functions/migrate-dotnet-to-isolated-model). It gives worked examples for .NET 8 and .NET Framework 4.8 only and says to adapt them for .NET 10.

Inventory which apps are still in-process:

```powershell
Get-AzFunctionApp | Where-Object { $_.Runtime -eq 'dotnet' } | Select-Object Name, Runtime
```

### Program.cs replaces Startup.cs

Delete the class with `[assembly: FunctionsStartup(typeof(Startup))]`. Everything on `IFunctionsHostBuilder.Services` moves to `builder.Services`.

```csharp
var builder = FunctionsApplication.CreateBuilder(args);
builder.ConfigureFunctionsWebApplication();
builder.Build().Run();
```

- `ConfigureFunctionsWebApplication()` → **ASP.NET Core integration** (`HttpRequest` / `IActionResult`). Needs `…Extensions.Http.AspNetCore`.
- `ConfigureFunctionsWorkerDefaults()` → built-in HTTP model (`HttpRequestData` / `HttpResponseData`).

`FunctionsApplication.CreateBuilder()` gives you default converters, `JsonSerializerOptions` ignoring property-name casing, Functions logging integration, output-binding and execution middleware, gRPC support, plus the usual `Host.CreateDefaultBuilder()` defaults.

**Configuration caveat:** custom configuration sources on the builder apply **only to your code**. Trigger/binding configuration (`Connection` names) is resolved by the platform from application settings, Key Vault references, or App Configuration references — not from your `IConfiguration` providers.

### Attribute and signature changes

| In-process | Isolated |
|---|---|
| `[FunctionName("X")]` | `[Function("X")]` / `[Function(nameof(X))]` |
| `using Microsoft.Azure.WebJobs;` | `using Microsoft.Azure.Functions.Worker;` |
| `public static class` | non-static class with constructor DI |
| Triggers (`[QueueTrigger]`, `[BlobTrigger]`, …) | same names |
| Input bindings `[CosmosDB]`, `[Blob]`, `[Table]` | add `Input` suffix → `[CosmosDBInput]`, `[BlobInput]`, `[TableInput]` |
| Output bindings `[Queue]`, `[Blob]`, `[ServiceBus]` | add `Output` suffix |
| `out T` / `ICollector<T>` output params | move to the return type, or a POCO with one attributed property per output |
| `IAsyncCollector<T>` | bind to `T[]`, or inject the service client |
| `IBinder` (imperative binding) | **removed, no equivalent** — inject a service client or use SDK-type input bindings |
| `ILogger log` parameter | constructor-injected `ILogger<T>`, or `FunctionContext.GetLogger(…)` |
| `ExecutionContext` (Functions type) | gone — use the `<Using Alias>` shim above |

### HTTP

| Model | Types | Package |
|---|---|---|
| **ASP.NET Core integration** (recommended) | `HttpRequest` → `IActionResult` | `…Extensions.Http.AspNetCore` + `ConfigureFunctionsWebApplication()` |
| Built-in worker HTTP | `HttpRequestData` → `HttpResponseData` | `…Extensions.Http` + `ConfigureFunctionsWorkerDefaults()` |
| `HttpRequestMessage`/`HttpResponseMessage` | in-process only — gone | — |

```csharp
// before (in-process)
public static class HttpTriggerCSharp
{
    [FunctionName("HttpTriggerCSharp")]
    public static IActionResult Run(
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = null)] HttpRequest req,
        ILogger log)
    { log.LogInformation("…"); return new OkObjectResult($"Hello {req.Query["name"]}"); }
}

// after (isolated + ASP.NET Core integration)
public class HttpTriggerCSharp(ILogger<HttpTriggerCSharp> logger)
{
    [Function("HttpTriggerCSharp")]
    public IActionResult Run([HttpTrigger(AuthorizationLevel.Function, "get")] HttpRequest req)
    { logger.LogInformation("…"); return new OkObjectResult($"Hello {req.Query["name"]}"); }
}
```

Prefer the ASP.NET Core integration: it keeps function bodies near-identical, and it makes functions **unit-testable with `DefaultHttpContext`** and no Functions host. Mocking `HttpRequestData`/`FunctionContext` requires substantial fake plumbing.

Multiple outputs including an HTTP result:

```csharp
public class MyOutputType
{
    [HttpResult] public IActionResult Result { get; set; }
    [QueueOutput("myQueue")] public string MessageText { get; set; }
}
```

### Middleware (isolated only)

```csharp
builder.UseMiddleware<ExceptionHandlingMiddleware>()
       .UseWhen<StampHttpHeaderMiddleware>(ctx =>
           ctx.FunctionDefinition.InputBindings.Values
              .First(a => a.Type.EndsWith("Trigger")).Type == "httpTrigger");
```

`FunctionContext` extensions available in middleware: `GetHttpRequestDataAsync`, `GetHttpResponseData`, `GetInvocationResult`, `GetOutputBindings`, `BindInputAsync`. This is the natural home for cross-cutting exception handling that used to be try/catch boilerplate. Directly unit-testable against a fake `FunctionContext` + `FunctionExecutionDelegate`.

### JSON serialization — a real migration risk

**In-process defaulted to Newtonsoft; isolated defaults to System.Text.Json.** Payload shapes can silently change: casing, `null` handling, `DateTime` formats, and `[JsonProperty]` attributes that STJ ignores entirely.

Either port attributes to `[JsonPropertyName]`, or de-risk the first pass by opting back into Newtonsoft:

```csharp
builder.Services.Configure<WorkerOptions>(o =>
{
    var settings = NewtonsoftJsonObjectSerializer.CreateJsonSerializerSettings();
    settings.ContractResolver = new CamelCasePropertyNamesContractResolver();
    o.Serializer = new NewtonsoftJsonObjectSerializer(settings);
});
builder.Services.AddMvc().AddNewtonsoftJson();   // for the ASP.NET Core integration path
```

### Worker 2.x default changes (bite on upgrade)

- Service provider **scope validation enabled by default in development** — latent captive-dependency bugs now throw at startup.
- `EnableUserCodeException` enabled by default (the property is obsolete).
- `ILoggerExtensions` renamed to `FunctionsLoggerExtensions`.
- **`HttpResponseData.WriteAsJsonAsync()` no longer sets status 200 automatically.** Silent behaviour change — audit every call site.
- `IncludeEmptyEntriesInMessagePayload` enabled by default.

### Retry policies

Function-level retry attributes are supported in the isolated model for **Cosmos DB, Event Hubs, Kafka, and Timer** triggers only:

```csharp
[Function(nameof(TimerFunction))]
[FixedDelayRetry(5, "00:00:10")]
public static void Run([TimerTrigger("0 */5 * * * *")] TimerInfo timer, FunctionContext ctx) { … }
```

`[ExponentialBackoffRetry]` uses `minimumInterval`/`maximumInterval`. Queue and Service Bus retries are **not** function-level — they remain the service's own delivery/dead-letter semantics. Host-level retry goes in `host.json`; `function.json` does not exist in the isolated model.

## Durable Functions

The highest-risk area. [Migration guide](https://learn.microsoft.com/en-us/azure/azure-functions/durable/durable-functions-migrate).

Namespaces: `Microsoft.DurableTask`, `.Client`, `.Entities` replace `Microsoft.Azure.WebJobs.Extensions.DurableTask`.

| In-process | Isolated |
|---|---|
| `IDurableOrchestrationContext` | `TaskOrchestrationContext` |
| `IDurableOrchestrationClient` / `IDurableClient` | `DurableTaskClient` |
| `IDurableEntityContext` | `TaskEntityDispatcher` + a POCO entity class |
| `client.StartNewAsync(…)` | `client.ScheduleNewOrchestrationInstanceAsync(…)` |
| `client.CreateCheckStatusResponse(…)` | `client.CreateCheckStatusResponseAsync(…)` |
| `RetryOptions` | `TaskRetryOptions` inside `TaskOptions` |
| `context.CallActivityWithRetryAsync<T>(name, retry, input)` | `context.CallActivityAsync<T>(name, input, taskOptions)` |
| `ILogger log` in orchestrator | `context.CreateReplaySafeLogger(…)` |

```csharp
[Function(nameof(Counter))]
public static Task Counter([EntityTrigger] TaskEntityDispatcher dispatcher)
    => dispatcher.DispatchAsync<CounterEntity>();

public class CounterEntity
{
    public int Value { get; set; }
    public void Add(int amount) => Value += amount;
    public int Get() => Value;
}
```

**Feature gaps and behaviour changes:**

- **Entity proxies removed** — no `CreateEntityProxy<T>`. Use `Entities.CallEntityAsync()` / `SignalEntityAsync()`.
- **Cross-task-hub operations removed** — overloads taking `taskHubName`/`connectionName` are gone.
- **Serialization default Newtonsoft → System.Text.Json. This affects *persisted* orchestration state.** Do not in-place upgrade an app with live in-flight orchestrations without draining them or pinning the serializer.
- `ContinueAsNew`: `preserveUnprocessedEvents` default `false` → **`true`**.
- `RestartAsync`: `restartWithNewInstanceId` default `true` → **`false`**.
- `DurableOrchestrationStatus.History` removed → `DurableTaskClient.GetOrchestrationHistoryAsync()`.

## Deployment procedure

Microsoft is explicit that the two changes must land together, and both restart the app:

1. Create a staging slot.
2. On the slot set `FUNCTIONS_WORKER_RUNTIME` = `dotnet-isolated`. **Do not mark it as a slot setting** — it must swap with the code.
3. Update stack config (`netFrameworkVersion` → `v10.0`).
4. Publish the migrated project to the slot.
5. Test, swap, verify production.

**Flex Consumption has no deployment slots** — use rolling updates or blue/green with two apps behind Front Door / Traffic Manager.

## Hosting plans

| Plan | .NET 10 isolated |
|---|---|
| Flex Consumption | ✅ (.NET 8, 9, 10). In-process not supported at all. |
| **Linux Consumption** | ❌ — .NET 9 is the last version added; plan retires 2028-09-30 |
| Premium (Elastic) / Dedicated | ✅ — set `netFrameworkVersion` / `linuxFxVersion` |
| Windows Consumption / Container Apps | Verify with `az functionapp list-runtimes` before committing |

**If you are on Linux Consumption today, .NET 10 forces a plan migration.** In-place migration to Flex is **not supported** — you create a new app.

Flex Consumption specifics that change the migration shape:

- Runtime is configured via `properties.functionAppConfig.runtime`, **not** app settings. `FUNCTIONS_WORKER_RUNTIME`, `FUNCTIONS_EXTENSION_VERSION`, `WEBSITE_RUN_FROM_PACKAGE`, `WEBSITE_CONTENTSHARE`, `netFrameworkVersion`, `linuxFxVersion`, `alwaysOn`, `use32BitWorkerProcess` and many others are **deprecated there** — remove them.
- **No deployment slots.**
- **30-second host initialization timeout, not configurable.** Heavy `Program.cs` startup (EF Core model building, warm-up calls, Key Vault fetches) can hard-fail. Audit the DI graph before moving.
- Blob trigger: **Event Grid source only** — polling blob triggers must be reworked.
- Durable: Azure Storage or Durable Task Scheduler backends only (no Netherite/MSSQL).
- 1 app per plan; NFS unsupported; instance memory 512 / 2048 / 4096 MB (2048 recommended).

## Local tooling

Azure Functions Core Tools must be recent enough to launch a `net10.0` worker; use the latest 4.x. Known field issues (check whether they still reproduce):

- net10 isolated host times out in CI when **only** .NET 10 is installed — works when .NET 8 is also present. **Install both SDKs on build agents.** ([core-tools#5138](https://github.com/Azure/azure-functions-core-tools/issues/5138))
- Core Tools can't find .NET 10 installed by `UseDotNet@2` on Windows ADO agents ([#4725](https://github.com/Azure/azure-functions-core-tools/issues/4725))
- Windows isolated worker exits with code 1 when published via ADO pipeline but works from VS ([dotnet-worker#3424](https://github.com/Azure/azure-functions-dotnet-worker/issues/3424))

## Execution order for Functions

1. Migrate in-process → isolated **on `net8.0`**. Deploy through a staging slot. Verify.
2. Bump to `net10.0`, Worker 2.x. Absorb the Worker 1.x → 2.x default changes — especially `WriteAsJsonAsync` status codes and scope validation.
3. Migrate the hosting plan if on Linux Consumption.

Each step is independently deployable. Do not bundle them.
