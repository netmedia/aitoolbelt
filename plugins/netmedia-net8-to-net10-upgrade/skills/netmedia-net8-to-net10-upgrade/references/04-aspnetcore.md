# ASP.NET Core 8 → 10 — Web APIs and website projects

Contents: [1. Adopt](#1-what-to-adopt) · [2. Hosting](#2-hosting-modernization) · [3. Blazor](#3-blazor) · [4. Breaking changes](#4-breaking-changes) · [5. Pitfalls](#5-upgrade-pitfalls) · [6. Order](#6-suggested-order)

Mechanical first: `<TargetFramework>net10.0</TargetFramework>`, bump every `Microsoft.AspNetCore.*`, `Microsoft.Extensions.*`, `Microsoft.EntityFrameworkCore.*`, `System.Net.Http.Json` to `10.0.*`, Docker base image → `mcr.microsoft.com/dotnet/aspnet:10.0`. Then build and treat the `ASPDEPR*` warnings as the work list (§4).

Migration guides: [8→9](https://learn.microsoft.com/en-us/aspnet/core/migration/80-to-90) · [9→10](https://learn.microsoft.com/en-us/aspnet/core/migration/90-to-100)

## 1. What to adopt

### 1.1 Built-in OpenAPI replacing Swashbuckle / NSwag

Swashbuckle was removed from the `webapi` templates in .NET 9+. The in-box replacement (`Microsoft.AspNetCore.OpenApi`) generates the **document only** — no UI.

```csharp
// before (.NET 8)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c => { c.SwaggerDoc("v1", new OpenApiInfo { Title = "My API" }); });
app.UseSwagger();
app.UseSwaggerUI();

// after (.NET 10)
builder.Services.AddOpenApi();                 // document name defaults to "v1"
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();                          // GET /openapi/v1.json
    app.MapScalarApiReference();               // GET /scalar   (package: Scalar.AspNetCore)
}
```

| Concern | API |
|---|---|
| Multiple documents | `AddOpenApi("v1")`, `AddOpenApi("internal")`; endpoints tagged with `.WithGroupName("v1")` |
| Filter endpoints per doc | `options.ShouldInclude = desc => desc.GroupName == "public"` |
| Spec version | `options.OpenApiVersion = OpenApiSpecVersion.OpenApi3_0` (**default in .NET 10 is 3.1**) |
| YAML | `app.MapOpenApi("/openapi/{documentName}.yaml")` |
| Auth on the doc endpoint | `app.MapOpenApi().RequireAuthorization("ApiTesterPolicy")` |
| Caching | `app.MapOpenApi().CacheOutput()` |
| Doc access outside a request | inject `IOpenApiDocumentProvider` (new in .NET 10) |
| Build-time generation | `Microsoft.Extensions.ApiDescription.Server` + `<OpenApiDocumentsDirectory>` |

Transformers replace Swashbuckle filters:

```csharp
builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer((doc, ctx, ct) => { doc.Info.Title = "My API"; return Task.CompletedTask; });
    options.AddOperationTransformer(async (op, ctx, ct) => { /* … */ });
    options.AddSchemaTransformer(/* … */);
});
```

Per-endpoint: `.AddOpenApiOperationTransformer((op, ctx, ct) => { … })`.

**What breaks:**

1. `.WithOpenApi()` deprecated — `ASPDEPR002`. Signature changed: the old form returned `operation`, the new returns `Task`.
   ```csharp
   .WithOpenApi(op => { op.Summary = "…"; return op; });                                    // .NET 8/9
   .AddOpenApiOperationTransformer((op, ctx, ct) => { op.Summary = "…"; return Task.CompletedTask; });  // .NET 10
   ```
2. `Microsoft.OpenApi` 2.0 GA: `OpenApiSchema.Nullable` gone; `OpenApiAny`/`OpenApiString`/`OpenApiInteger` replaced by `System.Text.Json.Nodes.JsonNode`; entity types are interfaces; HTTP method is an object not an enum.
   ```csharp
   schema.Example = new OpenApiObject { ["date"] = new OpenApiString("2026-01-01") };  // .NET 9
   schema.Example = new JsonObject      { ["date"] = "2026-01-01" };                   // .NET 10
   ```
3. **OpenAPI 3.1 output shape**: nullable is `type: ["string","null"]` / `oneOf: [{$ref},{type:null}]` rather than `nullable: true`. **Downstream client generators pinned to 3.0 will choke.** Force 3.0 if needed.
4. `Microsoft.Extensions.ApiDescription.Client` (`<OpenApiReference>`, `dotnet openapi`) deprecated → NSwag CLI, Kiota, or `openapi-generator-cli`.
5. `IncludeOpenAPIAnalyzers` / MVC API analyzers deprecated (`ASPDEPR007`) → `TypedResults` / `Results<T1,T2>` return types.

**UI options:** Scalar (`app.MapScalarApiReference()`, what the docs lead with) or keep Swagger UI without SwaggerGen (`Swashbuckle.AspNetCore.SwaggerUi` + `app.UseSwaggerUI(o => o.SwaggerEndpoint("/openapi/v1.json", "v1"))`). Gate any UI behind `IsDevelopment()`. Set `launchUrl` in `launchSettings.json`.

**XML comments → OpenAPI (new in .NET 10):** just set `<GenerateDocumentationFile>true</GenerateDocumentationFile>`. A source generator reads `<summary>`, `<remarks>`, `<param>`, `<returns>`. **Requires named methods, not lambdas** — another reason to move handlers out of `Program.cs`.

**Decision:** if the project has deep Swashbuckle customization (`IDocumentFilter`, `ISchemaFilter`, security definitions, polymorphism config), Swashbuckle still works as a NuGet package on .NET 10. Migrate per project, and **propose** rather than apply — downstream client generation is usually owned by someone else.

### 1.2 HybridCache replacing `IMemoryCache` + `IDistributedCache`

Package `Microsoft.Extensions.Caching.Hybrid` (GA). Targets netstandard2.0+, so shared libraries can use it.

```csharp
builder.Services.AddHybridCache(options =>
{
    options.MaximumPayloadBytes = 1024 * 1024;
    options.DefaultEntryOptions = new HybridCacheEntryOptions
    {
        Expiration = TimeSpan.FromMinutes(5),           // L2
        LocalCacheExpiration = TimeSpan.FromMinutes(5)  // L1
    };
});

public class SomeService(HybridCache cache)
{
    public Task<SomeInfo> GetAsync(string name, int id, CancellationToken token = default)
        => cache.GetOrCreateAsync($"someinfo:{name}:{id}",
               async cancel => await ExpensiveAsync(name, id, cancel),
               cancellationToken: token).AsTask();
}
```

Zero-closure overload for hot paths:

```csharp
await cache.GetOrCreateAsync(key, (name, id, obj: this),
    static async (state, ct) => await state.obj.ExpensiveAsync(state.name, state.id, ct),
    cancellationToken: token);
```

Also: `RemoveByTagAsync("tag")` and reserved wildcard `RemoveByTagAsync("*")` (logical invalidation), `.AddSerializer<T, TSerializer>()`, `[ImmutableObject(true)]` to skip deserialization. L2 comes from whatever `IDistributedCache` is registered; with none, it degrades to L1-only.

Why adopt: **stampede protection** (one factory invocation per key), tag invalidation, unified L1/L2 — none of which the .NET 8 pair gives you.

### 1.3 Built-in validation (`AddValidation`)

New in .NET 10. Package `Microsoft.Extensions.Validation`. Roslyn source-generator based (AOT/trim friendly). **Minimal APIs and Blazor only — MVC is not supported**; MVC keeps `ModelState` / `[ApiController]` automatic 400s.

```csharp
builder.Services.AddValidation();

app.MapPost("/products", (Product product) => TypedResults.Ok(product));
public record Product([Required] string Name, [Range(1, 1000)] int Quantity);
```

Invalid input → automatic 400 with `HttpValidationProblemDetails`, customizable via `IProblemDetailsService`. Order per type: property attributes → type-level attributes → `IValidatableObject.Validate`, short-circuiting at the first failing stage.

```csharp
[ValidatableType]                      // force discovery of a type the generator can't see statically
public class Order { public Customer Customer { get; set; } = new(); }

app.MapPost("/x", …).DisableValidation();   // opt an endpoint out
[SkipValidation] public string Internal { get; set; }
```

**Multi-assembly gotcha:** the generator only sees the assembly where `AddValidation()` is called. If endpoints live in another project, wrap the call there and call the wrapper from `Program.cs`.

Known limitation: nullable value types as minimal API parameters are not validated ([aspnetcore#67033](https://github.com/dotnet/aspnetcore/issues/67033)).

### 1.4 `TypedResults` and typed return signatures

Now effectively required, since OpenAPI metadata is inferred from the return type and the MVC OpenAPI analyzers are deprecated.

```csharp
public static async Task<Results<Ok<Todo>, NotFound, ValidationProblem>> GetTodo(int id, TodoDb db)
    => await db.Todos.FindAsync(id) is Todo t ? TypedResults.Ok(t) : TypedResults.NotFound();

// controllers too — replaces stacked [ProducesResponseType]
[HttpGet("{id}")]
public async Task<Results<Ok<Product>, NotFound>> GetProduct(int id) => …;
```

New in .NET 9: `TypedResults.InternalServerError()`, `Problem(…)`/`ValidationProblem(…)` accepting extension dictionaries, `.ProducesProblem()` applicable to a **route group**. Test benefit: `Assert.IsType<Ok<WeatherForecast[]>>(result)`.

### 1.5 Route groups

```csharp
app.MapGroup("/private/todos")
   .MapTodosApi()
   .WithTags("Private")
   .RequireAuthorization()
   .RequireRateLimiting("fixed")
   .ProducesProblem();
```

Filters run outer group → inner group → endpoint. An empty-prefix group (`MapGroup("")`) attaches shared metadata without changing routes. Prefer `IEndpointRouteBuilder`/`RouteGroupBuilder` extension methods over a 500-line `Program.cs`.

### 1.6 Server-Sent Events (.NET 10)

```csharp
app.MapGet("/heartrate", (CancellationToken ct) =>
    TypedResults.ServerSentEvents(GetHeartRate(ct), eventType: "heartRate"));
```

Overloads take `IAsyncEnumerable<string>`, `IAsyncEnumerable<T>`, or `IAsyncEnumerable<SseItem<T>>` (per-item `EventId`/`EventType`). Strings are written raw; other types use configured JSON options. The right replacement for polling endpoints and one-way SignalR streams that don't need a hub. Client side: `System.Net.ServerSentEvents.SseParser`.

### 1.7 `MapStaticAssets` (.NET 9)

```diff
- app.UseStaticFiles();
+ app.MapStaticAssets();
```

```csharp
app.MapRazorPages().WithStaticAssets();
app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}").WithStaticAssets();
```

Build/publish-time compression (gzip in build, gzip+brotli on publish), content-based SHA-256 ETags, fingerprinted filenames with `Cache-Control: max-age=31536000, immutable`. Microsoft's measured numbers: default Razor Pages 331 KB → 65 KB.

Reference fingerprinted assets with `@Assets["app.css"]` and `<ImportMap />` in Blazor; tag helpers resolve automatically in MVC/Razor Pages.

**It does not replace `UseStaticFiles` in all cases** — only files in the build manifest. You still need `UseStaticFiles` for default documents (`UseDefaultFiles()` + `UseStaticFiles()`, otherwise routing matches first and you get a 404), files outside the web root, runtime-generated/uploaded files, embedded resources, directory browsing, custom per-file headers, `ServeUnknownFileTypes`. They compose:

```csharp
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapStaticAssets();
app.MapStaticAssets().ShortCircuit();   // optional
```

Large asset sets (~1000+): `<StaticWebAssetEndpointExclusionPattern>$(StaticWebAssetEndpointExclusionPattern);lib/icons/**</StaticWebAssetEndpointExclusionPattern>`.

### 1.8 Keyed DI

Keyed services landed in .NET 8; .NET 9 extended them to **middleware constructors and `Invoke` parameters**:

```csharp
public MyMiddleware(RequestDelegate next, [FromKeyedServices("test")] MySingleton svc) => _next = next;
public Task Invoke(HttpContext ctx, [FromKeyedServices("test2")] MyScoped scoped) => _next(ctx);
```

Use this to delete `IServiceProvider`-sniffing factories and `Func<string, IFoo>` named-registration hacks.

### 1.9 `IExceptionHandler` + ProblemDetails

```csharp
builder.Services.AddProblemDetails(o => o.CustomizeProblemDetails =
    ctx => ctx.ProblemDetails.Extensions.Add("nodeId", Environment.MachineName));
builder.Services.AddExceptionHandler<CustomExceptionHandler>();   // singleton; multiple run in registration order

if (!app.Environment.IsDevelopment()) { app.UseExceptionHandler(); app.UseHsts(); }
app.UseStatusCodePages();
```

.NET 9 added `ExceptionHandlerOptions.StatusCodeSelector`.

⚠️ **.NET 10 silent observability regression:** when `TryHandleAsync` returns `true`, diagnostics are suppressed by default — no `UnhandledException` log, no EventSource event, no `error.type` tag on `http.server.request.duration`. Restore:

```csharp
app.UseExceptionHandler(new ExceptionHandlerOptions { SuppressDiagnosticsCallback = _ => false });
```

### 1.10 Service discovery + OpenTelemetry defaults

Even without adopting Aspire orchestration, lift the `ServiceDefaults` shape into a shared project — it is the current recommended observability baseline.

```csharp
builder.Services.AddServiceDiscovery();
builder.Services.ConfigureHttpClientDefaults(http =>
{
    http.AddStandardResilienceHandler();   // Microsoft.Extensions.Http.Resilience
    http.AddServiceDiscovery();
});
builder.Services.AddHttpClient<CatalogClient>(c => c.BaseAddress = new("https+http://catalog"));
```

`https+http://` tries HTTPS endpoints first. Config-driven: `{ "Services": { "catalog": { "https": [ "localhost:8080" ] } } }`. Kubernetes / Container Apps native DNS: `AddPassThroughServiceEndpointProvider()`.

New telemetry worth wiring to dashboards: .NET 9 — `kestrel.connection.duration` gains `error.type`, SignalR `ActivitySource`s, `.DisableHttpMetrics()` on health checks. .NET 10 — authentication/authorization metrics, the `Microsoft.AspNetCore.Identity` meter, Blazor component/circuit metrics, memory-pool metrics.

### 1.11 Migrating off the classic Application Insights SDK

If a project references `Microsoft.ApplicationInsights.*` (`.AspNetCore`, `.WorkerService`, or plain `Microsoft.ApplicationInsights`), ask: **is this project ready to move to the Azure Monitor OpenTelemetry Exporter?** The classic SDK is in maintenance mode; Microsoft's actively-developed path — and, for isolated-worker Azure Functions specifically, the explicitly documented one — is OpenTelemetry via `Azure.Monitor.OpenTelemetry.Exporter`. This is a good Modernization-phase candidate, same tier as `IExceptionHandler`/HybridCache: usually applied per-project, not solution-wide in one commit, since a shared library (e.g. a `netmedia`-style base project) can pull the classic SDK into some projects and not others — check each project's own package references rather than assuming solution-wide uniformity.

**Full migration vs. running both.** Running the classic SDK and OpenTelemetry side by side is not free — both would typically export to the same Application Insights resource, so anything both track (request/dependency telemetry) risks being double-counted. Prefer a full migration per project unless there's a specific reason to stage it (e.g. validating OTel output against a known-good classic-SDK baseline before cutting over). A full migration removes the classic SDK's package references and its `Add*Telemetry*()`/`Configure*ApplicationInsights()` calls entirely, replacing them with the pattern below — not an additive change.

**Minimal working pattern** (ASP.NET Core or Azure Functions isolated worker):

```csharp
if (!string.IsNullOrEmpty(builder.Configuration["APPLICATIONINSIGHTS_CONNECTION_STRING"]))
{
    builder.Logging.AddOpenTelemetry(o =>
    {
        o.IncludeFormattedMessage = true;
        o.IncludeScopes = true;
    });

    builder.Services.AddOpenTelemetry()
        // Azure Functions isolated worker only — avoids host/worker telemetry duplication.
        // Omit for plain ASP.NET Core.
        .UseFunctionsWorkerDefaults()
        .WithTracing(t => t
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddEntityFrameworkCoreInstrumentation())
        .WithMetrics(m => m
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddRuntimeInstrumentation())
        .UseAzureMonitorExporter();
}
```

Requires `using OpenTelemetry;`, `using OpenTelemetry.Trace;`, `using OpenTelemetry.Metrics;`, `using OpenTelemetry.Logs;` — `WithTracing`/`WithMetrics` are extension methods on `IOpenTelemetryBuilder` that live in the root `OpenTelemetry` namespace, easy to miss since the instrumentation calls inside the lambdas (`AddAspNetCoreInstrumentation()` etc.) come from `OpenTelemetry.Trace`/`OpenTelemetry.Metrics` instead — a plausible-looking `using` list that's missing just the root namespace still fails to compile.

Gotchas that come up in a legacy codebase doing this migration for the first time:

- **`builder.Logging.AddOpenTelemetry(...)` is a separate opt-in from `builder.Services.AddOpenTelemetry()`.** The services-level call wires tracing and metrics; it does *not* route `ILogger` output anywhere. Skip the logging-builder call and logs silently stop flowing to Azure Monitor — no error, no warning, just missing log data in production.
- **For Azure Functions isolated worker, always include `Microsoft.Azure.Functions.Worker.OpenTelemetry`'s `UseFunctionsWorkerDefaults()`.** Isolated-worker Functions run a host process and a worker process; without this call, both can emit overlapping telemetry for the same invocation.
- **`UseAzureMonitorExporter()` is "cross-cutting"** — one call wires the exporter for traces, metrics, *and* logs together (confirmed in the Azure Monitor Exporter docs; has worked this way since exporter version 1.4.0-beta.3). Don't hunt for a separate logs-specific exporter registration call — the single call is correct as long as the logging opt-in above is also present.
- **A `PackageReference` added without a matching `Directory.Packages.props` `PackageVersion` entry is a common half-finished-migration smell in a CPM repo.** If you find OpenTelemetry package references already present but the project doesn't build, check for exactly this before assuming a real version-resolution conflict — it's usually someone having added the reference and not yet the central version, not a genuine NuGet conflict.
- **`OpenTelemetry.Instrumentation.EntityFrameworkCore` has no stable release** — every version ever published to NuGet is a beta (verify against the current version list at implementation time; this has been true for years, not a temporary gap). Using it means accepting a real prerelease dependency in production, not a placeholder that will resolve to stable later without action.
- **`Live Metrics`, a feature associated with the classic SDK, is preserved** — the Azure Monitor OpenTelemetry Exporter enables it by default. Not a capability lost in the migration.

Not runtime-verifiable without a live `APPLICATIONINSIGHTS_CONNECTION_STRING` and an Azure Monitor resource to inspect — flag actual trace/metric/log delivery as a MUST-TEST item if this lands without that available in the session.

### 1.12 Rate limiting (`Microsoft.AspNetCore.RateLimiting`)

Ask during Modernization: **does any public-facing endpoint have zero rate limiting?** On a legacy codebase the answer is usually yes — check with `grep -rn "AddRateLimiter\|UseRateLimiter"` before assuming. This is built into the ASP.NET Core shared framework since .NET 7 — no NuGet package needed, just `using Microsoft.AspNetCore.RateLimiting;` and `using System.Threading.RateLimiting;`.

Minimal global policy, partitioned per client IP:

```csharp
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
});
```

`app.UseRateLimiter()` goes after `UseRouting()`, before `UseCors`/`UseAuthorization` — reject abusive traffic before spending work on CORS/auth. Differentiate limits by trust level: an admin-auth-gated API can afford a higher `PermitLimit` than a public customer-facing endpoint.

**This is a starting default, not a tuned production value** — say so explicitly in the commit/report. `PermitLimit`/`Window` need real traffic data to tune correctly; a wrong-but-present limiter is still strictly better than none on a codebase that's never had one, but don't imply it's been validated against real load.

### 1.13 Output caching (`Microsoft.AspNetCore.OutputCaching`)

Ask during Modernization: **which GET endpoints return data that's safe to serve slightly stale?** This is a genuine domain-risk question, not a mechanical one — do not apply broadly without checking what each candidate endpoint actually returns. The canonical trap: an availability/booking-check endpoint looks like a read-only GET and is a tempting caching target, but caching it risks serving a stale "available" result after another request just booked that slot — a real double-booking bug, not a theoretical one. Exclude anything time-sensitive or transactional from consideration outright.

Safe candidates are pure reference/lookup data: enum-backed lookup tables, static country/language lists, rarely-edited admin-configured settings. If the endpoint's response would only change when an admin explicitly edits something (not because of concurrent user activity), it's a reasonable candidate.

```csharp
builder.Services.AddOutputCache(options =>
{
    options.AddPolicy("LookupData", p => p.Expire(TimeSpan.FromMinutes(10)));
});
// ...
app.UseOutputCache(); // after UseAuthorization(), per Microsoft's guidance - avoids caching pre-auth-check responses
```

Apply via `[OutputCache(PolicyName = "LookupData")]` per action, not globally — this keeps the "is this endpoint safe to cache" decision visible at each call site instead of buried in one global default.

### 1.14 Health checks (`Microsoft.Extensions.Diagnostics.HealthChecks`)

Ask during Modernization: **is there a `/health` endpoint anywhere?** `grep -rn "AddHealthChecks"` — usually absent on a legacy codebase. Standard pattern for an ASP.NET Core project with EF Core:

```csharp
builder.Services.AddHealthChecks().AddDbContextCheck<TContext>();
// ...
app.MapHealthChecks("/health");
```

Needs the `Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore` package — check its EF Core version requirement against the solution's central EF Core version before adding; a patch-version mismatch (e.g. health-checks package requires EF Core `>=10.0.11` but the solution centrally pins `10.0.9`) produces a `CS1705`/`NU1109` immediately, requiring the whole EF Core family bumped together. Verify the higher version is EF Core's actual current release before bumping, not a speculative jump.

**Azure Functions isolated worker doesn't have this endpoint-routing surface** — `[Function]`-attributed triggers aren't `app.Map*` endpoints, so `MapHealthChecks` doesn't apply directly. Add a lightweight HTTP-triggered function instead, following whatever HTTP-trigger pattern the rest of the Functions app already uses, checking dependency health manually (e.g. `await _context.Database.CanConnectAsync()`) and returning a simple status code.

### 1.15 Passkeys (.NET 10)

Built into `Microsoft.AspNetCore.Identity`, no extra package. `IdentityPasskeyOptions` (set `ServerDomain` explicitly), `signInManager.MakePasskeyCreationOptionsAsync` / `PerformPasskeyAttestationAsync` / `PasskeySignInAsync`, extension point `IPasskeyHandler<TUser>`. Storage via standard EF Identity migrations (`UserPasskeyInfo`) — **requires a new migration**.

Only the Blazor Web App template ships UI; MVC/Razor Pages Identity UI means rolling your own. Limitations: primary factor only (not a second factor), HTTPS mandatory, applies to all subdomains, not full WebAuthn coverage (use fido2-net-lib for that).

## 2. Hosting modernization

### 2.1 Current `Program.cs` shape

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();                       // OTel + health + discovery + resilience
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddOpenApi();
builder.Services.AddValidation();
builder.Services.AddHybridCache();
builder.Services.AddOutputCache();
builder.Services.AddRateLimiter(/* … */);
builder.Services.AddAuthentication().AddJwtBearer();
builder.Services.AddAuthorization();
builder.Services.AddApplicationServices(builder.Configuration);   // your own grouping extensions
builder.Services.AddPersistence(builder.Configuration);

var app = builder.Build();

if (app.Environment.IsDevelopment()) { app.MapOpenApi(); app.MapScalarApiReference(); }
else { app.UseExceptionHandler(); app.UseHsts(); }

app.UseHttpsRedirection();
app.UseRouting();
app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.UseOutputCache();
app.UseAntiforgery();

app.MapStaticAssets();
app.MapDefaultEndpoints();
app.MapTodoEndpoints();
app.Run();
```

Ordering constraints that bite: `UseRateLimiter` **after** `UseRouting`; `UseCors` before authentication/authorization; `UseAuthentication` before `UseAuthorization`; `UseAntiforgery` after auth and before endpoints; `MapStaticAssets` after `UseHttpsRedirection`.

### 2.2 Killing `Startup.cs`

`WebHostBuilder`, `IWebHost`, and `WebHost` are obsolete in .NET 10 (`ASPDEPR004`, `ASPDEPR008`). `UseStartup<T>()` itself is not removed — it still works via `IHostBuilder.ConfigureWebHost` — but `WebApplicationBuilder` does **not** support it, so a .NET 8 app on generic host + `Startup.cs` should convert.

```csharp
// before
public class Startup
{
    public Startup(IConfiguration configuration) => Configuration = configuration;
    public IConfiguration Configuration { get; }
    public void ConfigureServices(IServiceCollection services) { services.AddControllers(); }
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment()) app.UseDeveloperExceptionPage();
        app.UseRouting();
        app.UseEndpoints(e => e.MapControllers());
    }
}
Host.CreateDefaultBuilder(args).ConfigureWebHostDefaults(wb => wb.UseStartup<Startup>()).Build().Run();

// after
var builder = WebApplication.CreateBuilder(args);          // == ConfigureServices
builder.Services.AddControllers();
var app = builder.Build();                                 // == Configure
app.UseRouting();                                          // DeveloperExceptionPage is automatic in Development
app.MapControllers();
app.Run();
```

Mapping: `Startup.Configuration` → `builder.Configuration`; `IWebHostEnvironment env` → `builder.Environment` / `app.Environment`; `ConfigureWebHostDefaults(wb => wb.ConfigureKestrel(…))` → `builder.WebHost.ConfigureKestrel(…)`; `ConfigureLogging` → `builder.Logging`; `ConfigureAppConfiguration` → `builder.Configuration.AddX(…)`; `UseServiceProviderFactory(new AutofacServiceProviderFactory())` → `builder.Host.UseServiceProviderFactory(…)`.

Integration tests on `new WebHostBuilder()` / `TestServer` → `WebApplicationFactory<TProgram>`. `Program.cs` must expose the entry point: `public partial class Program { }` appended to top-level statements, or `<InternalsVisibleTo>`.

### 2.3 Organizing services and endpoints

```csharp
public static IServiceCollection AddApiServices(this IServiceCollection s, IConfiguration cfg)
    => s.AddOpenApi()
        .AddValidation()                 // must be called in the assembly holding the endpoints
        .AddProblemDetails()
        .Configure<MyOptions>(cfg.GetSection("My"));

public static IEndpointRouteBuilder MapTodoEndpoints(this IEndpointRouteBuilder app)
{
    var g = app.MapGroup("/todos").WithTags("Todos").RequireAuthorization().ProducesProblem();
    g.MapGet("/", GetAll);
    g.MapGet("/{id:int}", GetById);
    return app;
}
private static async Task<Results<Ok<Todo[]>, NotFound>> GetAll(AppDb db) => TypedResults.Ok(await db.Todos.ToArrayAsync());
```

Use **named static methods, not lambdas**, so the OpenAPI XML-comment generator picks up docs. For options: `AddOptions<T>().Bind(cfg.GetSection("X")).ValidateDataAnnotations().ValidateOnStart()` — pairs with the .NET 9 change that turns on `ValidateOnBuild`/`ValidateScopes` in Development.

### 2.4 Which builder

| | `CreateBuilder` | `CreateSlimBuilder` | `CreateEmptyBuilder` |
|---|---|---|---|
| appsettings / user secrets / env config | ✅ | ✅ | ❌ |
| Kestrel | ✅ | ✅ | ❌ |
| Kestrel HTTPS | ✅ | ❌ (`UseKestrelHttpsConfiguration()`) | ❌ |
| QUIC / HTTP/3 | ✅ | ❌ (`UseQuic()`) | ❌ |
| IIS integration | ✅ | ❌ | ❌ |
| `UseStaticWebAssets`, regex route constraints | ✅ | ❌ | ❌ |

**Keep `CreateBuilder` for MVC, Razor Pages, Blazor Server, and anything IIS-hosted.** `CreateSlimBuilder` is for Native AOT / trimmed minimal-API microservices only, and requires JSON source generation.

Native AOT support matrix: ✅ minimal APIs, gRPC, JWT auth, CORS, health checks, rate limiting, static files, WebSockets, SignalR (limited). ❌ **MVC, Razor Pages, Blazor Server, Session, SPA, OData, and all non-JWT authentication.** So AOT is a Web-API-only option.

## 3. Blazor

**Blazor Server (`AddServerSideBlazor` / `_Host.cshtml`) still works unchanged.** You do not have to convert to the Blazor Web App model. Converting means `AddRazorComponents().AddInteractiveServerComponents()` + `MapRazorComponents<App>().AddInteractiveServerRenderMode()`, `App.razor` replacing `_Host.cshtml`, plus `app.UseAntiforgery()`.

Required/recommended edits for 8 → 10:

1. `UseStaticFiles` → `MapStaticAssets`, plus `@Assets["app.css"]` and `<ImportMap />` in `App.razor`.
2. Blazor Web App with WASM/Auto — delete the .NET 8 template's hand-written auth-state providers:
   ```diff
   - builder.Services.AddScoped<AuthenticationStateProvider, PersistingAuthenticationStateProvider>();
     builder.Services.AddRazorComponents().AddInteractiveServerComponents().AddInteractiveWebAssemblyComponents()
   +    .AddAuthenticationStateSerialization();
   // client
   - builder.Services.AddSingleton<AuthenticationStateProvider, PersistentAuthenticationStateProvider>();
   + builder.Services.AddAuthenticationStateDeserialization();
   ```
3. `@attribute [StreamRendering(true)]` → `@attribute [StreamRendering]`.
4. Remove `<BlazorCacheBootResources>`.
5. Standalone WASM: `Blazor-Environment` header mechanism deprecated → `<WasmApplicationEnvironmentName>`.
6. Standalone WASM fingerprinting needs `<OverrideHtmlAssetPlaceholders>true</OverrideHtmlAssetPlaceholders>` and `blazor.webassembly#[.{fingerprint}].js`.
7. `blazor.boot.json` is now inlined into `dotnet.js` — **breaks custom boot-resource loaders**.

**Render modes** (.NET 9 additions): `RendererInfo.Name` / `.IsInteractive` / `AssignedRenderMode`; `@attribute [ExcludeFromInteractiveRouting]` + `HttpContext.AcceptsInteractiveRouting()` to carve static-SSR pages out of a globally-interactive app; component constructor injection; WebSocket compression on by default.

**`[PersistentState]`** (.NET 10) replaces the imperative `PersistentComponentState` + `RegisterOnPersisting` + `TryTakeFromJson` dance:

```razor
@code {
    [PersistentState]
    public int? CurrentCount { get; set; }
    protected override void OnInitialized() => CurrentCount ??= Random.Shared.Next(100);
}
```

Public properties only; nullable types to distinguish unset from null. Options: `AllowUpdates`, `RestoreBehavior.SkipInitialValue`, `RestoreBehavior.SkipLastSnapshot`. Service-level persistence via `RegisterPersistentService<T>(RenderMode.InteractiveAuto)`. Multiple instances of a component need `@key`. **Security:** under `InteractiveServer` the state is Data-Protection-protected; under WebAssembly/Auto it is **plainly exposed to the browser** — never persist secrets.

**Reconnection:** .NET 9 immediate reconnect + computed backoff via `Blazor.start({ circuit: { reconnectionOptions: … } })`. .NET 10 adds a `ReconnectModal` component, a `components-reconnect-state-changed` DOM event, a `"retrying"` state, and circuit state persistence / pause-resume. Azure SignalR Service SDK **v1.26.1+** required for stateful reconnect.

**Static SSR forms:** `app.UseAntiforgery()` mandatory; .NET 10 adds `<InputHidden>` and `<BlazorDisableThrowNavigationException>true</BlazorDisableThrowNavigationException>` (the fix for the awkward `[DoesNotReturn]` patterns in .NET 8 Identity scaffolding — strip them from `IdentityRedirectManager.cs`).

**QuickGrid:** .NET 9 `OverscanCount`; .NET 10 `RowClass` and `HideColumnOptionsAsync()`.

**Other .NET 10:** `<Router NotFoundPage="typeof(Pages.NotFound)">` and `NavigationManager.NotFound()`; `NavigateTo` no longer scrolls to top for fragment-only navigation; `NavLinkMatch.All` now ignores query string and fragment; `IJSRuntime.InvokeConstructorAsync`/`GetValueAsync<T>`/`SetValueAsync`; `OwningComponentBase` supports `IAsyncDisposable`; PWA service worker registration changed to `{ updateViaCache: 'none' }`.

## 4. Breaking changes

### ASP.NET Core 9

| Change | Impact |
|---|---|
| **Middleware types with multiple constructors** | Runtime `InvalidOperationException` — "Multiple constructors accepting all given argument types have been found". Previously the greediest won. Fix with `[ActivatorUtilitiesConstructor]`. **Known to break Autofac.Extensions.DependencyInjection 7.x.** |
| **`ValidateOnBuild`/`ValidateScopes` on in Development** | Latent DI bugs (scoped-into-singleton, unresolvable deps) now fail at startup. Fix the bugs rather than opting out. |
| **Forwarded headers ignored from unknown proxies** | Highest-risk item for reverse-proxy / TLS-terminating deployments. Infinite HTTPS redirect loops, auth failures, wrong scheme in URLs. Fix: populate `KnownProxies` / `KnownIPNetworks`. |
| `DefaultKeyResolution.ShouldGenerateNewKey` meaning changed | Data Protection key-ring internals; custom `IKeyManager` code. |
| `dotnet dev-certs https -ep` no longer creates the folder | CI script fix. |
| Legacy Mono/Emscripten globals not exported | Blazor WASM custom JS interop against `Module`/`MONO`. |

### ASP.NET Core 10

| Change | Diagnostic | Impact |
|---|---|---|
| **Cookie login redirects disabled for known API endpoints** | — | Unauthenticated requests to endpoints with `IApiEndpointMetadata` get **401/403, not 302**. Auto-applied to `[ApiController]`, JSON minimal APIs, `TypedResults` endpoints, SignalR. Restore via `OnRedirectToLogin`/`OnRedirectToAccessDenied` (§5.2). |
| **Exception diagnostics suppressed when `TryHandleAsync` returns true** | — | Silent loss of logs and metrics. `SuppressDiagnosticsCallback = _ => false`. |
| `WithOpenApi` deprecated | `ASPDEPR002` | → `.AddOpenApiOperationTransformer(…)` |
| Razor runtime compilation obsolete | `ASPDEPR003` | `AddRazorRuntimeCompilation()` etc. → Hot Reload in dev, build-time compilation in prod. |
| `WebHostBuilder` / `IWebHost` / `WebHost` obsolete | `ASPDEPR004`, `ASPDEPR008` | Mostly hits old integration tests. |
| `IPNetwork` / `KnownNetworks` obsolete | `ASPDEPR005` | `Microsoft.AspNetCore.HttpOverrides.IPNetwork` → `System.Net.IPNetwork`; `KnownNetworks` → `KnownIPNetworks`. |
| `IActionContextAccessor` obsolete | `ASPDEPR006` | → `IHttpContextAccessor` + `httpContext.GetEndpoint()?.Metadata.GetMetadata<ActionDescriptor>()`. Common in MVC apps generating URLs from services. |
| OpenAPI analyzers deprecated | `ASPDEPR007` | Remove `IncludeOpenAPIAnalyzers`; migrate to `TypedResults`. |
| `Microsoft.Extensions.ApiDescription.Client` deprecated | — | `<OpenApiReference>` / `dotnet openapi` → NSwag CLI / Kiota. |

Runtime/BCL breaks that hit web apps specifically: STJ property-name conflict validation, `XmlSerializer` and `[Obsolete]`, HTTP/3 off under `PublishTrimmed`, browser `HttpClient` streams responses by default (Blazor WASM), W3C trace propagator, `System.Linq.AsyncEnumerable` moving in-box.

## 5. Upgrade pitfalls

### 5.1 JSON

- **PipeReader-based deserialization (.NET 10).** Minimal API binding, MVC input formatters, and `ReadFromJsonAsync` now deserialize over a `PipeReader`. **Custom `JsonConverter<T>` implementations reading `reader.ValueSpan` directly can break** — the payload may arrive as a multi-segment sequence:
  ```csharp
  var span = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
  ```
- **Web defaults unchanged**: minimal APIs and MVC both use `JsonSerializerDefaults.Web`, but configured through **separate option objects** — `ConfigureHttpJsonOptions` (minimal APIs) vs `AddControllers().AddJsonOptions()` (MVC). Classic source of "it works in one endpoint style but not the other".
- **Minimal API empty string → `null` for nullable value types (.NET 10).** An empty form field bound to `DateOnly?`/`int?` is now `null` instead of a 400.
- **JsonPatch:** .NET 10 adds `Microsoft.AspNetCore.JsonPatch.SystemTextJson`. **Not a drop-in replacement** for the Newtonsoft one — no dynamic types, and STJ conventions change matching behaviour. Validate `Copy` operation counts yourself; the framework does not mitigate the memory-amplification DoS.

### 5.2 Authentication

Cookie auth on API endpoints — restore the old redirect behaviour selectively:

```csharp
options.Events.OnRedirectToLogin = ctx =>
{
    if (IsXhr(ctx.Request)) { ctx.Response.Headers.Location = ctx.RedirectUri; ctx.Response.StatusCode = 401; }
    else ctx.Response.Redirect(ctx.RedirectUri);
    return Task.CompletedTask;
};
```

**JWT claim mapping.** Security token events hand you a **`JsonWebToken`, not a `JwtSecurityToken`** — `(JwtSecurityToken)context.SecurityToken` throws `InvalidCastException`. `JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear()` no longer affects the new handler; use `options.MapInboundClaims = false`. Symptoms of getting it wrong: `User.FindFirst(ClaimTypes.NameIdentifier)` returns null (the claim is now `sub`), role policies stop matching. **Verify claim types after upgrading rather than assuming.** Watch for transitive `Microsoft.IdentityModel.*` conflicts if you also reference `Microsoft.Identity.Web`.

Analyzer **ASP0026** flags a farther-away `[AllowAnonymous]` silently overriding a nearer `[Authorize]` — treat findings as real security issues.

.NET 9 OIDC additions worth adopting: `PushedAuthorizationBehavior`, and `AdditionalAuthorizationParameters` replacing manual `OnRedirectToIdentityProvider` string-munging.

### 5.3 CORS, Kestrel, HTTP/3, IIS

- **CORS:** no breaking changes, but the ordering traps get re-triggered when `Program.cs` is rewritten — `UseCors` after `UseRouting` and before authentication/authorization/response caching; `AllowAnyOrigin()` + `AllowCredentials()` is rejected at runtime. Moving endpoints into route groups means re-applying `.RequireCors("policy")` at group level.
- **Kestrel:** no default-value changes in 9 or 10. .NET 10 adds `*.localhost` TLD support (re-run `dotnet dev-certs https --trust`) and **automatic memory-pool eviction** — expect lower steady-state RSS and **re-baseline memory alerts** rather than reading it as a regression.
- **HTTP/3:** still not enabled by default. Needs `HttpProtocols.Http1AndHttp2AndHttp3` + TLS 1.3, `builder.WebHost.UseQuic()`. Off by default under `PublishTrimmed` in .NET 10; excluded entirely from `CreateSlimBuilder`; macOS unsupported.
- **IIS:** install the .NET 10 Hosting Bundle on every server first. `ANCM_shutdownDelay` (default 1s since .NET 9) fixes recycle-time 503s — raise it via `<handlerSetting name="shutdownDelay" value="5000" />`. Behind IIS/ARR, re-check the forwarded-headers change first when diagnosing redirect loops.

### 5.4 Misc

Template asset versions bumped in .NET 9 (Bootstrap 5.3.3, jQuery 3.7.1) — scaffolded `wwwroot/lib` is stale. The developer exception page now shows endpoint metadata, which is the fastest way to diagnose most of the above.

## 6. Suggested order

1. TFM + package bump, build, capture every `ASPDEPR*`/`CS0618` warning. Fix §4 items only.
2. Boot in Development — expect DI validation failures and multi-constructor middleware exceptions first.
3. Verify behind the real proxy/IIS — forwarded headers, then cookie-auth 401/403.
4. Verify observability — `SuppressDiagnosticsCallback`, W3C propagator, memory baselines.
5. Then adopt, in ROI order: `MapStaticAssets` → `TypedResults`/route groups → built-in OpenAPI + Scalar → `AddValidation` → `IExceptionHandler`/ProblemDetails → HybridCache → ServiceDefaults/OTel → classic Application Insights → OpenTelemetry migration (§1.11, if applicable) → health checks (§1.14) → rate limiting (§1.12) → output caching (§1.13, only after auditing which endpoints are actually safe) → SSE → passkeys.
