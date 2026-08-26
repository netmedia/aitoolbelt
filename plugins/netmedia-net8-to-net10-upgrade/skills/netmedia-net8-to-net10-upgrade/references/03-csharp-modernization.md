# C# 13 / C# 14 modernization

`net10.0` implies **C# 14**; `net9.0` implies C# 13. Read in Phase 5.2.

Collection expressions, primary constructors, and `ref readonly` params are **C# 12** — already available at `net8.0`. If the codebase doesn't use them, that's pre-existing debt to sweep, not new capability.

**Sequencing rule:** retarget with `<LangVersion>12</LangVersion>` pinned, ship that, *then* unpin. The C# 14 overload-resolution changes below are silent behaviour changes; you want them isolated from the runtime bump so a bisect lands somewhere useful.

Contents: [Tier A](#tier-a--mechanical-high-volume-low-risk) · [Tier B](#tier-b--judgment-based) · [Compiler breaking changes](#c-14-compiler-breaking-changes--screen-for-these) · [New APIs worth adopting](#new-bcl-apis-worth-adopting)

## Tier A — mechanical, high volume, low risk

Drive these with `dotnet format style --severity info --diagnostics <ID>`, one diagnostic per commit.

### `field` keyword (C# 14)

Replaces a backing field whose only purpose was validation or normalization in the setter.

```csharp
// before
private string _message = "";
public string Message
{
    get => _message;
    set => _message = value ?? throw new ArgumentNullException(nameof(value));
}

// after
public string Message
{
    get;
    set => field = value ?? throw new ArgumentNullException(nameof(value));
}
```

Roslyn ships a fixer. **Caveat:** a type that already declares a field literally named `field` produces **CS9258** (binding change warning), and a local named `field` inside an accessor is now **CS9272** (error). Escape with `@field`.

### Collection expressions (C# 12)

```csharp
List<int> x = [1, 2, 3];
int[] empty = [];                 // replaces Array.Empty<T>() / Enumerable.Empty<T>()
int[] all = [..a, ..b];           // replaces a.Concat(b).ToArray()
```

Diagnostics IDE0300 / IDE0301 / IDE0303. Watch: `[]` assigned to an interface-typed target synthesizes a compiler-chosen concrete type — fine for consumption, surprising if the code later casts.

### `System.Threading.Lock` (C# 13 + .NET 9)

```csharp
// before
private readonly object _sync = new();
// after
private readonly System.Threading.Lock _sync = new();
```

The `lock` statement auto-detects the type and uses the faster API. **Two caveats:**

- If the object is ever assigned to or passed as `object`, codegen silently reverts to `Monitor`. Search for such leaks before claiming the win.
- Do **not** apply where the lock object is also used with `Monitor.Wait`/`Pulse`/`TryEnter` directly.

### Null-conditional assignment (C# 14)

```csharp
// before
if (customer is not null) customer.Order = GetCurrentOrder();
// after
customer?.Order = GetCurrentOrder();
```

The right-hand side is evaluated **only if** the left is non-null — a real short-circuit, so this is a semantic improvement over some hand-written equivalents that evaluated eagerly. `++`/`--` are not allowed.

### `params` collections (C# 13)

```csharp
public void Log(params ReadOnlySpan<string> parts)
```

Eliminates the array allocation at call sites. **Mechanical for internal APIs. Judgment for public ones** — changing `params T[]` to `params ReadOnlySpan<T>` is a *binary* breaking change for consumers. Add an overload with `[OverloadResolutionPriority]` instead.

### Small ones

- `nameof(List<>)` on unbound generics (C# 14) → `"List"`.
- `\e` escape (C# 13) replaces `''` / `'\x1b'`. Worth doing where `\x1b` was followed by hex digits — that was a latent bug.
- Implicit indexer `^` in object initializers (C# 13). Low value.

## Tier B — judgment-based

| Feature | Ver | Replaces | Notes |
|---|---|---|---|
| **Extension members (`extension` blocks)** | 14 | Static extension classes where you wanted a property or operator but had to write a method | Real change to API surface shape. Enables extension **properties**, **static** members, and **operators**: `extension<T>(IEnumerable<T> source) { public bool IsEmpty => !source.Any(); }`. `extension` is now a contextual keyword — a type or type-parameter named `extension` breaks; escape as `@extension`. |
| **Partial properties / indexers** | 13 | Generator boilerplate | Payoff is `[GeneratedRegex]` on partial properties. The implementing declaration cannot use auto-property syntax. |
| **Partial constructors and events** | 14 | Same, extended | **Breaking:** partial interface properties/events are now implicitly `virtual` and `public` — add explicit `private`/`sealed` to preserve prior behaviour. |
| **Implicit span conversions** | 14 | `.AsSpan()` noise | Best payoff is deleting `.AsSpan()` calls — but see the overload-resolution break below. Highest-risk item in this table. |
| **`ref`/`unsafe` in iterators and async** | 13 | Splitting a method in two to use `Span<T>` alongside `await` | Spans still cannot cross an `await`/`yield return` boundary. |
| **`allows ref struct`** | 13 | Duplicated generic algorithms specialized for spans | Library/perf-layer only. `where T : allows ref struct`. |
| **`[OverloadResolutionPriority]`** | 13 | Adding a faster overload without breaking source compat | The correct tool for adding span overloads beside array overloads. |
| **Lambda parameter modifiers without types** | 14 | `(string text, out int result) => …` | `(text, out result) => int.TryParse(text, out result)`. `params` still needs explicit types. |
| **User-defined compound assignment operators** | 14 | `operator +` on large mutable structs forcing a copy on `+=` | Perf-motivated, niche. |

## C# 14 compiler breaking changes — screen for these

[Full list](https://learn.microsoft.com/en-us/dotnet/csharp/whats-new/breaking-changes/compiler%20breaking%20changes%20-%20dotnet%2010)

1. **Span overload resolution shifts.** `ReadOnlySpan<T>` is now preferred over `Span<T>`; span extension methods on `T[]` become applicable where they weren't. Produces new ambiguity errors and — worse — **`ArrayTypeMismatchException` at runtime with covariant arrays**.

2. **`Enumerable.Reverse` → `MemoryExtensions.Reverse`.** When a project targets **older than `net10.0`** while using C# 14, `array.Reverse()` can bind to the in-place, `void`-returning `MemoryExtensions.Reverse` instead of LINQ's lazy one. Silent semantic disaster. Fix: `Enumerable.Reverse(x)`. Relevant to any multi-targeted project in the solution — **grep for `.Reverse()` on arrays.**

3. **Expression trees + spans.** `M((arr, num) => arr.Contains(num))` now binds to `MemoryExtensions.Contains`, throwing at runtime under `Compile(preferInterpretation: true)`. This is the one that bites LINQ-heavy business code. Fix: `((IEnumerable<int>)array).Contains(num)`, `array.AsEnumerable().Contains(num)`, or `Enumerable.Contains(array, num)`. **Grep for LINQ calls inside `Expression<Func<…>>` lambdas.**

4. `scoped`, `partial`, `extension` are contextual keywords in more positions — escape with `@scoped`, `@partial`, `@extension`.
5. `record` / `record struct` can no longer declare pointer members even with custom `Equals` (**CS8908**).
6. Warning for redundant patterns in `or` patterns (`is not null or 42`).
7. Diagnostics such as `[Obsolete]` now reported for pattern-based disposal in `foreach` / `await foreach`.
8. `MoveNext()` on a disposed enumerator returns `false` without running user code.
9. `UnscopedRefAttribute` no longer applies under pre-C#-11 ref-safety rules — old code may fail to compile.

From .NET 9, same family: overload resolution prefers `params` span-type overloads; `String.Trim(params ReadOnlySpan<char>)` overload removed.

**Escape hatch:** `<LangVersion>13</LangVersion>` (or `12`) restores prior binding while still running on `net10.0`.

## New BCL APIs worth adopting

Not required for the upgrade — pick these up in Phase 5 where they delete hand-rolled code.

### .NET 9

- **LINQ:** `CountBy`, `AggregateBy`, `Index()` — replace `GroupBy().ToDictionary(g => g.Key, g => g.Count())` and `Select((x, i) => …)`.
- **Collections:** `OrderedDictionary<TKey,TValue>`, `ReadOnlySet<T>`, `Dictionary.GetAlternateLookup<TAlternate>()` (span-keyed lookup, zero string allocation — big win in parsers and routers).
- **`Guid.CreateVersion7()`** — sequential, time-ordered UUIDs. Directly relevant if you use GUID clustered primary keys.
- **`Base64Url`** — replaces the `Replace('+','-').Replace('/','_').TrimEnd('=')` idiom.
- **`Task.WhenEach(…)`** — `await foreach` over tasks as they complete; replaces the `WhenAny` + remove-from-list loop.
- **`SearchValues.Create(string[], StringComparison)`** — SIMD multi-substring search.
- **`X509CertificateLoader`** — the SYSLIB0057 replacement.
- **STJ:** `JsonSerializerOptions.Web`, `RespectNullableAnnotations`, `RespectRequiredConstructorParameters`, `JsonSchemaExporter`, `JsonStringEnumMemberNameAttribute`.
- `Regex.EnumerateSplits`; `ReadOnlySpan<char>.Split(char)`; `System.Net.ServerSentEvents.SseParser`; `Channel.CreateUnboundedPrioritized<T>()`.

### .NET 10

- **`JsonSerializerOptions.Strict`** — one preset enabling `JsonUnmappedMemberHandling.Disallow`, duplicate-property rejection, case-sensitive binding, `RespectNullableAnnotations`, `RespectRequiredConstructorParameters`. **Adopt for inbound API and config deserialization** — converts a large class of silent data-loss bugs into exceptions. Breaking for lenient legacy payloads, so opt in per contract.
- **Async ZIP:** `ZipFile.CreateFromDirectoryAsync`, `ExtractToDirectoryAsync`, `ZipArchive.CreateAsync`, `ZipArchiveEntry.OpenAsync` — removes sync-over-async in export features.
- **`ISOWeek.GetWeekOfYear(DateOnly)`** and friends — useful in reporting/finance code.
- **`StringComparer.Create(CultureInfo, CompareOptions.NumericOrdering)`** — natural sort ("Item2" < "Item10") without a custom comparer.
- **STJ `PipeReader` support**; `JsonSourceGenerationOptionsAttribute.ReferenceHandler`.
- Post-quantum crypto: `MLKem` (stable), `MLDsa`/`SlhDsa` (experimental); `X509Certificate2Collection.FindByThumbprint(HashAlgorithmName, string)` for non-SHA-1 lookup.
- `System.Numerics.Tensors` now stable; `TimeSpan.FromMilliseconds(long)` single-arg overload.

### Free performance (no code change)

JIT: struct args in shared registers, array interface method devirtualization (`foreach` over an array as `IEnumerable<T>` no longer pays a virtual call), escape analysis now stack-allocates small fixed-size arrays and non-escaping closures. GC: Arm64 dynamic write-barrier switching, ~8–20% pause improvement. Measure before and after so you can attribute changes correctly.
