# Profile Pack: .NET

Covers two distinct variants with different performance models: **Modern .NET** (detected by TFM
`net8.0`+ or `netcoreapp*` in `.csproj` / `<PackageReference>`-based restore) and **.NET Framework**
(detected by TFM `net4x` and/or `packages.config`-based restore).

---

## Algorithmic complexity & data structures (lane `algorithmic`)
- LINQ chains that enumerate a sequence multiple times (e.g., calling `.Count()` then iterating);
  materialise with `.ToList()`/`.ToArray()` once when re-use is needed.
- `.Contains` on `List<T>` inside loops — O(n) per call yields O(n²) overall; replace with
  `HashSet<T>` or `FrozenSet<T>` for read-heavy lookup sets (verify against the currency brief for
  your version).
- Repeated/recomputed LINQ projections or sort keys inside loops that could be hoisted.
- Nested loops over entity collections loaded from a database — accidental O(n²) better solved at
  the query layer.
- `Dictionary<K,V>` used for a collection that is built once then queried many times: prefer
  `FrozenDictionary<K,V>` / `FrozenSet<T>` for lower lookup overhead and better cache locality
  (verify against the currency brief for your version).
- `PriorityQueue<TElement, TPriority>` for any "next cheapest item" pattern rather than
  sorted lists with O(n log n) re-sort on every insert (verify against the currency brief for your
  version).
- Culture-aware string comparison/search where ordinal would do: `==`/`.Equals`/`.IndexOf`/`.Contains`
  /`.StartsWith` default to **culture-sensitive** collation (slower, allocates, and locale-dependent)
  — pass `StringComparison.Ordinal`/`OrdinalIgnoreCase` for identifiers, keys, and lookups; use
  `StringComparer.Ordinal[IgnoreCase]` for `Dictionary`/`HashSet`/sorts; and avoid
  `ToUpper()/ToLower()` purely to compare (allocates a throwaway string per call — compare with
  `OrdinalIgnoreCase` instead).

## Memory & allocation (lane `memory`)
- LINQ on hot paths allocates iterators and delegates; prefer `for`/`foreach` with early exit, or
  array-based tight loops for throughput-critical code.
- Boxing of value types (`struct` passed as `object`, stored in non-generic collection, used as
  `IComparable`/`IEquatable` without constraints).
- Large Object Heap (LOH) pressure: arrays or strings over ~85 KB allocated and discarded
  frequently; prefer `ArrayPool<T>.Shared.Rent`/`Return` to pool buffers and
  `Microsoft.Extensions.ObjectPool.ObjectPool<T>` for heavier objects (verify against the currency
  brief for your version).
- `string` concatenation in loops — use `StringBuilder`, `string.Join`, or interpolated string
  handlers (modern .NET); raw interpolation still allocates on every call in tight loops.
- `Span<T>` / `Memory<T>` / `ReadOnlySpan<T>` / `stackalloc` opportunities to slice or work with
  buffers without heap allocation or copying (modern .NET; verify against the currency brief for
  your version).
- Collection expressions (`[x, y, z]` syntax) let the compiler choose stack- or inline-array-
  backed storage rather than a heap allocation — prefer over explicit `new List<T> { … }` where the
  declared type allows it (verify against the currency brief for your version).
- Inline arrays (`[InlineArray(N)]` structs) provide fixed-size stack storage exposed as
  `Span<T>`; used internally by the runtime and useful in hot-path structs (verify against the
  currency brief for your version).

## Data access & I/O (lane `data-access`)
- EF Core N+1: navigating a collection property inside a loop instead of using `.Include()`
  (eager loading) or a projection query; lazy loading makes this easy to trigger accidentally
  (verify against the currency brief for your version).
- Per-row saves in loops — use `ExecuteUpdate`/`ExecuteDelete` for bulk server-side mutations
  without loading entities into memory; prefer `SaveChanges` batching over per-entity calls
  (verify against the currency brief for your version).
- Missing `AsNoTracking()` on read-only queries; the change-tracker allocates and retains entity
  snapshots unnecessarily — use `AsNoTrackingWithIdentityResolution()` when de-duplication of
  related entities is still needed (verify against the currency brief for your version).
- Over-fetching: full entity materialisation when only a few columns are needed; use projections
  (`.Select()`) to pull only what is used.
- Cartesian explosion from multi-level `Include` — use `AsSplitQuery()` to issue separate SQL
  statements and avoid row multiplication (verify against the currency brief for your version).
- Hot LINQ-to-EF queries executed repeatedly with identical shapes: pre-compile with
  `EF.CompileQuery` / `EF.CompileAsyncQuery` to amortise the LINQ-to-SQL translation cost
  (verify against the currency brief for your version).
- Synchronous database calls on async paths; missing connection-pool reuse.
- Offset-based pagination (`Skip(n).Take(m)`) on large tables scans n rows on the DB; prefer
  keyset/cursor pagination for production data volumes.

## Concurrency & parallelization (lane `concurrency`)
- **Sync-over-async:** calling `.Result` or `.Wait()` on a `Task` blocks a thread-pool thread and
  causes deadlocks in contexts with a synchronisation context (classic ASP.NET / WinForms).
- Missing `ConfigureAwait(false)` in library code risks deadlock when consumed by a caller with a
  synchronisation context (particularly .NET Framework; verify against the currency brief for your
  version).
- Sequential `await` over independent async operations — use `Task.WhenAll` to run concurrently
  (verify correctness: no shared mutable state, no ordering dependency).
- Thread-pool starvation: long-running synchronous work on pool threads, or too many concurrent
  blocking calls; consider `Task.Run` with explicit sizing or dedicated threads.
- Lock contention from coarse-grained `lock` blocks; consider `SemaphoreSlim`,
  `ReaderWriterLockSlim`, or lock-free structures for read-heavy paths (verify against the
  currency brief for your version).
- `ValueTask` avoids allocations on the common synchronous-completion path; misuse (awaiting
  twice, storing in collections, not checking `IsCompleted` before awaiting) is a correctness and
  perf hazard (verify against the currency brief for your version).

## Framework-idiom currency (lane `idiom-currency`)
- Consult the currency brief. Key candidates: source-generated `System.Text.Json` vs reflection-
  based serialisation; EF Core query pipeline version and available bulk-op APIs; Regex source
  generator vs `new Regex(…)`; `SearchValues<T>` for multi-char search; `HttpClient` lifecycle
  (`IHttpClientFactory`); `Parallel.ForEachAsync` for async fan-out work (verify against the
  currency brief for your version).
- Offline (no brief): note candidate idiom concerns at LOW confidence, flagged for manual currency
  check.
- **.NET LTS/STS cadence — support-track constraint:** .NET even-numbered majors are LTS (3-year
  support); odd-numbered are STS (18-month). The current LTS is .NET 10 (Nov 2025). When
  recommending a feature that first shipped in an STS release, explicitly flag that adopting it
  requires the project to accept STS support terms — enterprise and regulated environments are
  typically pinned to the LTS track and cannot act on STS-only features. Always prefer the latest
  feature available on the project's LTS line. See the **Support cadence** section of the version
  index (`version-indexes/dotnet.md`) for the current LTS/STS table.

## Payload / startup / build (lane `payload-startup`, conditional)
- Cold-start cost: static constructors, eager DI registration of expensive services, large assembly
  loads at startup — consider lazy initialisation or background warm-up.
- AOT compilation and trimming can eliminate JIT overhead but require annotation discipline;
  reflection-heavy code silently breaks under trimming — `JsonSerializerIsReflectionEnabledByDefault`
  set to `false` forces early detection of missing source-gen coverage (modern .NET; verify against
  the currency brief for your version).
- `ReadyToRun` (R2R) pre-compiles assemblies to reduce first-JIT latency; combined with tiered PGO
  it enables re-optimisation based on runtime profiles (modern .NET; verify against the currency
  brief for your version).
- Publishing self-contained vs framework-dependent affects payload size and update surface.
- Unused NuGet package references pulled into the output; dead code that trimming could remove.

---

## Variant notes

### Modern .NET (8+/Core)
- Prefer source-generated JSON serialisation (`[JsonSerializable]` on a `partial JsonSerializerContext`
  subclass) over reflection-based `JsonSerializer` defaults — eliminates runtime reflection,
  reduces startup overhead, and is required for Native AOT (verify against the currency brief for
  your version).
- `Regex.GeneratedRegex` source generator compiles patterns at build time; prefer it over
  `new Regex(…)` or static `Regex` fields with `RegexOptions.Compiled` on hot paths (verify
  against the currency brief for your version).
- `SearchValues<T>` pre-computes search state for repeated `IndexOfAny`/`ContainsAny` operations
  across `string` or `Span<char>`; look for inline char-set arguments in search calls that could
  be promoted to a cached `SearchValues<char>` or `SearchValues<string>` (verify against the
  currency brief for your version).
- `Vector<T>`, `Vector128<T>`, `Vector256<T>`, `Vector512<T>` and hardware intrinsics (via
  `System.Runtime.Intrinsics`) enable explicit SIMD; the JIT also auto-vectorises loops over
  `Span<T>` when conditions allow — avoid branching and non-unit strides that defeat vectorisation.
- `TensorPrimitives` provides SIMD-backed bulk numerical operations (add, multiply, dot-product,
  etc.) over spans; prefer it over manual loops for numeric workloads (verify against the currency
  brief for your version).
- `IHttpClientFactory`-managed `HttpClient` instances recycle handlers correctly; a single long-
  lived manually-created `HttpClient` can exhaust sockets or hold stale DNS.
- Native AOT / ReadyToRun / tiered PGO / GC-mode options affect startup vs throughput trade-offs,
  and their defaults shift between versions (see the version index) — check that project publish
  settings are intentional (verify against the currency brief for your version).

### .NET Framework (4.x)

> High-value focus: large 4.8 codebases that grew from the 3.5/4/4.5 era. Many of these are
> *conditions to look for* in legacy code where an in-Framework upgrade (no platform migration)
> unlocks a real win. Cross-reference the **`.NET Framework (4.x timeline)`** area of the version
> index for "available since 4.Y" facts.

#### Runtime & GC configuration
- **Workstation GC running on a multi-core server**: Workstation GC is the default for standalone
  (non-hosted) apps — Server GC is **NOT** the default for non-ASP.NET processes. On a multi-core
  server, enabling Server GC (`<runtime><gcServer enabled="true"/>`) gives a per-CPU heap + dedicated
  collection threads and dramatically cuts pause time / raises throughput for allocation-heavy
  services; pair with background/concurrent GC (`<gcConcurrent enabled="true"/>`, the default).
  Caveat: don't enable Server GC on machines running many app instances — they contend (verify
  against the currency brief for your version).
- **LOH fragmentation with no compaction**: apps that churn large transient buffers/arrays (>85 KB)
  fragment the Large Object Heap, which is swept-not-compacted by default; set
  `GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce` (4.5.1+)
  before a full blocking `GC.Collect()` at a quiet point to reclaim fragmentation (verify against
  the currency brief for your version).
- **Quirks / 4.0 compatibility mode on a 4.8 app**: a big overlooked one — an app upgraded to run on
  4.8 but still *targeting* an older framework (no `<httpRuntime targetFramework="4.8"/>` in
  web.config for ASP.NET, or an old `TargetFrameworkAttribute`/build target) runs in older-version
  *quirks* compatibility mode and silently misses runtime/perf improvements. Confirm the app both
  runs on **and targets** 4.8 (verify against the currency brief for your version).
- **Legacy 64-bit JIT instead of RyuJIT**: RyuJIT is the default 64-bit JIT since **4.6** (x64);
  check no `<useLegacyJit enabled="1"/>` (or `COMPLUS_useLegacyJit=1` env/registry) is forcing the
  slower legacy x64 JIT. Also `<gcAllowVeryLargeObjects enabled="true"/>` (4.5+) is required for
  arrays >2 GB on 64-bit (verify against the currency brief for your version).

#### Memory & allocation
- **Non-generic collections that box value types**: `ArrayList` / `Hashtable` / `Queue` / `Stack`
  (non-generic) box every value-type element and lose type safety — migrate to `List<T>` /
  `Dictionary<K,V>` / `Queue<T>` to eliminate boxing allocations and per-access casts.
- **`Span<T>` / `Memory<T>` via the `System.Memory` NuGet backport** (4.5+): slice arrays/strings
  without copying. This is the portable "slow span" — real and useful, but **without the runtime
  fast-path intrinsics** of Core, and ref-struct language features need **C# 7.2+**. Pair with
  `System.Buffers` (`ArrayPool<T>.Shared`, 4.5.1+ NuGet) to pool temporary buffers and
  `System.Threading.Tasks.Extensions` (`ValueTask`, NuGet) on hot async paths (mark all three as
  NuGet backports; verify against the currency brief for your version).
- **`DataSet` / `DataTable` for large reads**: heavy per-cell `object` boxing and bookkeeping
  overhead vs streaming a `DataReader` or projecting straight to POCOs; prefer the reader/POCO path
  for large result sets and one-way reads.
- **LOH churn from large `MemoryStream`s and unsized `StringBuilder`**: repeatedly allocating large
  `MemoryStream` buffers thrashes the LOH — use `Microsoft.IO.RecyclableMemoryStream` (NuGet) to
  pool them; preallocate `StringBuilder` capacity when the final size is known; review
  `string.Intern` misuse (interned strings are never collected).

#### Networking & I/O
- **`ServicePointManager.DefaultConnectionLimit` left at 2**: defaults to **2 connections per host**
  in non-web apps (10 for ASP.NET-hosted) — a classic outbound-HTTP throughput killer; raise it
  early at AppDomain load for services that fan out to a downstream host (verify against the
  currency brief for your version).
- **Nagle + Expect100Continue latency on small requests**: `ServicePointManager.UseNagleAlgorithm`
  and `Expect100Continue` are **on by default** and add latency to small/chatty requests — disable
  both for low-latency outbound calls.
- **`HttpClient` lifecycle**: a `new HttpClient()` per request exhausts sockets (TIME_WAIT); reuse a
  single static/long-lived instance — **but** a long-lived `HttpClient` caches DNS, so set
  `ServicePoint.ConnectionLeaseTimeout` (via `ServicePointManager.FindServicePoint`) to force
  periodic connection recycling and pick up DNS changes (no `IHttpClientFactory` on Framework;
  verify against the currency brief for your version).

#### Async & threading
- **Pre-TAP async patterns**: code still using APM (`Begin*`/`End*`), `ThreadPool.QueueUserWorkItem`,
  or raw `new Thread(...)` where `async`/`await` + TAP (**4.5+**) fits — migrate I/O-bound work to
  async to free pool threads.
- **Sync-over-async deadlocks**: `.Result` / `.Wait()` / `.GetAwaiter().GetResult()` on a `Task`
  blocks a pool thread and deadlocks under the ASP.NET / WinForms `SynchronizationContext`; add
  `ConfigureAwait(false)` throughout library code (critical on Framework — the captured context is
  the deadlock source).
- **Coarse locks & legacy lock types**: `ReaderWriterLock` (legacy) is slower and more error-prone
  than `ReaderWriterLockSlim`; prefer `ReaderWriterLockSlim` / `SemaphoreSlim` for read-heavy paths.
- **ASP.NET thread-pool tuning for burst load**: under bursty load, default `minWorkerThreads` /
  `minIoThreads` (`<processModel>` / `ThreadPool.SetMinThreads`) cause 500 ms thread-injection
  stalls; tune them and `maxConcurrentRequestsPerCPU` (`aspnet.config`) for spiky workloads (verify
  against the currency brief for your version).

#### Data access (ADO.NET / EF6 / LINQ-to-SQL)
- **Buffering whole `DataSet`s instead of streaming**: prefer `DataReader` for forward-only reads;
  add `CommandBehavior.SequentialAccess` for large BLOB/CLOB columns to stream them without buffering
  the whole row.
- **Row-by-row inserts**: replace per-row `INSERT` loops with **`SqlBulkCopy`** for bulk load — orders
  of magnitude faster for large batches.
- **EF6 / LINQ-to-SQL N+1 & tracking overhead**: lazy-loading a navigation property inside a loop
  fires a SQL query per access — use eager `.Include()`; add `AsNoTracking()` (EF6) /
  `MergeOption.NoTracking` (LINQ-to-SQL / ObjectContext) for read-only queries to skip change-tracker
  snapshots; pre-compile hot query shapes with `CompiledQuery.Compile` (LINQ-to-SQL) — EF6 has an
  automatic compiled-query cache but explicit compilation still helps complex queries. EF6 has **no**
  `ExecuteUpdate`/`ExecuteDelete`; for bulk mutations use raw SQL (`Database.ExecuteSqlCommand`) or a
  stored proc (verify against the currency brief for your version).
- **Connection-pool defeating patterns**: inconsistent connection strings spawn separate pools;
  not disposing connections leaks them out of the pool — always `using`/`Dispose` `SqlConnection`
  and keep connection strings byte-identical.

#### Classic ASP.NET (WebForms / MVC5 / Web API 2)
- **`<compilation debug="true">` left on in production**: the classic, huge one — disables JIT
  optimisations, disables request timeouts, bloats output, and prevents batched compilation; set
  `debug="false"` and add `<deployment retail="true"/>` in machine.config on production servers to
  force it regardless of per-app web.config.
- **ViewState bloat (WebForms)**: large serialized ViewState on every postback inflates payload —
  disable ViewState on controls that don't need it (`EnableViewState="false"`) or use
  `ViewStateMode`.
- **Missing output caching & bundling**: no `OutputCache` directive / `[OutputCache]` on cacheable
  pages/actions re-executes expensive handlers; missing ASP.NET bundling+minification ships
  unminified, unbundled JS/CSS.
- **Synchronous pages/controllers & `Response.Redirect` overuse**: blocking pages/actions where
  async pages (`Page.RegisterAsyncTask`) / `async` MVC/Web API actions fit; `Server.Transfer` avoids
  the extra client round-trip that `Response.Redirect` incurs for same-server transfers.

#### CPU, reflection & serialization
- **`new Regex(...)` per call**: compile-once into a `static readonly Regex` (or use
  `RegexOptions.Compiled` for hot, repeatedly-reused patterns — **not** for one-shot matches, where
  compilation cost dominates) instead of constructing a `Regex` on every invocation.
- **Uncached reflection in mappers/serializers**: `Type.GetProperties()` / `MethodInfo.Invoke()` per
  call in hand-rolled mappers is expensive — cache `MemberInfo`/`PropertyInfo` and prefer compiled
  delegates (`Delegate.CreateDelegate` / expression trees) for hot property access.
- **Exceptions for control flow**: throwing/catching as normal flow is expensive on Framework (stack
  walks); use `TryParse`/`TryGetValue`/return codes instead. Also `Enum.ToString()` and
  `Enum.IsDefined` use reflection — cache results or avoid on hot paths.
- **`XmlSerializer` caching gotcha**: only `XmlSerializer(Type)` and `XmlSerializer(Type, String)`
  cache the dynamically generated serialization assembly. Constructors taking `XmlAttributeOverrides`
  / extra `Type[]` / `XmlRootAttribute` generate a **new temp assembly per instance that is never
  unloaded** — a memory leak + perf cliff if constructed per call; cache these serializer instances
  yourself (e.g., in a dictionary).
- **`BinaryFormatter` & per-call serializer settings**: avoid `BinaryFormatter` (slow and a known
  RCE security risk — deprecated/removed in modern .NET); cache `JsonSerializerSettings` /
  `DataContractSerializer` instances rather than allocating per call. Newtonsoft.Json is the typical
  default serialiser; review payload-widening settings (`TypeNameHandling`,
  `PreserveReferencesHandling`) (verify against the currency brief for your version).

---

## Framework / sub-stack modules (load on detection)

Load the core lanes + **Variant notes** above for *every* .NET project. Additionally load the matching
module file when its technology is detected in the audit scope, and include it as ecosystem context in
the relevant lane prompts. (These tech-specific lenses were split out of this pack so a run pastes only
what's relevant — see the version index `../version-indexes/dotnet.md` for version-specific facts.)

| Detected (signals) | Load module |
|---|---|
| **ASP.NET Core (hosting & pipeline)** — `Microsoft.AspNetCore.*`, Web-SDK `.csproj`, `Program.cs`/`Startup.cs`, controllers/minimal APIs | [`dotnet/aspnet-core.md`](dotnet/aspnet-core.md) |
| **Blazor** — `*.razor`, `Microsoft.AspNetCore.Components.*` | [`dotnet/blazor.md`](dotnet/blazor.md) |
| **WCF (services)** — `System.ServiceModel`, `*.svc`, `[ServiceContract]`, `ChannelFactory` | [`dotnet/wcf.md`](dotnet/wcf.md) |
| **Data access — SQL Server (EF6 / EF Core / ADO.NET / Dapper)** — EF6/EF Core, `System.Data.SqlClient`/`Microsoft.Data.SqlClient`, Dapper, `*.edmx`, `DbContext` | [`dotnet/sql-server-data.md`](dotnet/sql-server-data.md) |
| **WinForms** — `System.Windows.Forms`, `*.Designer.cs`, `OutputType=WinExe` + `net*-windows` | [`dotnet/winforms.md`](dotnet/winforms.md) |
| **WPF** — `*.xaml`, `PresentationFramework`/`System.Windows`, `<UseWPF>` | [`dotnet/wpf.md`](dotnet/wpf.md) |
| **Caching** — `IMemoryCache`/`MemoryCache`/`HttpRuntime.Cache`, `StackExchange.Redis`/`IDistributedCache`, `HybridCache` | [`dotnet/caching.md`](dotnet/caching.md) |
| **Dependency injection (containers)** — `Microsoft.Extensions.DependencyInjection`, Autofac/Unity/Ninject/SimpleInjector/Castle Windsor | [`dotnet/dependency-injection.md`](dotnet/dependency-injection.md) |
| **Native / COM interop (incl. Office automation)** — `[DllImport]`/`[LibraryImport]`, `Microsoft.Office.Interop.*`, `[ComImport]`, `Marshal.`, `ComWrappers` | [`dotnet/interop.md`](dotnet/interop.md) |
| **Object mapping** — `AutoMapper`, `Riok.Mapperly`, `IMapper`, `.Map<`, `.ProjectTo<` | [`dotnet/object-mapping.md`](dotnet/object-mapping.md) |
| **Messaging & realtime** — `Microsoft.AspNetCore.SignalR`/`Microsoft.AspNet.SignalR`, `System.Messaging` (MSMQ), `Azure.Messaging.ServiceBus`, `RabbitMQ.Client` | [`dotnet/messaging-realtime.md`](dotnet/messaging-realtime.md) |

## Sources

Durable signals in this pack are grounded in these authoritative sources; **version-specific** facts
and their per-entry citations live in `../version-indexes/dotnet.md` (which carries a full `sources:`
frontmatter list).

- **Runtime / BCL** — MS Learn .NET docs; devblogs.microsoft.com "Performance Improvements in .NET 6–10" (Stephen Toub); "What's new in .NET 8/9/10/11".
- **EF / data** — EF Core "Performance" docs (efficient querying/updating, tracking); EF6 "Performance Considerations for EF 4/5/6"; ADO.NET (connection pooling, `SqlBulkCopy`, `SqlDataReader`); SQL Server query-processing-architecture guide; Dapper README.
- **ASP.NET Core / Blazor** — release notes 6–10, performance best practices, output caching, Kestrel HTTP/3, Blazor virtualization & render-modes.
- **.NET Framework** — Workstation-vs-Server GC, `gcAllowVeryLargeObjects`, `LargeObjectHeapCompactionMode`, `<useLegacyJit>`, `ServicePointManager.DefaultConnectionLimit`, application-compatibility/quirks, `XmlSerializer` remarks, Framework TLS.
- **WCF** — `ServiceThrottlingBehavior`, "Large Data and Streaming", "Channel Factory and Caching".
- **WinForms / WPF** — "Optimizing WPF Application Performance" series; WinForms `DataGridView` performance & virtual mode.
- **Caching / DI / interop** — "Caching in .NET"; StackExchange.Redis (Basics, Pipelines & Multiplexers); ".NET dependency injection guidelines"; COM interop / Runtime Callable Wrapper / P/Invoke type-marshalling; "Considerations for unattended/server-side Automation of Office".
