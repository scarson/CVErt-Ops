# .NET performance module: Caching
> Load when `IMemoryCache`/`MemoryCache`/`HttpRuntime.Cache` (etc.) is detected — see the module map in `../dotnet.md`. Core lanes + Variant notes live in `../dotnet.md`; this file is the Caching lens only.

## Caching

> Cross-cutting on **both** runtimes. In-process caching APIs differ by runtime: `IMemoryCache`
> (`Microsoft.Extensions.Caching.Memory`) on modern .NET (and available on Framework via the
> NuGet package), `System.Runtime.Caching.MemoryCache` as the portable Framework option, and
> classic ASP.NET `HttpRuntime.Cache` / `System.Web.Caching.Cache` on Framework web apps. Bullets
> are *conditions to look for*. Note up front: **cache invalidation correctness** (stale/wrong
> values served, missed evictions on writes) is a **bug-hunt concern, not a perf finding** — flag
> the boundary, don't score it as a perf win.

- **No cache on an expensive idempotent read repeated under load**: an expensive, infrequently-
  changing computation or remote/DB fetch recomputed on every request is the canonical caching
  opportunity — wrap it in an in-process cache (`IMemoryCache.GetOrCreate`/`GetOrCreateAsync`,
  `System.Runtime.Caching.MemoryCache`, or `HttpRuntime.Cache` on Framework) keyed by its inputs.
- **Cache stampede / thundering herd**: on a cold or just-evicted key, many concurrent requests
  all miss and recompute the same expensive value simultaneously, amplifying load at the worst
  moment. `IMemoryCache.GetOrCreate` does **not** coordinate concurrent factory calls by default —
  a per-key lock/`SemaphoreSlim` (single-flight) or `HybridCache` (built-in stampede protection,
  **.NET 9+**) is needed so only one caller computes while the rest await the result (verify
  against the currency brief for your version).
- **Eviction & expiration not configured**: distinguish **absolute** (`AbsoluteExpiration` /
  `AbsoluteExpirationRelativeToNow` — entry dies at a fixed time) from **sliding**
  (`SlidingExpiration` — resets on each access, so a hot key can live forever); a sliding-only
  policy on a popular key never refreshes and can serve stale data indefinitely.
- **`IMemoryCache` with no size limit grows unbounded**: by default `IMemoryCache` has **no size
  limit** and only evicts on expiration or memory pressure — set `SizeLimit` on
  `MemoryCacheOptions` and a per-entry `Size` (`SetSize`) so it bounds itself, or a cache of
  large/variable entries can drive the process toward OOM. Watch for entries cached with no
  expiration *and* no size accounting.
- **Distributed cache connection opened per call**: with `IDistributedCache` over
  **StackExchange.Redis**, the `ConnectionMultiplexer` is **expensive to create and fully
  thread-safe** — create **one** shared/long-lived instance (singleton) and reuse it; opening a
  multiplexer per operation (or per request) is a classic throughput killer. The multiplexer
  already pipelines and multiplexes concurrent callers over a single connection, so connection
  *pools* are unnecessary (verify against the currency brief for your version).
- **Serialization cost & large/hot keys on distributed entries**: `IDistributedCache` stores
  `byte[]`, so every read/write pays serialize/deserialize plus network I/O — large payloads,
  chatty per-field caching, and a single hot key funneling all traffic to one Redis node are the
  cost centers. Cache coarse, right-sized values; mind the serializer choice (`System.Text.Json`
  source-gen vs reflection — cross-reference the idiom-currency lane).
- **N sequential Redis round-trips instead of a batch/pipeline**: a loop issuing one
  `StringGet`/`StringSet` per key pays a network round-trip each time. Fire the calls concurrently
  (`StringGetAsync` × N then await), use `CreateBatch`, or `MGET`/`MSET`-style multi-key commands
  so the multiplexer pipelines them into far fewer round-trips; reserve `CommandFlags.FireAndForget`
  for non-critical writes (verify against the currency brief for your version).
- **Missing output/response caching on cacheable endpoints**: re-executing an expensive handler for
  identical requests that could be served from a cached response — see the **ASP.NET Core (hosting
  & pipeline)** subsection (`AddOutputCache`/`UseOutputCache`, response caching) and the **Classic
  ASP.NET** `OutputCache` bullet.
