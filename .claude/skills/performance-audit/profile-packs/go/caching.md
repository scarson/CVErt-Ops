# Go performance module: Caching (in-process: ristretto/bigcache/freecache — distributed: go-redis/memcache)
> Load when `github.com/dgraph-io/ristretto`, `github.com/allegro/bigcache`, `github.com/coocood/freecache`, `github.com/patrickmn/go-cache`, `github.com/redis/go-redis`, `github.com/bradfitz/gomemcache`, or `golang.org/x/sync/singleflight` is detected — see the module map in `../go.md`. Core lanes + Runtime & GC notes live in `../go.md`; this file is the Caching lens only.

## Caching (in-process: ristretto/bigcache/freecache — distributed: go-redis/memcache)

> Scope: in-process caches (ristretto, bigcache, freecache, go-cache, sync.Map) and distributed
> caches (go-redis, gomemcache). The recurring themes are **bounded eviction** (cap memory before
> the process OOMs), **stampede control** (single-flight prevents goroutine pile-ons at miss time),
> **GC-friendly storage** for huge caches (off-heap byte slices vs pointer-rich maps), **connection
> reuse** (one long-lived client, not one per request), and **batching** (pipelines/MGET instead
> of serial round-trips). Bullets are *conditions to look for*.

- **Cache stampede / thundering herd on a hot miss**: on a cache miss, many goroutines launching
  the same expensive fetch or computation concurrently — wrap the fill with
  `golang.org/x/sync/singleflight` (`Group.Do` / `Group.DoChan`) so exactly one call executes per
  key and all waiters share its result; this is especially critical at startup or after a TTL
  expiry wave (verify against the currency brief for your version).

- **Unbounded in-process cache → memory growth / OOM**: a bare `map` or `sync.Map` used as a
  cache with no eviction policy and no size cap grows without bound; replace with a cache that
  enforces limits — ristretto's cost-based admission/TinyLFU eviction, or freecache/bigcache's
  fixed-size ring-buffer — rather than a hand-rolled map; cross-reference the core **Memory &
  allocation** lane and the **payload/startup** notes for init-time allocation cost.

- **GC pressure from a huge pointer-rich in-process cache**: Go's GC scans every pointer in the
  live heap, so a cache holding millions of entries backed by pointers (e.g., `map[string]*T`)
  lengthens stop-the-world and concurrent mark phases; **bigcache and freecache store entries as
  `[]byte` serialized off the GC's pointer-scanning path** specifically to avoid this overhead —
  prefer them when the working set is very large (cross-reference Runtime & GC notes in
  `../go.md`).

- **`sync.Map` misuse for a balanced-read/write or high-churn cache**: `sync.Map` is optimized
  for **read-heavy / write-once** (or disjoint-key) workloads; using it for a cache with frequent
  updates or high key churn is slower than a sharded `map`+`sync.RWMutex` because dirty-map
  promotions and key-set rebuilds dominate; match the structure to the measured access pattern
  (verify against the currency brief for your version).

- **go-redis `Client`/`ClusterClient` created per request**: a `redis.Client` is itself a
  connection pool and is designed to be **long-lived and shared**; constructing one per request
  or per goroutine exhausts file descriptors and TCP connections; create a single client at
  startup, tune `PoolSize`, `MinIdleConns`, `DialTimeout`, `ReadTimeout`, and `WriteTimeout` for
  the expected concurrency, and inject it as a dependency (verify against the currency brief for
  your version).

- **Redis serial round-trips instead of pipelining or multi-key commands**: issuing many
  sequential `Get`/`Set` calls each pays a full network round-trip; use `client.Pipelined` (or
  `client.Pipeline()`) to batch commands, `MGET`/`MSET` for bulk key access, and `TxPipelined`
  where atomicity is needed; N serial round-trips dominate latency even on a local Redis instance
  (cross-reference the core **Data access & I/O** lane).

- **Over-large or serialization-heavy cache values in Redis**: caching large serialized blobs
  inflates network bandwidth, (de)serialization CPU, and Redis memory on every cache hit; right-
  size cached values to what callers actually consume, avoid caching entire documents when a
  projection suffices, and consider compression only after measuring that it pays; also avoid
  caching values cheaper to recompute than to fetch and deserialize.

- **TTL & invalidation gaps causing stale growth or expiry-wave stampedes**: no TTL on cache
  entries produces indefinite stale growth; identical TTLs on a large batch of keys causes a
  synchronized expiry spike and a recompute stampede — add per-key jitter (e.g., base TTL ±
  random fraction); also apply **negative caching** (caching a sentinel for missing keys) to
  prevent repeated backend misses for non-existent entries that are queried at high rate.
