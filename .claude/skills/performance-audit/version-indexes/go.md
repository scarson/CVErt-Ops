---
index_schema_version: 1
ecosystem: go
covered_through: "Go 1.24"
built_on: 2026-06-03
sources:
  - https://go.dev/doc/go1.19
  - https://go.dev/doc/go1.20
  - https://go.dev/doc/go1.21
  - https://go.dev/doc/go1.22
  - https://go.dev/doc/go1.23
  - https://go.dev/doc/go1.24
  - https://go.dev/doc/gc-guide
  - https://pkg.go.dev/runtime/debug#SetMemoryLimit
  - https://pkg.go.dev/unique@go1.23.0
  - https://pkg.go.dev/runtime#AddCleanup
  - https://pkg.go.dev/slices@go1.21.0
  - https://pkg.go.dev/maps@go1.21.0
  - https://pkg.go.dev/sync/atomic#Int64
  - https://pkg.go.dev/golang.org/x/sync/errgroup
  - https://go.dev/blog/pgo
---
# Go performance version index
> Build-once lookup. The idiom-currency lane consults this first; live research only extends past
> `covered_through`.

## Compiler & Build

- **Profile-Guided Optimization (PGO) — preview** — landed in **Go 1.20** — compiler uses a pprof CPU profile (`-pgo=path/to/profile.pprof`) to inline hot call sites; 3–4% throughput gain — supersedes static heuristic-only inlining — use when a representative production CPU profile (`default.pgo`) is available in the main package directory.
- **Profile-Guided Optimization (PGO) — GA** — promoted to production in **Go 1.21** (default: `-pgo=auto` picks up `default.pgo`) — extends inlining to include interface-call devirtualisation; 2–7% CPU improvement on representative programs; build speed itself 6% faster (compiler was PGO-compiled) — supersedes Go 1.20 preview — commit `default.pgo` alongside source for reproducible builds.
- **PGO devirtualisation improvements** — **Go 1.22** — higher proportion of interface method calls can be devirtualised; 2–14% runtime improvement with a profile — no API change; re-profile and rebuild to benefit.
- **PGO build-time overhead reduction** — **Go 1.23** — PGO build overhead reduced from 100%+ to single-digit percentage, making PGO practical for CI/CD pipelines — no API change.
- **Compilation speed recovery** — **Go 1.20** — build speed restored to Go 1.17 levels (~10% faster than 1.18/1.19) after generics-induced regression; front-end data structure improvements — no code change required.
- **`go run` / `go tool` executable caching** — **Go 1.24** — compiled executables cached in the Go build cache; repeated `go run` invocations skip recompilation — no code change; benefits scripting and tooling loops.
- **Switch statement jump tables** — **Go 1.19** (amd64, arm64) — large integer and string switch statements compiled to O(1) jump tables instead of O(n) comparisons; ~20% faster for large switches — automatic for switch on `int`/`string` types with 8+ cases.
- **Hot basic-block alignment** — **Go 1.23** (386, amd64) — compiler aligns hot loop-header blocks to CPU cache-line boundaries; 1–1.5% throughput improvement for loop-heavy code — automatic; disable with `-gcflags=-d=alignhot=0` if binary size is a constraint.
- **Stack frame slot overlapping** — **Go 1.23** — compiler overlaps stack slots of local variables in disjoint code regions, reducing per-goroutine stack usage — automatic; benefits goroutine-heavy programs by reducing peak memory.

## Runtime & GC

- **`GOMEMLIMIT` / `debug.SetMemoryLimit`** — **Go 1.19** — soft heap ceiling respected by the GC even when `GOGC=off`; GC caps its CPU use at 50% to prevent thrashing — supersedes sole reliance on `GOGC` for memory-bound container workloads — use as `GOMEMLIMIT=<limit>` env var or `debug.SetMemoryLimit(bytes)`; leave 5–10% headroom below container memory limit; pair with higher `GOGC` (e.g. 200) to trade GC frequency for throughput.
- **GC CPU limiter** — **Go 1.19** — runtime enforces a 50% ceiling on GC CPU time over a `2×GOMAXPROCS` CPU-second window, preventing GC from starving application goroutines during heap spikes — automatic; no API required.
- **Goroutine initial stack sizing** — **Go 1.19** — initial goroutine stacks allocated based on historic average stack usage per function, reducing early stack-growth copying; at most 2× wasted space — automatic; reduces alloc pressure for programs spawning many goroutines.
- **Transparent huge page management** — **Go 1.21** (Linux) — runtime explicitly manages heap regions eligible for THP; up to 50% memory reduction for small heaps, up to 1% latency improvement for large dense heaps — automatic on Linux.
- **GC tail-latency reduction** — **Go 1.21** — GC tuning yields up to 40% reduction in tail (p99+) latency at a small throughput trade-off — automatic; tune back with `GOGC`/`GOMEMLIMIT` if throughput regression observed.
- **C-to-Go call overhead reduction** — **Go 1.21** (Unix) — cgo setup preserved across multiple calls from the same thread; cost drops from 1–3 µs to 100–200 ns per call — automatic for existing cgo code; benefits mixed-language hot paths.
- **Swiss Tables built-in map** — **Go 1.24** — `map` backed by a Swiss Tables hash table; parallel 8-slot probing via control-word metadata; up to 60% faster in map microbenchmarks, ~1.5% geometric-mean CPU improvement in real programs, lower average memory footprint — supersedes prior open-addressing map — automatic; no code changes needed; revert with `GOEXPERIMENT=noswissmap` to isolate issues.
- **`sync.Map` hash-trie implementation** — **Go 1.24** — internal `sync.Map` rewritten; modifications of disjoint key sets no longer contend on larger maps; no ramp-up time for low-contention loads — supersedes the prior read-optimised copy-on-write structure for write-heavy concurrent workloads — revert with `GOEXPERIMENT=nosynchashtriemap`.
- **`runtime.AddCleanup`** — **Go 1.24** — attaches a cleanup function to an object pointer; runs concurrently (not sequentially like finalizers), supports multiple cleanups per object, safe with cycles, and supports interior pointers — supersedes `runtime.SetFinalizer` for resource-release patterns — use when: closing file descriptors, releasing C memory, or evicting cache entries keyed on object lifetime; call `.Stop()` on the returned handle to cancel.
- **`race` detector upgrade (TSan v3)** — **Go 1.19** — race detector upgraded to ThreadSanitizer v3; 1.5–2× faster execution under `-race`, 50% less memory, supports unlimited goroutines — automatic when using `-race`; no code change needed.
- **Execution tracer overhaul** — **Go 1.22** — trace format redesigned; latency impact of starting/stopping execution traces dramatically reduced; streamable on-the-fly output — use `runtime/trace` or `golang.org/x/exp/trace` (1.22+ format only) for production tracing.

## Concurrency

- **`sync/atomic` typed values (`atomic.Int64`, `atomic.Bool`, `atomic.Pointer[T]`, etc.)** — **Go 1.19** — struct-based atomics with method receivers; `atomic.Int64` / `atomic.Uint64` are always 64-bit aligned even on 32-bit platforms, removing the alignment-fault footgun of raw `atomic.AddInt64(&x, n)` — supersedes `sync/atomic` function-based API for new code — use as struct fields; call `.Load()`, `.Store()`, `.Add()`, `.CompareAndSwap()`.
- **`sync/atomic.And` / `atomic.Or` bitwise ops** — **Go 1.23** — atomic bitwise AND/OR on `int32`/`uint32`/`int64`/`uint64` without a read-modify-write CAS loop — supersedes manual `for { old := Load(); if CompareAndSwap(old, old&mask) { break } }` patterns — use for bit-flag manipulation in concurrent hot paths.
- **`sync.Map.Clear`** — **Go 1.23** — bulk-deletes all keys without iterating via `Range`+`Delete`; O(1) allocation path — supersedes `range`-based manual deletion loop — use when resetting or expiring an entire concurrent map.
- **`errgroup.SetLimit` / `TryGo`** — **`golang.org/x/sync` v0.1.0+ (Go 1.18+)** — `SetLimit(n)` caps concurrent goroutines in the group; `TryGo(f)` submits work non-blocking (returns `false` if at limit) — supersedes manual semaphore channels for bounded parallelism — use when fanning out I/O-bound work (file reads, HTTP calls) to prevent goroutine explosion; `SetLimit(runtime.GOMAXPROCS(0))` for CPU-bound fan-out.
- **Loop variable per-iteration semantics** — **Go 1.22** — each `for`-range iteration gets its own copy of the loop variable; goroutine closures over loop variables no longer need the explicit `v := v` shadow copy — supersedes the `v := v` copy idiom (that copy is now a no-op on 1.22+) — no code change required to get correct behaviour; remove stale `v := v` copies when targeting 1.22+.
- **Unreferenced timer/`time.After` early collection** — **Go 1.23** — the runtime reworked timers so an unreferenced `Timer`/`Ticker` (including the one created by `time.After`) becomes eligible for GC as soon as it is unreachable, instead of being retained until it fires; also `Timer.Stop`/`Reset` no longer need the stale-value drain workaround — reduces (does not eliminate) the classic `time.After`-in-a-`select`-loop leak — the durable fix is still a single reusable `time.NewTimer`/`NewTicker` with `Reset`, but the per-iteration leak on 1.23+ is far cheaper than on ≤1.22.

## Stdlib & Generics

- **`slices` package** — **Go 1.21** (`slices`) — generic slice functions: `Sort`, `SortFunc`, `BinarySearch`, `Contains`, `Index`, `Compact`, `Grow`, `Clone`, `Delete`, `Insert`, `Max`, `Min`, `Reverse` — supersedes manual `sort.Slice` + index-hunting loops — use `slices.Sort`/`slices.SortFunc` instead of `sort.Slice` to avoid the per-call closure allocation; `slices.BinarySearch` replaces `sort.Search` boilerplate.
- **`slices` iterator functions** — **Go 1.23** — `slices.All`, `slices.Values`, `slices.Backward`, `slices.Collect`, `slices.AppendSeq`, `slices.Sorted`, `slices.Chunk` — lazy iteration and collection without intermediate allocations — use with `for range` and `iter.Seq`; avoids materialising intermediate slices in pipeline patterns.
- **`maps` package (core utilities)** — **Go 1.21** (`maps`) — generic map helpers: `Clone`, `Copy`, `DeleteFunc`, `Equal`, `EqualFunc` — supersedes manual map-copy loops and reflect-based equality — use `maps.Clone(m)` instead of a `for k, v := range` copy loop; avoids per-element type assertions.
- **`maps` iterator functions** — **Go 1.23** — `maps.All`, `maps.Keys`, `maps.Values`, `maps.Collect`, `maps.Insert` — key/value iteration without allocating a `[]K` or `[]V` intermediate slice — use with `for range maps.Keys(m)` to avoid the common `append`-keys-to-slice pattern.
- **`min` / `max` / `clear` builtins** — **Go 1.21** — compiler-intrinsic min/max over any ordered type (no function-call overhead, no generic instantiation cost); `clear(m)` zeroes a slice or deletes all map keys in one call — supersedes hand-written `if a < b { return a }` helpers and `for k := range m { delete(m, k) }` loops.
- **`sort` algorithm rewrite (pdqsort)** — **Go 1.19** — `sort.Slice`, `sort.Sort`, and `sort.Stable` use pattern-defeating quicksort; faster for common real-world distributions (sorted, reverse-sorted, few uniques) — automatic; also adds `sort.Find` as a cleaner alternative to `sort.Search`.
- **`math/rand/v2`** — **Go 1.22** — new PRNG package with PCG and ChaCha8 generators; unconditionally random-seeded global source enables per-thread states and eliminates the legacy global lock; `rand.N[T](max)` is generic over any integer type — supersedes `math/rand` (v1) for new code; global `math/rand` functions in v1 had a shared mutex; v2 global is lock-free — import `math/rand/v2` in new code.
- **`unique.Make` / `unique.Handle`** — **Go 1.23** (`unique`) — canonicalises (interns) any comparable value; two `Handle[T]` values compare equal iff their source values were equal, via a pointer comparison — reduces memory by deduplicating repeated equal values (strings, structs); O(1) handle comparison vs O(n) string comparison — use for interning repeated strings, IP addresses, struct keys; call `unique.Make(v)` once per value, store/compare `Handle[T]`.
- **`weak.Pointer[T]`** — **Go 1.24** (`weak`) — GC-aware weak reference; `Value()` returns `nil` after the referent is collected — supersedes `unsafe.Pointer` hacks for cache/canonicalisation maps — use with `runtime.AddCleanup` to build weak-keyed maps or bounded caches that don't prevent GC; primary use case is implementing the pattern underlying `unique.Make`.
- **`fmt.Append` / `fmt.Appendf` / `fmt.Appendln`** — **Go 1.19** — format directly into a `[]byte` without intermediate `string` allocation — supersedes `buf = append(buf, fmt.Sprintf(…)…)` — use when building byte buffers from formatted output in hot paths.
- **`encoding/binary` append variants** — **Go 1.19** — `binary.BigEndian.AppendUint16/32/64`, `binary.AppendVarint`, `binary.AppendUvarint` — write integers into an existing `[]byte` without allocation — supersedes `buf = append(buf, binary.BigEndian.Uint64ToBytes(v)…)` workarounds.
- **`reflect.Value` stack allocation** — **Go 1.21** — `reflect.ValueOf(arg)` no longer unconditionally forces the argument to the heap; most reflect operations also support stack-allocated values — automatic; reduces GC pressure in reflection-heavy hot paths.

## Maps & Data Structures

- **Built-in `map` (Swiss Tables)** — **Go 1.24** — see Runtime & GC section; the same built-in `map` type now uses Swiss Tables; all existing map code benefits without changes.
- **`maphash.Comparable[T]` / `maphash.WriteComparable`** — **Go 1.24** — hash any comparable value (struct, array, interface) consistently with Go's map key semantics — use when building custom hash maps, sharded maps, or cache keys from struct values without rolling a custom hash function.
- **`sync.Map`** — best for **read-heavy / write-once** workloads (Go 1.9+); disjoint-key write workloads improved in **Go 1.24** (hash-trie) — supersedes `map` + `sync.RWMutex` when keys are written once and read many times; for balanced read/write or highly contended writes prefer a sharded `map`+`Mutex` array.
