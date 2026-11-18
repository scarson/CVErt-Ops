# Profile Pack: Rust

Specializes the generic performance lanes for Rust codebases. Load alongside `generic-pack.md`; the
signals below narrow each lane to Rust-specific idioms and common footguns.

This is the **core** Rust pack (always-loaded lanes + Runtime & build notes). Deep, tech-specific
lenses (async/tokio, web frameworks, serde, databases, data parallelism) live in load-on-detection
modules under `profile-packs/rust/` — see **`## Framework / sub-stack modules`** at the bottom. The
core lanes are always-loaded quick-hits; a module *deepens* its area when its signals are material to
the scope.

---

## Algorithmic complexity & data structures (lane `algorithmic`)
- `Vec::contains` or `.iter().any()` inside a loop is O(n²); replace with `HashSet`/`BTreeSet`
  (verify against the currency brief for your version).
- `HashMap`/`HashSet` with default SipHash-1-3 on hot integer-keyed maps; faster non-cryptographic
  hashers (`rustc-hash`'s `FxHashMap`, `ahash`'s `AHashMap`) can give large wins for non-DoS paths
  — benchmark before switching; `ahash` can outperform `fxhash` on AES-capable CPUs while
  `fxhash` often wins on general integer keys (verify against the currency brief for your version).
- `Vec::remove` inside a loop is O(n) per call (shifts elements); prefer `Vec::swap_remove` when
  order doesn't matter, or `Vec::retain` / `HashMap::retain` for batch removal.
- Sorting or de-duplicating on every iteration rather than once at construction time.
- Repeated computation inside a loop that could be hoisted: re-parsing strings, re-compiling
  regexes, re-constructing maps or sets that are invariant over iterations.
- Large enum where all variants are sized by the biggest one; box the rare fat variant
  (`Box<LargeVariant>`) to reduce the footprint of every enum instance; use
  `RUSTFLAGS=-Zprint-type-sizes cargo +nightly build` to reveal the dominant variant's cost.
- Collecting an iterator into a `Vec` only to immediately iterate or pass it — chain lazy
  adapters instead; prefer returning `impl Iterator<Item=T>` from functions over `Vec<T>`;
  use `extend` to grow an existing collection from an iterator rather than collecting then
  appending.
- `Option::ok_or(expensive_fn())` eagerly evaluates the error argument even on `Some`; use
  `ok_or_else(|| expensive_fn())` — the same pattern applies to `unwrap_or`, `map_or`,
  `Result::or`, and `Result::map_or`.

## Memory & allocation (lane `memory`)
- Needless `.clone()`/`.to_owned()`/`.to_vec()` where a borrow (`&T`, `&str`, `&[T]`) would
  suffice; likewise `.to_string()` on a hot path when a `&str` is usable. When you must clone
  over an existing allocation, prefer `a.clone_from(&b)` — it reuses the existing buffer rather
  than allocating fresh.
- `format!` on a hot path allocates a `String` on every call; write into a pre-allocated buffer
  (`write!` into a `String`/`Vec<u8>`), use `std::format_args` to defer formatting, or replace
  with a string literal where the value is static (verify against the currency brief for your version).
- `Vec`/`String`/`HashMap` grown by repeated push without `with_capacity`; pre-size when the
  final length is known or estimable to avoid repeated doubling reallocations. Reciprocally,
  call `Vec::into_boxed_slice()` on a fully-built, stable `Vec` to drop the spare-capacity word
  and free excess memory.
- Loop-body allocations that could be "workhorse" buffers: declare the collection outside the
  loop, `clear()` inside — preserves capacity and eliminates per-iteration allocation.
- `Cow<'_, str>` (or `Cow<'_, [T]>`) where a value is almost always borrowed but occasionally
  needs mutation; avoids the unconditional `to_owned()`. `Cow::to_mut` will clone only on the
  first mutation.
- `Rc`/`Arc` wrapping small `Copy` types: the initial allocation and indirection are unnecessary
  for types cheaper to copy outright; conversely, `clone` on `Rc`/`Arc` only bumps the refcount
  and does not allocate, so using it to share large read-mostly data is appropriate.
- Types wider than 128 bytes are copied with `memcpy` rather than inline code; check hot
  oft-moved types with `std::mem::size_of` — shrink via field boxing, smaller integer widths
  (`u32`/`u16` indices instead of `usize`), or replacing a `Vec<T>` field with `Box<[T]>`
  (saves one `usize`). For vectors frequently empty inside hot structs, `ThinVec<T>` from
  `thin_vec` shrinks the struct by one word (verify against the currency brief for your version).
- `smallvec::SmallVec<[T; N]>` eliminates heap allocation for short vectors that fit in `N`
  elements inline; `arrayvec::ArrayVec<T, N>` is faster when the maximum size is statically
  known (no heap-fallback path) — benchmark before adopting; larger `N` or large `T` makes
  the inline struct heavier and copy-slower (verify against the currency brief for your version).

## Data access & I/O (lane `data-access`)
- Unbuffered file/socket I/O: `std::fs::File`, `std::net::TcpStream` are unbuffered by default;
  wrap in `BufReader`/`BufWriter` for many small reads/writes to cut syscall count. For
  high-volume stdout output, combine manual locking (`let lock = stdout.lock()`) with
  `BufWriter` — locking alone doesn't buffer.
- `println!`/`print!` acquire a mutex on every call; in output-heavy loops lock stdout once
  (`let lock = stdout.lock()`) and use `writeln!(lock, …)`.
- Blocking I/O (`std::fs`, `std::net`, synchronous HTTP clients) called from inside an async
  executor thread; move to async drivers or wrap with `spawn_blocking`
  (verify against the currency brief for your version).
- Serde repeated serialization of unchanged data on a hot path; cache the serialized bytes or
  the parsed form. Prefer borrowed `Deserialize<'de>` (zero-copy) forms to avoid allocation
  when deserializing byte slices or string data (verify against the currency brief for your version).
- Over-fetching: deserializing full structs when only a subset of fields is read; use
  `#[serde(skip)]`, partial structs, or a dedicated projection type.
- Per-item database/HTTP calls inside a loop (N+1); batch into a single query/request.
- `String` I/O incurs UTF-8 validation overhead; for ASCII or opaque-byte workloads use
  `BufRead::read_until` or byte-string crates (`bstr`) to avoid that cost.
- Missing connection pooling for database or HTTP clients; reconstructing clients per-request
  pays handshake and allocation cost every time.

## Concurrency & parallelization (lane `concurrency`)
- `Arc<Mutex<T>>` (or `Arc<RwLock<T>>`) guard held across an `.await` point; the lock stalls
  the executor thread for the full suspension period — drop or scope the guard before any
  `.await`.
- Oversized critical sections: computation, allocation, or I/O done while a mutex is held that
  could be moved outside the lock; minimize the code between lock acquisition and release.
- Independent futures `await`-ed serially (`let a = f1().await; let b = f2().await;`) when they
  can run concurrently with `tokio::join!`/`futures::join!` or a buffered `FuturesUnordered`
  stream (verify independence: no shared mutable state, no causal ordering dependency).
- Unbounded task spawning in a loop (`spawn` per item) with no back-pressure; replace with a
  bounded concurrency pattern — semaphore, a buffered `FuturesUnordered` stream with a fixed
  buffer size, or a task pool (verify against the currency brief for your version).
- CPU-bound work on the async executor thread starving I/O tasks; offload to `rayon` thread
  pool or `spawn_blocking` — rayon is idiomatic for data-parallel workloads but requires
  data independence; confirm no shared mutable state before parallelizing
  (verify against the currency brief for your version).
- False sharing: hot fields accessed from multiple threads landing on the same cache line;
  pad to cache-line alignment (`#[repr(align(64))]`) or separate into distinct structs.
- `std::sync::Mutex`/`RwLock` vs. `parking_lot` equivalents: the standard library versions
  have improved significantly on modern platforms; measure under your contention profile before
  switching — don't assume `parking_lot` wins (verify against the currency brief for your version).

## Framework-idiom currency (lane `idiom-currency`)
- Consult the currency brief for the exact versions of `tokio`, `axum`/`actix-web`, `serde`,
  `rayon`, `hyper`, and any ORM/query crate in use (verify against the currency brief for your
  version).
- Flag patterns the brief/index marks superseded or deprecated; flag fast-path APIs they list
  that the code doesn't use; flag changed defaults the code still fights.
- Offline (no brief): note candidate idiom concerns at LOW confidence, flagged for manual
  currency check.

## Payload / startup / build (lane `payload-startup`)
- Unneeded crate features via `default-features = true` inflating binary size and compile time;
  audit with `cargo tree --edges features`. (Build-profile and allocator tuning live in
  **Runtime & build notes** below.)
- Heavy `lazy_static!` / `OnceLock` / `once_cell::sync::Lazy` initializers — especially ones
  that open sockets, parse large configs, or spawn threads — running synchronously on first
  hot-path access; move to an explicit, early `init()` step.
- Work done at runtime that could be `const`-evaluated or pre-computed in `build.rs` (parsing or
  code-generation that is invariant across executions).

---

## Runtime & build notes (load for every Rust project)

Rust has no GC and "zero-cost abstractions", but those guarantees hold only under the right build, and
the compilation model has its own performance and size consequences. These durable realities are the
Rust analog of a "variant notes" section — *how the code is built, allocated, and measured* — and cut
across all the lanes above and every module below.

- **Always benchmark and profile the `--release` build**: `cargo build` (debug, `opt-level = 0`) runs
  the same code 10–100× slower, with overflow checks and debug assertions on and no inlining — a perf
  conclusion from a debug build is meaningless. Zero-cost abstractions (iterators, closures, `async`,
  generics) are zero-cost *in release*, not in debug. For a faster dev inner loop, `[profile.dev]
  opt-level = 1` keeps builds quick without full release cost (verify against the currency brief for
  your version).
- **Build-profile levers trade compile time / portability for runtime speed**: `lto = "thin"`/`"fat"` +
  `codegen-units = 1` (cross-crate inlining / whole-program opt; thin *local* LTO is on by default but
  weaker), `opt-level = 3` (or `"s"`/`"z"` to optimize for size), `panic = "abort"` (drops unwinding
  tables and landing-pad code), `-C target-cpu=native` when the build host equals the run host (unlocks
  SIMD), and PGO via `cargo-pgo` for long-lived binaries. All need benchmarking; `target-cpu=native`
  and PGO don't apply to portably-distributed binaries (verify against the currency brief for your
  version).
- **Monomorphization is zero-cost at runtime, real cost at build and binary size**: a generic function
  is compiled once per concrete type — fast and inlinable with no vtable, but duplicated code inflates
  compile time and binary size. `dyn Trait` trades one vtable indirection per call for a single shared
  copy (smaller binary, slightly slower call). A heavily-generic API instantiated over many types is a
  bloat source; `cargo bloat` and `RUSTFLAGS=-Zprint-type-sizes` (nightly) reveal where (verify against
  the currency brief for your version).
- **The global allocator is a one-line lever**: on allocation-heavy or multi-threaded workloads, the
  default system allocator vs `tikv-jemallocator` or `mimalloc` as a drop-in `#[global_allocator]` can
  cut tail latency and peak memory measurably — measure under your workload before adopting (verify
  against the currency brief for your version).
- **No GC, but cost is explicit — and bounds checks are real**: there are no GC pauses, but allocations
  and `.clone()`s are visible costs you can see and remove, and indexed access (`a[i]`) emits a bounds
  check that iterators elide. Reach for the profiler, not intuition: `criterion` for
  statistically-sound microbenchmarks (not ad-hoc wall-clock loops), `perf` + `cargo-flamegraph` /
  `samply` for CPU, `cargo-bloat` / `twiggy` for binary size, `dhat` / heaptrack for allocations — all
  on a release build with realistic data (verify against the currency brief for your version).

## Framework / sub-stack modules (load on detection)

Load the core lanes + **Runtime & build notes** above for *every* Rust project. Additionally load the
matching module when its technology is material to the audit scope, and include it as ecosystem context
in the relevant lane prompts. See the version index `../version-indexes/rust.md` for version-specific
facts.

| Detected (signals) | Load module |
|---|---|
| **Async & tokio** — `tokio`, `#[tokio::main]`, `async fn`/`.await`, `futures`, `async-trait` | [`rust/async-tokio.md`](rust/async-tokio.md) |
| **Web frameworks** — `axum`, `actix-web`, `warp`, `hyper`, `tower`/`tower-http` | [`rust/web.md`](rust/web.md) |
| **Serialization** — `serde`, `serde_json`, `bincode`, `postcard`, `rmp-serde`, `prost`, `simd-json` | [`rust/serde-serialization.md`](rust/serde-serialization.md) |
| **Database access** — `sqlx`, `diesel`, `sea-orm`, `tokio-postgres`, `deadpool`, `redis` | [`rust/database.md`](rust/database.md) |
| **Data parallelism & compute** — `rayon` (`par_iter`), `polars`, `ndarray`, `std::simd`/portable-simd, `wide` | [`rust/data-parallelism.md`](rust/data-parallelism.md) |

---

## Sources

Durable signals in this pack are grounded in these authoritative sources (version-specific facts and
their per-entry citations live in `../version-indexes/rust.md`):

- The Rust Performance Book — Nicholas Nethercote (nnethercote.github.io/perf-book): heap-allocations,
  type-sizes, iterators, hashing, io, standard-library-types, build-configuration
- **Runtime & build** — Cargo book (profiles, LTO, `codegen-units`, `panic`), rustc codegen options
  (`target-cpu`), `cargo-pgo`, `criterion`/`cargo-flamegraph`/`cargo-bloat` docs, jemalloc/mimalloc.

**Sub-stack modules** carry their own grounding; key sources per module:

- **Async & tokio** (`rust/async-tokio.md`) — tokio docs (runtime, `spawn_blocking`/`block_in_place`,
  `sync::mpsc`, `select!`), `futures` (`FuturesUnordered`/`buffer_unordered`), async-book.
- **Web frameworks** (`rust/web.md`) — axum/actix-web/hyper/tower + tower-http docs (extractors,
  layers, state, body limits/timeouts).
- **Serialization** (`rust/serde-serialization.md`) — serde docs (`borrow`, `flatten`, tagging),
  serde_json (`from_reader`/`RawValue`/`arbitrary_precision`), bincode/postcard/rmp-serde/prost,
  simd-json.
- **Database access** (`rust/database.md`) — sqlx (`Pool`, `query!`/offline, `fetch` streaming),
  diesel / diesel-async, sea-orm, deadpool, redis-rs (pipelining).
- **Data parallelism & compute** (`rust/data-parallelism.md`) — rayon docs (`par_iter`, `with_min_len`,
  `join`/`reduce`), polars (lazy/`scan_*`), ndarray (+ BLAS), `std::simd`/portable-simd.
