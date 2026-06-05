# Rust performance module: Data parallelism & compute (rayon / polars / SIMD)
> Load when CPU-bound data-parallel or numeric compute is detected — `rayon` (`par_iter`), `polars`, `ndarray`, `std::simd`/portable-simd, `wide` — see the module map in `../rust.md`. Core lanes + Runtime & build notes live in `../rust.md`; this file is the Data parallelism & compute lens only.

## Data parallelism & compute (rayon / polars / SIMD)

> Scope: rayon data-parallel iterators, the polars columnar DataFrame engine, ndarray for
> n-dimensional numeric arrays, and explicit SIMD via `std::simd`/portable-simd and `wide`.
> The recurring theme is: parallelism only pays when total work significantly exceeds scheduling
> overhead; CPU thread pools and async I/O runtimes must stay separate to avoid core
> oversubscription; accumulate per-thread then reduce rather than sharing a contended sink; use
> lazy/columnar APIs for DataFrames rather than row-wise iteration; and rely on explicit SIMD or
> iterator forms when auto-vectorization cannot be confirmed.
> Cross-reference the **Concurrency** lane and Runtime & build notes in `../rust.md`, and the
> `async-tokio` sibling module for the CPU-pool / async-runtime boundary.

- **`par_iter` on too-small work or too-cheap per-item bodies**: rayon divides work via a
  work-stealing split protocol and schedules tasks across its thread pool — this has real
  overhead per split. When the collection is small or the per-element computation is a few
  arithmetic operations, `par_iter()` is measurably slower than a serial iterator; the
  crossover is workload-dependent and must be measured. Use `rayon::slice::ParallelSlice::
  par_chunks` or configure `with_min_len` on the parallel iterator to coarsen granularity
  so each rayon task processes enough elements to amortise the split cost (verify against the
  currency brief for your version).

- **rayon thread pool running inside a tokio worker — core oversubscription**: rayon's global
  pool defaults to `num_cpus` threads; a multi-thread tokio runtime also defaults to `num_cpus`
  workers. Calling into rayon from inside a tokio task doubles the active threads competing for
  the same cores, causing context-switch thrash and cache pressure. Keep CPU-bound rayon work
  entirely outside tokio workers — invoke it via `tokio::task::spawn_blocking` so the tokio
  executor remains free, and size the rayon pool and the tokio worker pool together to sum to a
  reasonable core budget (cross-reference the `async-tokio` sibling module and the Concurrency
  lane in `../rust.md`) (verify against the currency brief for your version).

- **Shared accumulation instead of per-thread reduce**: parallel writes to a shared sink —
  a `Mutex<Vec<T>>`, a `std::sync::atomic` counter in the inner loop, or adjacent slots of
  the same array — serialize threads or thrash cache lines. The idiomatic rayon pattern is
  `par_iter().map(…).reduce(||identity, |a, b| combine(a, b))` or `.fold(||initial, |acc,
  x| update(acc, x)).reduce(…)`, which accumulates privately per rayon task and merges at
  the end; this avoids both lock contention and false sharing (the core **Concurrency** lane
  in `../rust.md` names false sharing at a high level — the data-parallel instance is per-task
  private accumulation) (verify against the currency brief for your version).

- **`par_iter().collect()` ordering cost and `HashMap` contention**: collecting a parallel
  iterator into an ordered `Vec` requires rayon to buffer and stitch results in original order,
  which adds synchronization; when order is not needed, `par_iter().for_each(…)` or
  `.reduce(…)` avoids the bookkeeping. Collecting directly into a `HashMap` from parallel
  code contends on the map's internal lock; prefer accumulating per-task maps with
  `fold`+`reduce`, or use a concurrent map like `dashmap::DashMap` only after confirming the
  alternative is materially more complex (verify against the currency brief for your version).

- **polars eager API materialising intermediate DataFrames**: the eager `DataFrame` API
  executes and materialises each operation immediately; a pipeline of filter → select →
  groupby → aggregation produces several full intermediate allocations. The **lazy** API —
  `LazyFrame`, `scan_parquet`/`scan_csv`/`scan_ipc` + `.collect()` — defers execution and
  applies predicate pushdown, projection pruning, and parallel partition execution in a single
  pass. Row-wise iteration (`apply` with a closure over rows, Python-style `map` over
  individual values) discards the columnar engine entirely and performs individual allocations
  per row; reformulate as columnar expressions. Switch any large or chained pipeline to the
  lazy API before tuning anything else (verify against the currency brief for your version).

- **ndarray non-contiguous views and unintended copies**: ndarray operations on
  non-contiguous views (sliced with non-unit strides, transposed layouts, or views into
  Fortran-order arrays in C-order code) force the library to copy data into a contiguous
  buffer before dispatching to numeric kernels or BLAS; a `.to_owned()` in a hot path is
  often this copy surfacing. Keep arrays contiguous (`Array::as_standard_layout()`) for
  hot kernels; check memory order (row-major C vs column-major F) against the operation's
  access pattern; and enable the `blas` feature flag for ndarray to delegate linear-algebra
  operations to a tuned BLAS (OPENBLAS, MKL) rather than the pure-Rust fallback (verify
  against the currency brief for your version).

- **Auto-vectorization that silently didn't happen**: the compiler auto-vectorizes inner loops
  only when it can prove safety (no aliasing between input/output pointers, statically-known
  bounds, the target ISA is enabled). Without `-C target-cpu=native` (or the equivalent
  `target-feature` flags in `RUSTFLAGS`) the compiler targets the baseline ISA, leaving
  AVX2/AVX-512/NEON disabled even on hardware that supports them. Bounds checks on indexed
  access (`a[i]`) can also break the vectorizer's dependence analysis. Confirm vectorization
  happened by inspecting the output of `cargo asm` / `cargo-show-asm` or LLVM IR — if SIMD
  instructions are absent where expected, switch to explicit `std::simd` (portable-simd) or
  the `wide` crate to guarantee vector width regardless of optimizer mood (cross-reference
  Runtime & build notes in `../rust.md` for `-C target-cpu=native` guidance) (verify against
  the currency brief for your version).

- **Indexed access blocking vectorization in hot numeric loops**: `for i in 0..n { a[i] + b[i] }`
  emits a bounds check on each access that the optimizer cannot always eliminate, breaking the
  loop into scalar iterations or introducing conditional branches that prevent clean SIMD
  lowering. Iterating over slices directly (`for (x, y) in a.iter().zip(b.iter())`) elides
  bounds checks because the iterator carries its own length; `slice::chunks_exact(N)` gives
  the optimizer a fixed-stride loop body with no remainder check inside the main loop — prefer
  iterator forms and `chunks_exact` over manual index arithmetic in inner numeric kernels
  (verify against the currency brief for your version).

- **Adding threads to a memory-bandwidth-limited workload**: a loop that streams through a
  large array with low arithmetic intensity (sum, copy, simple element-wise transform) is
  bounded by DRAM or cache bandwidth, not by CPU compute. Throwing more rayon threads at it
  saturates the memory bus faster but does not increase throughput — threads contend on the
  same bandwidth budget and the wall time plateaus or regresses. Distinguish memory-bound
  from compute-bound with a roofline estimate or a hardware-counter profiler (perf stat,
  LIKWID) before reaching for parallelism; the payoff for parallelising memory-bound work
  is rarely proportional to thread count (cross-reference the **Algorithmic complexity**
  lane in `../rust.md`) (verify against the currency brief for your version).
