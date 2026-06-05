# Rust performance module: Async & tokio
> Load when async Rust on tokio is detected — `tokio`, `#[tokio::main]`, `async fn`/`.await`, `futures`, `async-trait` — see the module map in `../rust.md`. Core lanes + Runtime & build notes live in `../rust.md`; this file is the Async & tokio lens only.

## Async & tokio

> Scope: the tokio runtime and the broader `futures` ecosystem — task scheduling, channel selection,
> combinators, and `async fn` in traits. The recurring theme is: don't block the executor (any
> synchronous work that stalls a worker thread stalls every task multiplexed on it), bound
> concurrency and channels so a fast producer can't blow out memory, treat cancellation as a
> first-class control-flow event rather than an afterthought, and keep futures small and `Send` so
> they remain schedulable on the multi-thread runtime without boxing. The **Concurrency** lane in
> `../rust.md` covers the high-frequency async footguns (`Arc<Mutex<T>>` across `.await`, serial
> awaits, unbounded spawn, CPU-bound on executor); this module goes deeper into runtime mechanics.

- **`spawn_blocking` vs `block_in_place` for synchronous work**: synchronous or CPU-bound code
  called from a worker thread stalls every other task multiplexed on that thread; `tokio::task::
  spawn_blocking` moves the work to a separate blocking-thread pool so the worker stays free, while
  `block_in_place` (multi-thread runtime only) lets a worker execute blocking code in-place by
  first migrating its other tasks away — prefer `block_in_place` when the blocking call must share
  stack/locals with the async context and a full `spawn_blocking` roundtrip is awkward; note the
  blocking pool is bounded and flooding it with long-running work has its own queuing cost (verify
  against the currency brief for your version).

- **Runtime flavor and `worker_threads` sizing**: `#[tokio::main]` defaults to a multi-thread
  runtime with `worker_threads = num_cpus`, which is optimal for I/O-heavy services but
  over-subscribes a CPU-bound service where fewer workers + a rayon pool is a better split;
  `current_thread` (single-threaded runtime) removes work-stealing overhead and is appropriate for
  `!Send`-heavy or embedded/test contexts but serialises all tasks; misconfigured sizing either
  starves I/O (too few) or creates scheduler contention with OS thread thrashing (too many) —
  confirm the flavor and thread count match the workload character (verify against the currency
  brief for your version).

- **Unbounded channels as implicit queues without back-pressure**: `tokio::sync::mpsc::
  unbounded_channel` (and the `futures` unbounded equivalents) let a fast sender grow the queue
  without limit — memory grows unboundedly and tail latency spikes before the OOM; a bounded
  `mpsc::channel(n)` applies back-pressure that propagates to the sender; also check channel
  semantics against the fan-out pattern: `mpsc` for single-consumer pipelines, `broadcast` for
  multi-consumer fan-out where receivers can lag, `watch` for "last-value-wins" state sharing
  (verify against the currency brief for your version).

- **Task granularity — spawn overhead and cooperative scheduling starvation**: spawning a task
  per tiny unit of work (e.g., per message in a tight loop) pays scheduling overhead, per-task
  heap allocation for the future, and wakeup costs that dominate at high rates — batch work into
  coarser tasks; conversely, a long-running task that computes without ever reaching an `.await`
  point monopolises its worker thread because tokio uses cooperative scheduling (the task-budget
  yield is triggered by tokio I/O/timer primitives, not raw CPU loops) — insert
  `tokio::task::yield_now().await` at loop checkpoints or offload the CPU work (verify against
  the currency brief for your version).

- **`select!` cancellation drops in-flight futures**: when a `tokio::select!` branch loses the
  race its future is **dropped** immediately — any work in progress in that branch is silently
  discarded; futures that are not cancellation-safe (partial reads from a `BufReader`, half-sent
  writes, state machines midway through a multi-step transaction) corrupt their own state or lose
  data when dropped this way; restructure with cancellation tokens, move state out of the future
  before the select, or use only cancellation-safe primitives in select branches (verify against
  the currency brief for your version).

- **`join_all` vs `FuturesUnordered` / `buffer_unordered` for bounded in-flight concurrency**:
  `futures::future::join_all` (and `tokio::join!`) runs all futures concurrently with no cap on
  in-flight count — appropriate when N is small and bounded by construction, but creates a
  concurrency spike for large or dynamic N; `stream::iter(...).buffer_unordered(k)` caps
  in-flight work at `k`, applying back-pressure to the stream; `FuturesUnordered` gives finer
  control but only makes progress when polled — if the enclosing task yields or is not selected,
  pending futures stall, which manifests as a "stalled stream" where all futures appear queued
  but none complete (verify against the currency brief for your version).

- **`#[async_trait]` boxing on hot dispatch paths**: the `async-trait` macro rewrites every
  `async fn` in a trait to return `Pin<Box<dyn Future + Send>>`, incurring a heap allocation and
  dynamic dispatch on every call; on a hot path (per-request, per-message) this compounds; native
  `async fn in traits` (stabilised in a later Rust edition) and `-> impl Future` return-position
  opaque types avoid the allocation where the concrete type is statically known — cross-reference
  the **Framework-idiom currency** lane and the currency brief for the minimum compiler version
  where native async traits are available (verify against the currency brief for your version).

- **Large or `!Send` futures: footprint and runtime compatibility**: every local variable live
  across an `.await` point is captured in the future's state machine, so large buffers, big
  temporary structs, or recursive layouts inflate the per-task allocation; box large
  intermediate values (`Box::pin(...)` the sub-future, or heap-allocate the big local) to keep
  the state-machine frame small; `!Send` types (`Rc`, a `std::sync::MutexGuard`, raw pointers)
  held across `.await` make the enclosing future `!Send`, which prevents `tokio::spawn` on the
  multi-thread runtime — scope non-Send values to before the await point or restructure so they
  don't straddle a suspension (cross-reference the **Concurrency** lane in `../rust.md` and the
  `data-parallelism` sibling module for rayon interaction patterns).
