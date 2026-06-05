---
index_schema_version: 1
ecosystem: python
covered_through: "Python 3.13 / Django 5.0 / SQLAlchemy 2.0 / pandas 2.x / NumPy 2.0"
built_on: 2026-06-03
sources:
  - https://docs.python.org/3/whatsnew/3.11.html
  - https://docs.python.org/3/whatsnew/3.12.html
  - https://docs.python.org/3/whatsnew/3.13.html
  - https://docs.djangoproject.com/en/5.2/releases/4.1/
  - https://docs.djangoproject.com/en/5.2/releases/4.2/
  - https://docs.djangoproject.com/en/5.2/releases/5.0/
  - https://docs.sqlalchemy.org/en/20/changelog/migration_20.html
  - https://docs.sqlalchemy.org/en/20/core/connections.html#engine-insertmanyvalues
  - https://pandas.pydata.org/docs/whatsnew/v2.0.0.html
  - https://numpy.org/doc/stable/release/2.0.0-notes.html
---
# Python performance version index
> Build-once lookup. The idiom-currency lane consults this first; live research only extends past
> `covered_through`.

## Interpreter / Runtime (CPython)

- **Faster CPython (Specializing Adaptive Interpreter, PEP 659)** — landed in **3.11** — adaptive bytecode specialises hot call sites for common types (binary ops, subscript, attribute load, method calls, globals); 10–25% speedup per operation class, geometric mean ~25% faster than 3.10 on pyperformance — automatic; no API change required; benefit is greatest in pure-Python CPU-bound loops.
- **Zero-cost `try/except` (when no exception is raised)** — landed in **3.11** — `try` blocks now have zero runtime overhead on the happy path; removes prior per-`try` cost — no API change; upgrade to 3.11+ to receive automatically; eliminates historic hesitation to wrap hot code in `try`.
- **Cheap, lazy frame objects** — landed in **3.11** — Python call frames reuse C-stack space and defer allocation of full frame objects until debugger/introspection requests them; 3–7% overall speedup, up to 1.7× for deeply recursive functions — automatic on 3.11+.
- **Frozen stdlib module imports** — landed in **3.11** — core startup modules are statically allocated as frozen bytecode; interpreter startup 10–15% faster — automatic; no API change; most impactful for short-lived scripts and CLI tools.
- **Comprehension inlining (PEP 709)** — landed in **3.12** — list/dict/set comprehensions are inlined into the enclosing frame rather than creating a disposable function object; up to 2× faster comprehension execution — automatic on 3.12+; no API change.
- **Per-interpreter GIL (PEP 684)** — landed in **3.12** (C-API only), Python-level `interpreters` module anticipated 3.13+ — each sub-interpreter can hold its own GIL enabling true CPU parallelism across interpreters without sharing the GIL — use when building multi-core parallel workloads via C extension or the `interpreters` stdlib module; not yet a drop-in `threading` replacement.
- **`sys.monitoring` low-overhead instrumentation (PEP 669)** — landed in **3.12** — pay-as-you-go event hooks for profilers/debuggers/coverage tools; replaces `sys.settrace`/`sys.setprofile` with near-zero overhead when no events are subscribed — supersedes `sys.settrace` for custom profilers; use when writing profiling/coverage tooling, not as an end-user perf feature.
- **Free-threaded / no-GIL build (PEP 703)** — landed experimentally in **3.13** (`python3.13t`) — GIL-free CPython build enables true threading parallelism for CPU-bound multi-threaded code; ~30–40% single-threaded regression expected — use only when all C extensions declare `Py_mod_gil` support; experimental in 3.13, not for production; track ecosystem readiness.
- **Experimental JIT compiler (PEP 744)** — landed in **3.13** (opt-in, `--enable-experimental-jit`) — copy-and-patch JIT translates Tier-2 IR to machine code; performance improvements modest in 3.13 ("a few percent"); significant improvement expected in 3.14+ — disabled by default in 3.13; enable with `PYTHON_JIT=1`; do not rely on for measurable gains until 3.14+.
- **Linux `perf` profiler support** — landed in **3.12** (improved in **3.13** with `PYTHON_PERF_JIT_SUPPORT`/`-X perf_jit`) — annotates the process so Linux `perf` can resolve Python frames by name; 3.13 removes the frame-pointer requirement — use `PYTHONPERFSUPPORT=1` / `-X perf` (3.12+) or `-X perf_jit` (3.13+) for CPU profiling without Py-Spy; requires a Linux host.

## asyncio

- **`asyncio.TaskGroup`** — landed in **3.11** — structured-concurrency context manager that creates and awaits a group of tasks, cancels all siblings on first failure; recommended over bare `asyncio.gather()` for new code — supersedes `asyncio.gather()` for fan-out patterns; safer cancellation semantics and `ExceptionGroup` error reporting; use when spawning independent concurrent coroutines.
- **`asyncio.eager_task_factory` / `asyncio.create_eager_task_factory`** — landed in **3.12** — tasks that complete synchronously (e.g. cache-hit coroutines) skip the event loop scheduling round-trip; 2–5× faster for workloads with many synchronous-completing coroutines — supersedes default `loop.set_task_factory(None)` — use by passing `asyncio.eager_task_factory` to `loop.set_task_factory()` or via `asyncio.run(…, loop_factory=…)`; net negative if most tasks are genuinely async.
- **`asyncio.current_task()` 4–6× speedup** — landed in **3.12** — internal implementation rework; hot-path cost dropped substantially — automatic on 3.12+; no API change.
- **`asyncio.timeout()` context manager** — landed in **3.11** — structured timeout via `async with asyncio.timeout(n):` block; recommended over `asyncio.wait_for()` for new code — supersedes `asyncio.wait_for()` for deadline management; more composable, no per-task wrapping overhead.

## stdlib

- **`itertools.batched(iterable, n)`** — landed in **3.12** — yields fixed-size tuples from an iterable without materialising a list; the canonical chunked-iteration primitive — supersedes `more-itertools.batched`, manual `zip(iter, iter, …)`, or `[seq[i:i+n] for i range(…)]` patterns — use for bulk processing, pagination, and chunk-based writes.
- **`ExceptionGroup` / `except*` (PEP 654)** — landed in **3.11** — raise/catch multiple independent exceptions in one `except*` block; enables `TaskGroup` error semantics — not a direct perf feature; included because it unlocks `TaskGroup` (above) which IS perf-relevant; use when handling multi-task failures.
- **`re` engine (computed gotos / threaded code)** — landed in **3.11** — regex matching engine refactored to use computed gotos on supported platforms; up to 10% faster than 3.10 on regex benchmarks — automatic on 3.11+; no API change.
- **`sum()` integer fast path** — landed in **3.11** — ~30% faster for integers smaller than a machine word — automatic.
- **List comprehension resize streamlining** — landed in **3.11** — up to 20–30% faster list comprehensions from smarter growth strategy — automatic on 3.11+.
- **`struct.pack`/`unpack` and `re` substitution** — landed in **3.12** — regex substitution with group references 2–3× faster; `struct` operations significantly faster (part of broader 3.12 stdlib improvements) — automatic on 3.12+.
- **`math.fma(x, y, z)`** — landed in **3.13** — fused multiply-add with single rounding; avoids double-rounding of `x*y + z` — use in numerically sensitive inner loops where rounding accuracy matters.

## Django ORM

- **`QuerySet.bulk_create(update_conflicts=True)`** — landed in **Django 4.1** — single-statement upsert (INSERT … ON CONFLICT DO UPDATE) on MariaDB, MySQL, PostgreSQL, SQLite 3.24+ — supersedes `get_or_create()` / load-then-save loop for bulk upsert scenarios; eliminates N round-trips — use when inserting or updating many rows where uniqueness conflicts are expected.
- **Async ORM interface (`aget`, `afilter`, `asave`, `abulk_create`, etc.)** — landed in **Django 4.1** — native `async def` view handlers and async queryset methods (prefixed `a…`) allow true async ORM calls under ASGI without `sync_to_async()` wrappers — supersedes `sync_to_async()` wrapping of ORM calls in async views — use when deploying on ASGI (Daphne/Uvicorn) with I/O-bound views.
- **`QuerySet.iterator(chunk_size=…)` with `prefetch_related`** — landed in **Django 4.1** — streaming iteration over large querysets now supports prefetch, previously all prefetch was skipped with `iterator()` — use for large result sets where related objects are needed but full materialisation into a list is undesirable.
- **`QuerySet.bulk_create()` / `abulk_create()` returning PKs** — landed in **Django 5.0** — methods now populate `pk` on each model instance after insert; PostgreSQL 15+ can also use `DEFAULT` keyword in bulk INSERT — supersedes a follow-up SELECT to retrieve generated IDs after bulk insert.
- **Persistent database connection health checks (`CONN_HEALTH_CHECKS`)** — landed in **Django 4.1** — reuses `CONN_MAX_AGE` connections but adds a health-check ping to avoid errors on stale TCP connections — use with `CONN_MAX_AGE > 0` in production to reduce per-request connection overhead without silent connection failures.

## SQLAlchemy

- **`session.execute(select(Model))` unified API** — landed in **SQLAlchemy 2.0** — single `Session.execute()` entry point replaces `Session.query()` legacy API; internally caches compiled SQL per statement shape — supersedes `session.query(Model).filter(…).all()` — use `select(Model).where(…)` fed to `session.execute()` or `session.scalars()` for all new code; 1.x-style query API still works but is legacy.
- **SQL compilation caching (transparent, `query_cache_size`)** — landed in **SQLAlchemy 1.4**, universally effective in **2.0** — compiled SQL strings are cached by statement structure (not bind values); amortises Python-side compilation across repeated executions; check logs for `[cached since N s]` — tune `create_engine(query_cache_size=N)` (default 500) for workloads with many distinct statement shapes; dynamic query builders that produce unbounded distinct shapes disable caching.
- **`insertmanyvalues` bulk INSERT with RETURNING** — landed in **SQLAlchemy 2.0** — transparently replaces `executemany()` with batched single-statement `INSERT … VALUES (…),(…) RETURNING …` for PostgreSQL, SQLite 3.35+, MariaDB, SQL Server; resolves the ORM server-generated PK retrieval bottleneck — automatic; no API change; controlled by `insertmanyvalues_page_size` (default 1000) engine parameter — replaces `session.bulk_insert_mappings()` for multi-row ORM inserts.
- **`session.bulk_insert_mappings()` / `session.bulk_update_mappings()`** — available since **1.x** (superseded path) — bypasses ORM unit-of-work overhead for raw dict inserts; still faster than adding tracked objects one-by-one — superseded by `session.execute(insert(Model), [dicts])` in 2.0 which benefits from `insertmanyvalues` — use legacy bulk APIs only when targeting 1.x compatibility.
- **`relationship(lazy="write_only")`** — landed in **SQLAlchemy 2.0** — write-only relationship strategy never issues a SELECT on access; raises `InvalidRequestError` on read attempt — supersedes `lazy="dynamic"` (deprecated in 2.0) for append-heavy one-to-many collections — use when a collection is large enough that loading it would be prohibitive; append/remove only.
- **Async Core + ORM (`AsyncSession`, `AsyncEngine`)** — landed in **SQLAlchemy 1.4**, stabilised in **2.0** — full async support via `sqlalchemy.ext.asyncio`; `AsyncSession.execute()` and `AsyncSession.scalars()` mirror the sync API — use with `asyncpg` or `aiosqlite` drivers under async frameworks (FastAPI, Starlette); avoid mixing sync and async sessions.
- **`Result.yield_per(n)` / server-side cursors** — available since **1.4** — streams result rows in batches of `n` without buffering the full result set — supersedes `.all()` for large result sets where incremental processing is possible — use `conn.execution_options(stream_results=True)` + `yield_per()` for large exports/migrations.

## pandas / NumPy

- **Copy-on-Write (CoW, `pd.options.mode.copy_on_write = True`)** — opt-in in **pandas 2.0**, default in **pandas 3.0** — chained operations return views and only copy lazily when a mutation occurs; eliminates defensive copies in read-heavy pipelines — supersedes manual `.copy()` guards and avoids silent chained-assignment mutations — use when upgrading from 1.x; enable opt-in CoW early to catch code that relied on chained-assignment side-effects.
- **PyArrow-backed dtypes (`dtype_backend="pyarrow"`)** — landed in **pandas 2.0** — I/O functions (`read_csv`, `read_parquet`, etc.) accept `dtype_backend="pyarrow"` to store columns as Arrow arrays; zero-copy interchange with Arrow ecosystem, faster string/bool/nullable-int operations — supersedes object-dtype string columns and numpy float64 for nullable numerics — use `pd.read_csv(…, dtype_backend="pyarrow")` or `df.convert_dtypes(dtype_backend="pyarrow")` for string-heavy or nullable workloads.
- **`ArrowDtype` for individual columns** — landed in **pandas 2.0** — explicitly assign `pd.ArrowDtype(pa.large_string())` etc. per column for mixed backends — use when only specific columns benefit from Arrow storage while rest remain numpy-backed.
- **NumPy 2.0 sort/partition SIMD acceleration** — landed in **NumPy 2.0** — `np.sort`, `np.argsort`, `np.partition`, `np.argpartition` accelerated via Intel x86-simd-sort and Google Highway; hardware-specific speedups can be large — automatic on NumPy 2.0+; no API change.
- **NumPy 2.0 `StringDType` and `numpy.strings` ufuncs** — landed in **NumPy 2.0** — variable-length UTF-8 string dtype with dedicated SIMD-backed ufuncs in `numpy.strings`; faster string operations than object-dtype arrays — supersedes `dtype=object` string arrays for vectorised string work — use `np.array(data, dtype=np.dtypes.StringDType())`.
- **NumPy 2.0 macOS Accelerate linear algebra** — landed in **NumPy 2.0** — macOS ≥14 wheels link against Apple's Accelerate framework; linear algebra operations (`np.linalg.*`) significantly faster and wheel size ~3× smaller — automatic when installing from PyPI on macOS 14+; no API change.
- **`np.fft` / `np.linalg` via OpenBLAS / MKL** — durable baseline (all versions) — NumPy's BLAS/LAPACK operations are only fast when linked against optimised BLAS (OpenBLAS, MKL, or Accelerate); `numpy.show_config()` confirms linkage — if benchmarking shows slow `np.dot`/`np.matmul`, the NumPy wheel may lack optimised BLAS; reinstall via `conda` or use `numpy[openblas]` extras.
