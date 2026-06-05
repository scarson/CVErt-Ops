# Profile Pack: Python

Loaded for Python codebases. Augments the generic pack with Python-specific performance signals
across CPython's runtime model, the standard library, and common frameworks.

This is the **core** Python pack (always-loaded lanes + Runtime & interpreter notes). Deep,
tech-specific lenses (web frameworks, ORM/DB, the data stack, async I/O, serialization, task queues)
live in load-on-detection modules under `profile-packs/python/` — see **`## Framework / sub-stack
modules`** at the bottom. The core lanes are deliberately kept as always-useful quick-hits; a module
*deepens* its area when its signals appear in scope (it does not merely restate the core bullet).

---

## Algorithmic complexity & data structures (lane `algorithmic`)
- `in` membership test against a `list` inside a loop is O(n) per test; replace with a `set` or `dict` key lookup (O(1) average).
- Repeated pure computation on the same arguments inside a loop or per-request path — hoist invariants out of the loop or memoize with `functools.cache` / `functools.lru_cache` (verify against the currency brief for your version).
- Materializing a full collection (`list(...)`, `[x for x in ...]`) when a single-pass generator expression or `itertools` pipeline (`chain`, `islice`, `takewhile`, `batched`) would avoid the allocation entirely.
- `pandas` `.apply(axis=1)`, `.iterrows()`, or explicit Python loops over DataFrame rows — these are Python-speed row dispatch; replace with NumPy/pandas vectorized operations, `pd.eval()` for large arithmetic expressions, or Numba/Cython for tight numerical loops (verify against the currency brief for your version).
- Slow `numpy` linear-algebra / FFT (`np.dot`, `np.matmul`, `np.linalg.*`, `np.fft`) — these are only fast when NumPy is linked against an optimized BLAS/LAPACK (OpenBLAS, MKL, Apple Accelerate); a build lacking it can be an order of magnitude slower. Confirm linkage with `numpy.show_config()` (verify against the currency brief for your version).
- Aggregation or filtering done in Python after a full fetch — push it to the database (`annotate()`, `F()` expressions, SQL aggregates) or to NumPy/pandas; the cost of data transfer plus Python iteration typically exceeds a database- or array-level operation.
- Recomputing a derived value on every call that could be a `@functools.cached_property` or a module-level constant.
- Building a string by `+=` in a loop: CPython sometimes optimizes this in-place when the left operand's refcount is 1, but that path is fragile (breaks under another reference, on PyPy, or when the result is built from a list) and degrades to O(n²) copying — prefer `"".join(parts)` over a list, or `io.StringIO` for incremental construction.

## Memory & allocation (lane `memory`)
- Materializing a large sequence that is iterated only once — a generator expression or `itertools` pipeline defers allocation to one element at a time.
- Unnecessary defensive copies on hot paths: `list[:]`, `dict.copy()`, `DataFrame.copy()` — audit whether a view or reference is safe before copying.
- Reading entire files into memory (`file.read()`) when line-by-line iteration or chunked streaming bounds peak resident size.
- Unbounded in-memory accumulation (appending to a list/dict indefinitely without eviction, pagination, or streaming to a sink).
- `functools.lru_cache` / `functools.cache` with an unbounded or very large key space grows for the process lifetime (no TTL, no size cap unless `maxsize` is set) — and on an **instance method** it pins every `self` ever passed in memory for the life of the cache (a classic leak); prefer a bounded `maxsize`, a module-level cache keyed by value not object, or a `cached_property` for per-instance memoization (verify against the currency brief for your version).
- Many small, homogeneous objects without `__slots__`: each instance normally carries a per-instance `__dict__` (~280 + bytes in CPython); declaring `__slots__` eliminates that dictionary. Subclasses must also declare `__slots__` or the saving is lost.
- Retaining large intermediate DataFrames after a pipeline step that could be overwritten in place or narrowed in dtype (e.g., `object` column holding low-cardinality strings → `Categorical`; oversized `int64` → `int16/int32`).

## Data access & I/O (lane `data-access`)
- ORM N+1: accessing a related attribute inside a loop without eager loading. Django — missing `select_related` (foreign key / one-to-one) or `prefetch_related` (reverse FK, M2M); SQLAlchemy — missing `selectinload` (preferred for collections) or `joinedload` (many-to-one scalar refs) (verify against the currency brief for your version).
- Per-row writes inside a loop — replace with `bulk_create` / `bulk_update` (Django), `session.add_all` + `execute(insert(...).values(...))` (SQLAlchemy), or `cursor.executemany` (verify against the currency brief for your version).
- Over-fetching: loading full ORM objects or `SELECT *` when only a few columns are needed — use `.values()` / `.values_list()` (Django), `query(Model.col)` / `select(col)` (SQLAlchemy), or `.only()` / `.defer()` to exclude large deferred fields.
- `QuerySet.iterator(chunk_size=N)` absent on queries that stream thousands of rows — without it the entire result set is cached in the QuerySet, holding peak memory until GC.
- Accessing `obj.foreign_key.id` instead of the already-loaded `obj.foreign_key_id` — triggers an unnecessary SQL round-trip.
- Synchronous DB drivers or blocking file I/O called directly inside an `async def` handler — this parks the entire event loop; use async-native drivers or offload via `asyncio.to_thread` (verify against the currency brief for your version).
- Calling `.exists()`, `.count()`, or `.contains()` separately after a queryset that will also be iterated — evaluate the queryset once and reuse the cached result.
- Persisting medium/large DataFrames as CSV or pickle on a hot or repeated path — prefer a columnar binary format (`to_parquet`/`read_parquet` via PyArrow, or Feather) for far smaller files, faster read/write, dtype preservation, and column/row pruning on read (verify against the currency brief for your version).

## Concurrency & parallelization (lane `concurrency`)
- CPU-bound work dispatched to `threading.Thread` or `ThreadPoolExecutor` — the GIL serializes Python bytecode across threads; use `multiprocessing` or `ProcessPoolExecutor` for true parallelism on CPU-bound tasks.
- Independent `await` calls chained sequentially — replace with `asyncio.gather(*coros)` or an `asyncio.TaskGroup` (prefer `TaskGroup` for structured concurrency and automatic cancellation of siblings on failure) (verify against the currency brief for your version).
- Blocking calls (`time.sleep`, synchronous file I/O, sync DB drivers, CPU-bound computation) called directly inside `async def` — offload via `asyncio.to_thread(fn, *args)` or `loop.run_in_executor(None, fn)` to avoid parking the event loop.
- Fire-and-forget `asyncio.create_task(...)` with no reference stored — the event loop holds only a weak reference; the task can be silently garbage-collected mid-execution. Store tasks in a `set` and discard on completion via `add_done_callback`.
- `asyncio.gather(...)` without `return_exceptions=True` and no surrounding `try/except` — a single coroutine failure cancels siblings without giving them a chance to clean up; use `TaskGroup` or handle exceptions explicitly.
- Thread pool sized by default without profiling — `ThreadPoolExecutor` defaults may be too small for I/O-bound workloads or wastefully large for CPU-bound ones; size explicitly after measurement.

## Framework-idiom currency (lane `idiom-currency`)
- Consult the currency brief for the detected framework (Django, Flask, FastAPI, SQLAlchemy, pandas, NumPy, Celery, etc.) — flag superseded patterns, newly available fast paths, and changed defaults the code still fights.
- Offline (no brief): note candidate idiom concerns at LOW confidence, flagged for manual currency check.

## Payload / startup / build (lane `payload-startup`, conditional)
- Heavy initialization at module import time (opening DB connections, loading ML models, compiling large data structures) — defer to first use, application startup hooks, or explicit lazy-init patterns.
- `re.compile(pattern)` called inside a loop or per-request function — compile patterns once at module level; the internal cache (`re._cache`) is bounded and can evict entries under high pattern variety.
- Logging calls with pre-computed strings in hot paths: f-strings (`logger.debug(f"val={x}")`) or concatenation always evaluate the expression even when the level is disabled. Use `%`-style lazy args (`logger.debug("val=%s", x)`) or guard with `if logger.isEnabledFor(logging.DEBUG):`; in tight loops, cache the boolean before entering.
- Importing heavyweight packages unconditionally at module top level when only a narrow submodule or optional path needs them — use lazy imports (`import` inside the function/branch) or narrower alternatives to reduce startup latency and memory footprint.
- `pandas` `DataFrame.apply` / `Series.apply` with a pure-Python callable on a large dataset used at request time rather than precomputed or vectorized — startup-phase preprocessing is far cheaper than per-request Python-speed dispatch.

---

## Runtime & interpreter notes (load for every Python project)

CPython's execution model shapes every lane: a dynamic, bytecode-interpreted runtime where pure-Python
loops are slow and parallelism is constrained by the GIL. These durable realities are the Python analog
of a "variant notes" section — *how the interpreter behaves and how to measure it*, cutting across all
the lanes above and every module below.

- **The GIL governs what concurrency buys you**: a single GIL serializes Python bytecode, so threads
  give **concurrency for I/O-bound work but not parallelism for CPU-bound work** — the GIL is released
  during blocking I/O and *inside* C extensions (NumPy, `hashlib`, compression), so threading *does*
  speed up array/C-level work but not pure-Python compute. CPU-bound parallelism needs
  `multiprocessing`/`ProcessPoolExecutor`, a C/Cython/Numba extension, or the experimental
  free-threaded build (`python3.13t`, PEP 703) — confirm the interpreter and C-extension readiness
  before assuming no-GIL (verify against the currency brief for your version).
- **Pure-Python tight loops are the cost model's sharpest edge**: attribute/global lookups, dynamic
  dispatch, and per-iteration bytecode make a Python loop one to two orders of magnitude slower than
  the equivalent in C — push hot loops into vectorized C (NumPy, built-ins, `str`/`bytes` methods),
  inlined comprehensions, or a compiled extension (Cython/Numba). The 3.11+ specializing adaptive
  interpreter narrows the gap on hot code but does not close it (verify against the currency brief for
  your version).
- **Interpreter and version choice is a real lever**: major CPython releases ship broad speedups
  (3.11 ≈ +25% over 3.10; comprehension inlining in 3.12), so the running version matters; for
  long-running pure-Python workloads **PyPy**'s tracing JIT can be several times faster, while
  sub-interpreters (PEP 684) and the experimental CPython JIT (PEP 744) are emerging options — match
  the runtime to the workload rather than assuming stock CPython is the only target (verify against the
  currency brief for your version).
- **The Python↔C boundary is fast in bulk, slow per-call**: crossing into a C extension is cheap once
  but has per-call marshaling cost, so *many tiny crossings* (per-element NumPy scalar access, calling
  a vectorizable op inside a Python loop) lose badly to *one bulk call* over the whole array — the fix
  is almost always "do it in one vectorized call," not "call C more often."
- **Profile before optimizing — the tooling is good and cheap**: justify hot-path claims with
  `cProfile`/`pstats`, a sampling profiler (`py-spy`, `Scalene` — which also attributes memory and
  GPU), or Linux `perf` (3.12+ `-X perf`), not intuition; for short-lived processes (CLIs, serverless,
  workers) import-time cost often dominates — measure it with `python -X importtime` before blaming
  request handling (verify against the currency brief for your version).

## Framework / sub-stack modules (load on detection)

Load the core lanes + **Runtime & interpreter notes** above for *every* Python project. Additionally
load the matching module when its technology is detected in the audit scope, and include it as
ecosystem context in the relevant lane prompts. Each module *deepens* its area beyond the core
quick-hits — see the version index `../version-indexes/python.md` for version-specific facts.

| Detected (signals) | Load module |
|---|---|
| **Web frameworks** — `django`, `flask`, `fastapi`/`starlette`, `gunicorn`/`uvicorn` (WSGI/ASGI) | [`python/web-frameworks.md`](python/web-frameworks.md) |
| **ORM & database** — `django` ORM, `sqlalchemy`, `psycopg`/`psycopg2`, `asyncpg` | [`python/orm-database.md`](python/orm-database.md) |
| **Data stack** — `numpy`, `pandas`, `polars`, `pyarrow` | [`python/data-stack.md`](python/data-stack.md) |
| **Async I/O** — `aiohttp`, `httpx`, `uvloop`, async DB drivers (`asyncpg`/`aiomysql`/`motor`), **or** `asyncio` used materially (an async service, not one stray `await`) | [`python/async-asyncio.md`](python/async-asyncio.md) |
| **Serialization & validation** — `orjson`/`ujson`/`msgspec`, `pydantic`, `marshmallow`, `pickle`, `msgpack`, **or** stdlib `json` on a hot/large path (not one incidental `json.loads`) | [`python/serialization.md`](python/serialization.md) |
| **Task & job queues** — `celery`, `rq`, `dramatiq`, `arq` | [`python/task-queues.md`](python/task-queues.md) |

## Sources

Durable signals in this pack are grounded in these authoritative sources (version-specific facts and
their per-entry citations live in `../version-indexes/python.md`):

- Django — "Database access optimization" (docs.djangoproject.com/en/stable/topics/db/optimization/)
- SQLAlchemy 2.0 — relationship/loader guide (docs.sqlalchemy.org/en/20/orm/queryguide/relationships.html)
- pandas — "Enhancing performance" (pandas.pydata.org/docs/user_guide/enhancingperf.html)
- CPython docs — asyncio, profiling HOWTO, `itertools`, data model (`__slots__`), logging HOWTO (docs.python.org)
