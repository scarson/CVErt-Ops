# Python performance module: Async I/O (asyncio / aiohttp / httpx / uvloop)
> Load when `asyncio`, `aiohttp`, `httpx`, `uvloop`, or an async DB driver (`asyncpg`/`aiomysql`/`motor`) is detected — see the module map in `../python.md`. Core lanes + Runtime & interpreter notes live in `../python.md`; this file is the Async I/O lens only.

## Async I/O (asyncio / aiohttp / httpx / uvloop)

> Scope: the CPython event loop and the I/O-ecosystem that runs on it — aiohttp (client and
> server), httpx async client, uvloop, and async DB drivers (asyncpg, aiomysql, motor). The
> core pack covers asyncio primitives (gather vs TaskGroup, blocking-in-async→to_thread,
> fire-and-forget GC, gather return_exceptions, thread-pool sizing, GIL→multiprocessing for
> CPU-bound work); this module goes deeper into the mechanics that determine real async
> throughput: client/pool reuse, bounded fan-out, loop-blocking anywhere in the call stack,
> loop selection, per-task scheduling cost, timeout hygiene, streaming vs buffering, and
> tool-mismatch (async used where a process pool is the right answer).

- **Client/session created per request instead of once per application**: constructing an
  `aiohttp.ClientSession` or `httpx.AsyncClient` inside a coroutine or view handler means each
  call allocates a new connection pool, pays TCP (and TLS) handshake cost on every request, and
  leaks the underlying socket resources until the finalizer runs — there is no keep-alive and
  no connection reuse. The correct pattern is one long-lived client shared across the
  application lifetime (e.g., created at startup and closed at shutdown via a lifespan hook).
  Once shared, tune pool limits to match actual concurrency: for aiohttp use
  `TCPConnector(limit=<total>, limit_per_host=<per-origin>)`; for httpx use
  `Limits(max_connections=<total>, max_keepalive_connections=<idle>)` (verify against the
  currency brief for your version).

- **Unbounded concurrent fan-out without back-pressure**: `asyncio.gather(*[coro(item) for item
  in large_list])` or a `TaskGroup` that spawns one task per item with no upper bound opens one
  connection (or socket or DB cursor) per item simultaneously — this can exhaust file
  descriptors, overwhelm the remote server's accept queue, or hit connection pool limits and
  raise. Neither `gather` nor `TaskGroup` limits concurrency by itself. Bound the fan-out with
  an `asyncio.Semaphore` guarding each coroutine's I/O, a fixed worker-pool pattern
  (`asyncio.Queue` + N consumer tasks), or `itertools.batched` to process in bounded chunks
  (cross-reference the core **Concurrency** lane in `../python.md`).

- **Hidden blocking that parks the loop — beyond the obvious**: the core pack flags
  `time.sleep`/sync file I/O; this module covers the subtler sources. A single synchronous call
  anywhere on the event-loop thread stalls *every* concurrently waiting coroutine for its
  duration: `requests` or `urllib` instead of aiohttp/httpx; a sync DB driver (`psycopg2`,
  `pymysql`, `pymongo`) instead of asyncpg/aiomysql/motor; `socket.getaddrinfo` (DNS, which is
  synchronous by default in CPython — use `aiodns` or rely on aiohttp's built-in async
  resolver); `json.loads` on a megabyte-scale payload; CPU-bound parsing or validation
  (protobuf decode, regex on large strings); `logging` to a blocking file handler or a network
  log sink with no async adapter. The symptom is event-loop latency that does not improve as
  concurrency rises. Audit every import used inside `async def` code for sync-only
  implementations; offload unavoidable blocking via `asyncio.to_thread` or
  `loop.run_in_executor` (verify against the currency brief for your version).

- **Default selector event loop on a high-RPS async service**: CPython's default event loop is
  a selector-based pure-Python loop; on Linux `uvloop` (libuv-backed) replaces it and delivers
  ~2–4× higher I/O throughput for connection-heavy workloads. Install and activate with
  `asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())` before `asyncio.run()`, or pass
  `--loop uvloop` to uvicorn. Not applicable on Windows (libuv has no IOCP backend there).
  Running a high-RPS aiohttp or FastAPI/Starlette service without uvloop on Linux is leaving
  measurable throughput on the table (verify against the currency brief for your version).

- **Per-task scheduling overhead and eager-task bypass**: spawning an `asyncio.Task` for each
  trivial item in a tight loop adds scheduler round-trips even when the coroutine completes
  synchronously (e.g., a cache hit that returns immediately). In CPython 3.12+,
  `asyncio.eager_task_factory` makes synchronously-completing coroutines skip the event-loop
  round-trip entirely — set it via `loop.set_task_factory(asyncio.eager_task_factory)` or pass
  a compatible `loop_factory` to `asyncio.run()`. Net negative if most tasks are genuinely
  async and yield at least once. Also look for `await coro()` inside a loop over independent
  items where the items could instead be batched with `gather`/`TaskGroup`: sequential `await`
  serialises work that could overlap (cross-reference the core **Concurrency** lane in
  `../python.md` and the `asyncio` section of `../version-indexes/python.md`).

- **Missing or coarse timeouts and `CancelledError` mishandling**: coroutines that issue
  outbound HTTP calls or DB queries without per-operation timeouts let a slow peer pin a
  connection and a task indefinitely, eventually exhausting the pool. Use `asyncio.timeout(n)`
  (3.11+, preferred) or aiohttp/httpx client-level `timeout=` parameters to bound each
  operation; `asyncio.wait_for()` carries wrapping overhead and is superseded by
  `asyncio.timeout()` for new code. When a task is cancelled, `CancelledError` must propagate
  — catching it without re-raising (or catching `BaseException` and not re-raising) leaves
  connections half-closed and can deadlock `TaskGroup` cancellation. Also audit asyncpg/aiomysql
  for missing `command_timeout` or `timeout` arguments on query calls (verify against the
  currency brief for your version; see `asyncio.timeout` entry in `../version-indexes/python.md`).

- **Async generators and streaming responses buffered into memory**: code that does
  `data = [item async for item in async_gen]` or `body = await resp.read()` on a large HTTP
  response materialises the full payload before processing — this couples peak memory to
  response size and delays first-byte processing. Prefer aiohttp's
  `resp.content.iter_chunked(n)` or `resp.content.iter_any()` and httpx's
  `async with client.stream(...) as resp: async for chunk in resp.aiter_bytes()` to process
  incrementally. For async generators that produce faster than the consumer can process, add
  back-pressure via a bounded `asyncio.Queue` between producer and consumer rather than
  collecting into a list (cross-reference the core **Memory** lane in `../python.md`).

- **Async used for CPU-bound work, or `asyncio.run` called repeatedly in a hot path**: async
  concurrency gives interleaved I/O waits on one thread — it does not provide parallelism and
  the GIL still serialises Python bytecode. Dispatching CPU-bound work (image processing,
  cryptography, data transformation, parsing) to `asyncio.gather` or a `TaskGroup` keeps
  everything on one core and may be slower than synchronous code due to scheduling overhead;
  a `ProcessPoolExecutor` (or `multiprocessing`) is the correct tool. Separately, calling
  `asyncio.run(coro)` inside a loop or per-request path creates and tears down a fresh event
  loop on every invocation — this is expensive; use `loop.run_until_complete` on a persistent
  loop or restructure so a single `asyncio.run` drives the entire program
  (cross-reference the core **Concurrency** lane and Runtime & interpreter notes in `../python.md`).
