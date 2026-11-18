# Python performance module: Web frameworks (Django / Flask / FastAPI / gunicorn / uvicorn)
> Load when Django (`django`), Flask (`flask`), FastAPI/Starlette (`fastapi`/`starlette`), or a
> WSGI/ASGI server (`gunicorn`/`uvicorn`) is detected — see the module map in `../python.md`.
> Core lanes + Runtime & interpreter notes live in `../python.md`; this file is the Web frameworks
> lens only.

## Web frameworks (Django / Flask / FastAPI / gunicorn / uvicorn)

> Scope: the request path through Django (including DRF), Flask, and FastAPI/Starlette, and the
> WSGI/ASGI servers that host them — gunicorn (sync and UvicornWorker), uvicorn standalone. The
> recurring themes are worker/event-loop model mismatch (sync work in async contexts, async work
> without the right worker class), per-request construction of objects that should be built once at
> startup, and serializer/validation cost that compounds on list endpoints. The core pack covers
> ORM N+1 strategy, asyncio primitives, and import-time startup cost; this module covers the
> framework mechanics that sit between the request arriving at the server and the response leaving.

- **WSGI/ASGI worker model & sizing mismatch**: gunicorn `sync` workers (the default) each serve
  one request at a time, so a single blocking call (DB, outbound HTTP, filesystem) stalls that
  worker — throughput scales only by adding workers (heuristic ≈2·CPU+1), not by writing `async`
  code. ASGI apps (FastAPI, Starlette, Django async views) need `uvicorn.workers.UvicornWorker` or
  uvicorn directly; a sync gunicorn worker in front of an ASGI app falls back to a compatibility
  shim and loses all async concurrency. Async workers need fewer processes (each runs an event
  loop), but CPU-bound work blocks the whole loop for its duration (verify against the currency
  brief for your version).

- **Blocking call inside an `async def` handler (event-loop parking)**: a `def` (sync) endpoint
  in FastAPI/Starlette runs in a threadpool — bounded by the threadpool size — so a slow sync
  endpoint can exhaust the pool and queue requests, but it does not park the event loop. An
  `async def` endpoint that calls any synchronous blocking operation (sync DB driver, `requests`
  library, blocking file I/O, `time.sleep`) parks the event loop for every concurrent request
  on that worker. Django `async def` views calling the sync ORM without wrapping in
  `sync_to_async` are the canonical Django instance of this. Offload via
  `asyncio.to_thread` / `sync_to_async`, or replace with an async-native driver
  (cross-reference the **Concurrency** lane in `../python.md` and the `async-asyncio` module).

- **Per-request construction of expensive objects**: building a `requests.Session`,
  `httpx.Client`, DB engine, or other connection-bearing object inside a view/handler instead
  of once at startup or application lifespan means no connection pool is shared across
  requests, TCP and TLS handshake costs are paid per request, and teardown races can leak file
  descriptors. FastAPI `Depends()` dependencies that instantiate such clients without caching
  re-run on every request unless declared as a singleton or bound to a lifespan resource.
  Similarly, compiling a regex, loading a config file, or deserializing a static resource
  inside the view pays that cost on every call (cross-reference the `payload-startup` lane in
  `../python.md`).

- **Middleware runs on every request — health checks, 404s, and OPTIONS included**: an auth
  middleware issuing a DB query per request, a session store deserializing unconditionally, or
  per-request log serialization on a hot route adds latency that no cache amortizes and that
  per-endpoint profiling hides. Scope heavy middleware to the sub-router / route-prefix that needs
  it, or short-circuit before the expensive step (e.g. skip session loading on stateless
  endpoints); Django's `MIDDLEWARE` list is ordered and additive — each entry is a Python
  call-chain plus any I/O it performs (cross-reference the `orm-database` module for per-request DB
  cost).

- **DRF `ModelSerializer` cost and N+1 hidden in serialization**: Django REST Framework's
  `ModelSerializer` uses reflection to build field maps at class-definition time and iterates
  result rows through Python-speed attribute access, making it noticeably slow on lists of
  hundreds of rows or more. `SerializerMethodField` implementations that issue a DB query per
  row are N+1 hidden inside serialization, invisible to queryset-level eager loading. Nested
  serializers multiply this cost. On hot list endpoints, consider `.values()` /
  `.values_list()` with manual dict-assembly, a non-reflective serializer (e.g.,
  `orjson`-backed), or `select_related` / `prefetch_related` wired to exactly match the fields
  the serializer accesses (cross-reference the `orm-database` and `serialization` modules).

- **FastAPI `response_model` re-validation on every response**: declaring `response_model=` on
  a FastAPI endpoint causes every response to be validated and serialized through pydantic —
  field filtering, type coercion, alias mapping — before bytes are sent. On large list payloads
  or high-frequency endpoints this is measurable, especially with pydantic v1 (pure-Python)
  where serialization is not Rust-accelerated. If the returned object is already a validated
  pydantic model or a plain dict with a known shape, returning a pre-serialized `ORJSONResponse`
  (via `fastapi.responses`) or setting `response_model=None` and handling serialization
  explicitly skips the redundant pass (verify against the currency brief for your version;
  pydantic v2 performance profile differs — cross-reference the `serialization` module).

- **Template rendering over lazy querysets and large context dicts**: Django/Jinja2 template
  rendering is synchronous and Python-speed; a `{% for %}` loop over a queryset that was not
  evaluated before the template renders triggers the lazy SQL at render time, making the cost
  hard to attribute to the database in profiling. Passing large unevaluated QuerySets into
  context (especially with chained `.filter()` calls that have not yet hit the DB) or rendering
  deeply nested template inheritance chains on high-volume pages multiplies per-request Python
  work. For API endpoints returning JSON, replacing the default Django `JSONResponse` or DRF
  renderer with an `ORJSONResponse` / `UJSONResponse` renderer can materially reduce encoding
  time on large payloads (verify against the currency brief for your version).

- **Serving static files or large responses through the application process**: routing static
  files through Django's `staticfiles` in production, or streaming large binary responses
  (file exports, reports, media) through gunicorn/uvicorn without `StreamingHttpResponse`
  (Django) or `StreamingResponse` (FastAPI/Starlette), ties up a worker for the full duration
  of the transfer. A worker held open to stream 50 MB to a slow client is unavailable for any
  other request for that entire time. Static assets should be served by the reverse proxy
  (nginx) or a CDN with appropriate cache headers; large dynamic responses should use streaming
  responses with chunked transfer encoding so the worker is freed as soon as the last chunk is
  handed to the OS socket buffer (cross-reference the `payload-startup` lane in `../python.md`).
