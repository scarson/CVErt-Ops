# Profile Pack: JavaScript / TypeScript

Specializes the generic lanes for Node.js and browser JS/TS stacks. Signals below are durable
idioms; volatile version details live in the currency brief / version index, not here.

This is the **core** JS/TS pack (always-loaded lanes + Runtime notes). Deep, tech-specific lenses
(React, Angular, Vue, the Node.js backend runtime, the Node data layer, and bundling/build) live in
load-on-detection modules under `profile-packs/javascript-typescript/` — see **`## Framework /
sub-stack modules`** at the bottom. Load the core for every JS/TS project; add a module only when its
signals are *material* to the scope.

---

## Algorithmic complexity & data structures (lane `algorithmic`)
- `.includes`/`.indexOf`/`.find` inside loops → accidental O(n²); replace with `Set`/`Map` lookups.
- Repeated array rebuilds on every render/call where a single pass or memoized result would do.
- Object key enumeration (`Object.keys`/`Object.entries`) inside hot loops over large objects; cache
  the keys array or use `Map` with better big-O iteration.
- Recomputing derived values on every access instead of caching them (pure functions, stable inputs).
- Sorting, filtering, or slicing the same source array on every render/request rather than once on
  data change; pay attention to large list operations that run in tight update loops.
- Using `Array.prototype` methods that create intermediate arrays (`.map().filter()`) where a single
  `for` loop or generator pipeline would avoid O(n) extra allocation.
- Deeply nested object traversal on hot paths where a flat structure or indexed map would achieve
  O(1) access.

## Memory & allocation (lane `memory`)
- Chained `.map().filter().map()` building large intermediate arrays; consider a single `.reduce`
  or a generator-based lazy pipeline.
- Needless spread/clone of large objects (`{ ...bigObj }`, `[...bigArr]`) on hot paths; prefer
  mutating a working copy or using structured references.
- Closures inadvertently retaining large scopes: event listeners, timers, or async callbacks holding
  entire module scope or large DOM subtrees, preventing garbage collection.
- Unbounded `Map`/`Set`/plain-object caches with no eviction policy; growing event-listener lists
  never removed; `setInterval` callbacks never cleared.
- Large, deeply reactive data structures unnecessarily wrapped in the framework's proxy/reactive
  system (Vue `reactive`, MobX, etc.) — store non-reactive data outside reactive scope or mark as
  raw (verify against the currency brief for your version).
- Attaching large non-reactive datasets (lookup tables, raw blob data) directly to component state
  or global stores, causing framework overhead on every state read.
- Holding `ArrayBuffer` / `TypedArray` slices longer than needed; prefer transferable objects over
  structured-clone copies when moving data to Workers.

## Data access & I/O (lane `data-access`)
- N+1 fetches: one `fetch`/DB call per loop iteration instead of batching or a single bulk request;
  applies equally to REST, GraphQL, and ORM-generated queries.
- Missing `Promise.all` / `Promise.allSettled` for independent parallel requests (sequential awaits
  when the calls have no data dependency on each other).
- Over-fetching in GraphQL (selecting all fields) or REST (no sparse fieldsets); missing pagination
  causing unbounded response sizes.
- `JSON.parse`/`JSON.stringify` on large payloads in hot paths; consider streaming JSON parsers or
  NDJSON line-by-line processing (verify against the currency brief for your version).
- Missing or invalidated HTTP/service-worker/CDN cache layers; headers that cause cache-busting on
  every request (e.g., aggressive `Cache-Control: no-store` on static assets).
- Synchronous `localStorage` reads on hot rendering paths (main-thread blocking); prefer async
  storage or a one-time in-memory cache populated at startup.
- Inefficient ORM queries: missing `.select()` field projection, missing `.include()` preloads
  causing N+1, or fetching full rows when only aggregates are needed.

## Concurrency & parallelization (lane `concurrency`)
- **Exploit:** sequential `await` in loops for independent async work — replace with `Promise.all`.
  Verify independence (no shared mutable state, no ordering requirement) before parallelizing.
- **Exploit:** missing streaming for large responses/files; buffering entire payload before
  processing when a pipeline would reduce peak memory and time-to-first-byte.
- **Exploit:** unparallelized initialization: multiple independent async setup steps (DB connect,
  config load, cache warm) run sequentially at startup instead of via `Promise.all`.
- **Defend:** blocking the event loop with synchronous CPU-heavy work (large sorts, crypto, image
  processing, complex regex on large inputs) — offload to Worker Threads or a worker pool
  (verify against the currency brief for your version).
- **Defend:** `setTimeout`/`setInterval` drift from long synchronous tasks starving the event loop;
  split large work into chunks with `setImmediate` / `queueMicrotask` yielding.
- **Defend:** uncontrolled concurrency — spawning N promises for N items with no concurrency limit
  (connection pool exhaustion, rate-limit errors, memory spikes); use a semaphore or batching.
- **Defend:** Worker Thread creation on every request rather than using a persistent pool; thread
  startup is ~30 ms; pools amortize that cost across many tasks.

## Framework-idiom currency (lane `idiom-currency`)
- Consult the version index and currency brief. Flag patterns the brief marks superseded/deprecated
  (e.g., legacy lifecycle hooks, deprecated build APIs, removed render methods); flag fast-path APIs
  listed in the index that the code doesn't use; flag changed defaults the code still fights.
- Check for manual memoization (`useMemo`/`useCallback`/`React.memo`, Angular pure pipes, Vue
  `computed`) that the current toolchain may auto-handle — or, conversely, memoization that is
  missing where it would matter (verify against the currency brief for your version).
- Offline (no brief): note candidate idiom concerns at LOW confidence, flagged for manual currency
  check.

## Payload / startup / build (lane `payload-startup`)
- Bundle size: large dependencies pulled in entirely when only a small slice is used; prefer named
  imports to enable tree-shaking (verify against the currency brief for your version).
- Missing code-splitting / lazy-loading for routes or heavy components; everything shipped upfront
  causes slow Time-to-Interactive even when the user only visits one route.
- Source maps or dev-only artifacts (`console.log`, debug builds, devDependency code) shipped to
  production; `NODE_ENV` not set to `production` in the build pipeline.
- Duplicate dependencies (multiple versions of the same package bundled); audit with bundle analyzer
  tools (verify against the currency brief for your version).
- Expensive module-level side effects executed at import time (global polyfills, eager DB connects,
  heavy regex compilation), delaying first meaningful response.
- Missing minification, dead-code elimination, or modern target transpilation (e.g., shipping
  over-polyfilled ES5 when the target supports ES2020+).
- Render-blocking scripts or stylesheets loaded synchronously; missing `<link rel="preload">` /
  `<link rel="modulepreload">` for critical assets (verify against the currency brief for your
  version).

---

## Runtime notes (load for every JS/TS project)

JS/TS runs on two single-threaded, JIT-compiled, garbage-collected engines — V8 in Node.js and the
browser's main thread — that share one cost model. These durable realities are the JS analog of a
"variant notes" section: *how the engine executes and how to measure it*, cutting across all the
lanes above and every module below.

- **One main thread does everything**: in the browser the same thread runs JS, layout, paint, and
  user input; in Node it serves every concurrent request. A long synchronous task (big loop, large
  `JSON.parse`/`stringify`, sync crypto, complex regex) blocks *all* of it — jank in the browser,
  stalled requests in Node. The durable fix is to keep the synchronous slice short: yield
  (`setTimeout`/`queueMicrotask`/`scheduler.postTask`), stream, or offload to a Web Worker /
  `worker_threads` (verify against the currency brief for your version).
- **V8 rewards stable object shapes (hidden classes)**: objects built with a consistent property set
  and types stay monomorphic and on the JIT fast path; adding/deleting properties after construction,
  mixing types in one field, or feeding a call site many shapes turns it polymorphic→megamorphic and
  deoptimizes it. On hot paths prefer stable-shape objects (or `Map` for dynamic keys) and consistent
  argument types; `delete obj.x` and sparse/holey arrays are classic deopts (verify against the
  currency brief for your version).
- **Allocation churn drives GC pauses**: V8's generational GC collects short-lived garbage cheaply,
  but per-frame / per-request allocation of objects, closures, and intermediate arrays
  (`.map().filter()` chains) still adds up to measurable minor-GC time and main-thread jank — reuse
  buffers, avoid needless spreads/clones on hot paths, and prefer `TypedArray`s for numeric-heavy
  work (all JS numbers are float64 unless they fit V8's small-integer "SMI" fast path).
- **Forced synchronous layout / reflow (browser)**: interleaving DOM reads (`offsetWidth`,
  `getBoundingClientRect`, `getComputedStyle`, `scrollTop`) with writes (style/class/DOM mutations)
  inside a loop forces the engine to re-run layout on every read — "layout thrashing" that pegs the
  main thread. Batch all reads, then all writes (or use `requestAnimationFrame` to schedule writes,
  `IntersectionObserver`/`ResizeObserver` instead of polling geometry, and `content-visibility` /
  `contain` to bound layout scope); frameworks mostly batch this for you, so look hardest in raw-DOM
  or escape-hatch code (verify against the currency brief for your version).
- **Runtime and version are a lever**: V8 ships broad speedups by version, so the Node LTS line (even
  majors = LTS; an odd/Current-only feature isn't adoptable on an LTS-bound project) and the target
  browser engines matter; alternative runtimes (**Bun**, **Deno**) change the performance profile —
  match the runtime to the workload rather than assuming stock Node (verify against the currency brief
  for your version; see the version index's Support-cadence note).
- **Profile before optimizing — the tooling is first-class**: justify hot-path claims with Node
  `--cpu-prof`/`--prof`, `clinic.js`/`0x` flame graphs, or the browser DevTools Performance panel,
  `performance.now()`, and the framework profilers (React Profiler, Angular DevTools, Vue DevTools) —
  not intuition. Main-thread long-task and Web Vitals (LCP/INP/CLS) instrumentation tells you whether
  a render-path concern is actually reaching users.

## Framework / sub-stack modules (load on detection)

Load the core lanes + **Runtime notes** above for *every* JS/TS project. Additionally load the
matching module when its technology is *material* to the audit scope (not on an incidental import),
and include it as ecosystem context in the relevant lane prompts. These tech-specific lenses were
split out of this pack so a run pastes only what's relevant — see the version index
`../version-indexes/javascript-typescript.md` for version-specific facts.

| Detected (signals) | Load module |
|---|---|
| **React** — `react`/`react-dom`, JSX in `*.jsx`/`*.tsx`, Next.js | [`javascript-typescript/react.md`](javascript-typescript/react.md) |
| **Angular** — `@angular/core`, `*.component.ts`, `angular.json` | [`javascript-typescript/angular.md`](javascript-typescript/angular.md) |
| **Vue** — `vue`, `*.vue` SFCs, Nuxt | [`javascript-typescript/vue.md`](javascript-typescript/vue.md) |
| **Node.js backend** — `express`, `fastify`, `@nestjs/*`, or a custom `http`/`https` server | [`javascript-typescript/node-backend.md`](javascript-typescript/node-backend.md) |
| **Node.js data layer** — `@prisma/client`, `typeorm`, `drizzle-orm`, `knex`, `sequelize`, `mongoose`, `pg`, `mysql2`, `ioredis` | [`javascript-typescript/node-data.md`](javascript-typescript/node-data.md) |
| **Bundling & build** — `vite`/`webpack`/`esbuild`/`rollup`/`turbopack` config, a `dist/` bundle, or a browser-targeted `package.json` | [`javascript-typescript/bundling-build.md`](javascript-typescript/bundling-build.md) |

## Sources

Durable signals in this pack are grounded in these authoritative sources (version-specific facts and
their per-entry citations live in `../version-indexes/javascript-typescript.md`):

- **Runtime notes** — V8 blog (hidden classes / inline caches, GC, "shapes"); nodejs.org "Don't block the event loop"; web.dev Web Vitals (LCP/INP/CLS) + long-tasks; Node `--cpu-prof`/`clinic.js` docs.

**Sub-stack modules** carry their own grounding; key sources per module:

- **React** (`javascript-typescript/react.md`) — react.dev (memo, render-and-commit, `useMemo`/`useCallback`, `lazy`/Suspense, "You Might Not Need an Effect", React Compiler, Server Components).
- **Angular** (`javascript-typescript/angular.md`) — angular.dev (runtime-performance, signals, `OnPush`, `@defer`, built-in control flow, zoneless, hydration).
- **Vue** (`javascript-typescript/vue.md`) — vuejs.org (best-practices/performance, reactivity-in-depth, async components) + blog.vuejs.org (3.4/3.5 reactivity).
- **Node.js backend** (`javascript-typescript/node-backend.md`) — nodejs.org (event loop, `worker_threads`, `cluster`, streams/`pipeline`, undici); Fastify docs (`fast-json-stringify`); pino docs.
- **Node.js data layer** (`javascript-typescript/node-data.md`) — Prisma/TypeORM/Drizzle/Sequelize/Mongoose performance docs; node-postgres `Pool`; ioredis pipelining; `dataloader`.
- **Bundling & build** (`javascript-typescript/bundling-build.md`) — web.dev (tree-shaking, reduce-JavaScript-payloads); Vite/Rollup/webpack/esbuild docs; bundle-analyzer tooling; `browserslist`/`core-js`.
