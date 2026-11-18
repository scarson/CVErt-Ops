---
index_schema_version: 1
ecosystem: javascript-typescript
covered_through: "React 19 / Angular 19 (zoneless GA in 21) / Vue 3.5 / Node.js 22 LTS"
built_on: 2026-06-04
sources:
  - https://react.dev/blog/2022/03/29/react-v18        # url-to-markdown + WebFetch
  - https://react.dev/blog/2024/04/25/react-19         # url-to-markdown
  - https://react.dev/blog/2024/04/25/react-19-upgrade-guide  # WebFetch
  - https://react.dev/reference/react/memo             # WebFetch (compiler/memo details)
  - https://react.dev/learn/react-compiler             # WebFetch
  - https://angular.dev/guide/signals                  # WebFetch
  - https://angular.dev/guide/templates/defer          # WebFetch
  - https://angular.dev/guide/templates/control-flow   # WebFetch
  - https://angular.dev/guide/zoneless                 # WebFetch
  - https://blog.vuejs.org/posts/vue-3-4               # url-to-markdown
  - https://blog.vuejs.org/posts/vue-3-5               # url-to-markdown
  - https://vuejs.org/guide/best-practices/performance # WebFetch
  - https://vuejs.org/guide/components/async           # WebFetch
  - https://vuejs.org/guide/extras/reactivity-in-depth # WebFetch
  - https://nodejs.org/en/blog/announcements/v18-release-announce  # WebFetch
  - https://nodejs.org/en/blog/release/v20.0.0         # WebFetch
  - https://nodejs.org/en/blog/release/v21.0.0         # WebFetch
  - https://nodejs.org/en/blog/release/v22.0.0         # WebFetch
  - https://nodejs.org/en/blog/release/v22.12.0        # WebFetch (LTS stabilizations)
  - https://nodejs.org/api/worker_threads.html         # WebFetch
  - https://nodejs.org/en/about/previous-releases      # WebFetch (LTS timeline)
---
# JavaScript / TypeScript performance version index
> Build-once lookup. The idiom-currency lane consults this first; live research only extends past
> `covered_through`.

## Support cadence (LTS)
**Node.js**: even-numbered majors (18, 20, 22, 24) become **LTS** (~30 months support); odd-numbered
majors (19, 21, 23) are short-lived "Current" only — a perf feature that shipped in an odd/Current
release is usually **not adoptable** by an LTS-bound project until it lands in the next even/LTS major.
Recommend the best option on the project's Node LTS line, or flag the support-track tradeoff.
**Frameworks**: React has no formal LTS; Angular supports each major ~18 months (12 active + 6 LTS);
Vue's latest minor is the supported line — for these, "currency" is about the framework version the
app already targets, not a separate LTS track.

## React — Rendering & Concurrency

- **`createRoot` / `hydrateRoot`** — landed in **React 18** — unlocks all concurrent rendering features (automatic batching, transitions, streaming SSR); supersedes `ReactDOM.render` / `ReactDOM.hydrate` (removed in React 19) — use when migrating any React 17 app.
- **Automatic batching** — landed in **React 18** — state updates inside `setTimeout`, Promises, native event handlers, and any async context are now batched into one re-render by default; supersedes React 17 behavior that only batched inside React event handlers — no opt-in needed once `createRoot` is used.
- **`useTransition` / `startTransition`** — landed in **React 18** — marks state updates as non-urgent so React can interrupt them to respond to higher-priority input; supersedes synchronous state updates that blocked the main thread — use when a state change triggers expensive re-renders (search, filter, pagination).
- **`useDeferredValue`** — landed in **React 18** — defers re-rendering a derived value until the browser is idle; no fixed debounce delay; interruptible — supersedes manual `setTimeout`-based debounce for display values — use for derived expensive computations fed by a fast-updating input.
- **`useSyncExternalStore`** — landed in **React 18** — safe subscription to external stores in concurrent mode without `useEffect`; supersedes ad-hoc `useEffect` subscription patterns in library code.
- **Streaming SSR (`renderToPipeableStream` / `renderToReadableStream`)** — landed in **React 18** — full Suspense support on the server; out-of-order HTML streaming; improves LCP and TTFB; supersedes `renderToString` for server rendering.
- **`React.memo` / `useMemo` / `useCallback` auto-replaced by React Compiler** — React Compiler (RC shipped alongside **React 19**, also back-compatible with React 18 + Babel) — auto-memoizes components and intermediate values throughout the tree; supersedes manual `React.memo` + `useMemo` + `useCallback` in codebases that adopt the compiler.
- **`use()` API** — landed in **React 19** — reads a Promise or Context inside render, suspending the component until resolved; Promises from Server Components are stable across re-renders (Client Component Promises recreate each render); supersedes `useEffect`-based data loading and `useContext` for conditional context reads.
- **`useOptimistic`** — landed in **React 19** — shows final state immediately while async request is in flight, reverting on failure; supersedes manual `useState` optimistic-UI patterns.
- **`useActionState`** — landed in **React 19** — manages pending/error/reset lifecycle for async form actions automatically; supersedes manual `useState` + try/catch request-state management.
- **Resource preloading APIs (`prefetchDNS`, `preconnect`, `preload`, `preinit`)** — landed in **React 19** via `react-dom` — declarative resource hints hoisted to `<head>` without DOM manipulation; supersedes manual `useEffect` with `document.head.appendChild` for critical resource hints.
- **`useDeferredValue` with `initialValue`** — landed in **React 19** — avoids blank initial render by providing an immediate fallback value on first paint — supersedes empty-string/null workarounds that caused layout shifts.

## React — Removed / Superseded APIs

- **`ReactDOM.render`** — removed in **React 19**; use `createRoot` from `react-dom/client`.
- **`ReactDOM.hydrate`** — removed in **React 19**; use `hydrateRoot` from `react-dom/client`.
- **`unmountComponentAtNode`** — removed in **React 19**; use `root.unmount()`.
- **`ReactDOM.findDOMNode`** — removed in **React 19**; use `useRef` and attach the ref directly.
- **`UNSAFE_componentWillMount` / `UNSAFE_componentWillReceiveProps` / `UNSAFE_componentWillUpdate`** — deprecated since React 16.9; unsafe in concurrent mode — migrate to `componentDidMount` / `getDerivedStateFromProps` / `componentDidUpdate` or function components.
- **String refs** — removed in **React 19**; use ref callbacks or `useRef`.
- **Legacy context (`contextTypes` / `getChildContext`)** — removed in **React 19**; use `createContext`.
- **`propTypes` / `defaultProps` on function components** — removed in **React 19**; use TypeScript types + ES6 default parameters.
- **UMD builds** — removed in **React 19**; use ESM-based CDN (e.g., esm.sh) or a bundler.

## React — Ecosystem libraries (version-independent)
> Durable React-ecosystem perf levers (not tied to a React release), carried so the idiom-currency lane
> is grounded on common React performance work beyond core React APIs. Verify the exact API against the
> library version in the lockfile.

- **List virtualization (`@tanstack/react-virtual`, `react-window`)** — version-independent — render only the rows in/near the viewport instead of the whole collection; for long or unbounded lists this turns O(N) mounted DOM nodes + reconciliation into O(visible) — the dominant win for large tables/feeds/logs — supersedes mapping an entire large array to elements (even memoized rows still mount N nodes) — use once a list can exceed a few hundred rows.
- **Server-state caching (`@tanstack/react-query`, SWR)** — version-independent — dedupes in-flight requests, caches responses by key, and avoids refetch waterfalls and the redundant re-renders of ad-hoc `useEffect` fetching; cuts both network and render cost — supersedes per-component `useEffect` + `useState` fetch-on-mount for shared/remote data — use for any remote data read by more than one component.

## Angular — Change Detection & Signals

- **Signals (`signal()`, `computed()`, `effect()`)** — developer preview in **Angular 16**, stable in **Angular 17** — fine-grained push-based reactivity; `computed()` is lazy and memoized; signal reads in templates mark only the affected `OnPush` component for re-check without Zone.js; supersedes RxJS-only patterns and improves over `async` pipe subscription overhead — use for any state that drives template updates.
- **Signal inputs (`input()`)** — landed in **Angular 17** (developer preview), stable in **Angular 18** — `@Input` values exposed as signals, enabling computed/effect integration without `ngOnChanges`; supersedes `@Input()` decorator for signal-based components.
- **`linkedSignal` / `resource` API** — landed in **Angular 19** (experimental) — `linkedSignal` creates a writable signal derived from another source; `resource` manages async data loading with built-in request/loading state; supersedes manual `computed` + `effect` data-loading patterns.
- **`OnPush` change detection** — available since Angular 2; pairs with signals and `async` pipe — components only re-check when an `@Input` reference changes, an Observable emits via `async` pipe, or a signal notifies; supersedes default CheckAlways strategy for data-driven components.
- **Zoneless change detection (`provideZonelessChangeDetection()`)** — experimental in **Angular 18**, default in **Angular 21** — removes Zone.js from the dependency graph, eliminating monkey-patching overhead, reducing payload (~14 kB gzip), and improving startup time; supersedes Zone.js-driven change detection — requires explicit notification via signals, `AsyncPipe`, `markForCheck()`, or reactive forms.

## Angular — Templates & Lazy Loading

- **Built-in control flow (`@if`, `@for`, `@switch`)** — landed in **Angular 17** (stable) — `@for` has mandatory `track` expression compiled to key-based reconciliation, outperforming `*ngFor`'s optional `trackBy`; supersedes `*ngIf` / `*ngFor` / `*ngSwitch` structural directives — use `track item.id` not `track $index` for reorderable lists.
- **Deferrable views (`@defer`)** — landed in **Angular 17** (stable) — declarative lazy loading of component subtrees with triggers (`on viewport`, `on idle`, `on interaction`, `on hover`, `when <expr>`) and `prefetch`; reduces initial bundle and improves LCP/TTFB; supersedes ad-hoc `*ngIf` + router lazy loading for below-the-fold content — only works with standalone components.
- **Standalone components** — stable since **Angular 15**, default scaffold since **Angular 17** — tree-shaking-friendly; no `NgModule` wrapper; enables per-component lazy loading via `loadComponent` router API; supersedes `NgModule`-based feature modules for new components.

## Vue — Reactivity & Rendering

- **Proxy-based reactivity** — Vue 3.0 — `reactive()` uses ES Proxy instead of Vue 2's `Object.defineProperty`; no need to pre-declare properties; better performance for deeply nested objects and dynamic keys; supersedes Vue 2 reactivity — upgrade path via `@vue/compat`.
- **`shallowRef` / `shallowReactive`** — Vue 3.0 — only the top-level reference is reactive; deep mutation does not trigger updates; avoids O(n) proxy cost on large arrays/objects — supersedes putting large datasets in deep `ref`/`reactive` — use when only bulk replacement (not in-place mutation) is needed.
- **`markRaw`** — Vue 3.0 — exempts an object from being made reactive when assigned into reactive state; supersedes workaround of storing non-reactive data outside component scope — use for third-party class instances, lookup tables, large static datasets.
- **`v-memo`** — Vue 3.2 — memoizes a template subtree, skipping diffing when listed dependencies are unchanged; supersedes manual conditional rendering tricks for expensive list items — use on `v-for` rows with stable, infrequently changing keys.
- **Computed stability (only triggers on value change)** — Vue 3.4 — `computed()` now only re-triggers watchers/effects when its return value actually changes (not just when dependencies run); supersedes pre-3.4 behavior where every dependency change re-triggered downstream effects — no code change needed, automatic upgrade.
- **Reactivity system refactor (-56% memory, 10× large-array perf)** — Vue 3.5 — internal rewrite of the reactivity system; large deeply-reactive array operations up to 10× faster; 56% lower memory for reactive tracking structures; also fixes stale computed and SSR memory leaks — automatic upgrade, no API changes.
- **Reactive props destructure (`defineProps` in `<script setup>`)** — stable in **Vue 3.5** — destructured props remain reactive; compiled to `props.x` access; supersedes `withDefaults()` wrapper pattern — use default ES6 destructuring syntax instead.
- **`defineAsyncComponent`** — Vue 3.0, lazy hydration added in **Vue 3.5** — splits component into separate chunk loaded on demand; `hydrate` option accepts `hydrateOnIdle()`, `hydrateOnVisible()`, `hydrateOnInteraction()`, `hydrateOnMediaQuery()` strategies for SSR apps; supersedes webpack-specific `() => import()` Vue 2 pattern and eager hydration of all async components.

## Node.js — Runtime & APIs

- **`worker_threads`** — stable since **Node.js 12**; `BroadcastChannel` stable since **Node.js 18** — true parallelism for CPU-bound JS without spawning a new V8 process; supports `SharedArrayBuffer` / `Atomics` for zero-copy shared memory; supersedes `child_process` for CPU-intensive JavaScript work — use a pool (creation ~30 ms each); not a win for I/O-bound work.
- **`structuredClone()`** — landed globally in **Node.js 17** — deep-clones objects including `Date`, `Map`, `Set`, `ArrayBuffer`, `TypedArray`, circular references; supersedes `JSON.parse(JSON.stringify(...))` (which loses types) and `lodash.cloneDeep` for most cases.
- **Native `fetch` API** — experimental in **Node.js 18** (built on `undici`), stable in **Node.js 21** — global `fetch`, `Request`, `Response`, `Headers`; supersedes `node-fetch`, `axios`, and `got` as the default HTTP client in new code.
- **Web Streams API (`ReadableStream`, `WritableStream`, `TransformStream`)** — experimental in **Node.js 18**, stabilized progressively — standard browser-compatible streaming primitives; supersedes custom stream-compat shims and enables sharing streaming code with edge runtimes.
- **`require(ESM)` for synchronous ESM graphs** — unflagged (default) in **Node.js 22.12 LTS** — CommonJS `require()` can load native ESM modules that have no top-level `await`; supersedes `--experimental-require-module` flag and dynamic `import()` workaround in CJS code — publish dual packages with `"module-sync"` exports condition.
- **Ada 2.0 URL parser** — landed in **Node.js 20** — significantly faster URL parsing, no ICU dependency for hostname; supersedes Ada 1.0 — automatic upgrade.
- **V8 Maglev compiler** — enabled on supported architectures in **Node.js 22** (V8 12.4) — mid-tier optimizing compiler that reduces JIT warm-up time; automatic, no API change.
- **Stream `highWaterMark` default bump** — **Node.js 22** — higher default buffer allows better pipe throughput on most workloads; automatic.
- **`AbortSignal` creation optimization** — **Node.js 22** — lower overhead for `AbortSignal`/`AbortController`; benefits `fetch` cancellation and timed operations.
- **`fs.Stats` lazy date fields** — **Node.js 22** — date objects computed on first access rather than eagerly; reduces allocation cost for stat-heavy workloads.
- **Custom ESM loader hooks on dedicated thread** — **Node.js 20** — loader logic runs isolated from application code; synchronous `import.meta.resolve()` available; supersedes `globalPreload` hook (removed in Node.js 21) — use `initialize` hook instead.
- **WebSocket client (stable)** — **Node.js 22** — built-in `WebSocket` global; supersedes `ws` package and `--experimental-websocket` flag for client-side real-time communication.

## Build Tooling (Bundler-independent)

- **Named ES module imports for tree-shaking** — requires a bundler that supports ESM (Vite, Rollup, webpack 5, esbuild); side-effect-free packages (`"sideEffects": false` in package.json) allow dead-code elimination; supersedes CommonJS `require()` entire-package imports for library code.
- **Dynamic `import()` for route/feature code-splitting** — available in all modern bundlers — splits into separate chunk loaded on demand; combined with `React.lazy`, Vue `defineAsyncComponent`, Angular `loadComponent`/`@defer` — supersedes up-front monolithic bundle.
- **`<link rel="modulepreload">`** — Chrome 66+, Safari 17+, Firefox 115+ — preloads ES module graphs (including deep dependencies) before the parser reaches them; supersedes `<link rel="preload" as="script">` for ESM bundles — use for critical route entry points.
