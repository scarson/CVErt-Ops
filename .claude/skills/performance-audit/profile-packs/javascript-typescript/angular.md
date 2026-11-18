# JS/TS performance module: Angular
> Load when Angular (`@angular/core`, `*.component.ts`, `angular.json`) is detected — see the module map in `../javascript-typescript.md`. Core lanes + Runtime notes live in `../javascript-typescript.md`; this file is the Angular lens only.

## Angular

> Scope: Angular applications using Zone.js or the zoneless scheduler, any change-detection
> strategy, and the modern standalone/signal APIs. The recurring theme is **shrink the
> change-detection surface**: Zone.js triggers a tree-wide check on every async event by default,
> so the work compounds with component count. The corrective directions are `OnPush` + observable/
> signal inputs to gate re-checks, signals for fine-grained push-based updates that skip whole
> subtrees, moving non-UI work outside the zone, and `@defer` / lazy routes to reduce what the
> browser bootstraps at all.

- **Default `CheckAlways` strategy inflates re-check scope**: every async event (click, XHR,
  timer, microtask) causes Angular to walk the entire component tree and re-evaluate all template
  expressions in `CheckAlways` components. `OnPush` limits re-checks to: an `@Input` reference
  changing, an `async`-pipe observable emitting, a signal notifying, or an explicit
  `markForCheck()` call. Audit components that receive only immutable or observable data and have
  no mutable local state — they are `OnPush` candidates. Leaving subtrees in `CheckAlways` means
  a single button click re-checks dozens of unrelated components (verify against the currency
  brief for your version).

- **Signals (stable 17+) for fine-grained, push-based updates**: Zone.js-based `OnPush` still
  re-checks the entire component on any notification; signals narrow the update to the specific
  binding that read the signal. A `computed()` signal is only re-evaluated when its dependencies
  change, making it the preferred replacement for getter calls and derived values read in
  templates. Look for `@Input` properties or component state that changes at high frequency — if
  the consuming template only reads one derived slice, a `computed` signal avoids re-evaluating
  the whole template (verify against the currency brief for your version).

- **Zone.js churn from third-party code or frequent microtasks**: Zone.js monkey-patches browser
  async APIs and triggers a CD cycle on every resolution, including those from third-party
  libraries, `requestAnimationFrame` loops, WebSocket message handlers, and micro-batched
  timers. Look for high-frequency event sources (scroll, mousemove, WebSocket, rAF) hooked
  directly inside the Angular zone — these schedule a CD check per event. `NgZone.runOutsideAngular`
  moves the handler off the CD trigger path; UI updates can then be batched and applied with
  `NgZone.run`. The **zoneless** scheduler (experimental ~18, targeted as default ~21) removes
  Zone.js monkey-patching (~14 kB) entirely and relies on signals/explicit notification —
  evaluate readiness of third-party dependencies before adopting (verify against the currency
  brief for your version).

- **Template expression cost — functions, getters, and impure pipes run every CD cycle**: Angular
  evaluates every template expression on each change-detection pass for the component. A getter
  method, a plain method call, or an impure pipe in the template therefore executes on every CD
  cycle — not just on relevant data change. Move expensive derivations to `computed` signals
  (evaluated lazily, cached until dependency changes), `async` pipe with an observable, or a
  `pure` pipe (called only when the input reference changes). Impure pipes (marked
  `pure: false`) re-run every cycle and should be rare and cheap; flag them as suspect when they
  appear on lists or in tight loops (verify against the currency brief for your version).

- **`@for` without `track` / `*ngFor` without `trackBy` on lists**: without a track expression,
  Angular tears down and rebuilds the full list DOM on every data refresh — even when only one
  item changed. The built-in `@for` block makes `track` mandatory (compiler error if omitted),
  which is stricter than the optional `trackBy` on `*ngFor`. For lists that can be reordered,
  `track item.id` (stable identity) is correct; `track $index` only avoids teardown when items
  are appended/removed at the tail and never reordered — using it on reorderable lists causes
  incorrect DOM reuse. Long lists (hundreds of items) need CDK virtual scroll regardless of
  tracking strategy (cross-reference the **payload-startup** lane in `../javascript-typescript.md`;
  verify against the currency brief for your version).

- **Unsubscribed RxJS subscriptions and subscription anti-patterns**: a `subscribe()` call without
  a corresponding teardown leaks the subscriber for the component's lifetime and beyond, keeping
  component references alive after destroy. Prefer `async` pipe (auto-unsubscribes on destroy)
  or `takeUntilDestroyed()` (verify against the currency brief for your version). Nested
  `subscribe()` inside `subscribe()` creates interleaved, un-cancellable streams — flatten with
  `switchMap`/`mergeMap`/`concatMap`. Look also for `shareReplay` without `refCount: true` on
  shared streams: without reference counting the source never completes and all subscribers stay
  alive (verify against the currency brief for your version).

- **Large eager feature modules and components — `@defer` and lazy routes**: feature modules or
  standalone components registered in the root module or the initial route's import list are
  bundled in and bootstrapped eagerly, bloating Time-to-Interactive. `@defer` (stable 17+) lets
  templates defer a component subtree until a trigger fires (`viewport`, `idle`, `interaction`,
  `hover`, `timer`, or `prefetch when`); use `@defer (on viewport)` for below-the-fold sections
  and `@defer (on idle; prefetch on hover)` for heavy widgets. Lazy router routes with
  `loadComponent` (standalone) or `loadChildren` achieve the same for route-level splits.
  Standalone components are tree-shaking-friendly compared to NgModule-declared components whose
  dependency graph is harder for bundlers to statically analyse (cross-reference the
  `bundling-build` module and the **payload-startup** lane in `../javascript-typescript.md`;
  verify against the currency brief for your version).

- **SSR hydration — double-fetch and full rerender on hydration**: Angular SSR with non-destructive
  hydration (stable 17+) reuses server-rendered DOM instead of discarding it, which cuts
  First-Contentful-Paint cost. Look for `provideClientHydration()` absence in the app config —
  without it Angular bootstraps by destroying and recreating the server DOM. Also check for HTTP
  requests made during SSR that are repeated on the client: Angular's `HttpClient` transfer
  state caches server responses and replays them to the browser; bypassing it (e.g., using
  native `fetch` or forgetting `withHttpTransferCache()`) causes a visible double-fetch waterfall.
  Pair with `@defer (prefetch on idle)` for below-the-fold sections to avoid hydrating content
  the user may never interact with (verify against the currency brief for your version).

- **Heavy `APP_INITIALIZER`, eager service instantiation, and expensive constructors**: services
  provided in root or in an eagerly-loaded module are constructed at bootstrap, before the first
  frame. `APP_INITIALIZER` tokens that make blocking HTTP calls, load config, or perform
  expensive computation delay the bootstrap promise and push out Time-to-Interactive. Look for
  `APP_INITIALIZER` functions that await multiple sequential operations — parallelize with
  `Promise.all` where order permits, or defer non-critical work to an `APP_BOOTSTRAP_LISTENER`.
  Widely-instantiated components (list rows, table cells) with expensive constructors or
  injected heavy services compound this cost at runtime each time the list refreshes
  (cross-reference the **payload-startup** lane in `../javascript-typescript.md`; verify against
  the currency brief for your version).
