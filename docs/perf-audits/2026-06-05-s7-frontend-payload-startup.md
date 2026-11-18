# S7 Frontend (Vue SPA) — payload / startup / build (bundle) lane

ABOUTME: Performance audit of the Vue 3 SPA's bundle weight, startup cost, and Vite build config.
ABOUTME: Lane = payload/startup/build for the embedded self-hosted SPA; first-load matters for analysts.

**Scope examined:** `web/vite.config.ts`, `web/package.json`, `web/index.html`,
`web/src/main.ts`, `web/src/App.vue`, `web/src/router/index.ts` (all routes),
`web/src/layouts/*`, `web/src/components/AppSidebar.vue`, the `web/src/components/ui/*`
shadcn-vue barrels, icon (`lucide-vue-next`) and `@vueuse/core` import styles, the Tailwind v4
CSS entry, and dependency tree-shakeability. No runtime profiling available (no `dist/`,
no bundle analyzer run) — all confidence is static reasoning about what the bundler emits.

**What is already good (stated to bound the findings, not as praise):**
- Every route in `router/index.ts` uses `() => import(...)` — fully lazy-loaded, including all
  7 admin views. No view is statically imported into the entry graph.
- `lucide-vue-next` is imported only via named per-icon imports (e.g. `import { Search } from
  'lucide-vue-next'`) — tree-shakes to the used icon set.
- `@vueuse/core` is imported only via named functions (`reactiveOmit`, `useVModel`) — tree-shakes.
- shadcn-vue / `reka-ui` components are imported per-use through small per-component barrels
  (`@/components/ui/<name>`), not a single global UI barrel. `reka-ui` is never imported directly
  in app code.
- Tailwind v4 via `@tailwindcss/vite` does JIT content scanning — no manual `content` array to
  misconfigure, near-zero unused CSS.

The lane's net result is a small first-load problem surface. The findings below are the real ones.

---

### MAJOR: No `manualChunks` / vendor split — shared deps re-bundled per route chunk, no cacheable vendor chunk
**Location:** `web/vite.config.ts:9-15` (no `build.rollupOptions.output.manualChunks`)
**Problem:** The config sets no `build` block at all, so Rollup uses default chunking. With
route-level `import()` splitting present (good) but no `manualChunks`, the framework runtime that
is shared across *every* route — `vue`, `vue-router`, `pinia`, and the `reka-ui` primitives +
`@vueuse/core` helpers that back the shadcn `ui/*` components — is not guaranteed to land in one
stable shared chunk. Vue's CVE-analyst workflow is multi-view (search → detail → watchlists →
admin), so a vendor chunk that changes hash only when deps change (rather than being duplicated or
co-mingled with app code) is exactly the cacheable unit you want for a self-hosted SPA served by
the Go binary. Without it: (a) shared library code can be duplicated into multiple route chunks or
folded into the entry, and (b) any app-code change busts the cache for the framework bytes too, so
repeat-visit analysts re-download Vue/router/pinia/reka-ui on every release.
**Impact:** First-load + every-release repeat-load. `vue` + `vue-router` + `pinia` + `reka-ui` +
`@vueuse/core` is on the order of ~120-180 kB min (pre-gzip) of framework code shared by all
authenticated routes. Pinning it into a `vendor`/`reka` manualChunk converts that from
"re-downloaded on each app deploy" to "downloaded once, cached across deploys," and removes any
cross-chunk duplication. Per-occurrence cost is paid by every analyst on every release.
**Confidence:** Heuristic — Rollup's defaults *sometimes* hoist shared code into the entry chunk
acceptably; the failure mode (duplication / cache-busting co-mingling) is config-dependent and
cannot be confirmed without building. The fix is unambiguously beneficial regardless.
**Effort:** Localized — add a `build.rollupOptions.output.manualChunks` factory (or the simple
`id.includes('node_modules')` → `'vendor'` split, ideally splitting `reka-ui` separately since it
is the largest single dep) to `vite.config.ts`. No app-code change.
**Verification plan:** Run `vite build` with `rollup-plugin-visualizer` before/after; confirm a
single `vendor`/`reka` chunk appears, that no `node_modules` library is duplicated across two
route chunks, and that the vendor chunk hash is stable across an app-only source edit. Correctness
guard: existing route navigation works (the lazy `import()` boundaries are unchanged); the
`router/__tests__/guards.test.ts` suite still passes.

---

### MINOR: No `modulepreload` hints for the post-login landing route — auth → `/cves` pays a chunk-fetch waterfall
**Location:** `web/index.html:11` (single `<script type="module">`, no preload); `web/src/router/index.ts:62-66` (`/cves` is the default authenticated landing, lazy)
**Problem:** The entry HTML loads only `main.ts`. Because every route is lazy (correctly), the
*first meaningful view* an analyst sees — `CveSearchView` at `/cves`, the redirect target from `/`
and the post-login destination — is a separate chunk fetched only after the entry JS executes,
the router resolves the guard, and the dynamic `import()` fires. That is a serial waterfall
(entry → parse → guard → fetch view chunk → fetch its `ui/table` + `cve/*` children) on the single
most-common first navigation. Vite emits `<link rel="modulepreload">` for statically-analyzable
imports, but route-level dynamic imports gated behind an async auth guard are not preloaded.
**Impact:** First-load latency on the dominant entry path (every login). One extra round-trip
(or two, counting the view's own child chunks) before first contentful render of the search UI.
Bounded — one waterfall, not per-interaction — hence MINOR, but it hits 100% of sessions.
**Confidence:** Strong-static — the import graph and guard ordering make the waterfall certain;
its wall-cost depends on network RTT (self-hosted LAN is cheap; remote is not).
**Effort:** Localized — either add `<link rel="modulepreload" href="...CveSearchView chunk...">`
(needs a build-time plugin to know the hashed name) or, simpler, prefetch the likely landing
chunk in a router `afterEach`/idle callback. Lowest-effort variant: name the chunk via
`manualChunks` and add a static modulepreload.
**Verification plan:** Build and inspect the network panel on a cold login: confirm `CveSearchView`
chunk fetch overlaps entry execution rather than following it. Correctness guard: guard tests
unaffected (preload is a fetch hint, not a behavior change).

---

### MINOR: `@tanstack/vue-table` is a production dependency reachable only from dead code
**Location:** `web/package.json:21` (`"@tanstack/vue-table": "^8.21.3"`); sole importer is
`web/src/components/ui/table/utils.ts:1,4` (`valueUpdater` / `isFunction`)
**Problem:** `@tanstack/vue-table` is a heavyweight headless-table library (~30-45 kB min). The
*only* code that imports it is `ui/table/utils.ts`'s `valueUpdater` helper — and nothing imports
`valueUpdater`. The `ui/table/index.ts` barrel exports only the plain presentational
`Table*.vue` wrappers (which are static HTML, no vue-table), and all 11 table-using views consume
those wrappers, never the data-table engine. So the dependency is present but reachable only via
dead code. Tree-shaking *should* drop it from the bundle (the dead `utils.ts` is never in any
import graph), making the runtime payload impact likely zero — but the dependency still installs,
sits in the lockfile, and is a supply-chain surface for a security product. If anyone later
imports `valueUpdater`, ~40 kB lands in whatever chunk references it.
**Impact:** Payload impact today is most likely zero (dead-code-eliminated). The real cost is a
latent ~40 kB landmine plus an unused dependency in a security-product supply chain.
**Confidence:** Strong-static — the importer is provably unreferenced; whether it currently adds
bytes depends on Rollup DCE (very likely drops it).
**Effort:** Localized — delete `ui/table/utils.ts` and remove `@tanstack/vue-table` from
`package.json`, OR (if a future data-table is planned) leave it but document the intent. The
former is correct under YAGNI.
**Verification plan:** Confirm no source references `valueUpdater`/`table/utils` (verified: zero).
Remove the file + dep, run `vue-tsc --build` and `vite build` — both succeed. Correctness guard:
all `ui/table` consumers still compile (they import from the barrel, not `utils.ts`).

---

### MINOR: Vite build leaves splitting/minify/target fully on defaults — fine today, but unpinned for the embedded-binary use case
**Location:** `web/vite.config.ts` (no `build.target`, `build.minify`, `build.cssCodeSplit`, or `build.reportCompressedSize` settings)
**Problem:** This is a *non-finding for raw performance* — Vite 8 defaults are good (esbuild
minify on, modern `baseline-widely-available` target, CSS code-splitting on, per-route chunks).
I flag it only because the SPA is embedded into a single Go binary and served self-hosted: the
build output is shipped once and cached aggressively, so it's the one place worth *pinning* the
target explicitly (`build.target`) and enabling a vendor split (see the MAJOR above) rather than
inheriting whatever the next Vite major changes the default to. No current payload regression.
**Impact:** None today. Listed so the consolidation doesn't re-discover "is minify on?" — it is,
by default.
**Confidence:** Strong-static (defaults are documented and correct for this Vite version).
**Effort:** Localized — only relevant if pinning is desired alongside the manualChunks change.
**Verification plan:** N/A (no change required); fold into the MAJOR fix if vite.config grows a
`build` block.

---

## Summary (ranked)

1. **MAJOR** — No `manualChunks`/vendor split → shared framework + reka-ui re-bundled/cache-busted
   per route and per release (`web/vite.config.ts`).
2. **MINOR** — No `modulepreload` for the `/cves` landing chunk → fetch waterfall on every login
   (`web/index.html`, `router/index.ts`).
3. **MINOR** — `@tanstack/vue-table` prod dependency reachable only from dead `ui/table/utils.ts`
   (`web/package.json`, `ui/table/utils.ts`).
4. **MINOR** — Vite `build` block absent; defaults are fine but unpinned for the embedded-binary
   shipping model (`web/vite.config.ts`).

The big wins the lens primes for — non-lazy routes, wholesale icon/date-lib imports, global UI
barrels defeating tree-shaking, disabled minification — are **not present**. The SPA's startup
surface is genuinely lean; the one material lever is vendor chunking for cache stability.

## Suspected Bugs (for follow-up)

- `web/src/components/ui/table/utils.ts` — `valueUpdater` is exported but never imported anywhere
  in `src/`. Not a perf bug; dead code. (Cross-listed as the MINOR `@tanstack/vue-table` finding
  because the dead code is the sole reason the dependency exists.)
</content>
</invoke>
