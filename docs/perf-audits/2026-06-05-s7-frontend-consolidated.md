---
run_schema_version: 1
run_id: 2026-06-05-s7-frontend
date: 2026-06-05T03:05:00Z
scope: "S7 — Frontend (Vue 3 SPA): web/src/** except components/ui/**"
methodology: { skill: performance-audit-cycle, plugin_version: "superpowers-plus@0.2.0 (vendored; version per source repo)" }
dispatch: { model_requested: "opus (latest; Claude Code Agent tool)", reasoning_effort: "default (harness exposes no knob)", overridden_by_user: false }
stack:
  - { ecosystem: npm, framework: "vue", version: "3.5.32" }
  - { ecosystem: npm, framework: "vite", version: "8" }
  - { ecosystem: npm, framework: "pinia / vue-router / @vueuse/core / reka-ui (shadcn-vue) / openapi-fetch", version: "3 / 5 / 14 / current" }
currency_briefs:
  - { framework: vue, researched_on: 2026-06-04, status: "version-index javascript-typescript.md covered_through Vue 3.5 — fresh" }
lanes_run: [render, reactivity-memory, data-fetching, payload-startup, idiom-currency]
lanes_skipped: { concurrency: "n/a in a single-threaded browser SPA (async covered by data-fetching)", dynamic: "no browser/Lighthouse runtime locally" }
finding_counts: { by_impact: { critical: 0, major: 4, minor: 9 }, by_lane: { render: 3, reactivity: 4, data-fetching: 4, payload-startup: 4, idiom-currency: 3 }, suspected_bugs: 6 }
regression: { prev_run_id: null, new: 13, persisting: 0, resolved: 0 }
---

# Performance Audit (consolidated + validated) — S7 Frontend (Vue 3 SPA)

**Scope:** web/src/** except components/ui/** (shadcn primitives, cold sub-region). **Tier:** REDUCED + payload-startup. **Verification:** static-only (no browser/Lighthouse). **Regression:** 13 new.

**Strong calibration — the feared hot spots aren't there.** The CVE search/results table (the obvious
"large list" worry) is **hard-capped at 25 rows and array-replaced** (not accumulated), so it needs no
virtualization. Search is **form-submit** (no per-keystroke request storm). There are **no
cross-navigation leaks**: all routes are lazy-loaded so views unmount and free reactive state; both
`setInterval` pollers are cleared on unmount; no stray `addEventListener`. `Promise.all` is already used
in the highest-fan-out spots; a coalesced 401 refresh and a `fetchId` stale-guard exist on CVE search.
Versions are all current (Vue 3.5.32 / Vite 8 / Pinia 3 / VueUse 14) — no framework-lag. The findings are a
real but bounded tail; the **biggest single lever is bundle vendor-chunking (P2)**, and the **only
genuinely large client list is the admin "Load More" set (P1)**.

## Major Findings

### P1. Admin "Load More" tables are unbounded, deeply reactive, and format every row with a per-row method (no virtualization)
**Lanes:** render, reactivity-memory (agreement ×2)  **Location:** `web/src/views/admin/{AdminAuditLogView,AdminDeliveriesView,AdminUsersView,AdminOrgsView}.vue` (e.g. `AdminAuditLogView.vue:77-85,148`)
**Fingerprint:** `render:admin-views:unbounded-loadmore`  **Status:** new
**Problem:** These views accumulate rows (`entries = [...entries, ...items]`) without bound or virtualization, store them as deep `ref([])` (full per-row/per-field `Proxy` wrapping though rows are read-only and never mutated), and bind a per-row `formatDate` **method** that builds `new Date().toLocaleDateString(...)` — a costly `Intl` formatting call re-run for every row on **every** re-render, on a list that grows to hundreds–thousands of rows.
**Impact:** DOM-node count + reactive-proxy overhead + `Intl` re-formatting all grow unbounded within a session on the admin tables. **Confidence:** Strong-static  **Effort:** Contained — three independent wins: (a) virtualize or hard-cap the list; (b) hoist row formatters to precomputed/`computed` values (format once when rows arrive); (c) `shallowRef`/`markRaw` the read-only row arrays (behaviorally identical, skips proxying).
**Verification plan:** render-count + DOM-node argument; correctness guard = the table renders the same rows/values.

### P2. Vite has no `manualChunks`/vendor split — the framework runtime isn't a stable cacheable chunk
**Lane:** payload-startup  **Location:** `web/vite.config.ts:9-15` (no `build` block)
**Fingerprint:** `payload:vite.config.ts:no-vendor-split`  **Status:** new
**Problem:** With no vendor chunking, the framework runtime shared by every route (`vue` + `vue-router` + `pinia` + `reka-ui` + `@vueuse/core`, ~120–180 kB min) isn't pinned to a stable, separately-cacheable vendor chunk; any app-code change can bust its cache and shared code may duplicate across route chunks. For the embedded-binary shipping model, repeat-visit analysts re-download the framework on every release. **Confidence:** Strong-static  **Effort:** Localized — add a `build.rollupOptions.output.manualChunks` vendor split (and pin the transpile target, P13, in the same block).
**Verification plan:** `vite build` chunk report before/after (stable vendor chunk hash across app-only changes); guard = app still loads.

### P3. `JSON.stringify(config, null, 2)` runs in the template, re-serializing on every render
**Lane:** reactivity-memory  **Location:** `web/src/views/admin/AdminSystemView.vue:185`
**Fingerprint:** `reactivity:AdminSystemView.vue:template-json-stringify`  **Status:** new
**Problem:** The full config object is re-stringified on each re-render (including the doctor-rerun interaction). **Confidence:** Strong-static  **Effort:** Localized — move to a `computed`.
**Verification plan:** render argument (serialize once per config change); guard = same rendered text.

### P4. Two independent-fetch request waterfalls on primary nav targets
**Lane:** data-fetching  **Location:** `web/src/views/WatchlistDetailView.vue:194-199` (await `fetchWatchlist()` then `fetchItems()`); `web/src/views/MembersView.vue:110-114` (await `/members` then `/invitations`, with a comment **falsely** claiming parallel)
**Fingerprint:** `data-fetching:views:independent-fetch-waterfall`  **Status:** new
**Problem:** Each pair has no data dependency (the `MembersView` admin gate derives from the auth store, not the members response), so the serial `await`s roughly double time-to-content on pages hit on every load. **Confidence:** Strong-static  **Effort:** Localized — `Promise.all`. **Blast radius:** preserve error handling per request.
**Verification plan:** request-timeline argument (serial → parallel); guard = both data sets still populate + errors handled.

## Minor Findings
- **P5** `reactivity:CveSourceComparison.vue:eager-stringify-all-tabs` — `CveSourceComparison.vue:48-51,83-110` + `CveDetailView.vue:24`: every source's `normalized_json` (~8 feed blobs) is `JSON.stringify`'d **for all tabs up front** (reka-ui renders all panels) and the `sources` are deep-proxied though inert. `markRaw` + serialize only the active tab. (render + reactivity + idiom agreement.) Contained.
- **P6** `render:CveResultsTable.vue:per-row-method-calls` — `CveResultsTable.vue:111-120`: `severityColor` called 5× per row inline in the badge `:class` (plus `truncate`/`formatEpss`/`formatDate`/`cvssDisplay` per-row methods); bounded to 25 rows. Localized (hoist to computed per-row view-model).
- **P7** `data-fetching:no-client-cache` — list/detail views + `stores/**`: no `<KeepAlive>` and no in-memory/HTTP cache, so list→detail→back re-issues the list query every time. Contained (cache or keep-alive the list route).
- **P8** `data-fetching:admin-no-staleguard` — `AdminDeliveriesView.vue:146-149`, `AdminAuditLogView.vue:73-75`: filter refetches lack the monotonic `fetchId` guard that `CveSearchView` already uses → out-of-order responses can show stale data. Localized.
- **P9** `idiom:feed-views:hand-rolled-interval-poll` — `FeedStatusView.vue:130-142`, `AdminFeedsView.vue:164-168`: hand-rolled `setInterval` (module-scoped `let pollTimer`, double-mount leak vector, polls while tab backgrounded) rebuilds the whole reactive `feeds` array every 30s; VueUse `useIntervalFn` is the idiom and pauses when appropriate. (render + reactivity + idiom agreement; bounded n≈8.) Localized.
- **P10** `payload:index.html:no-modulepreload-landing` — `index.html:11` + `router/index.ts:62-66`: the post-login landing chunk (`CveSearchView`, the `/` target) is lazy + behind the async auth guard, so it loads in a serial waterfall after entry parse + guard on 100% of logins. Localized (`<link rel="modulepreload">` or eager the landing route).
- **P11** `payload:vue-table-dead-dep` — `package.json:21` + `components/ui/table/utils.ts`: `@tanstack/vue-table` (~40 kB) is reachable only from `valueUpdater`, which nothing imports — likely tree-shaken to zero today, but an **unused supply-chain dependency in a security product**. Remove the dep + dead code. (Also SB6.)
- **P12** `idiom:dialogs:no-definemodel` — ~5 dialog components use manual `props.open` + `emit('update:open')` instead of `defineModel` (GA Vue 3.4–3.5). Maintainability/idiom (minimal perf). Localized.
- **P13** `payload:vite-no-build-block` — `vite.config.ts`: no `build` block; Vite 8 defaults are fine (esbuild minify, modern target, CSS splitting) but pin the transpile target alongside P2. Localized.

## Measurability
None observable here (no browser/Lighthouse). Recommend a one-off `vite build --report` (chunk sizes for
P2/P11) and a Lighthouse/Web-Vitals pass in CI to measure P1/P10 post-fix.

## Suspected Bugs (for follow-up — NOT addressed here)
> Kickoff: `docs/perf-audits/2026-06-05-s7-frontend-bug-hunt-kickoff.md`.
- **SB1.** Feed pollers set `loading=true` every 30s tick → flash the full-page spinner + lose expanded-row state (`FeedStatusView.vue`/`AdminFeedsView.vue`; use a separate `refreshing` flag).
- **SB2.** `WatchlistDetailView.vue:201-206` `watch(activeOrgId)` → `router.push('/watchlists')` fires on the initial auto-select, may bounce a user off a deep-linked watchlist on first load.
- **SB3.** `AdminDashboardView.vue:36,56` "Failed Deliveries" count derived from a `limit:1` probe — misleading count.
- **SB4.** `CveDetailView.vue:104-105` fragile `fetchId` capture — `fetchSources` doesn't mint its own token; stale-guard coupling between `fetchCve`/`fetchSources`.
- **SB5.** `MembersView.vue:108` missing `?? []` null-guard.
- **SB6.** `components/ui/table/utils.ts` `valueUpdater` exported but never imported — dead code (cross-listed with P11).

---
**Disposition:** all 13 findings default to **FIX** (P1 and P2 are the two material levers). The numerous
honest non-findings are recorded as calibration evidence, not padding. 6 suspected bugs handed off.
