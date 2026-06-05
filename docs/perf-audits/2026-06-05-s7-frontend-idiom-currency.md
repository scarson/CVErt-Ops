# S7 Frontend (Vue SPA) — Framework-Idiom Currency Audit

**Lane:** idiom-currency (Vue 3)
**Date:** 2026-06-05
**Scope:** `web/src/**` excluding `web/src/components/ui/**` (shadcn-vue primitives)

## Version baseline

From `web/package.json`:

- **vue `^3.5.32`** — current 3.5 line (latest minor; the supported Vue line). Currency target is therefore **Vue 3.5**, which includes everything through `defineModel` (3.4), reactive props destructure (3.5), `v-memo` (3.2), `shallowRef`/`markRaw` (3.0), and the 3.5 reactivity rewrite.
- vite `^8.0.5`, pinia `^3.0.4`, `@vueuse/core `^14.2.1`, `vue-router `^5.0.4`, `@tanstack/vue-table `^8.21.3`.

All on current major/minor lines — no stale-framework risk. Findings below are about **idioms the code does not yet use**, not version lag.

Overall the codebase is in good idiom shape: uniformly Composition API + `<script setup>`, no Options API, no `reactive()` over large structures, `computed` used correctly (no method-in-template derivations on hot paths), no `deep: true` watchers, no `watchEffect` over-reads, stable domain `:key` on lists, route-level code-splitting via dynamic `import()` in the router. The findings are a short tail.

---

### [MINOR] Eager `JSON.stringify` of every source tab's payload in `CveSourceComparison`

**Location:** `web/src/components/cve/CveSourceComparison.vue:48-51, 83-110` (`formatJson` called inside the `v-for="source in sources"` over `<TabsContent>`)

**Problem:** The component renders one `<TabsContent>` per source and calls `formatJson(source.normalized_json)` (a `JSON.stringify(data, null, 2)`) for **every** source in the loop, not just the active tab. reka-ui `TabsContent` renders all panels into the DOM by default (only visibility toggles), so all N source payloads are stringified and inserted as `<pre>` text on first render. Each `normalized_json` is a full per-feed normalized record (NVD/MITRE/GHSA/OSV/etc.), so this is N serializations of potentially large objects up front when only one is visible. The idiomatic fix is either to gate the serialization on the active tab (a `computed` keyed on the selected tab value) or pass `:unmount-on-hide`/lazy-mount so inactive panels don't render — and to memoize the stringify so re-renders of the parent don't re-serialize unchanged payloads.

**Impact:** Reachable on every CVE detail page view (a primary navigation target). Per-occurrence cost = O(total bytes across all sources) `JSON.stringify` + DOM text node creation, paid once per detail load, scaling with source count (typically 4–8) × payload size. Not hot-loop, but it is on the critical render path of a core page and does N× the necessary work (1 visible tab).

**Confidence:** Strong-static — the `v-for` over `TabsContent` with `formatJson()` in the binding is unconditional; reka-ui renders all tab panels by default.

**Effort:** Localized — convert to a `computed` selected-source serialization plus a tracked active-tab `ref`, or add lazy mounting to the inactive panels. Single component.

**Verification plan:** Count `JSON.stringify` invocations on mount with N sources: current = N, target = 1 (active tab). Allocation argument: stringify allocates a string proportional to serialized size per call; eliminating N−1 of them removes (N−1)×payload-bytes of transient allocation and the corresponding `<pre>` DOM text. Correctness guard: a component test asserting the active tab's JSON renders correctly and that switching tabs shows the newly-selected source's payload (pins behavior while the serialization moves behind tab selection).

---

### [MINOR] Manual `props.open` + `emit('update:open')` plumbing instead of `defineModel` (Vue 3.4+)

**Location:** dialog components — `web/src/components/watchlist/AddItemDialog.vue:53-61,91-98,136,155-157`; `web/src/components/watchlist/CreateWatchlistDialog.vue:35,86,97-99,143`; `web/src/components/settings/GroupDialog.vue:33,113,124-125,169`; `web/src/components/settings/InviteMemberDialog.vue:51,114-115,177`; `web/src/components/settings/GroupMembersDialog.vue:47,170-171`. Parent call sites: `WatchlistDetailView.vue:393-395`, `WatchlistListView.vue:230-232`, `MembersView.vue:384-386`, `GroupsView.vue:267-269,276-279`.

**Problem:** Every dialog declares `open: boolean` as a prop, declares an `'update:open': [value: boolean]` emit, binds `:open="props.open"` and re-emits `@update:open="emit('update:open', $event)"`, and the parents wire `:open="x"` + `@update:open="x = $event"`. This is the pre-3.4 two-way-binding boilerplate. Vue 3.4 stabilized `defineModel`, which collapses the prop + emit + re-bind into `const open = defineModel<boolean>()` (child) and `v-model:open="x"` (parent). The performance angle is secondary but real: `defineModel` produces a single compiler-generated local ref with one writable getter/setter rather than a prop read plus a separately-declared emit and an extra `@update:open` pass-through handler allocation per render; it also removes the manual `watch(() => props.open, …)` reset wiring some of these components carry (`AddItemDialog.vue:91`). Primary value is currency/maintainability; the per-render handler-allocation reduction is a minor secondary win.

**Impact:** Reachable wherever a dialog mounts (settings, watchlists, members — common authenticated flows). Per-occurrence cost is small (one extra closure binding + one prop/emit indirection per dialog render), so aggregate impact is low; this is flagged primarily as a superseded idiom for a current-version (3.5) codebase, per the lane mandate to flag superseded patterns where a current fast path exists.

**Confidence:** Strong-static — the prop/emit/re-bind triplet is present verbatim in each listed component; `defineModel` is GA in the project's Vue version.

**Effort:** Contained — mechanical change across ~5 dialog components plus their parent `v-model:open` call sites; behavior-preserving. Touches a module's worth of components and callers.

**Verification plan:** No fabricated numbers. Argument: each converted dialog drops one declared emit, one `:open` binding, and one `@update:open` pass-through handler (a per-render closure) in favor of a single `defineModel` ref. Correctness guard: the existing dialog tests already assert `update:open` emission (e.g. `CreateWatchlistDialog.test.ts:251`, `AddItemDialog.test.ts:315`) — `defineModel` emits the same `update:open` event, so those tests pin unchanged external contract through the refactor.

---

### [MINOR] Hand-rolled `setInterval` polling where VueUse `useIntervalFn` is the idiom (and already a dependency)

**Location:** `web/src/views/FeedStatusView.vue:130-142` and `web/src/views/admin/AdminFeedsView.vue:164-168` — module-scoped `let pollTimer`, `setInterval(fetchFeeds, 30_000)` in `onMounted`, manual `clearInterval` in `onUnmounted`.

**Problem:** Both views hand-roll a 30s poll with a raw `setInterval` and manual lifecycle teardown. `@vueuse/core ^14.2.1` is already installed and provides `useIntervalFn`, which is the current idiom: it auto-pauses/cleans up on scope dispose (no manual `onUnmounted`), returns `pause`/`resume`, and—paired with VueUse `useDocumentVisibility` or its `pauseWhenHidden`-style patterns—can stop polling when the tab is backgrounded. The raw `setInterval` keeps firing `fetchFeeds()` (a network round-trip) every 30s even when the tab is hidden, and `pollTimer` is a **module-scoped** `let` rather than instance-scoped — harmless today because these are singleton route-leaf views, but it is a latent footgun if either view is ever mounted twice (the second mount overwrites the first's timer handle, leaking the first interval). The idiomatic VueUse composable removes both the manual-teardown surface and the module-scope hazard.

**Impact:** Reachable while either admin/feed-status page is open. Per-occurrence cost = one `fetch` per 30s, indefinitely, including while the tab is backgrounded (wasted network + a full reactive re-render of the feed table each tick). Low absolute cost, but it runs unbounded for the page's lifetime and does avoidable work when hidden.

**Confidence:** Strong-static — the `setInterval`/`clearInterval` pattern and module-scoped timer are present in both files; VueUse is in the dependency set.

**Effort:** Localized — replace the `onMounted`/`onUnmounted`/`let pollTimer` block with `useIntervalFn(fetchFeeds, 30_000)` per view; optionally gate on visibility. Per-file change.

**Verification plan:** Argument: `useIntervalFn` ties the interval to the component effect scope, eliminating the manual `onUnmounted` teardown path and the module-scope timer handle (removes the double-mount leak vector); adding visibility-gating eliminates N background `fetch`+re-render cycles per hidden interval. Correctness guard: a test mounting the view with fake timers, advancing 30s, and asserting `fetchFeeds` fired once per tick — then unmounting and advancing again to assert no further calls (pins both the poll cadence and clean teardown).

---

## Things checked and found idiomatic (no finding)

- **Reactivity granularity:** No `reactive()` over large arrays/objects; CVE/audit/feed lists are held in `ref<T[]>` and replaced wholesale (e.g. `CveSearchView.vue:22`, `AdminAuditLogView.vue:32`). Wholesale replacement of a `ref` array is fine; `shallowRef` would be a micro-tweak with no argued aggregate benefit at these bounded page sizes (25/50 rows), so it is **not** a finding.
- **`computed` vs methods:** Derived values use `computed` (`auth.ts:22`, `CveDetailView.vue:66-76`, `AddItemDialog.vue:73`). Template-called formatter functions (`truncate`, `formatDate`, `formatEpss`, `cvssDisplay`) take per-row arguments, so they are correctly methods, not computeds — no footgun.
- **List keys / virtualization:** All `v-for` use stable domain keys (`item.cve_id`, `entry.id`, `feed.feed_name`), not array index on reorderable lists. Lists are server-paginated (25/50 rows), so virtualization is not warranted — `@tanstack/vue-table` is present but the bounded page sizes don't reach the threshold where it pays off.
- **Watchers:** Narrow source-getter `watch` throughout (`CveSearchFilters.vue:22-23`, `CveDetailView.vue:123`, `AddItemDialog.vue:91`); no `deep: true`, no `watchEffect` over-reads, no watcher-leak (all inside component scope).
- **Code-splitting:** Router uses dynamic `import()` per route (`router/index.ts:20-152`); `AuthenticatedLayout` Sheet uses `v-model:open` correctly (the modern idiom — contrast with the dialogs above).
- **`v-once`/`v-memo`:** No subtree is both static-after-mount and on a hot update path in a way that argues for `v-once`/`v-memo`; the list rows update only on full data replacement, not on high-frequency parent re-renders, so `v-memo` would add complexity without a measured win. Not a finding.

---

## Suspected Bugs (for follow-up)

- **`FeedStatusView.vue:47-69` (and `AdminFeedsView.vue` poll):** `fetchFeeds()` sets `loading.value = true` on **every** 30s poll tick, not just the initial load. On each background poll the table is torn down and replaced with the full-page "Loading feed status…" spinner (`:152-157`), causing a visible flash and loss of scroll/expanded-row state every 30 seconds. The initial-load spinner and the background-refresh path should be distinguished (a separate `refreshing` flag, as `AdminAuditLogView.vue:34` does with `loadingMore`). This is a UX/correctness issue, not the slowness itself, so recording per lane rules — not chasing.
- **`WatchlistDetailView.vue:201-206`:** `watch(() => auth.activeOrgId, () => router.push('/watchlists'))` fires on *any* `activeOrgId` change including the auto-select/initial set during session restore, which could bounce a user off a deep-linked watchlist URL on first load if the org gets auto-selected after mount. Possibly intended (org switch should leave the detail page), but the unconditional fire on initial set looks suspect. Recording, not chasing.

---

## Findings summary

1. **[MINOR]** Eager `JSON.stringify` of every source tab's payload in `CveSourceComparison` — `web/src/components/cve/CveSourceComparison.vue:48-51,83-110` — serializes all N source panels on render when only the active tab is shown.
2. **[MINOR]** Manual `props.open`+`emit('update:open')` plumbing instead of `defineModel` (Vue 3.4+) — ~5 dialog components + parent call sites — superseded two-way-binding boilerplate carrying per-render pass-through handlers.
3. **[MINOR]** Hand-rolled `setInterval` polling where VueUse `useIntervalFn` is the idiom — `FeedStatusView.vue:130-142`, `AdminFeedsView.vue:164-168` — manual lifecycle + module-scoped timer + polls while tab hidden; VueUse already installed.
