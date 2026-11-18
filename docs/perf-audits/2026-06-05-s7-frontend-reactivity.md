# S7 Frontend (Vue SPA) — Lane: memory & reactivity overhead / leaks

ABOUTME: Performance audit of the Vue 3 SPA for deep-reactivity overhead over large lists and
ABOUTME: retained-across-navigation leaks (timers, watchers, unbounded reactive collections).

**Scope examined:** `web/src/**` excluding `web/src/components/ui/**`. Focus: `views/**`,
`components/{cve,watchlist,settings}/**`, `composables/**`, `stores/**`, plus `main.ts`, `App.vue`,
`router/index.ts`. Lane: memory & reactivity overhead — deep `reactive`/`ref` over large
arrays where `shallowRef`/`markRaw` would avoid per-element proxying; uncleaned
listeners/timers/watchers across route changes; unbounded reactive collection growth.

**Runtime context that bounds severity:** the router uses lazy `import()` per route and there is
**no `<KeepAlive>`** anywhere (`App.vue` renders `<RouterView/>` bare). So every view component is
**unmounted on navigation**, and its `ref`-held arrays/proxies are released for GC. That ceiling
demotes most "unbounded list" concerns from leak-across-navigation to within-a-single-view-session,
and means there are no orphaned watchers surviving route changes (component-scoped `watch`/`computed`
auto-dispose on unmount). The two `setInterval` pollers are both correctly cleared in `onUnmounted`.

Net: **no true cross-navigation leaks found.** The real lane cost is **deep-reactivity proxy
overhead over large, append-only result lists** that never need element-level reactivity, and one
re-stringify-on-render hot path. Findings below are ranked on aggregate cost under realistic admin
use.

---

### MAJOR — Admin "Load More" lists are deeply reactive and grow unbounded within a view session (users / orgs / deliveries / audit-log)

**Location:** `web/src/views/admin/AdminUsersView.vue:37,60-65`; `AdminOrgsView.vue:35,60-65`;
`AdminDeliveriesView.vue:37,80-85`; `AdminAuditLogView.vue:32,59-64` — pattern
`const X = ref<Entry[]>([])` + `X.value = [...X.value, ...(data.items ?? [])]`.

**Problem:** Each "Load More" click fetches a 50-row page and appends with a spread into a plain
`ref([])`. Vue's reactive system deep-proxies **every object and every property of every row** the
first time the array is touched for rendering, and re-proxies the freshly-spread array each page.
Rows are pure display data — nothing mutates an individual row's fields in place (actions like
disable/suspend trigger a full `fetchUsers()`/re-`map`, never a field write), so element-level
reactivity is wasted machinery. With keyset pagination and no upper bound, an admin paging through
a large audit log or user base accumulates thousands of deeply-proxied row objects in one mounted
view; memory and the per-page re-proxy cost grow linearly with pages viewed. The mitigating ceiling
is that navigating away unmounts the view and frees it — so this is a within-session cost, not a
permanent leak.

**Impact:** Reachability: every admin list page; the audit log in particular is the canonical
"keep clicking Load More" surface. Frequency: once per page load. Per-occurrence cost: O(rows ×
fields) Proxy allocations on first render of each appended batch; retained heap is O(total rows
loaded) of proxy wrappers on top of the raw JSON. `shallowRef` (or `markRaw` on each fetched batch)
would make only the array reference reactive and skip per-row/per-field proxying entirely — the
template only reads fields, never writes them, so shallow reactivity is behaviorally identical.

**Confidence:** Strong-static — the append pattern and absence of any per-row in-place mutation are
both visible in source; rows are replaced wholesale on every mutating action.

**Effort:** Localized per view (swap `ref` → `shallowRef`, and on append either spread a `markRaw`'d
batch or call `triggerRef` after push). Repeated across 4 files, so Contained in aggregate. Low
effort each.

**Verification plan:** Argument — deep `reactive` wraps n objects × k fields in Proxies at O(n·k)
on first access and re-wraps the new array each page; `shallowRef` is O(1) reactive overhead with
the row objects left as raw POJOs. No correctness change because no code path mutates a row field in
place (audit grep: the only writes to these arrays are full reassignment via `.map`/`.filter`/spread,
which `triggerRef` covers). Correctness guard: existing component tests asserting rows render and
that disable/suspend/tier-change updates reflect after re-fetch must stay green; add one asserting a
second "Load More" appends without dropping prior rows.

---

### MAJOR — `AdminSystemView` re-serializes the full runtime config with `JSON.stringify` inside the template on every render

**Location:** `web/src/views/admin/AdminSystemView.vue:185` —
`<pre class="text-xs">{{ JSON.stringify(config, null, 2) }}</pre>`.

**Problem:** `JSON.stringify(config, null, 2)` is called **in the template binding**, which means it
re-runs on every re-render of the component, not just when `config` changes. `config` is a
`ref<Record<string, unknown>>` holding the entire runtime configuration object — re-stringifying a
large config tree (with 2-space pretty-printing, which is allocation-heavy) on each render is pure
waste. The component re-renders whenever any of its reactive deps change (e.g. the doctor "Run"
button toggles `runningDoctor` and refreshes `doctor.value`, forcing a re-render that re-stringifies
the unrelated config). A `computed` would cache the serialized string and recompute only when
`config` actually changes.

**Impact:** Reachability: the admin System page (read frequently for diagnostics). Frequency: every
re-render, including the doctor-rerun interaction which is the page's main action. Per-occurrence
cost: a full O(config-size) JSON serialization + pretty-print string allocation that is thrown away
and rebuilt. Wrapping in `computed(() => JSON.stringify(config.value, null, 2))` collapses this to
one serialization per actual config change.

**Confidence:** Strong-static — the call is in the template; Vue re-evaluates template expressions
on every render of the owning component, and a sibling reactive (`doctor`/`runningDoctor`) does
change on interaction.

**Effort:** Localized — introduce one `computed` and bind it.

**Verification plan:** Argument — method-in-template recomputes per render; `computed` memoizes on
`config` identity, eliminating redundant serialization during doctor reruns and any other reactive
churn. Correctness guard: a test rendering the config card and asserting the pretty-printed JSON
text appears must stay green.

---

### MINOR — `CveSourceComparison` stringifies every source's `normalized_json` for all tabs up front

**Location:** `web/src/components/cve/CveSourceComparison.vue:48-51,83-110` — `formatJson(...)` called
inside a `v-for` over every `TabsContent`.

**Problem:** The component renders one `<TabsContent>` per source (up to ~8 feeds: NVD, MITRE, GHSA,
OSV, KEV, MSRC, Red Hat, EPSS) and each calls `formatJson(source.normalized_json)` =
`JSON.stringify(data, null, 2)` directly in the template. Because the expression is in the template,
it re-runs on every re-render of the detail view, and reka-ui's `TabsContent` mounts all panels'
content in the DOM (tabs toggle visibility, they don't lazily mount), so all N normalized payloads —
each potentially a large per-source JSON blob — are serialized whether or not the user opens that
tab. `sources` is also a plain deep `ref<CVESourceResponse[]>` (`CveDetailView.vue:24`); the nested
`normalized_json` blobs get deep-proxied even though they're only ever read and dumped to a `<pre>`.

**Impact:** Reachability: the CVE detail page, viewed routinely. Frequency: once per detail render,
re-run on any re-render of `CveDetailView` (e.g. `cveId` route change triggers re-fetch + re-render).
Per-occurrence cost: N × O(payload-size) serialization + deep-proxy of N nested JSON trees that are
never mutated. Bounded N (≤ number of feeds), so not critical, but per-payload cost is non-trivial
for large source blobs. `markRaw` on the fetched `sources` (they're inert display data) avoids the
nested-proxy cost; memoizing per-source serialized strings (or only serializing the active tab)
avoids redundant stringify.

**Confidence:** Heuristic — payload sizes and reka-ui's eager `TabsContent` mounting are plausible
but I did not read the `ui/tabs` implementation (out of lane scope); the deep-proxy-on-inert-data
half is Strong-static from `CveDetailView.vue:24`.

**Effort:** Localized — `markRaw` the sources on assignment and/or convert `formatJson` results to a
keyed `computed` map.

**Verification plan:** Argument — inert nested JSON wrapped in deep `reactive` pays O(tree-size)
proxy cost for zero benefit (read-only); `markRaw` makes it O(1). Serializing only the active tab,
or memoizing, removes N−1 redundant stringifies per render. Correctness guard: `CveSourceComparison`
tests asserting each source tab shows its formatted JSON must stay green.

---

### MINOR — Feed pollers rebuild the entire deeply-reactive `feeds` array (with a `.map` clone) every 30s

**Location:** `web/src/views/FeedStatusView.vue:60-63,134`; `web/src/views/admin/AdminFeedsView.vue:60-63,168`
— `setInterval(fetchFeeds, 30_000)` where `fetchFeeds` does `feeds.value = (data.items ?? []).map(f => ({ ...f, recent_logs: f.recent_logs ?? [] }))`.

**Problem:** Every 30 seconds the poller replaces `feeds.value` with a freshly `.map`-cloned array of
spread objects, each of which (plus its nested `recent_logs` array of log entries) gets deep-proxied
on next render. `feeds` is a small, bounded list (one row per data source, ~8), so the absolute cost
is small — but it's a recurring allocation + re-proxy on a timer for data that is purely displayed,
and the clone-via-spread is only there to default `recent_logs`. The timer itself is correctly
cleared in `onUnmounted` (no leak). This is a minor, recurring constant-factor cost, not a scaling
problem.

**Impact:** Reachability: feed-status pages (one public, one admin) while left open. Frequency: every
30s for the page's lifetime. Per-occurrence cost: O(feeds × logs) object spread + re-proxy, on a
provably small n. Listed for completeness; `shallowRef`/`markRaw` on `feeds` would drop the per-cycle
re-proxy, but the bounded n makes this low-value.

**Confidence:** Strong-static.

**Effort:** Localized.

**Verification plan:** Argument — bounded n means the deep-proxy cost per cycle is small; converting
to `shallowRef` removes nested proxying but the win is marginal given n. Correctness guard: existing
FeedStatus tests asserting rows + expandable logs render must stay green. (Note: this is reported as
a design remark per calibration, given the provably small n — do not prioritize over the two MAJORs.)

---

## Lane summary

The SPA has **no retained-across-navigation leaks**: no `<KeepAlive>`, all routes lazy-loaded and
unmounted on navigation, both `setInterval` pollers cleared in `onUnmounted`, no manual
`addEventListener` (grep clean), no `watchEffect`, and all `watch`/`computed` are component-scoped
(auto-disposed). The Pinia stores (`auth`, `ui`) hold only small bounded state — no append-only
caches or event logs. `usePagination` keeps an unbounded `cursorStack` of strings, but strings are
cheap and it's released on unmount.

The actual lane cost is **deep-reactivity proxy overhead over read-only list/JSON data** that never
needs element-level reactivity (`shallowRef`/`markRaw` are used **nowhere** in the codebase — grep
confirmed zero usages), plus one **`JSON.stringify`-in-template** hot path on the admin System page.
The two MAJORs are the worthwhile fixes; the two MINORs are bounded-n constant-factor remarks.

## Suspected Bugs (for follow-up)

- `web/src/views/admin/AdminDashboardView.vue:36,56` — "Failed Deliveries" card fetches
  `/admin/deliveries` with `limit: 1` and reports `(items ?? []).length` (0 or 1) with a `+` suffix
  if `next_cursor` exists. The card therefore shows "0" or "1+" rather than a real failed-delivery
  count. Looks like an intended cheap "any failures?" probe, but the displayed number is misleading.
  Not a performance issue — recording only.
- `web/src/views/CveDetailView.vue:104-105` — `fetchSources()` captures `currentFetchId = fetchId`
  (the current value) rather than `++fetchId`, while `fetchCve()` increments `fetchId`. On a rapid
  `cveId` change both fire from the `watch`; the stale-guard coupling between the two fetches is
  subtle and the sources response could be checked against a `fetchId` already advanced by a newer
  `fetchCve`. Possible stale/dropped-sources edge case. Not a performance issue — recording only.
