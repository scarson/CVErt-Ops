# S7 Frontend (Vue SPA) — render-performance & algorithmic-complexity audit

ABOUTME: Performance audit of the Vue 3 SPA render path (S7, REDUCED/WARM tier).
ABOUTME: Lane = render performance & algorithmic complexity; covers views/, components/cve|watchlist|settings/, composables/.

**Lane:** render-performance (Vue render path). **Scope read:** `web/src/views/**`,
`web/src/components/{cve,watchlist,settings}/**`, `web/src/composables/**`, `web/src/App.vue`,
`AppSidebar.vue`. **Excluded (cold):** `web/src/components/ui/**` (shadcn-vue/reka-ui primitives).

**Stack confirmed from source:** Vue 3 `<script setup>`, no `vue-virtual-scroller` or any
virtualization dependency present, no `v-memo`/`v-once` anywhere, openapi-fetch client, Pinia.
All list rendering is plain `v-for` over `ref([])` arrays with stable domain `:key`s.

**Load model used:** analyst browsing a 250k+ CVE corpus. The two list shapes are (a) **paginated,
array-replaced** lists (CVE search: 25/page; members/groups/watchlists: one org-bounded page) and
(b) **"Load More" accumulating** lists (admin audit-log / deliveries / users / orgs: 50/page,
appended). Shape (b) is the one that grows without bound under realistic use.

---

### MAJOR — `toLocaleDateString` per row on unbounded "Load More" admin tables re-runs on every render

**Location:** `web/src/views/admin/AdminAuditLogView.vue:77-85` + `:148` (`v-for` over `entries`);
same pattern in `AdminDeliveriesView.vue:136-144`/`:216`, `AdminUsersView.vue:129-135`/`:171`,
`AdminOrgsView.vue:113-119`/`:154`.

**Problem:** Each of these views accumulates rows with `entries.value = [...entries.value,
...(data.items ?? [])]` (AuditLog `:60-64`, Deliveries `:80-85`, Users `:60-65`, Orgs `:60-65`) and
never resets except on filter change. The template binds a per-row method `formatDate(...)` that
calls `new Date(s).toLocaleDateString('en-US', { …, hour, minute })`. `formatDate` is a **method,
not a `computed`**, so Vue re-invokes it for *every row* on *every re-render* of the component — and
the component re-renders on any reactive change it touches (`loadingMore`, `retrying`, `nextCursor`,
a `statusFilter` Select, a toast-driven refetch, etc.). `Intl.DateTimeFormat` formatting is one of
the most expensive routine operations in browser JS (locale/timezone resolution per call when the
formatter isn't reused); the audit-log and deliveries variants use the date+time form, the costlier
one. After an analyst clicks "Load More" several times (250k-corpus org → audit/delivery history is
large), the list is 300–1000+ rows and each unrelated reactivity tick re-formats every visible row's
date from scratch.

**Impact:** Reachability high (admin operators live in these tables); frequency = every render of a
growing list; per-occurrence = O(rows) `Intl` formats per render, rows unbounded by Load-More. The
combination "no virtualization + accumulating array + per-row `Intl` method in template" is the worst
case the Vue list-rendering guidance names. Aggregate cost scales with how long the operator browses.

**Confidence:** Strong-static (method-in-template + append-only array are both visible in source;
`Intl` cost is a durable engine fact).

**Effort:** Contained — two complementary fixes, both local per file: (1) hoist a single
module-level `Intl.DateTimeFormat` instance and call `.format(date)` (eliminates per-call formatter
construction) and (2) precompute a `displayDate` once when rows arrive (map in the fetch handler) or
expose the list as a `computed` of formatted rows so formatting runs once per row per data change,
not once per row per render. Either alone helps; together they remove the cost from the render path.

**Verification plan:** Argument — a `v-for` binding a method recomputes per row per render
(Vue render-function semantics); a shared `Intl.DateTimeFormat` avoids re-resolving locale data per
call (MDN/V8 guidance). Correctness guard: existing `*View.test.ts` assert rendered date strings;
pin them so the formatted output is byte-identical after moving formatting off the render path
(same locale, same options).

---

### MINOR — `severityColor(item.severity)` invoked 5× per row inline in the CVSS badge `:class`

**Location:** `web/src/components/cve/CveResultsTable.vue:111-120` (and the helper at `:49-57`).

**Problem:** The badge's `:class` object literal calls `severityColor(item.severity)` five separate
times (one per color branch). It's a method, so all five calls run on every render of every row.
The function itself is a cheap `switch`, and the list is capped at `PAGE_LIMIT = 25`
(`CveSearchView.vue:28`) and array-replaced per page (not accumulated), so n is small and bounded.
The redundancy is real (5× the necessary calls) but the absolute cost is low at 25 rows.

**Impact:** Reachability high (primary landing page), but n ≤ 25 and the work is a string `switch`;
aggregate cost is small. Also note `truncate`, `formatEpss`, `formatDate`, `cvssDisplay` are
likewise per-row methods here — same class of issue, same bounded-25 mitigation.

**Confidence:** Strong-static.

**Effort:** Localized — compute the severity class once per row, e.g. resolve `severityColor` to a
single value (a small `computed`-backed lookup or a per-row map keyed by severity) and index a
static class map instead of re-deriving five times. Removes 4 of 5 calls.

**Verification plan:** Argument — collapses 5 method calls to 1 per row per render; class map lookup
is O(1). Correctness guard: `CveResultsTable.test.ts` (`data-testid="cvss-badge"`) already asserts
the badge color classes per severity — keep them green to prove the class output is unchanged.

---

### MINOR — 30s `setInterval` poll replaces the whole feeds array, forcing a full table re-render

**Location:** `web/src/views/FeedStatusView.vue:130-142` + `:60-64`; identical in
`AdminFeedsView.vue:164-176` + `:60-64`.

**Problem:** `setInterval(fetchFeeds, 30_000)` calls `fetchFeeds`, which does
`feeds.value = (data.items ?? []).map(f => ({ ...f, recent_logs: ... }))` — a brand-new array of
fresh object identities every 30s. Because every row object is a new reference, Vue re-patches the
entire table (and re-runs the per-row `formatTime`/`statusBadge` methods, including the expanded
log sub-rows) every cycle even when nothing changed. `formatTime` constructs `new Date()` twice and
may call `toLocaleDateString`. The saving grace is n: the number of feeds is small (≈8 adapters), so
the table is tiny. This is a structural smell more than a hot loop at current scale.

**Impact:** Reachability moderate (admin/feed pages, left open as a dashboard); frequency = every
30s for the page lifetime; per-occurrence = full re-render of a ~8-row table. Low aggregate at
current feed count; would matter only if feed count grew large (it won't materially).

**Confidence:** Strong-static (array fully replaced with new identities; methods in template).

**Effort:** Localized — merge by `feed_name` into existing rows on poll (preserve identities for
unchanged feeds) and/or hoist `formatTime`'s formatter. Given the tiny n, this is a design remark;
fix only if folded into the broader "formatter hoist" cleanup.

**Verification plan:** Argument — identity-preserving merge lets Vue skip patching unchanged rows;
n is provably small so the win is bounded. Correctness guard: `FeedStatusView` poll behavior /
`AdminSystemView.test.ts`-style tests should still observe refreshed values after the interval.

---

## What I examined and found clean

- **CVE detail view** (`CveDetailView.vue`): `hasAffectedProducts`/`hasReferences` are proper
  `computed`; packages/CPEs/references/CWEs lists are per-CVE bounded (tens, not thousands) and
  array-replaced, not accumulated. `:key="idx"` on packages/CPEs/references is index-keyed but these
  lists are static-after-load and never reordered/filtered, so the index-key footgun isn't reached.
  `formatDate`/`cvssDisplay` are methods but called O(1) times (header), not per-row. No finding.
- **`CveScoreCard.vue`**: derived values are `computed`. Clean.
- **`CveSourceComparison.vue`**: `formatJson` does `JSON.stringify(…, null, 2)` per source tab, but
  source count per CVE is tiny (≤8 feeds) and `defaultTab` is a `computed`. Bounded; no finding.
- **`CveSearchView.vue`**: `fetchId` stale-response guard is correct; pagination replaces (not
  appends) the array, keeping the CVE table bounded at 25 rows. Good.
- **`usePagination.ts`**: O(1) stack ops, `computed` flags. Clean.
- **Members/Groups/Watchlist views**: org-bounded single-page lists (no Load-More accumulation);
  per-row `formatDate` methods exist but n is small (members/groups/watchlists per org). Same
  formatter-hoist opportunity as the admin tables but far lower aggregate cost — not worth a separate
  finding.
- **No virtualization anywhere**, but the only list that could plausibly reach hundreds–thousands of
  DOM nodes is the Load-More admin set (the MAJOR above); the CVE search list is hard-capped at 25.
  So virtualization is a fix lever for the MAJOR, not an independent finding.

## Suspected Bugs (for follow-up)

- `web/src/views/admin/AdminDeliveries.../AdminUsers...` etc. call `data.items` after an early
  `if (fetchError) { error.value=…; return }` but **only `return` inside the `try`** — fine. However
  in several of these (`AdminAuditLogView.vue:54-57`, `AdminOrgsView.vue:55-58`,
  `AdminUsersView.vue:55-58`, `AdminDeliveriesView.vue:75-78`) the `if (fetchError) { … return }`
  leaves `loading`/`loadingMore` to the `finally`, which is correct — no bug, noting only that I
  checked it.
- `WatchlistDetailView.vue:59-82` `fetchWatchlist`: on the success path it does **not** set
  `loading.value = false` (only error/404 paths do); loading is cleared later in `fetchItems`'s
  `finally`. If `fetchItems` is skipped (it's only called when `watchlist.value` is truthy, which it
  is here) this is fine, but the success path relying on a second call to clear `loading` is fragile.
  Not a performance issue — recorded per lane rules, not chased.
</content>
</invoke>
