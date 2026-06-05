# Perf audit — S7 Frontend (Vue SPA), lane: data-fetching & network I/O

ABOUTME: Frontend data-fetching/network-I/O performance audit of the Vue 3 SPA slice.
ABOUTME: Covers stores, composables, views, the openapi-fetch client, and cve/watchlist components.

**Slice:** S7 "Frontend (Vue SPA)" (REDUCED, WARM). **Lane:** data fetching & network I/O (frontend).
**Scope read:** `web/src/lib/api/client.ts`, `web/src/stores/**`, `web/src/composables/**`,
`web/src/views/**` (incl. `admin/**`), `web/src/components/{cve,watchlist,settings}/**`,
`App.vue`, `main.ts`, `router/index.ts`, `OrgSwitcher.vue`. Excluded `components/ui/**` per instructions.

The codebase is, on the whole, careful about network I/O: it uses cursor (keyset) pagination
everywhere, `Promise.all` in the two highest-fan-out spots (`AdminDashboardView`,
`GroupMembersDialog`), a coalesced 401-refresh, and a `fetchId` stale-response guard on the CVE
search path. Search is form-submit driven (no search-as-you-type), so there is no missing-debounce
problem. The findings below are the remaining real waterfalls and a couple of contained gaps.

---

### [MAJOR] WatchlistDetailView serializes two independent fetches into a request waterfall

**Location:** `web/src/views/WatchlistDetailView.vue:194-199` (`onMounted`), with `fetchWatchlist`
(`:59`) and `fetchItems` (`:84`)
**Problem:** `onMounted` does `await fetchWatchlist()` and *then* `await fetchItems()`. The two
requests — `GET /orgs/{org}/watchlists/{id}` and `GET /orgs/{org}/watchlists/{id}/items` — share no
data dependency: both are keyed only by `org_id` + the route `id`, both already known at mount. The
items request is needlessly blocked behind the watchlist-metadata round-trip. The only reason to
gate is to skip items when the watchlist 404s, but a 404 on the metadata call does not make the items
call meaningfully more expensive, and the items call can be fired in parallel and its result discarded
on a metadata 404.
**Impact:** Reached on every visit to a watchlist detail page (a primary navigation target). Per
visit: time-to-content = `RTT(watchlist) + RTT(items)` instead of `max(RTT(watchlist), RTT(items))`.
On a typical ~100-300 ms API RTT this roughly doubles the page's data latency. Frequency: once per
page view / route revisit (no client cache, so every revisit pays it again — see the caching remark).
**Confidence:** Strong-static (the two `await`s are textually sequential and provably independent).
**Effort:** Localized — wrap both in `Promise.all` inside `onMounted` and branch on `notFound`
afterward; `fetchItems` already tolerates being called unconditionally.
**Verification plan:** Argument: two independent network round-trips currently run serially; parallelizing
collapses latency to the slower of the two — no extra requests, identical payloads. Correctness guard:
extend `WatchlistDetailView.test.ts` to assert (a) both endpoints are requested, (b) a 404 on the
metadata endpoint still renders the not-found state and does not render items, (c) items render when
both succeed. Pin that the parallel version issues exactly the same two requests as before.

---

### [MAJOR] MembersView fetches members then invitations sequentially (comment claims parallel)

**Location:** `web/src/views/MembersView.vue:110-114` inside `fetchMembers`; `fetchInvitations`
at `:121`
**Problem:** `fetchMembers` awaits `GET /orgs/{org}/members`, and only after it resolves does it
`await fetchInvitations()` (`GET /orgs/{org}/invitations`). The inline comment literally says
"Fetch invitations in parallel for admin+ users," but the code is strictly serial. The two calls are
independent (same `org_id`, no shared data). Invitations are gated on `isAdmin`, which is derived from
the already-loaded auth store — it does **not** depend on the members response — so the gate can be
evaluated before firing either request.
**Impact:** Reached on every Members page load for admin/owner users (the users most likely to open
this page). Per load for an admin: time-to-content = `RTT(members) + RTT(invitations)` instead of the
parallel `max(...)`. Non-admins are unaffected (they skip invitations). Frequency: once per page
view / org switch (the `watch(activeOrgId)` refetches on org change).
**Confidence:** Strong-static (sequential `await`; independence is structural).
**Effort:** Localized — when `isAdmin`, kick off both requests with `Promise.all` (or start the
invitations promise before awaiting members and await both). The misleading comment should be removed
or made true.
**Verification plan:** Argument: an admin currently pays two serial RTTs; the requests are independent,
so `Promise.all` halves data latency with identical request/response shapes. Correctness guard:
`MembersView.test.ts` — assert both endpoints fire for an admin, only `/members` fires for a
non-admin, and the rendered member + invitation tables are unchanged. Pin that a `/members` failure
still surfaces the error state (invitations failure remains silently swallowed, as today).

---

### [MINOR] No client-side caching: every route revisit re-fetches the full list/detail from scratch

**Location:** all list/detail views — e.g. `WatchlistListView.vue:128` (`onMounted` →
`fetchWatchlists`), `MembersView.vue:225`, `GroupsView.vue:146`, `CveDetailView.vue:118`,
the `admin/*` views; the Pinia layer (`stores/auth.ts`, `stores/ui.ts`) holds no fetched-data cache.
**Problem:** Each view fetches its data fresh in `onMounted` (and again in the `watch(activeOrgId)`
handlers), and the router uses lazy `import()` per route with no `keep-alive`. There is no
in-memory cache and no HTTP caching hints in the client (`client.ts` sets no `Cache-Control`/`ETag`
handling; `credentials: 'include'` requests are uncacheable by default). Navigating
list → detail → back (a very common flow) re-issues the list query every time, even when the
underlying data has not changed within the session.
**Impact:** Reachable on the dominant navigation pattern (browse list → open item → return). Per
back-navigation: one full list round-trip + re-render that could have been served from memory. Cost
is bounded by page size (lists are paginated to 25-50 rows) so each individual refetch is cheap, but
it recurs on every revisit across the whole app — aggregate, not localized. This is a design remark,
not a hot loop: the right scope is probably a small TTL cache or `keep-alive` on the list routes, not
a full data-layer rewrite.
**Confidence:** Heuristic (no cache is present; the user-cost depends on real navigation frequency,
which isn't measurable here).
**Effort:** Contained — either add `<keep-alive>` around the authenticated `<RouterView>` for list
routes (cheapest, preserves component state incl. fetched data), or introduce a lightweight
store-level cache with explicit invalidation on the mutating actions that already mutate local arrays
(create/delete handlers in the list views). Cross-cutting if done as a generic cached-fetch
composable.
**Verification plan:** Argument: list views currently refetch unconditionally on mount/revisit;
caching eliminates the repeat round-trip on back-navigation within a session. Correctness guard: tests
must pin that mutations (create/delete watchlist, invite/remove member) still reflect immediately —
the existing local-array updates already cover this; add an assertion that a cached list is bypassed
(refetched) after the cache is invalidated by a mutation. Do NOT cache across org switches: the
`watch(activeOrgId)` invalidation must remain.

---

### [MINOR] AdminDeliveries / AdminAuditLog filter changes lack a stale-response guard

**Location:** `web/src/views/admin/AdminDeliveriesView.vue:146-149` (`onStatusChange` → `fetchDeliveries`)
and `web/src/views/admin/AdminAuditLogView.vue:73-75` (`applyFilters` → `fetchAuditLog`)
**Problem:** Unlike `CveSearchView` (which uses a `fetchId` monotonic guard, `:29,:50`) and the
CVE detail view, these admin filter handlers fire a fresh `fetchDeliveries()` / `fetchAuditLog()`
without cancelling or sequencing against an in-flight request. Rapidly changing the status filter
(or hammering the Filter button) can leave the table showing the response of an earlier, slower
request that resolves last (last-write-wins on `deliveries.value` / `entries.value`). Each handler
also issues a brand-new full request per change with no debounce.
**Impact:** Low frequency in practice — these are admin-only screens, the deliveries filter is a
`<Select>` (discrete, infrequent changes) and the audit filter is button/Enter-triggered, so the
race window is narrow and the extra-request volume is small. The cost is correctness-flavored (stale
list) rather than raw throughput, which is why it ranks MINOR. Recording it because the slowness
("wrong/older data wins") is the user-visible symptom of the missing cancellation, and the fix is the
same `fetchId` pattern already used elsewhere in this codebase.
**Confidence:** Heuristic (race depends on overlapping request timing; structurally the guard is absent).
**Effort:** Localized — add the same `let fetchId = 0` monotonic-token guard used in `CveSearchView`
to both handlers (and ideally a short debounce on the audit text inputs if they ever become
filter-as-you-type; today they are Enter/button driven so debounce is optional).
**Verification plan:** Argument: concurrent filter changes currently have no ordering guarantee on
which response writes last; a monotonic fetch-id discards stale responses deterministically. Correctness
guard: a test that resolves two overlapping filter fetches out of order and asserts the latest filter's
result is the one rendered. No change to request payloads.

---

## Non-findings (examined, deliberately not flagged)

- **CveDetailView mount fetches** (`:118-126`): `fetchCve()` and `fetchSources()` are called as two
  un-awaited statements, so both promises start immediately — they already run **concurrently**, not
  serially. No waterfall. (There is a latent `fetchId`-capture subtlety in `fetchSources` — recorded
  under Suspected Bugs — but it is not a performance issue.)
- **CVE search debounce** (`CveSearchView.vue` + `CveSearchFilters.vue`): search is `@submit.prevent`
  form-driven, not input-driven, so there is no per-keystroke request storm. Correctly no debounce
  needed. It also already has a `fetchId` stale-response guard and discards stale pages.
- **AdminDashboardView** (`:32-37`) and **GroupMembersDialog** (`:68-75`): both correctly use
  `Promise.all` for their independent multi-endpoint fetches.
- **WatchlistListView** (`:196,:208`): renders `wl.item_count` from the list payload — no per-row
  detail fetch, so no client-side N+1. Same for `CveResultsTable` (pure props, no fetches).
- **FeedStatusView polling** (`:134`): 30 s interval, cleared in `onUnmounted` (`:137-142`). A 30 s
  cadence on an admin-only dashboard is not aggressive; not a finding.
- **API client** (`client.ts`): single module-scoped `createClient` (shared, not per-request), 401
  refresh is coalesced via `coalescedRefresh` to prevent duplicate concurrent refreshes — both good.
- **Admin list views** (Users/Orgs/Deliveries/AuditLog): single fetch on mount, keyset pagination,
  "Load More" appends — no over-fetch, no missing pagination.
- **OrgSwitcher / auth store**: org list comes from the single `/auth/me` payload; switching orgs is
  local state only (no refetch of the user) — correct.

---

## Suspected Bugs (for follow-up)

- `web/src/views/CveDetailView.vue:105` — `fetchSources` captures `const currentFetchId = fetchId`
  **without** incrementing it, while `fetchCve` (`:79`) does `++fetchId`. Because both are launched
  together un-awaited, `fetchSources` reads the value `fetchCve` just set. On a rapid `cveId` change
  (`watch`, `:123`), the ordering of the two `++fetchId` increments vs. the two `fetchSources` reads
  is fragile — a stale sources response could pass or fail the `currentFetchId !== fetchId` guard
  inconsistently relative to the CVE body. Looks like the sources fetch should mint/track its own
  token (or share a single increment). Not a perf issue; flagging for correctness review.
- `web/src/views/MembersView.vue:108` — `members.value = data.items as MemberEntry[]` assumes
  `data.items` is non-null (no `?? []`), unlike sibling views that guard with `?? []`. Possible
  runtime throw if the API ever returns a null `items`. Correctness only.
