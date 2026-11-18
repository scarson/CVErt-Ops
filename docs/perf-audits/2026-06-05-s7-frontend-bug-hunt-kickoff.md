# Bug-hunt kickoff — suspected bugs from the 2026-06-05 S7 frontend audit

Run: `bug-hunt-cycle` with the scope below.

**Scope:** `web/src/views/FeedStatusView.vue`, `web/src/views/admin/AdminFeedsView.vue`,
`web/src/views/WatchlistDetailView.vue`, `web/src/views/CveDetailView.vue`,
`web/src/views/MembersView.vue`, `web/src/views/admin/AdminDashboardView.vue`,
`web/src/components/ui/table/utils.ts`. Surfaced during S7.

**Seed findings (verify, don't trust):**
- Feed pollers set `loading=true` on every 30s tick → full-page spinner flash + lost expanded-row state (use a `refreshing` flag).
- `WatchlistDetailView.vue:201-206` `watch(activeOrgId)` → `router.push('/watchlists')` fires on initial auto-select; may bounce a user off a deep-linked watchlist on first load.
- `AdminDashboardView.vue:36,56` "Failed Deliveries" count uses a `limit:1` probe — likely misleading.
- `CveDetailView.vue:104-105` fragile `fetchId` capture — `fetchSources` doesn't mint its own token; stale-guard coupling with `fetchCve`.
- `MembersView.vue:108` missing `?? []` null-guard.
- `components/ui/table/utils.ts` `valueUpdater` exported but never imported — dead code pulling in `@tanstack/vue-table`.

Noticed while auditing performance; NOT investigated. Leads, not confirmed bugs.
