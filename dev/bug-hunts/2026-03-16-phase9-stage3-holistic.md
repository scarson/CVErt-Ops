# Phase 9 Stage 3 — Holistic Bug Hunt (Full Go API Layer)

**Date:** 2026-03-16
**Scope:** All 46 Go files in `internal/api/` modified during API contract convergence
**Strategy:** Read all source files, reason about cross-cutting correctness issues

## Confirmed Bugs

### Bug 1: Watchlist items cursor is not opaque (Medium)

**File:** `internal/api/watchlists.go`, lines 553-573

Same finding as exploratory hunt — `listWatchlistItemsHandler` uses raw UUID string as cursor instead of `encodePageCursor`/`decodePageCursor`. Breaks contract uniformity with all other paginated endpoints.

### Bug 2: `savedSearchExecuteResponse` bypasses `writeList` (Low)

**File:** `internal/api/saved_searches.go`, line 465

Uses `writeJSON` with custom struct instead of `writeList`. Safe today (non-nil empty slice from `make`), but fragile — lacks the nil-guard that `writeList` provides.

### Bug 3: `nlSearchResponse.Results` latent null-array risk (Low)

**File:** `internal/api/ai.go`, line 220

Same pattern as Bug 2 — custom `nlSearchResponse` with `Results []CVEItem` field bypasses `writeList`. If `store.ExecuteDSLQuery` ever returns nil instead of empty slice, JSON would serialize as `null`.

### Bug 4: CVE list uses Huma directly instead of `writeList` (Low — Structural)

**File:** `internal/api/cves.go`, lines 300-390

The only list endpoint going through Huma's return-value pattern (`*ListCVEsOutput`) rather than chi+writeList. Structurally identical to `listResponse[T]` but is a separate type. Future contract changes to `writeList`/`listResponse` won't propagate.

## Assessed as Intentional / Not Bugs

### `addGroupMemberHandler` returns 204 for POST

**File:** `internal/api/groups.go`, line 312

Flagged as potentially inconsistent (other POSTs return 201+Location), but adding a member is an idempotent association — 204 is defensible.

### `readyz.go` and `healthzHandler` use raw `json.NewEncoder`

**Files:** `internal/api/readyz.go` line 104, `internal/api/server.go` line 486

Infrastructure/health endpoints intentionally outside the API contract surface.

## Findings Contradicted by Exploratory Hunt

### Admin list endpoints leaking raw DB structs — FALSE POSITIVE

**Files:** `internal/api/admin_orgs.go` line 85, `internal/api/admin_deliveries.go` line 69

Initially flagged as passing raw sqlc structs to `writeList`. Exploratory hunt confirmed these are hand-crafted DTO types (`AdminOrgRow`, `AdminDeliveryRow`) with explicit JSON tags, not raw `generated.*` types. No data leak risk.
