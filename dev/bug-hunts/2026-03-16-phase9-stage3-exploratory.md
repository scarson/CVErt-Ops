# Phase 9 Stage 3 — Exploratory Bug Hunt (Go Infrastructure)

**Date:** 2026-03-16
**Scope:** API contract convergence — `contract.go`, `openapi_spec.go`, `server.go`, cursor/pagination infrastructure, high-risk handler consumers
**Strategy:** Depth-first from highest-risk infrastructure code, following threads into consumers

## Confirmed Bugs

### Bug 1: Watchlist items cursor is not opaque (Medium)

**File:** `internal/api/watchlists.go`, lines 553-573

The `listWatchlistItemsHandler` uses a **raw UUID string** as its cursor value, while every other paginated endpoint uses `encodePageCursor`/`decodePageCursor` to produce opaque base64url-encoded JSON cursors.

```go
// Decodes cursor as raw UUID
if a := r.URL.Query().Get("cursor"); a != "" {
    id, err := uuid.Parse(a)  // raw UUID, not decodePageCursor!
}

// Emits cursor as raw UUID
nextCursor = items[len(items)-1].ID.String()  // raw UUID, not encodePageCursor!
```

Every other cursor-paginated endpoint uses the `encodePageCursor`/`decodePageCursor` pattern. This endpoint was missed during the convergence.

**Impact:** Self-consistent (works in isolation), but breaks the contract uniformity. Frontend code treating all cursors as uniformly opaque could fail.

### Bug 2: `savedSearchExecuteResponse` bypasses `writeList` null-array protection (Low)

**File:** `internal/api/saved_searches.go`, lines 465-468

Uses `writeJSON` with a custom struct instead of `writeList`. Currently safe because `make([]CVEItem, len(results))` produces a non-nil empty slice, but lacks the `writeList` nil-guard. A future refactor that changes the allocation pattern could introduce a null-array bug.

## Investigated and Cleared

1. **`mergeSpecPaths` schema mutation** — Writing to `Components.Schemas.Map()` correctly mutates the underlying huma registry
2. **`writeLocation` + `writeJSON` ordering** — Headers set before `WriteHeader(status)`, correct per Go's `http.ResponseWriter` contract
3. **`writeProblem` return safety** — Every call followed by `return`, preventing double-writes
4. **`writeList` nil-safety** — Nil-to-empty-slice coercion at line 98-99 works correctly
5. **Cursor encoding round-trip** — `RawURLEncoding` (no padding) is URL-safe, padded fallback handles backward compat
6. **`parseLimitParam` boundary conditions** — Correctly rejects `limit < 1` and `limit > maxLimit`
7. **Two cursor type styles (string vs time.Time)** — Both self-consistent and round-trip correctly
8. **Admin list endpoints** — Use hand-crafted DTOs with JSON tags, NOT raw sqlc types. No data leak risk.
