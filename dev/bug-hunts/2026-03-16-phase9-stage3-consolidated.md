# Phase 9 Stage 3 — Consolidated Bug Hunt Report

**Date:** 2026-03-16
**Coverage:** 3 agents — exploratory (Go infrastructure), holistic (full Go API layer), multipass (frontend conversion)

---

## Medium Severity

### 1. Watchlist items cursor uses raw UUID instead of opaque cursor
**File:** `internal/api/watchlists.go:553-573`
**Found by:** Exploratory, Holistic

Only paginated endpoint that bypasses `encodePageCursor`/`decodePageCursor`. Uses raw UUID string. Self-consistent (works in isolation), but breaks contract uniformity. Frontend assuming opaque cursors will fail.

**Fix:** Convert to `encodePageCursor`/`decodePageCursor` pattern matching all other endpoints.

### 2. AdminSystemView doctor 503 responses silently discarded
**File:** `web/src/views/admin/AdminSystemView.vue:54,76`
**Found by:** Multipass

`/admin/doctor` returns 503 with valid JSON when unhealthy. Both `fetchAll()` and `runDoctor()` only parse when `resp.ok` (200-299). Health card shows nothing when system is unhealthy — the exact scenario users need it most.

**Fix:** Parse body when status is 200 or 503:
```typescript
if (doctorResp.status === 200 || doctorResp.status === 503) {
  doctor.value = (await doctorResp.json()) as DoctorResult
}
```

---

## Low Severity

### 3. `savedSearchExecuteResponse` and `nlSearchResponse` bypass `writeList` nil-guard
**Files:** `internal/api/saved_searches.go:465`, `internal/api/ai.go:220`
**Found by:** Exploratory, Holistic

Custom response structs bypass `writeList`'s nil→empty-slice coercion. Safe today (`make([]T, 0)` is non-nil), but fragile if allocation pattern changes.

### 4. CVE list endpoint uses Huma directly instead of `writeList`
**File:** `internal/api/cves.go:300-390`
**Found by:** Holistic

Only list endpoint using Huma's return-value pattern (`*ListCVEsOutput`). Separate `ListCVEsBody` type won't track future `listResponse[T]` changes.

### 5. AdminDeliveriesView `fetchError.status` without optional chaining
**File:** `web/src/views/admin/AdminDeliveriesView.vue:105`
**Found by:** Multipass

Safe at runtime (inside `else` branch where `fetchError` is truthy), but inconsistent with AdminFeedsView and FeedStatusView which use `fetchError?.status`.

---

## Pre-existing Observations (Not Stage 3 Regressions)

### InviteMemberDialog vs MembersView role filtering
- MembersView: admin can assign admin role (`<=`)
- InviteMemberDialog: admin cannot invite as admin (`<`)
May be intentional. Worth verifying.

### AdminDashboardView summary counts
Fetches with `limit: 1`, shows "1+" for any count > 1. Low-fidelity by design.

---

## False Positives (Cleared by Cross-Validation)

| Finding | Flagged by | Cleared by | Reason |
|---------|-----------|------------|--------|
| Admin list endpoints leak raw sqlc types | Holistic | Exploratory | Hand-crafted DTOs with JSON tags, not generated types |
| `addGroupMemberHandler` 204 vs 201 | Holistic | — | Idempotent association — 204 is defensible |

---

## Verified Clean

- `mergeSpecPaths` mutation safety — correct per huma internals
- `writeLocation` + `writeJSON` ordering — headers before status, correct
- `writeProblem` return safety — every call followed by `return`
- `writeList` nil-safety — nil→empty-slice coercion works
- Cursor encoding round-trip — `RawURLEncoding` URL-safe, padded fallback works
- `parseLimitParam` boundaries — correct
- All 18 frontend files use correct OpenAPI paths/params/bodies
- 415/415 frontend tests pass, TypeScript type-check clean, lint clean
- No `orgFetch` imports, `Content-Type` headers, or `JSON.stringify` calls remain
- Error propagation preserved faithfully across conversion
- No concurrency issues in reactive state updates
