# Phase 9 — Consolidated Bug Hunt Report

**Date:** 2026-03-16
**Coverage:** 6 agents (3 strategies × 2 scopes)
- Stage 3 API Contract Convergence: exploratory, holistic, multipass
- Health Review Remediation (PR #31): exploratory, holistic, multipass

---

## High Severity

### 1. PostFilter + pagination silently drops results
**File:** `internal/store/dsl_executor.go:188-214`
**Found by:** Health-Exploratory
**Cross-validated by:** (unique finding — only one agent examined this code path in depth)

PostFilters (regex conditions) are applied **after** SQL fetches `limit+1` rows, but next-page detection runs **after** filtering. If regex removes enough rows, `len(results) > limit` is false and no next-cursor is emitted — silently truncating results.

**Impact:** Users with regex-based saved searches or alert rules get incomplete results with no indication of missing data.

**Fix:** Run pagination check on pre-filtered result set. Preserve pre-filter count for cursor decision.

---

## Medium Severity

### 2. PostFilter case-sensitivity mismatch
**File:** `internal/store/dsl_executor.go:249-253` vs `internal/alert/evaluator.go:476`
**Found by:** Health-Exploratory, Health-Multipass

Alert evaluator pre-lowercases descriptions in SQL (`lower(cves.description_primary)`). DSL executor returns raw case from `cvePostFilterTarget.PostFilterField`. Same regex rule produces different results depending on evaluation path.

**Fix:** `cvePostFilterTarget.PostFilterField` should `strings.ToLower()` the description field.

### 3. Watchlist items cursor uses raw UUID instead of opaque cursor
**File:** `internal/api/watchlists.go:553-573`
**Found by:** Stage3-Exploratory, Stage3-Holistic, Health-Holistic

Only paginated endpoint that bypasses `encodePageCursor`/`decodePageCursor`. Uses raw UUID string. Self-consistent but breaks contract uniformity. Frontend assuming opaque cursors will fail.

**Fix:** Convert to `encodePageCursor`/`decodePageCursor` pattern.

### 4. AdminSystemView doctor 503 responses silently discarded
**File:** `web/src/views/admin/AdminSystemView.vue:54,76`
**Found by:** Stage3-Multipass

`/admin/doctor` returns 503 with valid JSON when unhealthy. Both `fetchAll()` and `runDoctor()` only parse when `resp.ok` (200-299). Health card shows nothing when system is unhealthy — the exact scenario users need it most.

**Fix:** Parse body when status is 200 or 503:
```typescript
if (doctorResp.status === 200 || doctorResp.status === 503) {
  doctor.value = (await doctorResp.json()) as DoctorResult
}
```

### 5. Middleware/OAuth errors use `http.Error()` (text/plain) not `writeProblem` (RFC 9457)
**Files:** `middleware_auth.go`, `middleware_rbac.go`, `middleware_csrf.go`, `middleware_site_admin.go`, `oauth_*.go`, `ratelimit.go`
**Found by:** Health-Holistic

All handlers converted to `writeProblem` (application/problem+json), but middleware still uses `http.Error()` (text/plain). Same 429 status arrives in two formats depending on which rate limiter triggers. Frontend parsing `Content-Type: application/problem+json` will fail on middleware errors.

**Note:** Middleware was not in Stage 3 scope, so this is a pre-existing gap.

---

## Low Severity

### 6. `savedSearchExecuteResponse` and `nlSearchResponse` bypass `writeList` nil-guard
**Files:** `internal/api/saved_searches.go:465`, `internal/api/ai.go:220`
**Found by:** Stage3-Exploratory, Stage3-Holistic

Custom response structs bypass `writeList`'s nil→empty-slice coercion. Safe today (`make([]T, 0)` is non-nil), but fragile if allocation pattern changes.

### 7. CVE list endpoint uses Huma directly instead of `writeList`
**File:** `internal/api/cves.go:300-390`
**Found by:** Stage3-Holistic

Only list endpoint using Huma's return-value pattern. Separate `ListCVEsBody` type won't track future `listResponse[T]` changes. Structural inconsistency.

### 8. `deleteGroupHandler` returns 204 for non-existent groups
**File:** `internal/api/groups.go:225-244`
**Found by:** Health-Holistic
**Pre-existing** — no fetch-before-delete, `:exec` SQL doesn't check rows affected.

### 9. `addGroupMemberHandler`/`removeGroupMemberHandler` don't validate group existence
**File:** `internal/api/groups.go:280-342`
**Found by:** Health-Holistic
**Pre-existing** — remove succeeds silently, add may surface FK violation as 500.

### 10. Stale comment in `jobs.go`
**File:** `internal/store/jobs.go:3-7`
**Found by:** Health-Multipass
Comment says "All methods use s.q" but `HasPendingOrRunningJob` uses `s.withBypassTx`.

### 11. Admin vs org cursor type inconsistency
**Found by:** Health-Holistic
Admin cursors use `T time.Time`, org-scoped use `T string`. Both round-trip correctly. Minor consistency gap.

---

## False Positives (Cleared by Cross-Validation)

| Finding | Flagged by | Cleared by | Reason |
|---------|-----------|------------|--------|
| Admin list endpoints leak raw sqlc types | Stage3-Holistic | Stage3-Exploratory | Hand-crafted DTOs with JSON tags, not generated types |
| `evictStaleSemaphores` wrong check | Health-Exploratory (self-retracted) | — | `len(sem) == 0` correctly means "no held slots" |
| `backoffDuration` overflow | Health-Exploratory (self-retracted) | — | `min(..., 10)` cap prevents overflow |
| `addGroupMemberHandler` 204 vs 201 | Stage3-Holistic | — | Idempotent association — 204 defensible |

---

## Recommendation Priority

1. **Fix #1 (PostFilter pagination)** — data correctness, users get silently wrong results
2. **Fix #2 (case-sensitivity)** — behavioral inconsistency between evaluation paths
3. **Fix #3 (watchlist cursor)** — contract uniformity, straightforward conversion
4. **Fix #4 (doctor 503)** — UI shows nothing when system unhealthy
5. **Track #5 (middleware errors)** — scope for a future convergence pass
6. **Track #6-11** — low-severity, fix opportunistically
