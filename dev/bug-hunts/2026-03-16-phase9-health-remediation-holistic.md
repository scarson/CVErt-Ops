# Phase 9 Health Review Remediation — Holistic Bug Hunt

**Date:** 2026-03-16
**Scope:** PR #31 — full backend cross-package analysis (81 files, 13 packages)
**Strategy:** Read all changed source files, reason about cross-cutting correctness issues

## Confirmed Bugs

### Bug 1: Middleware and OAuth error responses break contract consistency (Medium)

**Files:** `internal/api/middleware_auth.go`, `middleware_rbac.go`, `middleware_csrf.go`, `middleware_site_admin.go`, `oauth_github.go`, `oauth_google.go`, `oauth_oidc.go`, `ratelimit.go`

These files still use `http.Error()` which produces `text/plain; charset=utf-8` responses. All handler files were converted to `writeProblem()` which produces `application/problem+json`. This means:
- 401 Unauthorized (auth middleware) → plain text
- 403 Forbidden (RBAC, CSRF, site admin) → plain text
- 429 Too Many Requests (`ratelimit.go`) → plain text
- All OAuth errors → plain text

Notable: `orgRateLimitMiddleware` in `middleware_tier.go:70` WAS correctly converted to `writeProblem`, but the IP-level rate limiter in `ratelimit.go:90` was not — so the same 429 status arrives in two different formats depending on which limiter triggers.

### Bug 2: Watchlist items cursor uses raw UUID instead of opaque cursor (Medium)

**File:** `internal/api/watchlists.go`, lines 553-572

Same finding as Stage 3 exploratory/holistic. Raw UUID string vs `encodePageCursor`/`decodePageCursor` used everywhere else.

### Bug 3: Admin vs org cursor type inconsistency (Low)

**Files:** Admin cursor structs use `T time.Time`, org-scoped cursor structs use `T string`

Both round-trip correctly via JSON marshal, but `time.Time` serialization could produce subtly different formatting. Consistency defect, not a runtime crash.

### Bug 4: `deleteGroupHandler` returns 204 for non-existent groups (Low — pre-existing)

**File:** `internal/api/groups.go`, lines 225-244

Unlike other delete handlers that fetch-before-delete, `deleteGroupHandler` calls `SoftDeleteGroup` directly with `:exec` SQL — no rows-affected check. Returns 204 even when group doesn't exist. Other delete handlers return 404 in this case.

### Bug 5: `addGroupMemberHandler`/`removeGroupMemberHandler` don't validate group existence (Low — pre-existing)

**File:** `internal/api/groups.go`, lines 280-342

Neither handler validates that the group exists before operating. Remove succeeds silently for non-existent groups. Add may fail with FK violation surfacing as generic 500.

### Bug 6: `savedSearchExecuteResponse` nil fragility (Low)

**File:** `internal/api/saved_searches.go`, lines 460-468

Same finding as Stage 3 agents. Safe today but fragile vs `writeList`'s explicit nil-guard.

## Patterns Verified Clean

- All org-scoped store methods consistently take `orgID` parameter
- Transaction helpers correctly chosen across packages
- Error wrapping preserves chain throughout
- Context propagation correct in worker and notification paths
