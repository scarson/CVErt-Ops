# Phase 2 Test Coverage Gap Review

**Date:** 2026-03-02
**Scope:** All Phase 2 code (2a: auth/RBAC/middleware, 2b: watchlists/alert DSL/evaluator)
**Method:** Systematic path mapping using `test-coverage-review` skill — mapped every code path in source files and cross-referenced against test assertions
**Commits:** `15d190f` (test fixes), `71a91d5` (soft-delete cascade bugfix)

---

## Summary

| Metric | Count |
|--------|-------|
| Gaps identified | ~289 |
| Security-critical | 67 |
| Correctness | 137 |
| Nice-to-have | 85 |
| Tests added | ~210 new test functions |
| Files changed | 26 |
| Lines added | 6,421 |
| Bugs found & fixed | 1 (watchlist soft-delete cascade) |

---

## Findings by Package

### `internal/auth/` (7 tests added)

| Test | Category | Gap |
|------|----------|-----|
| `TestJWTRejectsAlgNone` | security-critical | `alg:none` JWT bypass attack not tested for access tokens |
| `TestJWTRejectsWrongSecret` | security-critical | Wrong signing key not tested for access tokens |
| `TestRefreshTokenRejectsExpired` | security-critical | Expired refresh token path untested |
| `TestRefreshTokenRejectsWrongAlgorithm` | security-critical | RS256 confusion attack not tested for refresh tokens |
| `TestRefreshTokenRejectsAlgNone` | security-critical | `alg:none` bypass not tested for refresh tokens |
| `TestRefreshTokenRejectsWrongSecret` | security-critical | Wrong secret not tested for refresh tokens |
| `TestHashPasswordOWASPParameters` | correctness | No assertion that argon2id uses OWASP-recommended params (m=19456, t=2, p=1) |
| `TestVerifyPasswordMalformedHash` (5 subtests) | correctness | Malformed hash inputs (empty, non-PHC, wrong algo, too few parts, bad params) not tested |

### `internal/api/middleware_*` (19 tests added)

**CSRF (`middleware_csrf_test.go` — 4 tests, 13 subtests)**

| Test | Category | Gap |
|------|----------|-----|
| `TestCSRF_SafeMethodsAllowed` | security-critical | No test that GET/HEAD/OPTIONS/TRACE bypass CSRF check |
| `TestCSRF_StateChangingMethodsBlocked` | security-critical | No test that POST/PUT/PATCH/DELETE require CSRF header |
| `TestCSRF_WrongHeaderValue` | security-critical | Wrong header value not tested (only missing header) |
| `TestCSRF_NoCookieBypassesCheck` | correctness | No-cookie path (API key auth) untested |

**Auth middleware (`middleware_auth_test.go` — 4 tests)**

| Test | Category | Gap |
|------|----------|-----|
| Non-Bearer prefix fallthrough | security-critical | Auth header with wrong prefix not tested |
| Malformed JWT → 401 | security-critical | Garbled JWT token path untested |
| Wrong secret → 401 | security-critical | JWT signed with different secret not tested |
| API key context values | correctness | API key auth path didn't verify context values set correctly |

**RBAC (`middleware_rbac_test.go` — 4 tests)**

| Test | Category | Gap |
|------|----------|-----|
| No userID → 401 | security-critical | Missing user context not tested |
| Invalid org_id → 400 | correctness | Malformed org_id in URL path untested |
| Exact role match (4 roles) | correctness | Only viewer tested, not member/admin/owner boundaries |
| API key role not capped upward | security-critical | API key with admin role shouldn't grant owner access |

**Rate limiter (`ratelimit_test.go` — 7 tests)**

| Test | Category | Gap |
|------|----------|-----|
| `clientIPMiddleware` host:port | correctness | Previously entirely untested |
| `clientIPMiddleware` bare IP | correctness | Previously entirely untested |
| `clientIPMiddleware` IPv6 | correctness | Previously entirely untested |
| `checkAuthRateLimit` within burst | correctness | Previously entirely untested |
| `checkAuthRateLimit` after burst | security-critical | Rate limit enforcement not tested |
| `checkAuthRateLimit` missing IP | correctness | Fallback behavior untested |
| `authRateLimit` port stripping | correctness | Port stripping for rate limit key untested |

### `internal/store/` (48 tests added)

**RLS fail-closed (`org_tx_test.go` — 6 tests)**

| Test | Category | Gap |
|------|----------|-----|
| `TestAPIKey_RLSFailClosed` | security-critical | No test proving 0 rows when `app.org_id` unset |
| `TestListOrgAPIKeys_AppStoreRLS` | security-critical | AppStore (no org context) returns 0 rows |
| `TestGroup_RLSFailClosed` | security-critical | Groups accessible without org context |
| `TestListOrgGroups_AppStoreRLS` | security-critical | AppStore group listing leaks data |
| `TestGroupMember_RLSFailClosed` | security-critical | Group members accessible without org context |
| `TestListGroupMembers_AppStoreRLS` | security-critical | AppStore group member listing leaks data |

**Auth store (`auth_test.go` — 8 tests)**

| Test | Category | Gap |
|------|----------|-----|
| `GetUserByID` happy + not-found | correctness | Basic CRUD path untested |
| `CountUsers` | correctness | User count for registration gate untested |
| `UpdateLastLogin` | correctness | Login timestamp update untested |
| `UpdatePasswordHash` + version bump | security-critical | Password change + token version bump untested |
| Identity upsert conflict | security-critical | Same `provider_user_id` for different user untested |
| `DeleteExpiredRefreshTokens` | correctness | Token cleanup untested |
| Duplicate email constraint | correctness | Unique constraint enforcement untested |

**Org store (`org_test.go` — 10 tests)**

| Test | Category | Gap |
|------|----------|-----|
| Duplicate member add | correctness | Idempotency behavior untested |
| Invitation accept flow | correctness | Full accept lifecycle untested |
| Owner count | correctness | Owner count for transfer/delete guard untested |
| `CreateOrgWithOwner` | correctness | Org creation happy path untested |
| Update + not-found | correctness | Org update paths untested |
| Cancel invitation + not-found | correctness | Invitation cancellation untested |
| `ListUserOrgs` empty | correctness | Empty result set untested |

**API key store (`apikey_test.go` — 7 tests)**

| Test | Category | Gap |
|------|----------|-----|
| Revoke idempotent | correctness | Double-revoke behavior untested |
| List empty | correctness | Empty list result untested |
| Get by ID + not-found + wrong org | security-critical | Cross-org API key access untested |
| Update last used | correctness | Last-used timestamp update untested |
| Lookup not-found | correctness | Missing key lookup path untested |

**Group store (`group_test.go` — 7 tests)**

| Test | Category | Gap |
|------|----------|-----|
| Remove member + non-existent | correctness | Member removal paths untested |
| Empty members list | correctness | Empty group edge case untested |
| Update group | correctness | Group update untested |
| List + empty + excludes deleted | correctness | Soft-delete filtering in list untested |

**Watchlist store (`watchlist_test.go` — 6 tests)**

| Test | Category | Gap |
|------|----------|-----|
| Soft-delete behavior | correctness | Watchlist deletion lifecycle untested |
| Item pagination | correctness | Cursor-based item pagination untested |
| Count after delete | correctness | Item count after item deletion untested |
| Get includes item count | correctness | `WatchlistRow.ItemCount` population untested |
| Deleted watchlist ownership validation | security-critical | `CountOwnedWatchlistsByIDs` excludes deleted untested |
| Item with namespace | correctness | Namespace field persistence untested |

**Alert rule store (`alert_rule_test.go` — 10+ tests)**

| Test | Category | Gap |
|------|----------|-----|
| List pagination | correctness | Cursor pagination untested |
| Update not-found | correctness | Missing rule update path untested |
| List active EPSS rules | correctness | EPSS-only rule filtering untested |
| Event different material hash | correctness | Event dedup allows different hashes untested |
| Event filters (last_match_state, since, pagination) | correctness | Event query filters untested |
| Soft-delete exclusion | correctness | Deleted rules excluded from lists untested |
| Suppress delivery flag | correctness | Activation-scan suppress_delivery untested |
| Run with error | correctness | Error status run recording untested |
| Create with watchlist_ids | correctness | Watchlist binding at creation untested |
| Default limit | correctness | Default limit guard untested |

### `internal/alert/dsl/` (63 tests added)

**Parser (3 tests)**

| Test | Category | Gap |
|------|----------|-----|
| Missing logic field | correctness | Parse error for missing `logic` untested |
| Nil conditions | correctness | Parse error for nil conditions untested |
| Multiple conditions | correctness | Multi-condition parse untested |

**Validator (25 tests)**

| Test | Category | Gap |
|------|----------|-----|
| Every field kind × operator combination | correctness | Only a subset of operator combos tested |
| Non-string typed field values | correctness | Type coercion errors untested |
| Affected ecosystem in/not_in/neq | correctness | Enum validation for affected fields untested |
| String `in` with non-array | correctness | Wrong value type for `in` operator untested |
| Text contains/starts_with/ends_with | correctness | Text-kind operator validation untested |
| Multiple errors collected | correctness | Error aggregation untested |
| Unknown field sets isEPSSOnly=false | correctness | EPSS-only flag logic gap |

**Compiler (27 tests)**

| Test | Category | Gap |
|------|----------|-----|
| All 6 numeric ops (table-driven) | correctness | Only `gte` tested, not eq/neq/gt/lt/lte |
| All 6 time ops (table-driven) | correctness | Only `gt` tested for time fields |
| String eq/neq/not_in | correctness | String operators beyond `contains` untested |
| Enum neq/not_in | correctness | Enum exclusion operators untested |
| Bool false | correctness | `kev_known = false` compiles correctly untested |
| CVSS v4 score | correctness | v4 accessor used for v4 field untested |
| OR logic with watchlists | correctness | OR + watchlist subquery interaction untested |
| Regex-only with/without watchlists | correctness | Regex validation with watchlist context untested |
| Affected ecosystem neq/in/not_in SQL | correctness | SQL generation for affected exclusion ops untested |
| Affected package starts_with/ends_with | correctness | ILIKE pattern generation untested |
| FTS join dedup | correctness | FTS + another condition doesn't duplicate join untested |
| Backslash escaping | security-critical | SQL injection via backslash in LIKE patterns untested |
| Unknown field error | correctness | Compiler error path for unknown fields untested |
| Invalid regex error | correctness | Regex compilation error path untested |
| EPSS-only flags | correctness | IsEPSSOnly/HasEPSS flag computation untested |
| Multiple post-filters | correctness | Multiple regex conditions combined untested |
| AND logic arg count | correctness | AND-joined SQL arg count correctness untested |

**Security (2 tests)**

| Test | Category | Gap |
|------|----------|-----|
| Watchlist org_id parameter binding | security-critical | Tenant isolation in watchlist SQL subquery untested |
| Watchlist deleted_at filter | correctness | Soft-deleted watchlists excluded from subquery untested |

**Types & accessors (3 tests)**

| Test | Category | Gap |
|------|----------|-----|
| `ValidationError.Error()` | correctness | Error interface method untested |
| `ExportFieldDescriptions` completeness | correctness | All fields exported for UI untested |
| CVSS v4 accessor nil/null/valid | correctness | Nil-safe accessor edge cases untested |

### `internal/alert/evaluator` (26 tests + 7 postfilter tests)

| Test | Category | Gap |
|------|----------|-----|
| `EvaluateEPSS` (5 subtests) | correctness | **Entirely untested** — happy path, threshold filtering, only EPSS rules, cursor, mixed rules |
| `DryRun` (5 subtests) | correctness | **Entirely untested** — match without persist, not-found, sample cap, regex post-filter, rejected exclusion |
| candidateCap fail-closed (5100 CVEs) | security-critical | 5000-cap enforcement → `Partial=true`, `MatchCount=0` |
| Batch cursor advancement | correctness | Cursor persisted after successful batch untested |
| Skips EPSS-only rules | correctness | Batch evaluator excludes EPSS-only rules untested |
| Activation keyset pagination (1005 CVEs) | correctness | Multi-page activation scan untested |
| Activation rule not found | correctness | Missing rule during activation untested |
| Zombie sweep | correctness | Stale job detection untested |
| Recent job not swept | correctness | Non-stale job preserved untested |
| `RuleCache` concurrent access (50 goroutines) | correctness | Thread safety untested |
| `RuleCache` concurrent evict | correctness | Concurrent eviction safety untested |
| `applyPostFilters` — 7 tests (new file) | correctness | Unexported function entirely untested |

### `internal/api/` handlers — Phase 2a (29 tests added)

**Auth handlers (`auth_test.go` — 11 tests)**

| Test | Category | Gap |
|------|----------|-----|
| Register invite-only mode | security-critical | Registration gate not tested |
| Refresh missing/invalid/revoked-version cookies | security-critical | Refresh token edge cases untested |
| `/auth/me` unauthenticated | security-critical | Unauthenticated access untested |
| Change password unauthenticated | security-critical | Password change without auth untested |
| Change password OAuth-only account | correctness | OAuth-only user password change behavior untested |
| Expired invitation (get + accept) | correctness | Invitation expiry enforcement untested |
| Accept invitation without auth | security-critical | Unauthenticated invitation accept untested |

**OAuth handlers (6 tests)**

| Test | Category | Gap |
|------|----------|-----|
| GitHub: mismatched state cookie | security-critical | CSRF protection on OAuth callback untested |
| GitHub: no verified primary email | correctness | Email verification requirement untested |
| GitHub: identity linking by provider_user_id | security-critical | Returning user identity match untested |
| Google: missing nonce cookie | security-critical | OIDC nonce validation untested |
| Google: mismatched state cookie | security-critical | CSRF protection on OIDC callback untested |
| Google: identity linking by provider sub | security-critical | Returning user identity match untested |

**Org handlers (`orgs_test.go` — 4 tests)**

| Test | Category | Gap |
|------|----------|-----|
| Cross-org member operations (7 subtests) | security-critical | Cross-tenant data access untested |
| Empty name | correctness | Input validation gap |
| Remove non-existent member | correctness | Not-found error path untested |
| Invalid invitation role | correctness | Role validation gap |

**Group handlers (`groups_test.go` — 4 tests)**

| Test | Category | Gap |
|------|----------|-----|
| Cross-org group access (6 subtests) | security-critical | Cross-tenant data access untested |
| Not-found | correctness | Missing group error path untested |
| Duplicate member | correctness | Idempotent member add untested |
| Empty name | correctness | Input validation gap |

**API key handlers (`apikeys_test.go` — 4 tests)**

| Test | Category | Gap |
|------|----------|-----|
| Viewer forbidden from create | security-critical | RBAC enforcement on key creation untested |
| Invalid role | correctness | Role validation gap |
| Revoke idempotent | correctness | Double-revoke behavior untested |
| Cross-org access (3 subtests) | security-critical | Cross-tenant API key access untested |

### `internal/api/` handlers — Phase 2b (32 tests added)

**Watchlist handlers (`watchlists_test.go` — 10 tests)**

| Test | Category | Gap |
|------|----------|-----|
| Cross-org read/write isolation (6 operations) | security-critical | Cross-tenant watchlist access untested |
| PATCH empty name | correctness | Input validation gap |
| Duplicate name | correctness | Unique constraint enforcement untested |
| Soft-delete behavior | correctness | Full delete lifecycle untested |
| List pagination | correctness | Cursor pagination untested |
| Create empty name | correctness | Input validation gap |
| Invalid item type | correctness | Enum validation untested |
| Get/patch/delete non-existent | correctness | Not-found error paths untested |

**Alert rule handlers (`alert_rules_test.go` — 17 tests)**

| Test | Category | Gap |
|------|----------|-----|
| Dry-run handler (4 tests) | correctness | **Previously entirely untested** |
| PATCH state machine transitions | correctness | State transition rules untested |
| Cross-org PATCH/DELETE | security-critical | Cross-tenant rule modification untested |
| Invalid watchlist ID | correctness | Foreign watchlist validation untested |
| Empty name | correctness | Input validation gap |
| Get/delete/patch non-existent | correctness | Not-found paths untested |
| Validate with parse error | correctness | Validation endpoint error response untested |
| List with status filter | correctness | Status filter query param untested |

**Alert event handlers (`alert_events_test.go` — 5 tests)**

| Test | Category | Gap |
|------|----------|-----|
| last_match_state filter | correctness | Resolution event filter untested |
| Pagination | correctness | Event cursor pagination untested |
| Invalid rule_id/since filters | correctness | Malformed filter handling untested |
| Empty list | correctness | Empty result set untested |

---

## Bug Found: Watchlist Soft-Delete Cascade

**Severity:** Correctness (potential data leak)
**Commit:** `71a91d5`

**Problem:** `ListWatchlistItems`, `CountWatchlistItems`, and `GetWatchlistItem` queried `watchlist_items` with `deleted_at IS NULL` but never checked whether the parent watchlist was soft-deleted. Items remained accessible after the parent watchlist was deleted.

**Fix:** Added `JOIN watchlists w ON w.id = wi.watchlist_id AND w.deleted_at IS NULL` to all three item read queries (both sqlc and squirrel). Updated the existing test `TestDeleteWatchlist_ItemCountDropsToZero` to assert count=0 and list=empty after parent soft-delete. Updated `TestWatchlist_SoftDeleteBehavior` API test to expect 0 items.

**Files changed:** `queries/watchlist.sql`, `generated/watchlist.sql.go`, `watchlist.go`, `watchlist_test.go`, `watchlists_test.go`

---

## Other Fixes Made During Review

| Fix | File | Description |
|-----|------|-------------|
| ai_test.go quota flakiness | `ai_test.go` | Rate limiter burst window (10) conflicted with quota limit (10). Reduced quota to 3, iterations to 3 |
| OAuth identity linking test isolation | `oauth_github_test.go`, `oauth_google_test.go` | Pre-created user had same email as mock OAuth provider, causing unique constraint violation. Used different emails |
| Alert rules test unused imports | `alert_rules_test.go` | Removed unused imports (`log/slog`, `os`, `github.com/google/uuid`, `github.com/scarson/cvert-ops/internal/alert`) |
| Cross-org member test setup | `orgs_test.go` | `BootstrapFirstUserOrg` only creates org for first user. Second user needed own org via API |

---

## Remaining Gaps (nice-to-have, deferred)

These were identified but intentionally not addressed as the risk/effort ratio was too low:

- Internal error wrapping consistency (correct error types returned but messages not asserted)
- Unlikely runtime failures (`rand.Reader` failure, `json.Marshal` of known types)
- Cache eviction edge cases in `RuleCache` (beyond the concurrent access tests added)
- Defensive checks that duplicate upstream validation
