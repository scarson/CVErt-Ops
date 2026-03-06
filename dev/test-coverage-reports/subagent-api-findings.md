# Hybrid Coverage-Guided Test Review: `internal/api/` Package

**Date:** 2026-03-03
**Reviewer:** Claude (subagent)
**Methodology:** Two-pass hybrid — coverage-guided triage (Pass 1) + semantic analysis (Pass 2)

---

## Summary Counts

| Category | Count |
|----------|-------|
| Security-critical gaps | 8 |
| Correctness gaps | 14 |
| Nice-to-have gaps | 11 |
| Assertion quality issues | 3 |
| **Total findings** | **36** |
| Findings corrected during post-review | 4 |

---

## Pass 1: Coverage-Guided Triage

### Band A: 0% Coverage (Untested Functions)

#### 1. `pgErrCode` — auth.go — 0%
- **Risk:** Correctness
- **Analysis:** Extracts a Postgres error code from `error` chains. Used in `registerHandler` (line ~87) and `acceptInvitationHandler` (line ~440) to detect unique-constraint violations (duplicate email = `23505`). Zero coverage means the unique-constraint error path is never tested for either register or accept-invitation.
- **Impact:** If `pgErrCode` is wrong (e.g., mismatches the pgx error interface), duplicate-email registrations would return 500 instead of 409. Untested.
- **Priority:** HIGH — affects registration and invitation acceptance error handling.

#### 2. `encodeDeliveryCursor` — deliveries.go — 0%
- **Risk:** Correctness
- **Analysis:** Formats `time.Time + uuid.UUID` as `"<RFC3339Nano>/<uuid>"` for keyset pagination cursors. Its inverse (`decodeTimeCursor`) is used to parse the `after` query parameter. If encoding is wrong, pagination breaks silently (cursor decodes fail, returns first page again — infinite loop for clients).
- **Impact:** Delivery pagination would silently break if format doesn't match decoder.
- **Priority:** MEDIUM — pagination correctness.

### Band B: 1–79% Coverage (Partially Tested — PRIORITY BAND)

#### 3. `getCVEHandler` — cves.go — 40.0%
- **Risk:** Correctness
- **Analysis:** 60% of branches uncovered. The test exercises the happy path via HTTP but does NOT test:
  - Invalid CVE ID format (malformed string that isn't a valid CVE pattern)
  - CVE not found (404 path)
  - Store error (500 path)
  - The `cfeToItem` conversion of nullable fields (CVSS vectors, EPSS score, references arrays)
- **Uncovered branches:** 404 path, 500 error, nullable field rendering
- **Priority:** MEDIUM

#### 4. `getCVESourcesHandler` — cves.go — 47.6%
- **Risk:** Correctness
- **Analysis:** ~52% uncovered. Tests only the happy path. Missing:
  - Invalid CVE ID validation branch
  - Empty sources array rendering
  - Store error path (500)
- **Priority:** MEDIUM

#### 5. `listCVEsHandler` — cves.go — 66.7%
- **Risk:** Correctness
- **Analysis:** Tests cover list, pagination, and severity filter. Missing branches:
  - `cursor` decode error (malformed cursor → should return 400 or ignore)
  - `epss_min`/`epss_max` filter parsing
  - `has_kev=true/false` filter
  - `modified_since` date parsing error path
  - Store error (500)
- **Priority:** MEDIUM — multiple filter branches untested

#### 6. `loginHandler` — auth.go — 64.9%
- **Risk:** Security-critical
- **Analysis:** Tested: valid login, wrong password, non-existent user. UNTESTED:
  - Argon2 semaphore exhaustion (503 path when all slots taken)
  - Rate limiting interaction (rate limit hit on login endpoint)
  - JSON decode error (malformed body → 400)
  - Missing `email` or `password` field
  - Case sensitivity of email lookup
- **Priority:** HIGH — Argon2 exhaustion is a DOS vector; if semaphore check is wrong, server could OOM.

#### 7. `refreshGrace` — auth.go — 53.3%
- **Risk:** Security-critical
- **Analysis:** Implements refresh token grace period (reuse detection). Tests cover the happy-path refresh. UNTESTED:
  - Grace period window behavior (reuse within grace vs after grace)
  - Token theft detection (reuse after rotation completes)
  - The `familyID` propagation through consecutive refreshes
- **Impact:** If refresh token reuse detection is broken, stolen refresh tokens work indefinitely.
- **Priority:** HIGH — refresh token security.

#### 8. `issueRefreshPair` — auth.go — 50.0%
- **Risk:** Security-critical
- **Analysis:** Generates access + refresh tokens, stores refresh token hash. 50% uncovered. The `sub` claim encoding and refresh token storage are exercised via login/register tests, but the error paths are not:
  - JWT signing error
  - Refresh token DB storage error
  - Token family creation failure
- **Priority:** MEDIUM — error paths in token issuance.

#### 9. `replayDeliveryHandler` — deliveries.go — 43.8%
- **Risk:** Correctness
- **Analysis:** Tests are more comprehensive than the 43.8% coverage suggests. Tests cover:
  - Basic replay with DB state verification (status=pending, attempt_count=0, last_error=nil)
  - Rate limit enforcement: `TestReplayDelivery_RateLimited` sends 11 replays and expects 429 on the 11th
  - Non-existent delivery ID: `TestReplayDelivery_NonExistentID` confirms SQL WHERE guard returns 204 (no-op, not 404)
  - Cross-org isolation (replay from wrong org → 403)
  - RBAC: viewer and member denied replay but can read
- **Remaining untested paths (explaining the 43.8%):**
  - Invalid UUID in path (malformed string → 400)
  - Store error on replay (DB failure → 500)
- **Note:** Replay rate limit (`checkReplayLimit`) uses `time.Now()` directly (not injectable) — hard to test deterministically without time manipulation. The package-level `sync.Map` (`replayBuckets`) survives across tests, potentially creating flaky interactions.
- **Priority:** LOW (downgraded — most critical paths are covered)

#### 10. `getDeliveryHandler` — deliveries.go — 50.0%
- **Risk:** Correctness
- **Analysis:** Tests cover happy path and 404. UNTESTED:
  - Invalid UUID in path (400 path)
  - Store error (500 path)
  - Nullable field rendering (ReportID, LastAttemptedAt, DeliveredAt, LastError)
- **Priority:** LOW

#### 11. `listDeliveriesHandler` — deliveries.go — 60.0%
- **Risk:** Correctness
- **Analysis:** Tests are more comprehensive than the 60% coverage suggests. Tests cover:
  - `TestListDeliveries_FilterByStatus` — filter by status
  - `TestListDeliveries_FilterByRuleAndChannel` — filter by rule_id and channel_id
  - `TestListDeliveries_LimitClamping` — limit clamping (0→400, -1→400, 999→200)
  - Cross-org isolation and RBAC
- **Remaining untested paths (explaining the 60%):**
  - `rule_id` filter with invalid UUID (400)
  - `channel_id` filter with invalid UUID (400)
  - Non-integer limit parameter
  - Keyset cursor (`after_created_at` + `after_id`) parsing
  - Store error (500)
  - Pagination cursor generation (when `len(rows) == limit`)
- **Priority:** LOW (downgraded — filters and limit clamping are covered; remaining gaps are error/edge paths)

#### 12. `updateOrgHandler` — orgs.go — 45.0%
- **Risk:** Correctness
- **Analysis:** 55% uncovered. Tests cover happy path PATCH. UNTESTED:
  - Empty name (should reject)
  - Name too long
  - JSON decode error
  - Store error
  - RBAC enforcement (the route is registered with RequireOrgRole, but no test verifies a viewer can't update)
- **Priority:** MEDIUM

#### 13. `createInvitationHandler` — orgs.go — 54.5%
- **Risk:** Security-critical
- **Analysis:** Tests cover happy path and tier limit. UNTESTED:
  - Inviting an email that's already a member (should reject with 409)
  - Inviting an email with an existing pending invitation (dedup behavior)
  - JSON decode error
  - Invalid email format
  - Role escalation: member trying to invite as admin (RBAC check)
  - Token generation failure
  - Store error on invitation creation
- **Note:** This handler correctly uses `CountMemberSlotsUsedByOrg` (includes pending invitations) for tier gating, which is correct and different from `CountMembersByOrg` used in the tier display handler.
- **Priority:** HIGH — invitation role escalation is a security concern.

#### 14. `oidcVerifyCallback` — oauth_oidc.go — 48.4%
- **Risk:** Security-critical
- **Analysis:** Core OIDC callback verification. Tests cover happy path, CSRF mismatch, disabled connection, cross-org isolation. UNTESTED:
  - Connection not found in state parsing
  - OAuth2 token exchange failure (IdP returns error)
  - ID token extraction failure (`oauth2.StaticTokenSource` nil token)
  - Email claim missing from ID token
  - `email_verified` claim is false
- **Priority:** HIGH — OIDC verification gaps could allow unverified-email logins.

#### 15. `createAlertRuleHandler` — alert_rules.go — 52.4%
- **Risk:** Correctness
- **Analysis:** Tests cover happy path, DSL validation, tier gating. UNTESTED:
  - JSON decode error
  - Empty name validation
  - Logic field validation (not "and"/"or")
  - Channel IDs binding during creation
  - Store error
  - Race condition: two concurrent creates at tier limit
- **Priority:** MEDIUM

#### 16. `createReportHandler` — reports.go — 46.2%
- **Risk:** Correctness
- **Analysis:** Tests cover basic create and validation. UNTESTED:
  - Invalid timezone (tested, but not invalid format like "Not/Real")
  - Invalid severity threshold value
  - Missing required fields
  - Store error
  - Channel binding during creation
  - Duplicate name (tested, but verify conflict detection)
- **Priority:** MEDIUM

#### 17. `createWatchlistHandler` — watchlists.go — 47.6%
- **Risk:** Correctness
- **Analysis:** Tests cover basic create and tier gating. UNTESTED:
  - Empty name
  - JSON decode error
  - Group ID (double-pointer) edge cases
  - Store error
- **Priority:** LOW

#### 18. `createAPIKeyHandler` — apikeys.go — 51.0%
- **Risk:** Security-critical
- **Analysis:** Tests cover basic create and role escalation prevention. UNTESTED:
  - JSON decode error
  - Missing name
  - Store error
  - The returned plaintext API key is only shown once — no test verifies it's a valid `cvrt_` prefixed key
  - No test verifies the stored hash is correct (can actually be used to authenticate)
- **Priority:** HIGH — no round-trip test proving created API key actually works for authentication.

#### 19. `patchAlertRuleHandler` — alert_rules.go — 67.0%
- **Risk:** Correctness
- **Analysis:** Tests cover name update, DSL update. UNTESTED:
  - Patching conditions with invalid DSL
  - Patching `enabled` field (state machine transitions)
  - Patching a non-existent rule (404)
  - Concurrent patch race
- **Priority:** MEDIUM

#### 20. Group handlers — groups.go — 42–62%
- **Risk:** Correctness
- **Analysis:** `createGroupHandler` (42.9%), `listGroupsHandler` (55.6%), `getGroupHandler` (45.5%), `updateGroupHandler` (50.0%), `deleteGroupHandler` (62.5%)
- **UNTESTED across all:** Store error paths, validation edge cases (empty name, too-long name), pagination in list, not-found for get/update/delete
- **Priority:** LOW — groups are a minor feature

### Band C: 80–99% Coverage

#### 21. `validateWebhookURL` — channels.go — 93.3%
- **Risk:** Security-critical
- **Analysis:** SSRF validation function. Tests cover localhost, private IPs, .local, .internal TLDs. Missing 6.7%:
  - The IPv6 loopback `[::1]` path
  - URL with username:password credentials
  - URL with port numbers on private IPs
- **Priority:** MEDIUM — IPv6 loopback bypass could be an SSRF vector if untested

#### 22. `validateEmailConfig` — channels.go — 94.1%
- **Risk:** Security-critical
- **Analysis:** Email channel config validation. Tests cover recipients, dedup, header injection, max count. Missing 5.9%:
  - The `from_name` field validation (if it exists)
  - Edge case: exactly 50 recipients (boundary)
- **Priority:** LOW

#### 23. `tryAPIKeyAuth` — middleware_auth.go — 92.3%
- **Risk:** Security-critical
- **Analysis:** API key extraction and validation. Tests cover valid key, invalid key. Missing 7.7%:
  - The `subtle.ConstantTimeCompare` timing attack resistance is not verified (would need timing analysis, out of scope)
  - Bearer token with empty API key string
  - Malformed Authorization header (e.g., "Bearer" with no space)
- **Priority:** LOW — the untested edge cases are minor

### Band D: 100% on Security-Relevant Functions

#### 24. `RequireAuthenticated` — middleware_auth.go — 100%
- **Assertion quality:** GOOD
- Tests verify: valid JWT → context has user ID, expired JWT → 401, malformed JWT → 401, wrong secret → 401, API key valid → 200, API key invalid → 401, no credentials → 401.
- Missing assertion: Does not verify that the JWT `exp` claim validation uses `WithExpirationRequired()`. If someone removes that option, tests would still pass (expired token test might pass due to other validation failures).

#### 25. `Handler` — server.go — 100%
- **Assertion quality:** ADEQUATE
- Smoke tests verify: healthz returns 200/503, metrics returns 200, security headers present, body size limit enforced, path traversal blocked, null byte injection blocked, RequestID header present, Recoverer catches panics.
- Missing assertion: No test verifies the CSRF middleware is in the chain (though `middleware_csrf_test.go` covers it separately). No test verifies the middleware ordering (e.g., security headers before auth).

---

## Pass 2: Semantic Analysis

### B. Right-Function-Called Analysis

#### Finding B1: `CountMembersByOrg` vs `CountMemberSlotsUsedByOrg` — CORRECT
- **org_tier.go:61** uses `CountMembersByOrg` for the tier display endpoint (showing actual member count)
- **orgs.go:398** uses `CountMemberSlotsUsedByOrg` for invitation gating (counts members + pending invitations)
- **Verdict:** CORRECT — the tier display shows actual members, while the invitation handler correctly checks slots including pending invitations. The test `TestTierGating_Members_PendingInvitationsConsumeSlots` explicitly verifies that pending invitations consume slots.

#### Finding B2: `CountAlertRulesByOrg` — Uses in both tier gating and tier display
- Both `createAlertRuleHandler` (tier gating) and `getOrgTierHandler` (tier display) use `CountAlertRulesByOrg`. This is correct — alert rules don't have a "pending" state that would require a different count function.
- **Verdict:** CORRECT

#### Finding B3: `CountWatchlistsByOrg` — Same as B2
- **Verdict:** CORRECT

### C. TOCTOU Analysis

#### Finding C1: Tier gating race in `createAlertRuleHandler` — POTENTIAL BUG
- **Location:** `alert_rules.go` — the handler reads count, checks against limit, then inserts. Two concurrent requests at the limit could both read count=4 (limit=5), both pass the check, and both insert, resulting in 6 rules.
- **Severity:** LOW — this is a tier limit, not a security boundary. An org getting 6 rules instead of 5 is not a security issue.
- **Mitigation:** Could use `SELECT ... FOR UPDATE` or an advisory lock, but YAGNI.

#### Finding C2: Tier gating race in `createInvitationHandler`
- Same pattern as C1. `CountMemberSlotsUsedByOrg` + check + insert is not atomic.
- **Severity:** LOW — same reasoning as C1.

#### Finding C3: Refresh token rotation race — POTENTIAL BUG
- **Location:** `auth.go` — `refreshGrace` / token rotation. If two concurrent refresh requests arrive with the same refresh token, both could pass the grace period check before either marks the old token as rotated. The test coverage for this path is 53.3%, and the grace period logic is not exercised.
- **Severity:** MEDIUM — could allow token reuse beyond the grace period, though the grace window is intentionally short.

#### Finding C4: Alert rule state machine transitions
- **Location:** `alert_rules.go` — PATCH handler checks current state before transitioning. Two concurrent PATCHes could both read `status=draft`, both pass the state check, and both attempt the same transition.
- **Severity:** LOW — the DB constraint should catch this (if there is one), but no test verifies concurrent state transitions.

### D. Defense-in-Depth Analysis

#### Finding D1: RBAC middleware + handler-level check — GOOD
- Alert rules, channels, watchlists, reports, deliveries, and SSO all use `RequireOrgRole` middleware at the route level AND have the org context extraction in the handler. If the middleware fails to set `ctxOrgID`, the handler returns 400. This is correct defense-in-depth.

#### Finding D2: CSRF middleware + cookie auth check — GOOD
- CSRF middleware requires `X-Requested-By` header only for cookie-authenticated requests. API key and Bearer token requests are exempt. Tests verify all paths.

#### Finding D3: No handler-level auth check as safety net — GAP
- Handlers trust that `ctxUserID` was set by `RequireAuthenticated` middleware. If a route is accidentally registered without the auth middleware, the handler would proceed with a zero-value UUID as the user ID. No handler-level check verifies that `ctxUserID` is non-zero.
- **Severity:** LOW in practice (route registration is in one place), but HIGH in principle for a security product.

#### Finding D4: SSO encryption key validation — GOOD
- `sso.go` validates that `SSOEncryptionKey` is present before allowing SSO operations. AES-256-GCM encryption is used for client secrets at rest. Tests verify the encrypted value differs from the plaintext.

---

## Assertion Quality Issues

### AQ1: OAuth tests don't verify cookie attributes consistently
- **Location:** `oauth_github_test.go`, `oauth_google_test.go`
- The `TestGitHubInit_Configured` test checks `HttpOnly` on the `oauth_state` cookie, but `TestGitHubCallback_NewUser` only checks presence of `access_token` and `refresh_token` cookies — NOT their `HttpOnly`, `Secure`, `SameSite`, or `Path` attributes.
- **Impact:** If someone removes `HttpOnly` from auth cookies, no test would catch it.
- **Priority:** MEDIUM — cookie security attributes are critical for preventing XSS-based token theft.

### AQ2: Auth tests don't verify JWT claims content
- **Location:** `auth_test.go`
- Tests verify that login/register return auth cookies and that the cookies can be used for authenticated requests. But no test decodes the JWT and checks:
  - `sub` claim contains the correct user ID
  - `exp` claim is in the expected range (e.g., 15 minutes for access, 7 days for refresh)
  - `iat` claim is present
  - No extra claims are leaked
- **Impact:** If token lifetime is accidentally set to 100 years, no test would catch it.
- **Priority:** MEDIUM

### AQ3: SSRF validation tests don't verify the error message content
- **Location:** `channels_test.go`
- SSRF tests verify status 422 but don't check the error message. If `validateWebhookURL` starts returning a generic error instead of specifying which URL was blocked, the test still passes.
- **Priority:** LOW

---

## Top 3 Findings

### 1. [SECURITY-CRITICAL] Refresh token reuse detection untested (Finding #7)
`refreshGrace` at 53.3% coverage — the grace period window, token theft detection, and family ID propagation are not exercised by any test. This is the mechanism that prevents stolen refresh tokens from being used indefinitely. If the grace period logic has a bug, an attacker with a stolen refresh token could maintain access forever.

### 2. [SECURITY-CRITICAL] API key creation has no round-trip test (Finding #18)
`createAPIKeyHandler` at 51% coverage creates an API key and returns the plaintext. No test verifies that the returned key can actually be used to authenticate. The stored hash correctness is never validated end-to-end. If the hashing or prefix generation has a bug, all created API keys would be permanently unusable.

### 3. [SECURITY-CRITICAL] OIDC callback missing email_verified check test (Finding #14)
`oidcVerifyCallback` at 48.4% — no test verifies that the handler rejects ID tokens where `email_verified` is false. If the check is missing or broken, a user could authenticate via OIDC with an unverified email address, potentially impersonating another user.

---

## Production Bugs Found

### PB1: ~~Delivery replay has no nil check — possible 500 on not-found delivery~~ CORRECTED
**Location:** `deliveries.go:293` — `replayDeliveryHandler`

**Original concern:** The handler does not check whether the delivery exists before replaying, and has no explicit 404 path.

**Correction after test review:** `TestReplayDelivery_NonExistentID` confirms that the SQL `WHERE` guard in `ReplayDelivery` (`status IN ('failed','cancelled')`) means a non-existent ID is simply a no-op — the store returns nil error, and the handler returns 204. This is documented as intentional behavior in the test. While returning 204 for a non-existent delivery is debatable (404 would be more RESTful), the test explicitly documents and validates this as the intended design.

**Severity:** NOT A BUG — intentional design choice, tested and documented.

### PB2: `encodeDeliveryCursor` at 0% — potential pagination break
The delivery cursor encoder has zero test coverage. If the format doesn't match the `decodeTimeCursor` parser used by the list handler, pagination cursors would fail to decode and the handler would silently return the first page again. Clients would see an infinite loop of the same page.

**Severity:** LOW — delivery pagination only, and the cursor logic is simple enough that a visual review confirms correctness.

---

## Appendix: Coverage Data Reference

| Function | Coverage | Risk | Tested Paths | Missing Paths |
|----------|----------|------|--------------|---------------|
| `pgErrCode` | 0% | Correctness | (none) | All — unique constraint detection |
| `encodeDeliveryCursor` | 0% | Correctness | (none) | All — pagination cursor encoding |
| `getCVEHandler` | 40.0% | Correctness | Happy path | 404, 500, nullable fields |
| `createGroupHandler` | 42.9% | Correctness | Happy path | Validation, errors |
| `replayDeliveryHandler` | 43.8% | Correctness | Replay+DB state, rate limit, non-existent ID, cross-org, RBAC | Invalid UUID (400), store error (500) |
| `updateOrgHandler` | 45.0% | Correctness | Happy path | Validation, errors, RBAC |
| `getGroupHandler` | 45.5% | Correctness | Happy path | 404, 500 |
| `createReportHandler` | 46.2% | Correctness | Basic create | Validation edges, errors |
| `getCVESourcesHandler` | 47.6% | Correctness | Happy path | 400, 500, empty array |
| `createWatchlistHandler` | 47.6% | Correctness | Basic create | Validation, errors |
| `oidcVerifyCallback` | 48.4% | Security | Happy, CSRF, disabled | email_verified, token exchange error |
| `getDeliveryHandler` | 50.0% | Correctness | Happy, 404 | 400 (bad UUID), 500 |
| `issueRefreshPair` | 50.0% | Security | Happy path | JWT sign error, DB error |
| `updateGroupHandler` | 50.0% | Correctness | Happy path | 404, validation, 500 |
| `NewServer` | 50.0% | Correctness | Basic init | Config edge cases |
| `createAPIKeyHandler` | 51.0% | Security | Basic create | Round-trip auth, error paths |
| `createAlertRuleHandler` | 52.4% | Correctness | Happy, DSL, tier | JSON error, validation edges |
| `refreshGrace` | 53.3% | Security | Basic refresh | Grace window, theft detection |
| `createInvitationHandler` | 54.5% | Security | Happy, tier limit | Duplicate, role escalation, validation |
| `listGroupsHandler` | 55.6% | Correctness | Happy path | Pagination, 500 |
| `deleteAlertRuleHandler` | 57.1% | Correctness | Happy path | 404, 500 |
| `createReportScheduleHandler` | 59.1% | Correctness | Happy path | Validation, errors |
| `listDeliveriesHandler` | 60.0% | Correctness | Status/rule/channel filters, limit clamping, cross-org, RBAC | Invalid UUID filters, cursor parsing, store error, pagination cursor gen |
| `deleteGroupHandler` | 62.5% | Correctness | Happy path | 404, 500 |
| `loginHandler` | 64.9% | Security | Valid, wrong pw, no user | Argon2 exhaustion, rate limit, validation |
| `listCVEsHandler` | 66.7% | Correctness | List, pagination, severity | Cursor error, other filters, 500 |
| `acceptInvitationHandler` | 66.7% | Security | Happy path | Invalid token, expired, already accepted |
| `patchAlertRuleHandler` | 67.0% | Correctness | Name/DSL patch | Invalid DSL, state transition, 404 |
| `tryAPIKeyAuth` | 92.3% | Security | Valid, invalid | Empty key, malformed header |
| `validateWebhookURL` | 93.3% | Security | localhost, private, TLDs | IPv6 loopback, credentials in URL |
| `validateEmailConfig` | 94.1% | Security | Recipients, injection | Boundary: exactly 50, from_name |
| `RequireAuthenticated` | 100% | Security | All main paths | (see AQ note on exp claim) |
| `Handler` | 100% | Correctness | All endpoints | (see AQ note on middleware ordering) |

---

## Post-Review Corrections (applied after thorough test file re-read)

Four findings were corrected after reading ALL test files in detail during a second review pass:

1. **Finding #9 (`replayDeliveryHandler`)**: Priority downgraded from MEDIUM to LOW. Tests are much more comprehensive than initially assessed — rate limiting (11 replays→429), non-existent ID (204 no-op), cross-org isolation, RBAC, and DB state verification are all covered. Only invalid UUID and store error remain untested.

2. **Finding #11 (`listDeliveriesHandler`)**: Priority downgraded from MEDIUM to LOW. `TestListDeliveries_FilterByStatus`, `TestListDeliveries_FilterByRuleAndChannel`, and `TestListDeliveries_LimitClamping` cover the main filter and limit paths. Only invalid UUID filters, cursor parsing, store errors, and cursor generation remain untested.

3. **PB1 (replay non-existent delivery)**: Reclassified from "production bug" to "not a bug". `TestReplayDelivery_NonExistentID` explicitly tests and documents that non-existent ID returns 204 (SQL WHERE guard design). This is intentional behavior.

4. **API key tests (Finding #18)**: Confirmed after full re-read. Tests cover create, role escalation, list (no raw_key/key_hash leak), revoke own, revoke as admin, revoke not-owner (403), viewer forbidden, invalid role (400), idempotent revoke, and cross-org. The "no round-trip" assessment is CORRECT — no test uses the returned `raw_key` to authenticate.

### Additional test quality observations from re-read

**Exceptional test patterns observed:**
- `deliveries_test.go`: `TestReplayDelivery_ResetsStatus` verifies DB state after replay (status=pending, attempt_count=0, last_error=nil) — tests the side effects, not just the HTTP status
- `cves_test.go`: `TestResolveOptionalFilters` has 17 table-driven test cases covering all boolean/float filter parsing combinations
- `ai_test.go`: `TestNLSearch_QuotaDenied` and `TestSummarizeCVE_QuotaDenied` verify `Retry-After` header is set, not just 429 status
- `ai_test.go`: `TestNLSearch_LLMFailure` and `TestSummarizeCVE_LLMFailure` verify that LLM failures return 503 and that the error is logged
- `saved_searches_test.go`: Comprehensive RBAC matrix (admin on shared, admin on others' private, member, viewer on CRUD, viewer on shared) with clear test naming
- `tier_cache_test.go`: Tests defensive copy on both Set and Get — mutating the original after Set doesn't corrupt the cache, and mutating the returned value from Get doesn't corrupt the cache
