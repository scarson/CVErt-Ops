# Phase 5 Test Coverage Review (Coverage-Tool-Guided)

**Date:** 2026-03-03
**Method:** `go test -coverprofile` + `go tool cover -func` → LLM-guided semantic analysis
**Scope:** `./internal/api/...`, `./internal/store/...`, `./internal/tier/...`
**coverpkg:** Same three packages (cross-package coverage captured)

## Test Environment Notes

- One pre-existing test failure: `TestWithBypassTx_SetsSessionVar` — RLS permission denied on `job_queue` table. Coverage data still generated (partial coverage from store tests).
- All other tests pass. Coverage profile is complete.

---

## Coverage Baseline

| Package | Functions | 0% | <80% | 80–99% | 100% | Avg Coverage |
|---------|----------:|---:|-----:|-------:|-----:|-------------:|
| internal/api | 181 | 3 | 105 | 21 | 52 | 73.4% |
| internal/store | 188 | 1 | 41 | 101 | 45 | 86.3% |
| internal/store/generated | 186 | 23 | 43 | 0 | 120 | 81.5% |
| internal/tier | 4 | 0 | 0 | 0 | 4 | 100.0% |
| **Overall** | **559** | **27** | **189** | **122** | **221** | **72.8%** |

**Phase 5 files specifically:**

| Scope | Functions | Avg Coverage |
|-------|----------:|-------------:|
| Phase 5 API files (org_tier, oauth_oidc, middleware_tier, orgs, sso, audit_log, tier_cache) | 38 | 72.6% |
| Phase 5 Store files (org, audit, sso, retention, store) | 56 | 86.1% |
| Phase 5 Tier files (limits, resolver) | 4 | 100.0% |

---

## Gap Context

| Category | Files | Gaps | Action |
|----------|------:|-----:|--------|
| Security-critical | 8 | 19 | Must fix — auth/tenant/crypto paths |
| Correctness | 12 | 73 | Should fix — business logic, error propagation |
| Nice-to-have | 15 | 42 | Skip for now — DB error wrapping, unlikely failures |
| Assertion quality | 3 | 3 | Strengthen existing tests |
| **Total** | | **137** | |

---

## What's Well-Covered

- **Tier resolver (`internal/tier/`)**: 100% coverage with thorough table-driven tests covering all three tiers, unknown-tier fallback, override precedence, zero-value overrides, wrong-key ignoring, wrong-type ignoring. The path-mapping review's claim of "100% gap rate, no test file" was incorrect — `resolver_test.go` exists and is comprehensive. `limits.go` functions (`ResolveInt`/`ResolveBool`) are one-line delegations covered by cross-package tests via `-coverpkg`.

- **Audit log endpoint (`audit_log.go` at 88.6%)**: Thorough RBAC tests (owner=200, admin=200, member=403, viewer=403), enterprise tier gating (free=403, pro=403, enterprise=200), cross-org isolation, keyset pagination with overlap detection, combined filter combinations, invalid parameter handling. All assertions check behavior, not just execution.

- **Tier cache (`tier_cache.go`)**: 100% coverage with strong assertion quality. Tests verify defensive copying on both Set and Get, TTL expiration at boundary (29s vs 31s), and invalidation semantics.

- **RLS fail-closed guarantees (`org_tx_test.go`)**: Tests verify 0 rows returned when no `app.org_id` is set on the app-role connection, covering `org_members`, `org_invitations`, `api_keys`, `groups`, `group_members`. Critical security invariants tested against real RLS policies.

- **OIDC login flow**: Despite per-function coverage being moderate, tested paths are high-quality integration tests. `TestOIDCFlow_Success` is end-to-end: init redirect → extract cookies → callback with state+nonce → verify JWT cookies → verify user_id. Cross-org isolation test proves same IdP `sub` scoped to different connections cannot cross-authenticate.

- **Retention cleanup**: All 10 cleanup functions covered with proper cutoff boundary verification, org filtering, batch size limits, and status filtering.

---

## Security-Critical Gaps (19)

### OIDC Callback Verification (10 gaps)

`oidcVerifyCallback` at 48.4% is the highest-risk gap. Only the CSRF-mismatch path (via `validateStateCookie`) and the success path are covered. Each untested branch is a distinct attack surface:

1. Malformed state string (no underscore separator) — `oauth_oidc.go:114`
2. Invalid UUID in state's connection_id — `oauth_oidc.go:119`
3. SSO connection not found in DB — `oauth_oidc.go:132`
4. SSO connection disabled — `oauth_oidc.go:136`
5. OAuth token exchange failure — `oauth_oidc.go:151`
6. Missing `id_token` in token response — `oauth_oidc.go:159`
7. ID token verification failure (signature, expiry, issuer) — `oauth_oidc.go:166`
8. Empty `sub` claim in verified token — `oauth_oidc.go:180`
9. Nonce cookie validation error — `oauth_oidc.go:187`
10. Nonce mismatch (cookie present, valid, but doesn't match token) — `oauth_oidc.go:191`

**Note:** The existing CSRF test (`TestOIDCFlow_CSRFMismatch`) only tests a missing cookie — it does not test a well-formed-but-tampered state value where the cookie is present but doesn't match.

### Tier Middleware Passthrough (1 gap)

11. `tierMiddleware` silently passes through without setting `ctxTierResolver` when `ctxOrgID` is absent — `middleware_tier.go:22`. Any downstream handler that accesses the resolver without checking `ok` would panic. Defended by comment ("should not happen after RequireOrgRole") but no test proves the passthrough is safe — `middleware_tier.go:22`

### Org Handler Auth/Isolation (3 gaps)

12. `createOrgHandler` missing `ctxUserID` returns 401 — untested — `orgs.go:56`
13. `updateOrgHandler` has no cross-org isolation test (user B PATCHing org A) — `orgs.go` (general)
14. `createInvitationHandler` performs no email format validation (`req.Email == ""` check only, no `@` or domain validation) — `orgs.go:377`. The `discoverHandler` in `sso.go:521` validates `@` presence, showing the codebase already has this pattern. This is both a test gap and a code gap.

### SSO Encryption Key Validation (1 gap)

15. `ssoEncryptionKey` wrong key length (not 32 bytes) path — untested — `sso.go:76`

### Store Invitation Acceptance (3 gaps)

16. `AcceptOrgInvitation` atomicity on `CreateOrgMember` failure — if member creation fails after entering the bypass tx, rollback is unverified — `store/org.go:290`
17. `AcceptOrgInvitation` atomicity on `AcceptInvitation` failure — if invitation marking fails after member creation, rollback is unverified — `store/org.go:297`
18. `AcceptInvitation` (standalone method, `store/org.go:302`) operates outside RLS — calls `s.q` directly with no transaction helper. On the app-role connection, the `UPDATE org_invitations` would silently affect 0 rows due to RLS. Currently production uses `AcceptOrgInvitation` (which correctly uses `withBypassTx`), but this method is exported and callable.

### Phantom File Note

19. The path-mapping review flagged `internal/api/writer.go` (audit log writer, URL redaction) — **no such file exists**. The `writeJSON` helper lives in `orgs.go:44`. This is a false positive from the path-mapping approach.

---

## Correctness Gaps (73)

### `internal/api/org_tier.go` (getOrgTierHandler at 61.8%) — 6 gaps

20. Missing `ctxOrgID` from context (bad request branch) — `org_tier.go:29`
21. Missing `ctxTierResolver` from context (500 branch) — `org_tier.go:35`
22. `CountAlertRulesByOrg` returns error — `org_tier.go:50`
23. `CountWatchlistsByOrg` returns error — `org_tier.go:56`
24. `CountMembersByOrg` returns error — `org_tier.go:62`
25. No test verifies watchlist/member count `used` field values (always 0 in test) — `org_tier.go` (general)

### `internal/api/oauth_oidc.go` — 10 gaps

26. `getOIDCProvider` cache miss hitting `oidc.NewProvider` error — `oauth_oidc.go:33`
27. `oidcBuildOAuthConfig` → `ssoEncryptionKey()` error — `oauth_oidc.go:52`
28. `oidcBuildOAuthConfig` → `crypto.Decrypt` error — `oauth_oidc.go:55`
29. `oidcInitRedirect` → `oidcBuildOAuthConfig` error — `oauth_oidc.go:74`
30. `oidcVerifyCallback` → `GetSSOConnectionByID` DB error — `oauth_oidc.go:127`
31. `oidcVerifyCallback` → claims extraction error — `oauth_oidc.go:175`
32. `oidcLoginHandler` → `GetSSOConnectionByID` DB error — `oauth_oidc.go:213`
33. `oidcCallbackHandler` → `GetUserByProviderID` DB error — `oauth_oidc.go:245`
34. `oidcCallbackHandler` → `IssueAccessToken`/`IssueRefreshToken`/`CreateRefreshToken` errors — `oauth_oidc.go:259-274`
35. `oidcLinkCallbackHandler` → `UpsertUserIdentity` DB error — `oauth_oidc.go:348`

### `internal/api/orgs.go` — 25 gaps

36. `createOrgHandler` invalid JSON body — `orgs.go:62`
37. `createOrgHandler` empty name — `orgs.go:66`
38. `createOrgHandler` store error — `orgs.go:72`
39. `getOrgHandler` missing ctxOrgID — `orgs.go:88`
40. `getOrgHandler` store error — `orgs.go:94`
41. `getOrgHandler` not found — `orgs.go:99`
42. `updateOrgHandler` missing ctxOrgID — `orgs.go:115`
43. `updateOrgHandler` invalid JSON — `orgs.go:121`
44. `updateOrgHandler` empty name — `orgs.go:125`
45. `updateOrgHandler` store error — `orgs.go:131`
46. `updateOrgHandler` not found — `orgs.go:136`
47. `listMembersHandler` missing ctxOrgID — `orgs.go:174`
48. `listMembersHandler` store error — `orgs.go:180`
49. `updateMemberRoleHandler` missing ctxRole — `orgs.go:209`
50. `updateMemberRoleHandler` invalid user_id UUID — `orgs.go:216`
51. `updateMemberRoleHandler` invalid JSON — `orgs.go:222`
52. `updateMemberRoleHandler` target not in org — `orgs.go:251`
53. `updateMemberRoleHandler` store error — `orgs.go:260`
54. `removeMemberHandler` missing ctxOrgID — `orgs.go:285`
55. `removeMemberHandler` invalid UUID — `orgs.go:291`
56. `removeMemberHandler` store errors — `orgs.go:298,311,323`
57. `createInvitationHandler` multiple untested branches (missing ctxOrgID/ctxUserID, invalid JSON, empty email, store errors) — `orgs.go:362-434`
58. `listInvitationsHandler` missing ctxOrgID + store error — `orgs.go:450-458`
59. `cancelInvitationHandler` missing ctxOrgID, invalid UUID, store error — `orgs.go:479-494`
60. `cancelInvitationHandler` no existence check (silent 204 on nonexistent invitation) — `orgs.go` (general)

### `internal/api/sso.go` — 16 gaps

61. `ssoEncryptionKey` invalid hex string — `sso.go:73`
62. `requireEnterpriseTier` missing tier resolver — `sso.go:87`
63. `createSSOHandler` missing ctxOrgID — `sso.go:104`
64. `createSSOHandler` encryption errors — `sso.go:136-145`
65. `createSSOHandler` non-unique-violation DB error — `sso.go:163`
66. `getSSOHandler` missing ctxOrgID + store errors — `sso.go:204-228`
67. `patchSSOHandler` missing ctxOrgID — `sso.go:254`
68. `patchSSOHandler` store errors (read, encrypt, update, re-read) — `sso.go:264-341`
69. `patchSSOHandler` invalid JSON — `sso.go:275`
70. `deleteSSOHandler` missing ctxOrgID + store errors — `sso.go:389-407`
71. `putSSODomainsHandler` missing ctxOrgID + store errors — `sso.go:429-467`
72. `putSSODomainsHandler` invalid JSON — `sso.go:449`
73. `discoverHandler` store error — `sso.go:529`

### `internal/store/org.go` — 7 gaps

74. `CreateOrgWithOwner` → `CreateOrgMember` failure within bypass tx (rollback unverified) — `store/org.go:49`
75. `BootstrapFirstUserOrg` → `CreateOrg` failure within tx — `store/org.go:104`
76. `BootstrapFirstUserOrg` → `CreateOrgMember` failure within tx (partial state rollback unverified) — `store/org.go:109`
77. `GetOrgTier` → `json.Unmarshal` error for malformed `tier_overrides` — `store/org.go:355`
78. `ListAllOrgs` → `json.Unmarshal` error for per-org `tier_overrides` — `store/org.go:389`
79. `SetSSOEmailDomains` → per-domain `UpsertSSOEmailDomain` internal DB error — `store/sso.go:97`
80. `fromNullUUID` → `!v.Valid` branch returning nil for NULL actor_id — never exercised through `ListAuditEntries` — `store/audit.go:144`

### `internal/api/middleware_tier.go` — 1 gap

81. `orgRateLimitMiddleware` no orgID passthrough — `middleware_tier.go:53`

### `internal/api/audit_log.go` — 2 gaps

82. `listAuditLogHandler` missing ctxOrgID — `audit_log.go:42`
83. `listAuditLogHandler` missing ctxTierResolver — `audit_log.go:49`

### `internal/store/store.go` — 4 gaps

84. `withBypassTx` panic recovery path — `store/store.go:56`
85. `withOrgRawTx` panic recovery path — `store/store.go:83`
86. `withOrgRawTx` → `fn` error triggering rollback (tested indirectly via `withOrgTx`) — `store/store.go:93`
87. `InsertAuditEntry` at 100% but no nullable-field round-trip (OldState, NewState, Metadata all nil in tests) — `store/audit.go:64`

### Other partially-covered functions — 5 gaps

88. `oidcInitRedirect` → `generateOAuthState` error for state — `oauth_oidc.go:82`
89. `oidcInitRedirect` → `generateOAuthState` error for nonce — `oauth_oidc.go:89`
90. `oidcLinkInitHandler` → `GetSSOConnection` DB error — `oauth_oidc.go:292`
91. `oidcLinkCallbackHandler` → `GetUserByProviderID` DB error — `oauth_oidc.go:337`
92. `removeMemberHandler` target not in org — `orgs.go:304`

---

## Nice-to-Have (42)

Mostly DB error wrapping paths (`if err != nil { return fmt.Errorf(...) }`) and unlikely runtime failures.

### Store DB error branches (37 gaps)

Functions at 75–87.5% where the only untested path is the generic DB error return. These follow an identical pattern across ~37 functions in `org.go`, `audit.go`, `sso.go`, `retention.go`, and `store.go`. Each individually wraps the error with context and returns. Representative examples:

- `store/org.go:CreateOrg` 75.0% — DB error on `s.q.CreateOrg`
- `store/org.go:GetOrgByID` 83.3% — DB error after ErrNoRows check
- `store/retention.go:CleanupCveRawPayloads` 87.5% — DB error within bypass tx
- (35 more following the same pattern)

### API nice-to-have (5 gaps)

93. `writeJSON` → `json.Encode` error — `orgs.go:48`
94. `oidcInitRedirect` → `generateOAuthState` random failure — `oauth_oidc.go:82,89`
95. `createInvitationHandler` → `rand.Read` error — `orgs.go:422`
96. `evictExpired` → empty loop body (no entries older than evictTTL) — `tier_cache.go:102`

---

## Assertion Quality Issues (3)

1. **`TestTierMiddleware_ResolverHasCorrectTier` conditional assertion** — `middleware_tier_test.go`. Test has `if resp.StatusCode == http.StatusOK { ... }`. If the tier endpoint returns anything other than 200, the test silently passes without checking the resolver. The comment says "This will be 404 until the tier endpoint is registered" — but the endpoint is now implemented and returns 200. The conditional should be converted to a hard assertion.

2. **`InsertAuditEntry` at 100% but shallow on nullable fields** — `store/audit.go:64`. All test entries use non-nil `ActorID` and nil `OldState`/`NewState`/`Metadata`. The `fromNullUUID` null branch and JSONB round-trip are never exercised through `ListAuditEntries`.

3. **OIDC CSRF test only checks missing cookie, not tampered value** — `oauth_oidc_test.go`. `TestOIDCFlow_CSRFMismatch` tests a missing cookie entirely — it does not test a well-formed-but-tampered state value where the cookie is present but doesn't match. This means the `validateStateCookie` comparison logic gets coverage from the success path but the mismatch-rejection path is only tested via absence, not a wrong value.

---

## Key Observations

### 1. `oidcVerifyCallback` is the single highest-risk function

At 48.4% coverage with 10 security-critical untested branches, this function handles the most sensitive part of the OIDC flow — validating the callback from the identity provider. The mock OIDC infrastructure in `oauth_oidc_test.go` already supports testing these paths (mock IdP, `SetNonce`, state manipulation). Priority 1 for remediation.

### 2. Systematic pattern: store error branches are universally untested

~40 of the 73 correctness gaps are store-error branches (`if err != nil { ... 500 ... return }`). These follow an identical pattern. Since tests use real Postgres via testcontainers, injecting store errors requires either a mock store layer or a pgx interceptor. Low individual risk but the largest gap by count.

### 3. `AcceptInvitation` standalone method bypasses RLS

The exported `AcceptInvitation` method at `store/org.go:302` calls `s.q` directly, bypassing all transaction helpers. Production code uses `AcceptOrgInvitation` (which correctly uses `withBypassTx`), but the standalone method is exported and callable. On the app-role connection, the `UPDATE` would silently affect 0 rows due to RLS. Should either be wrapped in `withBypassTx` or unexported.

### 4. Coverage ≠ confidence mismatch in `orgs.go`

Most org handlers are in the 45–62% range. The tested paths are all success paths with valid inputs. Error handling, input validation, and many RBAC boundary conditions are not tested. The tests verify "happy path works" but not "unhappy paths fail correctly."

### 5. Path-mapping review generated a phantom file

The path-mapping review flagged `internal/api/writer.go` as a highest-risk file with "audit log writer, URL redaction" — no such file exists. The `writeJSON` helper lives in `orgs.go:44` and is a 7-line JSON encoder. This demonstrates a structural limitation of path-mapping: it can hallucinate file organization.

### 6. Path-mapping review incorrectly flagged tier package

The path-mapping review reported `internal/tier/limits.go` as having "100% gap rate, no test file." In reality: `resolver_test.go` exists with comprehensive tests, and `limits.go` functions show 100% coverage via cross-package tests. The `-coverpkg` flag surfaces this cross-package coverage that path-mapping cannot detect.

### 7. Transaction helper panic recovery paths untested

Both `withBypassTx` and `withOrgRawTx` contain `defer` blocks that recover panics, rollback the transaction, and re-panic. These paths (4 gaps) are never exercised. While unlikely to fire in production, they are correctness-critical for preventing connection pool leaks.

### 8. `createInvitationHandler` has a code gap, not just a test gap

The handler checks `req.Email == ""` but performs no email format validation (no `@` check, no domain validation). The `discoverHandler` in `sso.go:521` validates `@` presence, showing the pattern exists in the codebase. An invitation to `"notanemail"` would succeed and persist. This is both a data quality issue and a potential security concern.

### 9. No TOCTOU windows detected

`BootstrapFirstUserOrg` correctly uses `pg_advisory_xact_lock` to serialize concurrent bootstrap attempts. SSO email domain uniqueness is enforced at the database level. `AcceptOrgInvitation` is atomic within a single transaction.

### 10. Pre-existing test failure

`TestWithBypassTx_SetsSessionVar` fails with `ERROR: permission denied for table job_queue (SQLSTATE 42501)`. This is an RLS configuration issue — the bypass tx test is trying to call `HasPendingOrRunningJob` but the app role lacks permission on `job_queue`. Unrelated to Phase 5 but should be fixed.

---

## Summary Statistics

| Metric | Value |
|--------|------:|
| Overall coverage (all coverpkg) | 72.8% |
| Phase 5 API files avg | 72.6% |
| Phase 5 Store files avg | 86.1% |
| Phase 5 Tier files avg | 100.0% |
| Total gaps found | 137 |
| Security-critical | 19 |
| Correctness | 73 |
| Nice-to-have | 42 |
| Assertion quality issues | 3 |
| Functions at 0% (in scope) | 27 |
| Functions at 100% (in scope) | 221 |
