# Phase 8 Coverage-Guided Triage: internal/store + internal/api

Date: 2026-03-18
Scope: internal/store (561 functions) + internal/api (308 functions)
Phase: 8 (Operational Maturity)

---

## Coverage Baseline

| Package | Approx Functions | 0% Coverage | 1-79% | 80-99% | 100% |
|---------|-----------------|-------------|-------|--------|------|
| internal/api (handlers + middleware) | ~170 non-spec | 19 | ~80 | ~30 | ~41 |
| internal/store (non-generated) | ~200 | 15 | ~70 | ~60 | ~55 |
| internal/store/generated | ~160 | 17 | ~45 (73.3%) | 0 | ~98 |

---

## SECURITY-CRITICAL: 0% Coverage Functions

### API Handlers (admin endpoints)

These are **site admin** endpoints -- they manage users, orgs, and system state across all tenants. Zero test coverage on admin operations is a security gap.

| # | Function | File | Risk | Detail |
|---|----------|------|------|--------|
| S1 | adminListUsersHandler | api/admin_users.go:25 | security-critical | Lists ALL users cross-org. No test for auth/site-admin enforcement, cursor injection, or data leakage. |
| S2 | adminDisableUserHandler | api/admin_users.go:66 | security-critical | Disables user accounts. No test for: (a) self-disable prevention, (b) auth enforcement, (c) security event emission, (d) idempotency on already-disabled. |
| S3 | adminEnableUserHandler | api/admin_users.go:124 | security-critical | Re-enables disabled accounts. No test verifying auth or that non-admins cannot re-enable. |
| S4 | adminUnlockUserHandler | api/admin_users.go:154 | security-critical | Clears login lockout. No test that non-admins cannot unlock accounts. Security event emission untested. |
| S5 | adminResetPasswordHandler | api/admin_users.go:195 | security-critical | Forces password reset. No test for auth enforcement or idempotency. |
| S6 | adminOrgUsageHandler | api/admin_orgs.go:148 | correctness | Returns org resource counts. No auth/RBAC test. |
| S7 | adminReindexHandler | api/admin_system.go:17 | correctness | Triggers search reindex job. No auth test. |
| S8 | adminConfigHandler | api/admin_system.go:34 | security-critical | Exposes runtime config with redacted secrets. No test verifying secrets ARE actually redacted. A broken redactSecret leaks JWT_SECRET, DATABASE_URL, etc. |
| S9 | adminAuditLogHandler | api/admin_system.go:110 | security-critical | Cross-org audit log. No test for auth enforcement or filter injection. |
| S10 | redactSecret | api/admin_system.go:178 | security-critical | Helper for secret masking. If broken, adminConfigHandler leaks all secrets. |
| S11 | adminListDeliveriesHandler | api/admin_deliveries.go:25 | correctness | Cross-org delivery listing. |
| S12 | adminRetryDeliveryHandler | api/admin_deliveries.go:75 | correctness | Single delivery retry. |
| S13 | pauseFeedHandler | api/feeds.go:113 | correctness | Pauses feed ingestion. No auth test. |
| S14 | resumeFeedHandler | api/feeds.go:127 | correctness | Resumes feed. |
| S15 | feedLogsHandler | api/feeds.go:147 | correctness | Paginated feed logs. |
| S16 | AddHealthCheck | api/server.go:465 | nice-to-have | Registration helper, 1 line. |

### Store Methods

| # | Function | File | Risk | Detail |
|---|----------|------|------|--------|
| S17 | AdminListUsers | store/admin_user.go:32 | security-critical | Dynamic squirrel query listing ALL users. No test for pagination correctness, SQL injection via cursor values, or correct withBypassRawTx usage. |
| S18 | AdminGetUserByID | store/admin_user.go:94 | correctness | Simple bypass-tx wrapper. |
| S19 | AdminEnableUser | store/admin_user.go:122 | security-critical | Clears disabled_at. No test verifying bypass-tx or not-found behavior. |
| S20 | AdminUnlockUser | store/admin_user.go:136 | security-critical | Clears locked_at + failed_login_count. Untested. |
| S21 | AdminUpdateOrgTier | store/admin_org.go:163 | correctness | Tier change. |
| S22 | AdminSuspendOrg | store/admin_org.go:180 | security-critical | Suspends an organization. |
| S23 | AdminUnsuspendOrg | store/admin_org.go:194 | security-critical | Unsuspends an organization. |
| S24 | AdminGetOrgUsage | store/admin_org.go:216 | correctness | Resource counting. |
| S25 | AdminListDeliveries | store/admin_delivery.go:36 | correctness | Cross-org delivery query. |
| S26 | AdminGetDeliveryByID | store/admin_delivery.go:97 | correctness | Single delivery fetch. |
| S27 | AdminRetryDelivery | store/admin_delivery.go:111 | correctness | Retry a failed delivery. |
| S28 | AdminListAuditEntries | store/admin_system.go:29 | security-critical | Cross-org audit log query with multiple optional filters. Untested SQL filter logic. |
| S29 | GetCVEMaterialHash | store/cve.go:32 | correctness | Uses s.db directly (bypasses RLS) -- acceptable since CVEs are global, but pattern is notable. |
| S30 | ListCVEs (store wrapper) | store/cve.go:78 | correctness | Thin wrapper, 6 lines. |
| S31 | PauseFeed | store/feed.go:201 | correctness | Feed management. |
| S32 | ResumeFeed | store/feed.go:208 | correctness | Feed management. |
| S33 | ListFeedFetchLogsPaginated | store/feed.go:215 | correctness | Paginated feed logs. |
| S34 | LookupAPIKeyByHash | store/apikey.go:112 | security-critical | Returns key regardless of revocation status -- used for security event logging of revoked-key usage. If this function has a bug, security event logging for revoked key attempts is broken. |

### Generated Store (0%)

| # | Function | File | Risk |
|---|----------|------|------|
| S35 | AdminGetDeliveryByID (generated) | generated/admin_deliveries.sql.go:63 | correctness |
| S36 | AdminRetryDelivery (generated) | generated/admin_deliveries.sql.go:96 | correctness |
| S37-S40 | AdminCountOrg{AlertRules,Channels,Members,Watchlists} | generated/admin_orgs.sql.go | correctness |
| S41-S43 | AdminSuspendOrg, AdminUnsuspendOrg, AdminUpdateOrgTier (generated) | generated/admin_orgs.sql.go | security-critical |
| S44 | AdminListAuditEntries (generated) | generated/admin_system.sql.go:43 | security-critical |
| S45-S47 | AdminEnableUser, AdminGetUserByID, AdminUnlockUser (generated) | generated/admin_users.sql.go | security-critical |
| S48 | ListFeedFetchLogs (generated) | generated/feed.sql.go:94 | correctness |
| S49-S50 | PauseFeed, ResumeFeed (generated) | generated/feed.sql.go | correctness |
| S51 | GetActiveEmailOTPChallenge (generated) | generated/mfa.sql.go:289 | correctness |
| S52 | GetUnusedRecoveryCodeByHash (generated) | generated/mfa.sql.go:481 | security-critical |
| S53 | ListSecurityEvents (generated) | generated/security_events.sql.go:70 | security-critical |
| S54 | InsertAffectedCPE (generated) | generated/cves.sql.go:377 | nice-to-have |
| S55 | UpsertEPSSStaging (generated) | generated/cves.sql.go:725 | correctness |
| S56 | ListCVEs (generated) | generated/cves.sql.go:470 | correctness |
| S57 | GetWatchlistItem (generated) | generated/watchlist.sql.go:167 | correctness |
| S58 | Scan (NullAlertRuleStatus) | generated/models.go:43 | nice-to-have |
| S59 | Value (NullAlertRuleStatus) | generated/models.go:53 | nice-to-have |

---

## SECURITY-CRITICAL: Partially Covered Functions

### API Handlers

| # | Function | Coverage | Likely Uncovered Branches | Severity |
|---|----------|----------|--------------------------|----------|
| P1 | adminResetMFAHandler | 53.8% | Error branches: ResetUserMFA failure, missing orgID/role context, security event nil check. RBAC enforcement paths (checkAdminMFAPermission denial). | security-critical |
| P2 | adminForcePasswordResetHandler | 44.2% | OAuth-only user rejection, GetUserByID failure, IncrementTokenVersion failure, DeleteRememberDeviceTokens failure. Over half the handler untested. | security-critical |
| P3 | adminRequireMFAHandler | 61.5% | CreateMFARequirement error, self-targeting rejection. | security-critical |
| P4 | adminUnrequireMFAHandler | 57.7% | DeleteMFARequirement error, self-targeting rejection. | security-critical |
| P5 | adminUpdateOrgMFASettingsHandler | 57.4% | Validation for mfa_remember_device_days range, org not found, security event for mfa_required_all toggle. | security-critical |
| P6 | checkAdminMFAPermission | 59.1% | Site admin bypass path, admin-targets-member path, permission denied path. **RBAC hierarchy enforcement is partially untested.** | security-critical |
| P7 | adminListOrgsHandler | 43.3% | Cursor pagination, DB error. | correctness |
| P8 | adminPatchOrgHandler | 43.3% | Tier validation, deleted org check, suspend/unsuspend. | security-critical |
| P9 | adminBulkRetryDeliveriesHandler | 50.0% | DB error path, security event emission. | correctness |
| P10 | adminSecurityEventsHandler | 55.6% | Date range parsing errors, cursor parsing, since/until filter paths. | correctness |
| P11 | adminReloadConfigHandler | 72.2% | Config holder nil, reload failure detection (old == new pointer check). | security-critical |
| P12 | loginHandler | 71.5% | Multi-step login is complex; uncovered branches likely include: disabled_at check, force_password_reset check, lockout check, MFA-required redirect. | security-critical |
| P13 | changePasswordHandler | 69.0% | Error paths in multi-step flow: token version stale, restricted session completion. | security-critical |
| P14 | mfaChallengeHandler | 60.9% | Email OTP send failure, challenge creation error paths, remember-device token check. | security-critical |
| P15 | mfaVerifyHandler | 75.0% | Recovery code path, remember device issuance, exhaustion handling. | security-critical |
| P16 | mfaTOTPConfirmHandler | 62.5% | Re-authentication failure, already enrolled check, recovery code generation. | security-critical |
| P17 | mfaEmailOTPConfirmHandler | 48.4% | Over half untested. Challenge verification, already enrolled, recovery codes. | security-critical |
| P18 | mfaRemoveMethodHandler | 54.8% | Re-auth, last-method protection, credential deletion error. | security-critical |
| P19 | clearEnrollmentPending | 50.0% | Full auth token issuance when all pending items cleared (known bug hunt pattern from testing-pitfalls.md S11). | security-critical |
| P20 | buildMFARequiredReasons | 50.0% | Site admin config check, org-level requirement check, per-member requirement check. Known multi-layer auth issue from testing-pitfalls.md S11. | security-critical |
| P21 | issueFullAuthTokens | 57.1% | Error path on token issuance or cookie writing. | security-critical |
| P22 | sendMFAOTPEmail | 37.5% | Email rendering failure, SMTP send failure. Nearly all paths untested. | correctness |
| P23 | RequireAuthenticated | 85.3% | Likely missing: previous JWT secret fallback path, API key auth error handling. | security-critical |
| P24 | tryAPIKeyAuth | 62.1% | Revoked key detection, expired key handling, disabled user check, org membership verification. | security-critical |
| P25 | issueRefreshPair | 50.0% | Error paths on refresh token creation or access token signing. | security-critical |
| P26 | refreshGrace | 53.3% | Grace period logic branches. | correctness |

### Store Methods (Partial Coverage)

| # | Function | Coverage | Likely Uncovered Branches | Severity |
|---|----------|----------|--------------------------|----------|
| P27 | AdminPatchOrg | 73.1% | Suspend/unsuspend branches, re-fetch error. Fixed the multi-attribute PATCH atomicity bug (testing-pitfalls.md S7) but test coverage of both branches is unclear. | security-critical |
| P28 | AdminListOrgs | 83.3% | Cursor-based keyset pagination branch. | correctness |
| P29 | AdminBulkRetryFailed | 80.0% | Error path on RowsAffected. | correctness |
| P30 | AdminDisableUser | 87.5% | Error path. | correctness |
| P31 | AdminForcePasswordReset | 87.5% | Error path. | correctness |
| P32 | ListSecurityEvents | 76.3% | Multiple optional filter combinations (since, until, actor_email as NULL vs non-NULL). | correctness |
| P33 | ResetUserMFA | 68.8% | Multi-step cleanup (DeleteAllMFACredentials + DeleteAllRecoveryCodes + DeleteAllUserChallenges + IncrementTokenVersion). Error in intermediate step. | security-critical |
| P34 | VerifyRecoveryCode | 78.3% | Already-used code rejection, wrong-user code rejection, hash mismatch. | security-critical |
| P35 | VerifyEmailOTPChallenge | 77.3% | Exhausted attempts, expired challenge, code mismatch, challenge consumption. | security-critical |
| P36 | ValidateRememberDeviceToken | 84.6% | Expired token, wrong user. | security-critical |
| P37 | withBypassRawTx | 50.0% | Panic recovery, SET LOCAL failure. | security-critical |
| P38 | withOrgRawTx | 64.3% | Panic recovery, SET LOCAL failure. | security-critical |
| P39 | OrgTx | 77.8% | Panic handling differs from withOrgRawTx (uses defer rollback). | correctness |
| P40 | WorkerTx | 77.8% | Panic handling. | correctness |

---

## 100% Coverage Security Functions: Assertion Quality Concerns

| # | Function | Coverage | Concern |
|---|----------|----------|---------|
| A1 | withOrgTx | 100% | Delegates to withOrgRawTx (64.3%). Line coverage of withOrgTx is trivially achieved since it is a 4-line wrapper. The real security behavior (SET LOCAL, panic recovery) is in the underlying function. |
| A2 | IsSiteAdmin | 100% | Need to verify test checks both true and false cases, not just happy path. |
| A3 | SetFirstSiteAdmin | 100% | Need to verify test checks idempotency (second call behavior). |
| A4 | ClearForcePasswordReset | 100% | Need to verify test checks the flag is actually cleared in DB, not just no error. |
| A5 | RequireOrgRole (middleware) | 100% | Need to verify each role permutation is tested (owner, admin, member, viewer, no role). |
| A6 | RequireSiteAdmin (middleware) | 100% | Need to verify non-admin rejection is tested. |
| A7 | csrfProtect | 100% | Need to verify CSRF rejection is tested, not just passthrough. |
| A8 | authCookies/clearAuthCookies | 100% | Need to verify cookie attributes (Secure, HttpOnly, SameSite) are asserted. |

---

## Cross-Cutting Patterns

### Pattern 1: Admin Endpoint Desert
All five admin_users.go handlers, three admin_system.go handlers, and two of three admin_deliveries.go handlers are at 0% coverage. This is a complete subsystem with zero tests -- 10 security-sensitive endpoints managing user disable/enable, account unlock, password reset, config exposure, and audit logs. This is the single highest-priority gap.

### Pattern 2: Admin MFA Handlers Systematically Under-Tested
All six admin_mfa.go handlers are between 44-62% coverage. The common uncovered pattern across all of them is:
- RBAC hierarchy enforcement via checkAdminMFAPermission (59.1%)
- Security event emission
- Self-targeting rejection
- Error branches

### Pattern 3: Feed Management Handlers at 0%
pauseFeedHandler, resumeFeedHandler, feedLogsHandler are all 0%. These are admin-only endpoints that control feed ingestion. The corresponding store methods (PauseFeed, ResumeFeed, ListFeedFetchLogsPaginated) are also 0%.

### Pattern 4: Generated 73.3% Cluster
Many generated sqlc functions show exactly 73.3% coverage. These are row-scanning functions where the scan-loop body is covered but the rows.Err() check and/or the rows.Close() error path are not. This is a systematic pattern, not individual gaps.

### Pattern 5: Transaction Helper Coverage Gaps
withBypassRawTx (50%), withOrgRawTx (64.3%) -- the raw SQL transaction helpers that implement RLS setup have significant uncovered branches. These are the Layer 2 tenant isolation implementation. The panic recovery paths in particular are untested.

---

## Severity Summary

| Severity | Count | Detail |
|----------|-------|--------|
| Security-critical (0%) | 21 | S1-S5, S8-S10, S17, S19-S20, S22-S23, S28, S34, S41-S47, S52-S53 |
| Security-critical (partial) | 22 | P1-P6, P8, P11-P21, P23-P25, P27, P33-P38 |
| Security-critical (assertion) | 8 | A1-A8 |
| Correctness (0%) | 22 | S6-S7, S11-S15, S18, S21, S24-S27, S29-S33, S35-S40, S48-S50 |
| Correctness (partial) | 11 | P7, P9-P10, P22, P26, P28-P32, P39-P40 |
| Nice-to-have | 4 | S16, S54, S58-S59 |
| **Total gaps** | **88** | |

---

## Production Bug Candidates

### B1: GetCVEMaterialHash bypasses transaction helpers
store/cve.go:32 -- uses s.db.QueryRowContext directly instead of a transaction helper. CVEs are global (no RLS), so this is not a tenant isolation bug, but it breaks the convention that ALL store method queries go through transaction helpers. If CVEs ever become org-scoped, this would be a silent RLS bypass.

### B2: adminConfigHandler + redactSecret untested
If redactSecret were to be accidentally modified (e.g., always returns empty string), the admin config endpoint would expose JWT_SECRET, DATABASE_URL, SMTP credentials, etc. in plaintext. Both functions are at 0% coverage.

### B3: adminForcePasswordResetHandler at 44.2% -- multi-step flow
This handler: (1) checks RBAC, (2) verifies native identity, (3) sets force_password_reset flag, (4) increments token_version, (5) deletes device tokens. Steps 3-5 are partially independent -- a failure in step 4 after step 3 succeeds leaves force_password_reset set but sessions still valid. The error on step 5 is explicitly non-fatal (logged only), which is documented but untested.

### B4: checkAdminMFAPermission RBAC hierarchy partially untested (59.1%)
The function implements a three-tier hierarchy: site admin > owner > admin > member. With only ~60% coverage, likely only 1-2 of the 4 permission paths are tested. An incorrect comparison operator could allow admins to target owners.

---

## What is Well-Covered

- **Contract helpers**: decodeJSON, decodePageCursor, parseLimitParam, writeList, writeLocation -- all 100%. The shared response/pagination infrastructure is solid.
- **MFA credential lifecycle (store)**: CreateMFACredential (100%), UpdateMFACredentialLastUsed (100%), DeleteAllRecoveryCodes (100%), DeleteAllUserChallenges (100%) -- core MFA store operations.
- **Notification delivery store**: UpsertDelivery, ClaimPendingDeliveries, InsertDigestDelivery -- all 87-100%.
- **OpenAPI spec generation**: All register*SpecOps functions at 100%.
- **Rate limiting infrastructure**: All IP/org rate limiter methods at 100%.
- **Auth middleware**: RequireOrgRole, RequireSiteAdmin, csrfProtect all at 100% (assertion quality needs verification).
