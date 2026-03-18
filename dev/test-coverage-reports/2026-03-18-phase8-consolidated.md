# Phase 8 (A-E) Test Coverage — Consolidated Findings

**Date:** 2026-03-18
**Scope:** Phase 8 Operational Maturity (all subphases A-E): shared foundation, observe, operate, extend, secure
**Methodology:** Hybrid (Go coverage tools + semantic analysis)
**Subagents:** 3 (API/auth/crypto, store/core, feeds/support/CLI) + main agent (security matrix, cross-handler)

---

## Coverage Baseline

**Overall: 72.1%** across 1258 functions (merged profile from all packages)

| Package | Avg Coverage | Functions | 0% | Partial | 100% |
|---------|-------------|-----------|-----|---------|------|
| internal/api | 72.3% | 308 | 19 | 192 | 97 |
| internal/store | 82.3% | 287 | 18 | 196 | 73 |
| internal/store/generated | 84.7% | 274 | 26 | 59 | 189 |
| internal/notify | 85.1% | 46 | 2 | 19 | 25 |
| internal/doctor | 87.9% | 29 | 0 | 12 | 17 |
| internal/alert | 84.7% | 24 | 0 | 15 | 9 |
| internal/alert/dsl | 93.9% | 22 | 0 | 8 | 14 |
| internal/merge | 94.1% | 22 | 0 | 7 | 15 |
| internal/feed/generic | 86.7% | 21 | 0 | 14 | 7 |
| internal/ingest | 75.9% | 21 | 4 | 4 | 13 |
| internal/secure | 88.7% | 19 | 0 | 9 | 10 |
| internal/config | 87.3% | 12 | 1 | 3 | 8 |
| internal/auth | 90.0% | 12 | 0 | 8 | 4 |
| internal/worker | 72.3% | 10 | 2 | 4 | 4 |
| internal/feed (all other) | 86-100% | ~64 | 1 | ~30 | ~33 |
| internal/audit | 93.9% | 9 | 0 | 3 | 6 |
| internal/retention | 97.6% | 5 | 0 | 2 | 3 |
| internal/crypto | 88.9% | 4 | 0 | 2 | 2 |
| cmd/cvert-ops | varies | 36 | 23 | 6 | 7 |
| internal/dbutil | 100% | 2 | 0 | 0 | 2 |
| internal/log | 100% | 3 | 0 | 0 | 3 |
| internal/metrics | 100% | 3 | 0 | 0 | 3 |
| internal/tier | 100% | 4 | 0 | 0 | 4 |

**Test failures during run:** `internal/store`, `internal/api`, `internal/alert`, `internal/ingest` all timed out when run together (Docker container contention from parallel agents). All passed when run individually. Coverage data captured from individual runs and merged.

---

## Security Checklist Matrix

### Admin Endpoints (RequireAuthenticated + RequireSiteAdmin)

| Endpoint | Unauth→401 | Site-admin check | Fail-closed |
|----------|------------|-----------------|-------------|
| GET /admin/feeds | Tested (middleware: TestRequireSiteAdmin_NoAuth_401) | Tested (TestRequireSiteAdmin tests) | N/A |
| POST /admin/feeds/{feed}/run | Tested (middleware) | Tested (middleware) | N/A |
| POST /admin/feeds/{feed}/pause | Tested (middleware) | Tested (middleware) | N/A |
| POST /admin/feeds/{feed}/resume | Tested (middleware) | Tested (middleware) | N/A |
| GET /admin/feeds/{feed}/logs | Tested (middleware) | Tested (middleware) | N/A |
| GET /admin/version | Tested (TestAdminVersion_Unauthenticated_401) | Tested (middleware) | N/A |
| GET /admin/doctor | Tested (TestAdminDoctor_Unauthenticated_401) | Tested (middleware) | N/A |
| GET /admin/orgs | Tested (middleware) | Tested (middleware) | N/A |
| PATCH /admin/orgs/{org_id} | Tested (middleware) | Tested (middleware) | N/A |
| GET /admin/orgs/{org_id}/usage | Tested (middleware) | Tested (middleware) | N/A |
| GET /admin/users | Tested (middleware) | Tested (middleware) | N/A |
| POST /admin/users/{id}/disable | Tested (middleware) | Tested (middleware) | N/A |
| POST /admin/users/{id}/enable | Tested (middleware) | Tested (middleware) | N/A |
| POST /admin/users/{id}/unlock | Tested (middleware) | Tested (middleware) | N/A |
| POST /admin/users/{id}/reset-password | Tested (middleware) | Tested (middleware) | N/A |
| GET /admin/deliveries | Tested (middleware) | Tested (middleware) | N/A |
| POST /admin/deliveries/{id}/retry | Tested (middleware) | Tested (middleware) | N/A |
| POST /admin/deliveries/retry-failed | Tested (middleware) | Tested (middleware) | N/A |
| POST /admin/reindex | Tested (middleware) | Tested (middleware) | N/A |
| POST /admin/reload-config | Tested (TestAdminReloadConfig_RequiresSiteAdmin) | Tested (same) | Tested (TestAdminReloadConfig_DoesNotLeakErrorDetails) |
| GET /admin/config | Tested (middleware) | Tested (middleware) | N/A |
| GET /admin/audit-log | Tested (middleware) | Tested (middleware) | N/A |
| GET /admin/security-events | Tested (TestAdminSecurityEvents_RequiresSiteAdmin) | Tested (same) | N/A |

### Org-Scoped Endpoints (Phase 8-Added or Modified)

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed | Audit log |
|----------|-----------|------------|-------------------|-----------------|------|-------------|-----------|
| **Groups (Phase 8C)** | | | | | | | |
| POST /orgs/:id/groups | Tested (TestCrossOrg_GroupAccess) | Tested (middleware) | Tested (middleware) | string (name, desc) | Tested (TestCreateGroup_AsViewer) | N/A | **GAP (no audit logging in handler)** |
| GET /orgs/:id/groups | Tested (TestCrossOrg_GroupAccess) | Tested (middleware) | Tested (middleware) | N/A | Tested (middleware: RoleViewer) | N/A | N/A |
| GET /orgs/:id/groups/:gid | Tested (TestCrossOrg_GroupAccess) | Tested (middleware) | Tested (middleware) | UUID (gid) | Tested (middleware: RoleViewer) | N/A | N/A |
| PATCH /orgs/:id/groups/:gid | Tested (TestCrossOrg_GroupAccess) | Tested (middleware) | Tested (middleware) | string (name, desc) | Tested (TestCreateGroup_AsViewer implied) | N/A | **GAP (no audit logging in handler)** |
| DELETE /orgs/:id/groups/:gid | Tested (TestCrossOrg_GroupAccess) | Tested (middleware) | Tested (middleware) | UUID (gid) | Tested (TestCreateGroup_AsViewer implied) | N/A | **GAP (no audit logging in handler)** |
| POST /orgs/:id/groups/:gid/members | Tested (TestCrossOrg_GroupAccess) | Tested (middleware) | Tested (middleware) | UUID (user_id) | Tested (middleware: RoleAdmin) | Tested (TestAddGroupMember_NonExistentGroup) | **GAP (no audit logging in handler)** |
| GET /orgs/:id/groups/:gid/members | Tested (TestCrossOrg_GroupAccess) | Tested (middleware) | Tested (middleware) | UUID (gid) | Tested (middleware: RoleViewer) | N/A | N/A |
| DELETE /orgs/:id/groups/:gid/members/:uid | Tested (TestCrossOrg_GroupAccess) | Tested (middleware) | Tested (middleware) | UUID (gid, uid) | Tested (middleware: RoleAdmin) | Tested (TestRemoveGroupMember_NonExistentGroup) | **GAP (no audit logging in handler)** |
| **MFA Admin Actions (Phase 8E)** | | | | | | | |
| POST /orgs/:id/members/:uid/reset-mfa | **GAP (no cross-org test)** | Tested (middleware) | Tested (middleware) | UUID (uid) | Tested (TestAdminMFAResetByMember, TestAdminMFAResetOwnerByAdmin) | N/A | Tested (audit.Entry in handler) |
| POST /orgs/:id/members/:uid/force-password-reset | **GAP (no cross-org test)** | Tested (middleware) | Tested (middleware) | UUID (uid) | Tested (TestAdminForcePasswordResetByMember) | N/A | Tested (audit.Entry in handler) |
| POST /orgs/:id/members/:uid/require-mfa | **GAP (no cross-org test)** | Tested (middleware) | Tested (middleware) | UUID (uid) | Tested (TestAdminRequireMFAByMember, TestAdminRequireMFASelfTarget, TestAdminRequireMFAAdminTargetsAdmin) | N/A | Tested (audit.Entry in handler) |
| DELETE /orgs/:id/members/:uid/require-mfa | **GAP (no cross-org test)** | Tested (middleware) | Tested (middleware) | UUID (uid) | Tested (TestAdminUnrequireMFASelfTarget) | N/A | Tested (audit.Entry in handler) |
| PATCH /orgs/:id/mfa-settings | **GAP (no cross-org test)** | Tested (middleware) | Tested (middleware) | int (days), bool | Tested (TestAdminUpdateOrgMFASettingsByMember) | Tested (TestAdminUpdateOrgMFASettingsRememberDeviceDaysRange) | Tested (audit.Entry in handler) |
| **Channel Mutations (Phase 8 convergence)** | | | | | | | |
| POST /orgs/:id/channels | **GAP (no cross-org test)** | Tested (middleware) | Tested (middleware) | string (name, url), json (config) | Tested (TestChannelMutations_RequireAdmin) | Tested (TestCreateChannel_SSRFBlockedURL, tier gating) | Tested (audit in channels.go) |
| PATCH /orgs/:id/channels/:cid | **GAP (no cross-org test)** | Tested (middleware) | Tested (middleware) | string, json | Tested (TestChannelMutations_RequireAdmin) | Tested (TestPatchChannel_WebhookSSRFBlocked) | Tested (audit in channels.go) |
| DELETE /orgs/:id/channels/:cid | **GAP (no cross-org test)** | Tested (middleware) | Tested (middleware) | UUID (cid) | Tested (TestChannelMutations_RequireAdmin) | Tested (TestDeleteChannel_409IfActiveRuleBound) | Tested (audit in channels.go) |
| POST /orgs/:id/channels/:cid/rotate-secret | **GAP (no cross-org test)** | Tested (middleware) | Tested (middleware) | UUID (cid) | Tested (TestChannelMutations_RequireAdmin) | Tested (TestRotateSecret_EmailChannel_Rejected) | Tested (audit in channels.go) |
| POST /orgs/:id/channels/:cid/clear-secondary | **GAP (no cross-org test)** | Tested (middleware) | Tested (middleware) | UUID (cid) | Tested (TestChannelMutations_RequireAdmin) | Tested (TestClearSecondary_EmailChannel_Rejected) | Tested (audit in channels.go) |
| POST /orgs/:id/channels/:cid/test | **GAP (no cross-org test)** | Tested (middleware) | Tested (middleware) | UUID (cid) | Tested (TestChannelTest_RequiresAdmin) | N/A | N/A |
| **Ingest (Phase 8D)** | | | | | | | |
| POST /orgs/:id/ingest | **GAP (no cross-org test)** | Tested (TestIngestHandler_Unauthenticated) | Tested (middleware) | json (patches array) | Tested (TestIngestHandler_ViewerDenied) | Tested (TestIngestHandler_ExceedsPatchLimit, ReservedSourceName) | **GAP (no audit logging in handler)** |

### Org-Scoped Endpoints (Pre-Existing — Spot-Check Sample)

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | RBAC | Audit log |
|----------|-----------|------------|-------------------|------|-----------|
| PATCH /orgs/:id | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested (middleware) | Tested (TestUpdateOrg_AsViewer) | Tested (TestAuditIntegration_Members) |
| POST /orgs/:id/invitations | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested (middleware) | Tested (TestCreateInvitation_AsViewer) | Tested (TestAuditIntegration_Members) |
| POST /orgs/:id/rules | Tested (TestAlertRule_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | Tested (middleware: RoleMember) | Tested (TestAuditIntegration_AlertRules) |
| POST /orgs/:id/watchlists | Tested (TestWatchlist_CrossOrgReadWriteIsolation) | Tested (middleware) | Tested (middleware) | Tested (TestWatchlist_ViewerCannotWrite) | Tested (TestAuditIntegration_Watchlists) |
| GET /orgs/:id/deliveries | Tested (TestDeliveries_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | Tested (middleware: RoleViewer) | N/A |
| GET /orgs/:id/saved-searches | Tested (TestSavedSearch_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | Tested (TestSavedSearch_RBAC) | Tested (TestAuditIntegration_SavedSearches) |
| POST /orgs/:id/sso | Tested (TestOIDCFlow_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | Tested (TestSSOConnection_RBAC) | Tested (TestAudit_SSOOperations) |

**Matrix GAP Summary: 17 gaps** — 11 cross-org, 6 audit logging (groups 5, ingest 1)

---

## Production Bugs Discovered (1)

### B1. Generic Feed Cursor Pagination Infinite Fetch
**Location:** internal/feed/generic/config.go:121-126 + adapter.go:321-329
**Blast radius:** Any generic feed configured with `pagination.type: cursor` but empty `cursor_param`
**Evidence:** `Validate()` checks that `pagination.type` is a valid value but does NOT validate that `cursor_param`/`cursor_path` are set when type is `cursor`. `buildURL` with empty `CursorParam` returns `cfg.URL + "?=<cursor_value>"` — malformed URL with empty query key. If `CursorPath` extracts a non-empty cursor from the response, `LastPage` remains false, causing infinite refetching of page 1.
**Fix:** Add sub-field validation in `Validate()`: when `type == "cursor"`, require `cursor_param` and `cursor_path` non-empty; when `type == "offset"`, require `page_param` non-empty.

---

## Confirmed Security-Critical Gaps (28)

### SC1. adminConfigHandler — Secret Redaction at 0%
**Location:** internal/api/admin_system.go:34 (handler) + :178 (redactSecret)
**Source:** coverage
**Evidence:** Handler calls redactSecret() on JWT_SECRET, DATABASE_URL, SMTP_PASSWORD, SSO_ENCRYPTION_KEY, and 6 other secrets. Zero test coverage means a refactoring mistake could expose all secrets in plaintext. Both the handler and the redactSecret helper are at 0%.

### SC2. Admin User Management — Complete 0% Desert (5 handlers)
**Location:** internal/api/admin_users.go:25-222
**Source:** coverage
**Evidence:** adminDisableUserHandler (self-disable prevention, security event emission), adminEnableUserHandler, adminUnlockUserHandler (lockout bypass), adminResetPasswordHandler, adminListUsersHandler — all at 0%. No test verifies self-disable prevention, disabled-user rejection, or security event logging for these operations.

### SC3. tryAPIKeyAuth — Revoked/Disabled Key Handling at 62.1%
**Location:** internal/api/middleware_auth.go:105
**Source:** coverage + semantic
**Evidence:** Revoked-key security event emission and disabled-user API key rejection paths are uncovered. A test with a revoked API key verifying the security event and 401 response does not exist.

### SC4. loginHandler — Critical Auth Paths at 71.5%
**Location:** internal/api/auth.go:265
**Source:** coverage
**Evidence:** Disabled-user rejection path, MFA enrollment-required redirect, remember-device cookie bypass — all uncovered. These are security-critical branches in the primary authentication flow.

### SC5. refreshHandler + refreshGrace + issueRefreshPair — Token Theft Detection
**Location:** internal/api/auth.go:547 (72.4%), auth.go:refreshGrace (53.3%), auth.go:issueRefreshPair (50%)
**Source:** coverage
**Evidence:** Refresh token theft detection (reuse after rotation) and grace window edge cases are partially uncovered. Token theft is a critical security property.

### SC6. MFA Email OTP Confirm — Over Half Untested at 48.4%
**Location:** internal/api/auth_mfa.go:825
**Source:** coverage
**Evidence:** Success path (valid OTP confirmation) is uncovered. Only error paths are tested.

### SC7. sendMFAOTPEmail — Only 37.5% Covered
**Location:** internal/api/auth_mfa.go:445
**Source:** coverage
**Evidence:** Only SMTP-not-configured error path is covered. Actual email sending, rate limiting, and template rendering are all uncovered.

### SC8. mfaRemoveMethodHandler — Security Downgrade at 54.8%
**Location:** internal/api/auth_mfa.go:972
**Source:** coverage
**Evidence:** MFA method removal is a security-sensitive operation. Removal paths and last-method-prevention logic are partially uncovered.

### SC9. buildMFARequiredReasons — Fail-Closed Logic at 50%
**Location:** internal/api/auth_mfa.go:1306
**Source:** coverage
**Evidence:** Three independent layers (org policy, per-user requirement, admin-set flag). DB error handling should fail-closed (require MFA). At least one negative case untested.

### SC10. clearEnrollmentPending — Token Issuance at 50%
**Location:** internal/api/auth_mfa.go (clearEnrollmentPending)
**Source:** coverage
**Evidence:** Issues full auth tokens when last MFA enrollment step completes. Previously broken per bug hunt.

### SC11. patchSSOHandler — Encryption Paths at 45.3%
**Location:** internal/api/sso.go (patchSSOHandler)
**Source:** coverage
**Evidence:** Client secret re-encryption during SSO config update is partially uncovered. Encryption key rotation fallback untested.

### SC12. createSSOHandler — Encryption Paths at 55.3%
**Location:** internal/api/sso.go (createSSOHandler)
**Source:** coverage
**Evidence:** SSO client secret encryption and dual-key handling partially uncovered.

### SC13. ssoEncryptionKeyPrevious — Fallback at 72.7%
**Location:** internal/api/sso.go
**Source:** coverage
**Evidence:** Previous encryption key fallback path for key rotation untested.

### SC14. checkAdminMFAPermission — RBAC Hierarchy at 59.1%
**Location:** internal/api/admin_mfa.go:397-435
**Source:** coverage
**Evidence:** Three-tier hierarchy (viewer < member < admin < owner) with ~60% branches covered. An incorrect comparison could allow admins to target owners.

### SC15. RequireAuthenticated — Disabled-User Path at 85.3%
**Location:** internal/api/middleware_auth.go (RequireAuthenticated)
**Source:** semantic
**Evidence:** Disabled-user rejection is only incidentally exercised through other tests. No dedicated test verifies that a disabled user gets 401. If middleware ordering changes, this protection could silently break.

### SC16. Admin Audit Log Handler — Cross-Org Data at 0%
**Location:** internal/api/admin_system.go:110-175
**Source:** coverage
**Evidence:** Site-admin audit log handler with optional filters and cursor pagination. Zero tests for this handler.

### SC17. Admin Org Store Methods at 0%
**Location:** internal/store/admin_org.go (AdminUpdateOrgTier, AdminSuspendOrg, AdminUnsuspendOrg)
**Source:** coverage
**Evidence:** AdminSuspendOrg/AdminUnsuspendOrg affect organization access. A bug could fail to suspend a compromised org.

### SC18. LookupAPIKeyByHash at 0%
**Location:** internal/store/apikey.go:112
**Source:** coverage
**Evidence:** Security audit function for revoked-key detection. If this function silently fails, revoked-key-usage events won't be logged.

### SC19. RLSCheck Doctor — Failure Detection at 62.5%
**Location:** internal/doctor/checks.go:125
**Source:** coverage
**Evidence:** Failure-detection paths untested. A misconfigured RLS will not be caught by the doctor check.

### SC20. EncryptionSentinelCheck Doctor — Dual-Key at 50%
**Location:** internal/doctor/checks.go:168
**Source:** coverage
**Evidence:** Dual-key rotation detection likely untested. If the sentinel can't decrypt with the current key, fallback to previous key path is uncovered.

### SC21. SecurityHeadersCheck Doctor at 48.0%
**Location:** internal/doctor/checks.go:274 (approx)
**Source:** coverage
**Evidence:** Missing-header detection paths partially untested.

### SC22. Webhook HMAC with Empty Signing Secret
**Location:** internal/notify/webhook.go:57
**Source:** semantic
**Evidence:** `hmac.New(sha256.New, []byte(cfg.SigningSecret))` computes HMAC with empty key if SigningSecret is empty. Signature header is sent, providing false sense of security. In practice, channels auto-generate secrets on creation, but defense-in-depth requires handling this case.

### SC23. EPSS applyRow at 0%
**Location:** internal/feed/epss/adapter.go:250
**Source:** coverage
**Evidence:** Two-statement EPSS pattern with advisory locking. Critical data pipeline function reports 0% function-level coverage. May be exercised through integration tests but needs verification.

### SC24. MFA Admin Cross-Org Isolation — No Dedicated Tests (5 endpoints)
**Location:** internal/api/admin_mfa.go (all 5 admin MFA endpoints)
**Source:** matrix
**Evidence:** No test verifies that admin in org A can't reset-mfa/force-password-reset/require-mfa for users in org B. Relies solely on RequireOrgRole middleware.

### SC25. Channel Cross-Org Isolation — No Dedicated Tests (6 endpoints)
**Location:** internal/api/channels.go (all CRUD + rotate-secret + clear-secondary + test)
**Source:** matrix
**Evidence:** No dedicated cross-org test for channel CRUD operations. Only cross-org channel BINDING tests exist (rules/reports). Channel operations rely solely on RequireOrgRole middleware for cross-org protection.

### SC26. Ingest Cross-Org Isolation — No Dedicated Test
**Location:** internal/api/ingest.go
**Source:** matrix
**Evidence:** No test verifies that user in org A can't ingest data into org B.

### SC27. Groups — No Audit Logging (5 mutating operations)
**Location:** internal/api/groups.go
**Source:** cross-handler consistency
**Evidence:** create, update, delete group and add/remove member have zero audit logging. Every other mutating handler group (channels, alert rules, watchlists, saved searches, SSO, orgs) has audit logging. Groups affect authorization (future RBAC). This is a code gap, not just a test gap.

### SC28. Ingest — No Audit Logging
**Location:** internal/api/ingest.go
**Source:** cross-handler consistency
**Evidence:** Custom CVE data ingestion has no audit trail. Every other data-modifying endpoint has audit logging.

---

## Confirmed Correctness Gaps (35)

### C1. Admin Deliveries List/Retry at 0%
**Location:** internal/api/admin_deliveries.go:25-110
**Source:** coverage

### C2. Feed Pause/Resume/Logs at 0% (3 store methods)
**Location:** internal/store/feed.go:201-234 (PauseFeed, ResumeFeed, ListFeedFetchLogsPaginated)
**Source:** coverage

### C3. Worker Periodic Job Framework at 0% (RegisterPeriodic + runPeriodic)
**Location:** internal/worker/pool.go:81-280
**Source:** coverage
**Evidence:** Periodic task system (batch evaluator, EPSS, retention) completely untested.

### C4. GetCVEMaterialHash at 0%
**Location:** internal/store/cve.go:32
**Source:** coverage
**Evidence:** Returns material_hash for alert deduplication. Raw SQL query, unvalidated at runtime.

### C5. Admin Store Functions at 0% (12 functions)
**Location:** admin_delivery.go, admin_org.go, admin_system.go, admin_user.go
**Source:** coverage
**Evidence:** AdminListDeliveries, AdminGetDeliveryByID, AdminRetryDelivery, AdminUpdateOrgTier, AdminGetOrgUsage, AdminListAuditEntries, AdminListUsers, AdminGetUserByID, AdminEnableUser, AdminUnlockUser, plus others.

### C6. ListSecurityEvents — Missing Filter Tests at 76.3%
**Location:** internal/store/security_events.go:99
**Source:** coverage
**Evidence:** Raw SQL with 8 nullable parameters. Missing: filter by severity, date range, cursor pagination.

### C7. BootstrapFirstUserOrg — Error Path at 76.2%
**Location:** internal/store/org.go:101
**Source:** coverage
**Evidence:** Multi-step transaction. Missing error path mid-transaction.

### C8. SearchCVEs — Missing Filter Tests at 91.5%
**Location:** internal/store/cve.go:124
**Source:** coverage
**Evidence:** 15 optional filters. Missing: EPSS range and ExploitAvail filter tests.

### C9. VerifyRecoveryCode — Wrong-Code Path at 78.3%
**Location:** internal/store/mfa.go:239
**Source:** coverage
**Evidence:** Missing wrong-code path or mark-used error path.

### C10. VerifyEmailOTPChallenge — Exhausted-Attempts at 77.3%
**Location:** internal/store/mfa.go:387
**Source:** coverage
**Evidence:** Missing exhausted-attempts path.

### C11. InsertAffectedCPE at 0% (sqlc-generated)
**Location:** internal/store/generated/cves.sql.go:377
**Source:** coverage
**Evidence:** Merge pipeline step 8 calls this, but no test provides CPE data.

### C12. UpsertEPSSStaging at 0% (sqlc-generated)
**Location:** internal/store/generated/cves.sql.go:725
**Source:** coverage
**Evidence:** EPSS staging for CVEs that don't exist yet. If staging INSERT has a bug, EPSS scores for new CVEs are silently lost.

### C13. EvaluateActivation — Compilation Error Path at 72.5%
**Location:** internal/alert/evaluator.go
**Source:** coverage
**Evidence:** Missing compilation error path, mid-batch error, concurrent status change.

### C14. bypassTx — Statement Timeout at 58.3%
**Location:** internal/alert/evaluator.go
**Source:** coverage
**Evidence:** Missing statementTimeoutMS > 0 path.

### C15. conditionToSQL — Unknown Field Category at 80%
**Location:** internal/alert/dsl/compiler.go
**Source:** coverage
**Evidence:** Default error branch for unknown field categories.

### C16. textSQL — Missing Operator at 77.8%
**Location:** internal/alert/dsl/compiler.go
**Source:** coverage
**Evidence:** Likely missing "ends_with" operator.

### C17. affectedPackageSQL — Missing Operators at 81.8%
**Location:** internal/alert/dsl/compiler.go
**Source:** coverage
**Evidence:** starts_with/ends_with for package names.

### C18. Ingest Function — Multi-Step Orchestration at 69.1%
**Location:** internal/merge/pipeline.go
**Source:** coverage
**Evidence:** 260-line function, 10 steps. Error branches in loops uncovered (happy paths all tested).

### C19. migrateCVEPKRename/Merge at 71.4% each
**Location:** internal/merge/pipeline.go
**Source:** coverage
**Evidence:** Happy paths tested. Error branches in loops uncovered.

### C20. LoadFromConfig — Invalid Hex Warning at 80%
**Location:** internal/config/config.go
**Source:** coverage
**Evidence:** Missing: invalid hex SSO key warning path.

### C21. formatCEF — Extension Branches at 61.9%
**Location:** internal/secure/events.go
**Source:** coverage
**Evidence:** Missing CEF extension branches for UserID, OrgID, ActorEmail.

### C22. Generic Feed fetchJSONStream — Error Paths at 72.5%
**Location:** internal/feed/generic/adapter.go
**Source:** coverage
**Evidence:** Non-object opening token, non-string key token, array open, decode record error, decode cursor error, skip key error.

### C23. Generic Feed nextPage at 37.5%
**Location:** internal/feed/generic/adapter.go
**Source:** coverage
**Evidence:** Cursor-with-nested-path uses buffered path.

### C24. Generic Feed applyAuth at 73.7%
**Location:** internal/feed/generic/adapter.go
**Source:** coverage
**Evidence:** Header auth with empty HeaderValueEnv, basic auth with both empty user/pass.

### C25. Generic Feed fetchCSAF at 72.2%
**Location:** internal/feed/generic/adapter.go
**Source:** coverage
**Evidence:** Rate limiter error, request build error, HTTP error status, CSAF parse error.

### C26. Generic Feed csafToPatches — CVSSv4 at 83.7%
**Location:** internal/feed/generic/adapter.go
**Source:** coverage
**Evidence:** No test provides cvss_v4 block for CSAF format or JSON gjson mapping.

### C27. Notify runDigest at 57.1%
**Location:** internal/notify/digest.go
**Source:** coverage
**Evidence:** ClaimDueReports error path, executeDigestReport error path.

### C28. Notify advanceReport — Timezone at 55.6%
**Location:** internal/notify/digest.go:178-192
**Source:** coverage
**Evidence:** Invalid timezone, skip-forward loop.

### C29. Notify EmailSend — TLS/Auth at 72.0%
**Location:** internal/notify/email.go
**Source:** coverage
**Evidence:** TLS mandatory path, SMTP auth path.

### C30. CLI rotateEncryptionKeys — Error Branches at 73.7%
**Location:** cmd/cvert-ops/rotate.go:87-156
**Source:** coverage
**Evidence:** Decrypt failure, encrypt failure, RowsAffected!=1 paths uncovered.

### C31. CLI doctor wiring at 0%
**Location:** cmd/cvert-ops/doctor.go:23-69
**Source:** coverage
**Evidence:** StandardChecksConfig field mapping untested.

### C32. CLI quotaGet/List/Delete at 0%
**Location:** cmd/cvert-ops/quota.go:64-170
**Source:** coverage

### C33. ParseEnrollmentToken — Unknown Key Rejection
**Location:** internal/auth/jwt.go
**Source:** coverage
**Evidence:** No UnknownKeyRejects test unlike other token types.

### C34. VerifyPassword — Invalid Base64
**Location:** internal/auth/password.go
**Source:** coverage
**Evidence:** Missing invalid base64 salt/key test cases.

### C35. createInvitationHandler at 54.5%, updateMemberRoleHandler at 54.5%
**Location:** internal/api/orgs.go
**Source:** coverage

---

## Assertion Quality Issues (16)

### AQ1. RLS Test — Shallow (only watchlists table)
**Location:** internal/store/rls_test.go
**Source:** assertion audit
**Evidence:** Tests only watchlists table. Does not verify all org-scoped tables have RLS.

### AQ2. EventWriter — Missing Syslog Assertion
**Location:** internal/secure/writer_test.go
**Source:** assertion audit
**Evidence:** Never verifies syslog.Send is actually called with a real or mock writer.

### AQ3. adminBulkRetryDeliveries — Limit Not Verified
**Location:** internal/api/admin_deliveries_test.go
**Source:** assertion audit
**Evidence:** Test doesn't actually verify the limit parameter is applied.

### AQ4. Lockout Integration — Missing Counter-Reset Test
**Location:** internal/api/lockout_test.go
**Source:** assertion audit
**Evidence:** Timing-dependent test, missing counter-reset after successful login.

### AQ5. API Key Tests — Missing Disabled-User Rejection
**Location:** internal/api/apikeys_test.go
**Source:** assertion audit
**Evidence:** No test verifies that an API key belonging to a disabled user is rejected.

### AQ6. ForcePasswordReset — Missing Allowlist Test
**Location:** internal/api/middleware_auth_test.go
**Source:** assertion audit
**Evidence:** No test verifies the /auth/logout allowlist path through force-password-reset middleware.

### AQ7. Generic Feed TestAdapter_URLUnreachable — Weak Assertion
**Location:** internal/feed/generic/adapter_test.go
**Source:** assertion audit
**Evidence:** Error message not verified, only assert.Error.

### AQ8. Generic Feed TestAdapter_NonJSONResponse — Weak Assertion
**Location:** internal/feed/generic/adapter_test.go
**Source:** assertion audit
**Evidence:** Error type not checked.

### AQ9. TestWorker_GracefulShutdown — Missing In-Flight Delivery
**Location:** internal/worker/pool_test.go
**Source:** assertion audit
**Evidence:** Does not test in-flight delivery survival during shutdown.

### AQ10. TestBuildSafeClient — Missing MaxConnsPerHost
**Location:** internal/notify/webhook_test.go
**Source:** assertion audit
**Evidence:** Does not verify MaxConnsPerHost=50.

### AQ11. RenderMFAOTP — Completely Untested
**Location:** internal/notify/render.go
**Source:** coverage
**Evidence:** Same pattern as 5 other tested render functions, but this one has 0%.

### AQ12. adminSecurityEventsHandler — Side-Effect Coverage Only
**Location:** internal/api/admin_security_events_test.go
**Source:** assertion audit
**Evidence:** Handler tested but some assertions may be incidental.

### AQ13. Alert Evaluator — GOOD (positive)
**Source:** assertion audit
**Evidence:** Thorough: event count, match_state, suppress_delivery, status transitions, dedup, resolution, regex, candidate cap.

### AQ14. Merge Pipeline — GOOD (positive)
**Source:** assertion audit
**Evidence:** 19 tests, assertions on specific column values not just "no error".

### AQ15. DecryptWithFallback — GOOD (positive)
**Source:** assertion audit
**Evidence:** Exemplary test design including truncated-ciphertext fallback prevention.

### AQ16. Store Transactions — Adequate (positive)
**Source:** assertion audit
**Evidence:** Behavioral assertions (RLS row visibility) stronger than variable-value checks.

---

## Nice-to-Have Gaps (30)

### N1. ListCVEs (store) at 0% — Thin Wrapper, Possibly Dead Code
**Location:** internal/store/cve.go:78

### N2. PauseFeed/ResumeFeed/ListFeedFetchLogsPaginated at 0% — Thin Wrappers
**Location:** internal/store/feed.go:201-234

### N3. GetActiveEmailOTPChallenge / GetUnusedRecoveryCodeByHash at 0%
**Location:** internal/store/generated — ForUpdate variants at 100%. Non-ForUpdate versions may be dead code.

### N4. ListSecurityEvents (generated) at 0% — Dead Code
**Location:** internal/store/generated — store uses raw SQL instead.

### N5. withBypassRawTx Error Paths at 50%
**Location:** internal/store/store.go:73 — BeginTx, SET LOCAL, panic recovery.

### N6. withOrgRawTx Error Paths at 64.3%
**Location:** internal/store/store.go:101 — Same pattern as N5.

### N7. OrgTx/WorkerTx Infrastructure Error Paths at 77.8%
**Location:** internal/store/store.go:138, 163

### N8. runStatus at 50% — Trivial 3-Way Switch
**Location:** internal/alert/evaluator.go — Missing "partial" branch.

### N9. Adapter.New nil-client paths at 66.7% (mitre, msrc, redhat)
**Location:** internal/feed/*/adapter.go

### N10. DownloadToTemp at 66.7% — OS-Level Error Paths
**Location:** internal/feed/util.go

### N11. WrapClientWithUA at 90.0% — nil-client Path
**Location:** internal/feed/util.go

### N12. Notify exhaust at 50% — One-Line Store Call
**Location:** internal/notify/delivery.go

### N13. Notify runStuckReset at 50% — One-Line Store Call
**Location:** internal/notify/delivery.go

### N14. Notify Start at 70.8% — Ticker Branches Tested Individually
**Location:** internal/notify/worker.go

### N15. Notify renderPair at 72.7% — Template Error Paths
**Location:** internal/notify/render.go

### N16. Notify runRecovery at 66.7% — OrphanedAlertEvents Error
**Location:** internal/notify/delivery.go

### N17. Notify scheduleRetention at 73.3% — Error Paths
**Location:** internal/notify/worker.go

### N18. Notify executeDigestReport at 78.8% — Error Paths
**Location:** internal/notify/digest.go

### N19. Notify deliver at 81.4% — CompleteDelivery DB Error After Send
**Location:** internal/notify/delivery.go

### N20. Notify runClaim at 82.4% — ClaimPendingDeliveries Error
**Location:** internal/notify/delivery.go

### N21. Notify BuildSafeClient at 83.3% — Defensive Dead Code
**Location:** internal/notify/webhook.go

### N22. Notify ComputeNextRunAt at 90.9% — Edge Case (candidate==now)
**Location:** internal/notify/digest.go

### N23. Notify Send (webhook) at 95.8% — Request Build Error
**Location:** internal/notify/webhook.go

### N24. autoMigrate advisory lock paths at 46.2%
**Location:** cmd/cvert-ops/main.go

### N25. Crypto Encrypt/Decrypt error paths — Unreachable with valid keys
**Location:** internal/crypto/aes.go

### N26. isGCMAuthError string matching — Low Risk
**Location:** internal/crypto/aes.go

### N27. IssueAccessToken/IssueRefreshToken SignedString error — HMAC never fails
**Location:** internal/auth/jwt.go

### N28. jwtPreviousSecretBytes startup config fallback at 66.7%
**Location:** internal/api/server.go

### N29. parseQueryDate unit tests missing
**Location:** internal/api/helpers.go

### N30. pauseFeedHandler/resumeFeedHandler tests missing
**Location:** internal/api/admin_feeds.go

---

## Semantic Analysis (Cross-Handler Consistency — §4A)

### Pattern: Audit Logging on Mutations
**Result: 2 handler groups violate the pattern**
- Handlers WITH audit: channels (4 entries), alert_rules (4), orgs (5), saved_searches (3), sso (4), watchlists (4), admin_mfa (5), oauth_oidc (1)
- Handlers WITHOUT audit: **groups** (0 entries — 5 mutating ops), **ingest** (0 entries)
- Pre-existing gaps (not Phase 8): reports (0), apikeys (0)

### Pattern: Cross-Org Isolation Tests
**Result: 3 endpoint groups lack dedicated cross-org tests**
- With tests: orgs, invitations, rules, watchlists, deliveries, saved_searches, sso, audit_log, api_keys, groups, reports, alert_events, ai
- Without dedicated tests: **channels CRUD**, **MFA admin actions**, **ingest**

### Semantic Checks (§4B-E)
- **SEM1. lockoutManager.Check fails open on DB errors** — Intentional design (comment at line 53-54), rate limiter as secondary defense. No regression test to prevent accidental change to fail-closed. (Design decision)
- **SEM2. ForcePasswordReset allowlist uses string suffix matching** — Fragile but not exploitable given known endpoint patterns. (Design decision)
- **SEM3. loginHandler double-query MFA check** — Two DB queries where one could suffice. Low-risk correctness concern.
- **SEM4. Store org_id enforcement** — PASS. Every org-scoped method uses withOrgTx/withOrgRawTx.
- **SEM5. LookupAPIKey bypass** — PASS. Correctly uses withBypassTx for auth hot-path.
- **SEM6. Merge advisory lock** — PASS. Concurrent write test proves serialization.
- **SEM7. Candidate cap fail-closed** — PASS. 5002 CVEs test proves partial=true with 0 events.
- **SEM8. Webhook delivery no open DB tx** — PASS. Claim-commit-deliver-update pattern correct.
- **SEM9. Fan-out error handling** — PASS. Per-channel error logging without abort.

---

## Design Decisions Requiring User Input (5)

### D1. Lockout Fail-Open Regression Test
**The concern:** lockoutManager.Check intentionally fails open on DB errors (rate limiter as backup). No regression test ensures this behavior isn't accidentally changed.
**Options:** (a) Add regression test that verifies fail-open on simulated DB error. (b) Accept as-is since comment documents intent.
**Recommendation:** (a) — a regression test is cheap insurance against an inadvertent security lockout of all users.

### D2. Generic Feed Client SSRF Protection
**The concern:** `feedClient` in main.go is `&http.Client{}` (no SSRF protection). Generic feeds use admin-configured URLs. Built-in feeds use hardcoded URLs.
**Options:** (a) Wrap feedClient in safeurl for all feeds. (b) Wrap only for generic feeds. (c) Accept as-is since URLs come from server-side config, not user input.
**Recommendation:** (b) — safeurl for generic feeds only, since those URLs are admin-configurable.

### D3. Webhook HMAC with Empty Secret
**The concern:** Empty SigningSecret still computes HMAC with empty key. In practice, channels auto-generate secrets on creation.
**Options:** (a) Skip HMAC when secret is empty. (b) Reject Send() with empty secret. (c) Accept as-is.
**Recommendation:** (a) — skip HMAC header when secret is empty, avoids false sense of security.

### D4. Groups Audit Logging — Code Gap
**The concern:** This is a CODE gap, not just a test gap. Groups handler has zero audit logging calls.
**Options:** (a) Add audit logging to groups (matches all other handler groups). (b) Defer since groups don't yet affect authorization.
**Recommendation:** (a) — add audit logging now, before groups become authorization-relevant.

### D5. Ingest Audit Logging — Code Gap
**The concern:** Same as D4 but for the ingest webhook. Custom CVE data ingestion has no audit trail.
**Options:** (a) Add audit logging. (b) Defer since ingest is admin-level and logged elsewhere (feed fetch logs).
**Recommendation:** (a) — data provenance requires audit trail.

---

## False Positives (3)

### FP1. Generic Feed SSRF via nil Client — Downgraded
**Why invalid as SC:** The `nil` client fallback in NewAdapter creates a bare HTTP client, but in production `main.go` always passes a non-nil `feedClient`. The SSRF concern is about the feedClient itself not being safeurl-wrapped — that's D2 above, not a nil-client issue.

### FP2. sqlc Generated 73.3% Cluster
**Why invalid:** Standard sqlc row-iteration pattern. The uncovered branch is `rows.Err()` on mid-iteration connection drop — a Go database/sql infrastructure concern, not a code bug.

### FP3. StartSIGHUPHandler at 0% on Windows
**Why invalid:** No-op stub on Windows. SIGHUP is Unix-only.

---

## What's Well-Covered
- **Middleware stack**: Auth, RBAC, CSRF, rate limiting — comprehensive tests
- **Contract helpers**: writeProblem, writeList, encodePageCursor — 100% with good assertions
- **Phase 8E security events**: async writer, rate limiting, CEF format — well-designed tests
- **Alert DSL + evaluator**: 93.9% and 84.7% with strong behavioral assertions
- **Merge pipeline**: 94.1% with 19 tests checking specific column values
- **Dual-key JWT rotation**: Tested for round-trip, expired, wrong-algorithm, alg:none, wrong-secret, dual-key
- **DecryptWithFallback**: Exemplary test design including truncated-ciphertext prevention

---

## Key Observations

1. **Admin Endpoint Desert**: 13 of 23 admin endpoints have 0% handler coverage. The middleware is tested but handler-specific behavior (self-disable prevention, secret redaction, data filtering) is not.
2. **MFA Handlers Systematically Under-Tested**: All Phase 11 MFA handlers range 37-55% coverage. The enrollment and removal flows are the most under-covered.
3. **Two Code Gaps (Not Just Test Gaps)**: Groups and Ingest handlers are missing audit logging entirely — a cross-handler consistency violation, not a testing oversight.
4. **Cross-Org Test Pattern Incomplete**: 17 of ~81 org-scoped endpoints lack dedicated cross-org tests. The middleware provides protection, but defense-in-depth tests are missing.
5. **Production Bug Found**: Generic feed cursor pagination can loop infinitely with misconfigured cursor_param.
6. **Strong Foundation**: Middleware, contract helpers, merge pipeline, alert evaluation, and crypto are all well-tested with good assertion quality.

---

## Test Gap Analysis

### B1. Generic Feed Cursor Pagination Infinite Fetch
**Why missed:** Config validation (`Validate()`) checks enum values but not field dependencies. No test passes a cursor-type config with empty `cursor_param`.
**Pitfall coverage:** New pitfall — "pagination config sub-field validation" (generalizable, added below)
**Catch test:** Config validation test with `{pagination: {type: "cursor", cursor_param: ""}}` expecting validation error.

### SC1. adminConfigHandler Secret Redaction at 0%
**Why missed:** Handler exists but no test was written. Likely deferred during Phase 8C (Operate pillar).
**Pitfall coverage:** New pitfall — "config endpoint secret redaction" (generalizable, added below)
**Catch test:** Call GET /admin/config, assert no field value contains the actual secret string.

### SC2. Admin User Management at 0%
**Why missed:** 5 handlers written during Phase 8C with no tests at all. Significant oversight.
**Pitfall coverage:** Covered by tp§11 "RBAC matrix coverage" and tp§13 "Admin flag enforcement at all entry points" — not followed.
**Catch test:** Per-handler tests with self-disable prevention, disabled-user idempotency, security event emission.

### SC3. tryAPIKeyAuth — Revoked/Disabled Key
**Why missed:** Auth middleware tests cover happy paths and basic rejection. Revoked-key and disabled-user paths are edge cases that require more test setup.
**Pitfall coverage:** Covered by tp§11 "Security check enforcement across similar endpoints" — not followed.
**Catch test:** Revoke an API key, make a request, assert 401 + security event logged.

### SC22. Webhook HMAC with Empty Secret
**Why missed:** In practice, channels always have a signing secret (auto-generated on creation). The empty-secret path isn't reachable through normal flows.
**Pitfall coverage:** Covered by tp§8 "Production client configuration exercised in tests" — not followed.
**Catch test:** Defense-in-depth: skip HMAC header when secret is empty rather than computing with empty key.

### SC27/SC28. Groups and Ingest — No Audit Logging
**Why missed:** CODE gap, not test gap. The audit logging calls were never added to these handlers.
**Pitfall coverage:** Covered by tp§7 "Audit trail completeness" — "verify ALL operations in the same category also have audit logging." Not followed during implementation.
**Catch test:** After code fix: audit integration test verifying group create/update/delete and ingest write audit entries.

### SC24/SC25/SC26. Cross-Org Isolation Gaps
**Why missed:** These endpoints rely on RequireOrgRole middleware for cross-org protection. The middleware is tested, so per-handler tests were skipped.
**Pitfall coverage:** Covered by tp§10 "Cross-tenant visibility assertion" — not followed.
**Catch test:** Per endpoint group: create resource in Org A, attempt access from Org B, assert 403.

### SEM-1. Lockout Fail-Open Design — No Regression Test
**Why missed:** Intentional design choice documented in comments. But comments get deleted; regression tests don't.
**Pitfall coverage:** New pitfall — "fail-open regression tests" (generalizable, added below)
**Catch test:** Inject DB error in GetLoginLockoutState, assert login is allowed (not 500).

### Testing Pitfalls Updates

Three new pitfalls added to `dev/testing-pitfalls.md`:
1. **Config endpoint secret redaction** (§5)
2. **Pagination config sub-field validation** (§5)
3. **Fail-open security mechanism regression tests** (§11)
