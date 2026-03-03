# Phase 5 Test Coverage Review — Enhanced v4 (Run I5)

**Date:** 2026-03-03
**Scope:** `./internal/api/...`, `./internal/store/...`, `./internal/tier/...`
**Method:** Go coverage tools (`coverage-ab.out`) + semantic analysis
**Skill version:** test-coverage-review-go enhanced v4

## §1 Coverage Baseline

**Overall:** 73.5% statement coverage

| Package | Functions | 0% | 1-79% | 80-99% | 100% |
|---------|-----------|-----|-------|--------|------|
| internal/api | 181 | 2 | 104 | 21 | 54 |
| internal/store | 374 | 24 | 84 | 102 | 164 |
| internal/tier | 4 | 0 | 0 | 0 | 4 |
| **Total** | **559** | **26** | **188** | **123** | **222** |

### Tier Package (all 100%)

| Function | Coverage |
|----------|----------|
| ResolveInt | 100.0% |
| ResolveBool | 100.0% |
| IntLimit | 100.0% |
| BoolFlag | 100.0% |

### 0% Functions

**API (2):**
- `pgErrCode` (auth.go:35) — error code extraction utility
- `encodeDeliveryCursor` (deliveries.go:88) — cursor encoding

**Store (24):**
- `ListCVEs` (cve.go:61) — dynamic CVE list query
- 18 sqlc-generated functions (cves.sql.go, feed.sql.go) — feed/merge pipeline CRUD
- `Scan`/`Value` (models.go:43/53) — enum type methods
- `GetWatchlistItem` (watchlist.sql.go:167) — single watchlist item lookup
- `GetFeedSyncState`, `InsertFeedFetchLog`, `UpsertFeedSyncState` (feed.sql.go) — feed sync

## §3 Security Checklist Matrix

**Endpoint count: 72 org-scoped endpoints enumerated from server.go.**
POST /orgs is auth-required but not org-scoped (no org_id); excluded.

Key: T(Test) = tested, GAP(reason) = gap, N/A = not applicable.
All org endpoints inherit RequireAuthenticated + RequireOrgRole(Viewer) middleware.

### Org Management (9 endpoints)

| # | Endpoint | Cross-org | RBAC | Fail-closed | Audit |
|---|----------|-----------|------|-------------|-------|
| 1 | GET /orgs/{id} | T(TestCrossOrg_MemberOperations) | T(TestGetOrg_NotMember) | N/A | N/A |
| 2 | GET /orgs/{id}/tier | GAP | T(TestGetOrgTier_FreeTier) | N/A | N/A |
| 3 | PATCH /orgs/{id} | T(TestCrossOrg_MemberOperations) | T(TestUpdateOrg_AsViewer) | N/A | GAP(no audit) |
| 4 | GET …/members | T(TestCrossOrg_MemberOperations) | T(TestListMembers_NotMember) | N/A | N/A |
| 5 | PATCH …/members/{uid} | T(TestCrossOrg_MemberOperations) | T(TestUpdateMemberRole_CannotExceedCallerRole) | T(TestUpdateMemberRole_CannotAssignOwner) | T(TestAuditIntegration_Members) |
| 6 | DELETE …/members/{uid} | T(TestCrossOrg_MemberOperations) | T(TestRemoveMember_Success) | T(TestRemoveMember_SoleOwner) | T(TestAuditIntegration_Members) |
| 7 | POST …/invitations | T(TestCrossOrg_MemberOperations) | T(TestCreateInvitation_AsViewer) | T(TestTierGating_Members_FreeLimit) | GAP(no audit on create/tier-deny) |
| 8 | GET …/invitations | T(TestCrossOrg_MemberOperations) | T(TestCreateInvitation_AsViewer) | N/A | N/A |
| 9 | DELETE …/invitations/{id} | GAP(not in cross-org test) | T(TestCreateInvitation_AsViewer) | N/A | GAP(no audit) |

### API Keys (3 endpoints)

| # | Endpoint | Cross-org | RBAC | Fail-closed | Audit |
|---|----------|-----------|------|-------------|-------|
| 10 | POST …/api-keys | T(TestCrossOrg_APIKeyAccess) | T(TestCreateAPIKey_ViewerForbidden) | T(TestCreateAPIKey_RoleEscalation) | GAP(no audit) |
| 11 | GET …/api-keys | T(TestCrossOrg_APIKeyAccess) | T(TestListAPIKeys_Success) | N/A | N/A |
| 12 | DELETE …/api-keys/{id} | T(TestCrossOrg_APIKeyAccess) | T(TestRevokeAPIKey_NotOwner) | T(TestRevokeAPIKey_Idempotent) | GAP(no audit) |

### Watchlists (8 endpoints)

| # | Endpoint | Cross-org | RBAC | Fail-closed | Audit |
|---|----------|-----------|------|-------------|-------|
| 13 | GET …/watchlists | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(TestWatchlist_ViewerCannotWrite) | N/A | N/A |
| 14 | POST …/watchlists | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(TestWatchlist_ViewerCannotWrite) | T(TestTierGating_Watchlists_FreeLimit) | T(TestAuditIntegration_Watchlists) |
| 15 | GET …/watchlists/{wid} | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(TestWatchlist_ViewerCannotWrite) | N/A | N/A |
| 16 | PATCH …/watchlists/{wid} | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(TestWatchlist_ViewerCannotWrite) | N/A | T(TestAuditIntegration_Watchlists) |
| 17 | DELETE …/watchlists/{wid} | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(TestWatchlist_ViewerCannotWrite) | N/A | T(TestAuditIntegration_Watchlists) |
| 18 | GET …/watchlists/{wid}/items | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(TestWatchlist_ViewerCannotWrite) | N/A | N/A |
| 19 | POST …/watchlists/{wid}/items | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(TestWatchlist_ViewerCannotWrite) | T(TestWatchlistItem_Duplicate) | N/A |
| 20 | DELETE …/watchlists/{wid}/items/{iid} | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(TestWatchlist_ViewerCannotWrite) | N/A | N/A |

### Channels (7 endpoints)

| # | Endpoint | Cross-org | RBAC | Fail-closed | Audit |
|---|----------|-----------|------|-------------|-------|
| 21 | GET …/channels | GAP | GAP(no RBAC test) | N/A | N/A |
| 22 | POST …/channels | GAP | GAP | T(TestTierGating_Channels_FreeBlocksEmail) | T(TestAuditIntegration_Channels) |
| 23 | GET …/channels/{cid} | GAP | GAP | N/A | N/A |
| 24 | PATCH …/channels/{cid} | GAP | GAP | T(TestPatchChannel_WebhookSSRFBlocked) | T(TestAuditIntegration_Channels) |
| 25 | DELETE …/channels/{cid} | GAP | GAP | T(TestDeleteChannel_409IfActiveRuleBound) | T(TestAuditIntegration_Channels) |
| 26 | POST …/channels/{cid}/rotate-secret | GAP | GAP | T(TestRotateSecret_EmailChannel_Rejected) | GAP(no audit) |
| 27 | POST …/channels/{cid}/clear-secondary | GAP | GAP | T(TestClearSecondary_EmailChannel_Rejected) | GAP(no audit) |

### Alert Events (1 endpoint)

| # | Endpoint | Cross-org | RBAC | Fail-closed | Audit |
|---|----------|-----------|------|-------------|-------|
| 28 | GET …/alert-events | T(TestAlertEvents_CrossOrgIsolation) | T(middleware) | N/A | N/A |

### SSO (6 endpoints)

| # | Endpoint | Cross-org | RBAC | Fail-closed | Audit |
|---|----------|-----------|------|-------------|-------|
| 29 | POST …/sso | GAP | T(TestSSOConnection_RBAC) | T(TestSSOConnection_TierGating) | T(TestAudit_SSOOperations) |
| 30 | GET …/sso | GAP | T(TestSSOConnection_RBAC) | N/A | N/A |
| 31 | PATCH …/sso | GAP | T(TestSSOConnection_RBAC) | N/A | T(TestAudit_SSOOperations) |
| 32 | DELETE …/sso | GAP | T(TestSSOConnection_RBAC) | N/A | T(TestAudit_SSOOperations) |
| 33 | PUT …/sso/domains | GAP | T(TestSSOConnection_RBAC) | T(TestPutSSODomains_NoConnection) | GAP(no audit) |
| 34 | GET …/sso/link | GAP | T(TestSSOConnection_RBAC) | N/A | N/A |

### Audit Log (1 endpoint)

| # | Endpoint | Cross-org | RBAC | Fail-closed | Audit |
|---|----------|-----------|------|-------------|-------|
| 35 | GET …/audit-log | T(TestAuditAPI_CrossOrgIsolation) | T(TestAuditAPI_RBAC) | T(TestAuditAPI_TierGating) | N/A |

### Deliveries (3 endpoints)

| # | Endpoint | Cross-org | RBAC | Fail-closed | Audit |
|---|----------|-----------|------|-------------|-------|
| 36 | GET …/deliveries | T(TestDeliveries_CrossOrgIsolation) | T(TestReplayDelivery_RBAC_ViewerMemberForbidden) | N/A | N/A |
| 37 | GET …/deliveries/{did} | T(TestDeliveries_CrossOrgIsolation) | T(TestReplayDelivery_RBAC_ViewerMemberForbidden) | N/A | N/A |
| 38 | POST …/deliveries/{did}/replay | T(TestDeliveries_CrossOrgIsolation) | T(TestReplayDelivery_RBAC_ViewerMemberForbidden) | T(TestReplayDelivery_RateLimited) | GAP(no audit) |

### Alert Rules (10 endpoints)

| # | Endpoint | Cross-org | RBAC | Fail-closed | Audit |
|---|----------|-----------|------|-------------|-------|
| 39 | GET …/alert-rules | T(TestAlertRule_CrossOrgIsolation) | T(TestAlertRule_ViewerCannotWrite) | N/A | N/A |
| 40 | POST …/alert-rules | T(TestAlertRule_CrossOrgIsolation) | T(TestAlertRule_ViewerCannotWrite) | T(TestTierGating_AlertRules_FreeLimit) | T(TestAuditIntegration_AlertRules) |
| 41 | POST …/alert-rules/validate | T(TestAlertRule_CrossOrgIsolation) | T(TestAlertRule_ViewerCannotWrite) | N/A | N/A |
| 42 | GET …/alert-rules/{rid} | T(TestAlertRule_CrossOrgIsolation) | T(TestAlertRule_ViewerCannotWrite) | N/A | N/A |
| 43 | PATCH …/alert-rules/{rid} | T(TestAlertRule_CrossOrgPatchAndDelete) | T(TestAlertRule_ViewerCannotWrite) | N/A | T(TestAuditIntegration_AlertRules) |
| 44 | DELETE …/alert-rules/{rid} | T(TestAlertRule_CrossOrgPatchAndDelete) | T(TestAlertRule_ViewerCannotWrite) | N/A | T(TestAuditIntegration_AlertRules) |
| 45 | POST …/alert-rules/{rid}/dry-run | T(TestDryRun_CrossOrgIsolation) | T(TestAlertRule_ViewerCannotWrite) | N/A | N/A |
| 46 | GET …/alert-rules/{rid}/channels | T(TestAlertRule_CrossOrgIsolation) | T(TestAlertRule_ViewerCannotWrite) | N/A | N/A |
| 47 | PUT …/alert-rules/{rid}/channels/{cid} | T(TestBindChannelToRule_CrossOrgChannelRejected) | T(TestAlertRule_ViewerCannotWrite) | N/A | GAP(no audit) |
| 48 | DELETE …/alert-rules/{rid}/channels/{cid} | GAP(no cross-org unbind test) | T(TestAlertRule_ViewerCannotWrite) | N/A | GAP(no audit) |

### Reports (8 endpoints)

| # | Endpoint | Cross-org | RBAC | Fail-closed | Audit |
|---|----------|-----------|------|-------------|-------|
| 49 | GET …/reports | T(TestReports_CrossOrgIsolation) | T(TestReports_RBAC_ViewerCannotWrite) | N/A | N/A |
| 50 | POST …/reports | T(TestReports_CrossOrgIsolation) | T(TestReports_RBAC_ViewerCannotWrite) | GAP(no tier test) | GAP(no audit) |
| 51 | GET …/reports/{rid} | T(TestReports_CrossOrgIsolation) | T(TestReports_RBAC_ViewerCannotWrite) | N/A | N/A |
| 52 | PATCH …/reports/{rid} | T(TestReports_CrossOrgIsolation) | T(TestReports_RBAC_ViewerCannotWrite) | N/A | GAP(no audit) |
| 53 | DELETE …/reports/{rid} | T(TestReports_CrossOrgIsolation) | T(TestReports_RBAC_ViewerCannotWrite) | N/A | GAP(no audit) |
| 54 | GET …/reports/{rid}/channels | T(TestReports_CrossOrgIsolation) | T(TestReports_RBAC_ViewerCannotWrite) | N/A | N/A |
| 55 | PUT …/reports/{rid}/channels/{cid} | T(TestBindChannelToReport_CrossOrgChannelRejected) | T(TestReports_RBAC_ViewerCannotWrite) | N/A | GAP(no audit) |
| 56 | DELETE …/reports/{rid}/channels/{cid} | GAP(no cross-org unbind test) | T(TestReports_RBAC_ViewerCannotWrite) | N/A | GAP(no audit) |

### AI (2 endpoints)

| # | Endpoint | Cross-org | RBAC | Fail-closed | Audit |
|---|----------|-----------|------|-------------|-------|
| 57 | POST …/ai/nl-search | T(TestAIHandlers_CrossOrgIsolation) | T(middleware) | T(TestNLSearchHandler_QuotaDenied) | N/A |
| 58 | POST …/ai/summarize/{cve_id} | T(TestAIHandlers_CrossOrgIsolation) | T(middleware) | T(TestSummarizeHandler_QuotaDenied) | N/A |

### Saved Searches (6 endpoints)

| # | Endpoint | Cross-org | RBAC | Fail-closed | Audit |
|---|----------|-----------|------|-------------|-------|
| 59 | GET …/saved-searches | T(TestSavedSearch_CrossOrgIsolation) | T(TestSavedSearch_RBAC) | N/A | N/A |
| 60 | POST …/saved-searches | T(TestSavedSearch_CrossOrgIsolation) | T(TestSavedSearch_RBAC) | N/A | T(TestAuditIntegration_SavedSearches) |
| 61 | GET …/saved-searches/{sid} | T(TestSavedSearch_CrossOrgIsolation) | T(TestSavedSearch_RBAC) | N/A | N/A |
| 62 | PATCH …/saved-searches/{sid} | T(TestSavedSearch_CrossOrgIsolation) | T(TestSavedSearch_RBAC) | N/A | T(TestAuditIntegration_SavedSearches) |
| 63 | DELETE …/saved-searches/{sid} | T(TestSavedSearch_CrossOrgIsolation) | T(TestSavedSearch_RBAC) | N/A | T(TestAuditIntegration_SavedSearches) |
| 64 | POST …/saved-searches/{sid}/execute | T(TestSavedSearch_CrossOrgIsolation) | T(TestSavedSearch_RBAC) | N/A | N/A |

### Groups (8 endpoints)

| # | Endpoint | Cross-org | RBAC | Fail-closed | Audit |
|---|----------|-----------|------|-------------|-------|
| 65 | GET …/groups | T(TestCrossOrg_GroupAccess) | T(TestCreateGroup_AsViewer) | N/A | N/A |
| 66 | POST …/groups | T(TestCrossOrg_GroupAccess) | T(TestCreateGroup_AsViewer) | N/A | GAP(no audit) |
| 67 | GET …/groups/{gid} | T(TestCrossOrg_GroupAccess) | T(TestCreateGroup_AsViewer) | N/A | N/A |
| 68 | PATCH …/groups/{gid} | GAP(update not tested) | T(TestCreateGroup_AsViewer) | N/A | GAP(no audit) |
| 69 | DELETE …/groups/{gid} | GAP(delete not tested) | T(TestCreateGroup_AsViewer) | N/A | GAP(no audit) |
| 70 | GET …/groups/{gid}/members | GAP(list not tested) | T(TestCreateGroup_AsViewer) | N/A | N/A |
| 71 | POST …/groups/{gid}/members | GAP(add not tested) | T(TestCreateGroup_AsViewer) | T(TestAddGroupMember_Duplicate) | GAP(no audit) |
| 72 | DELETE …/groups/{gid}/members/{uid} | GAP(remove not tested) | T(TestCreateGroup_AsViewer) | N/A | GAP(no audit) |

### §3 Summary

| Column | Tested | GAP |
|--------|--------|-----|
| Cross-org | 51 | 21 |
| RBAC | 65 | 7 |
| Fail-closed | 18 tested, 35 N/A | 1 |
| Audit log | 17 tested, 35 N/A | 20 |

**21 cross-org GAPs:** org tier (#2), all 7 channels (#21-27), all 6 SSO (#29-34), cancel invitation (#9), alert-rule-channel unbind (#48), report-channel unbind (#56), 5 group sub-endpoints (#68-72).

**7 RBAC GAPs:** all 7 channel endpoints (#21-27) have no viewer/member role enforcement test.

**20 audit log GAPs:** reports (5), groups (5), API keys (2), channels rotate/clear (2), invitation create/cancel (2), delivery replay (1), PATCH org (1), SSO domains (1), rule-channel bind/unbind (2).

## §4.5 Cross-Handler Consistency & Semantic Spot-Checks

### §4.5A: Cross-Handler Consistency

**Pattern 1: Tier-deny audit logging**

When a resource creation is blocked by a tier limit, the handler should audit the denial before returning 403. This pattern is implemented in 3 of 5 handlers:

| Handler | Tier deny | Audits on deny? | Code |
|---------|-----------|-----------------|------|
| `createAlertRuleHandler` | count ≥ limit → 403 | YES — `auditLog` at alert_rules.go:185 | ✓ |
| `createChannelHandler` | channel type blocked → 403 | YES — `auditLog` at channels.go:99 | ✓ |
| `createWatchlistHandler` | count ≥ limit → 403 | YES — `auditLog` at watchlists.go:190 | ✓ |
| `createInvitationHandler` | count ≥ limit → 403 | **NO** — straight to `http.Error` at orgs.go:405 | ✗ VIOLATION |
| `createSSOHandler` | not enterprise → 403 | **NO** — `requireEnterpriseTier` helper at sso.go:93 has no access to `srv` | ✗ VIOLATION |

**Impact:** Tier denials for invitations and SSO are invisible in the audit log. Admin can't see why an invitation failed without checking server logs.

**Pattern 2: CRUD audit logging**

Mutating endpoints should audit create/update/delete operations. 5 handler groups implement this fully; 4 do not:

| Handler group | Create | Update | Delete | Status |
|---------------|--------|--------|--------|--------|
| alert_rules | ✓ (263) | ✓ (509) | ✓ (554) | Full |
| channels | ✓ (166) | ✓ (324) | ✓ (378) | Full |
| watchlists | ✓ (240) | ✓ (409) | ✓ (453) | Full |
| saved_searches | ✓ (135) | ✓ (313) | ✓ (365) | Full |
| sso | ✓ (182) | ✓ (361) | ✓ (412) | Full |
| reports | ✗ | ✗ | ✗ | **NONE** |
| groups | ✗ | ✗ | ✗ | **NONE** |
| apikeys | ✗ | N/A | ✗ | **NONE** |
| deliveries (replay) | N/A | N/A | N/A | ✗ (replay is mutating but unaudited) |
| org members | N/A | ✓ (270) | ✓ (329) | Partial (no create/invite audit) |
| channel rotate/clear | N/A | N/A | N/A | ✗ (rotate-secret and clear-secondary unaudited) |

**Impact:** Reports, groups, API keys, and deliveries have zero audit trail. An admin deleting all reports or revoking API keys produces no audit record.

**Pattern 3: Wrong function called (PRODUCTION BUG)**

`getOrgTierHandler` (org_tier.go:61) calls `CountMembersByOrg` (active members only) for the tier dashboard display. `createInvitationHandler` (orgs.go:398) calls `CountMemberSlotsUsedByOrg` (members + pending invitations) for tier enforcement.

A user sees `used: 3 / limit: 5` on the dashboard, tries to invite 2 people, but gets blocked because 2 pending invitations already consume slots (actual slot usage: 5). The display and enforcement use different count functions, creating a confusing UX and misleading tier information.

### §4.5B: Right-Function-Called (subagent findings)

- `CountAlertRulesByOrg`: used consistently in both tier display (org_tier.go:49) and enforcement (alert_rules.go:178). **CORRECT.**
- `CountWatchlistsByOrg`: used consistently in both tier display (org_tier.go:55) and enforcement (watchlists.go:183). **CORRECT.**
- `CountMembersByOrg` vs `CountMemberSlotsUsedByOrg`: **INCONSISTENT** — see Pattern 3 above.

### §4.5C: Defense-in-Depth (subagent findings)

- **D1: RBAC middleware + handler-level orgID extraction** — All handlers verify `ctxOrgID` was set by middleware. If middleware fails to set it, handler returns 400. **GOOD.**
- **D2: CSRF middleware + cookie auth** — `X-Requested-By` required only for cookie auth. API keys exempt. Tests verify all paths. **GOOD.**
- **D3: No handler-level auth safety net** — Handlers trust `ctxUserID` from middleware with no zero-value check. If a route is accidentally registered without auth middleware, handler proceeds with `uuid.Nil` as user ID. **GAP** — LOW in practice (route registration centralized), but defense-in-depth principle violated.

## §4.6 TOCTOU Analysis

### Multi-step flows enumerated

| # | Flow | Step A | Step B | Window? | Mitigation | Status |
|---|------|--------|--------|---------|------------|--------|
| T1 | SSO login redirect → callback | Load connection, check enabled (oauth_oidc.go:212-225) | Re-load connection, re-check enabled (oauth_oidc.go:126-139) | YES — connection can be deleted/disabled between redirect and callback | Re-check at callback ✓ | Mitigated — but no test for "connection deleted between redirect and callback" |
| T2 | SSO link init → link callback | Load connection, check enabled (oauth_oidc.go:291-304) | Re-check via oidcVerifyCallback (oauth_oidc.go:316) | YES — same as T1 | Re-check at callback ✓ | Mitigated — but no test |
| T3 | Alert rule tier check → create | CountAlertRulesByOrg (alert_rules.go:178) | CreateAlertRule (alert_rules.go:225+) | YES — concurrent request can increment count between check and create | None — no lock or DB constraint | GAP — concurrent requests can exceed tier limit |
| T4 | Watchlist tier check → create | CountWatchlistsByOrg (watchlists.go:183) | create (watchlists.go:218+) | YES — same as T3 | None | GAP — same pattern |
| T5 | Invitation tier check → create | CountMemberSlotsUsedByOrg (orgs.go:398) | create invitation (orgs.go:420+) | YES — same as T3 | None | GAP — same pattern |
| T6 | Refresh token rotation | Read token + check grace (auth.go refreshGrace) | Rotate token + issue new | YES — concurrent refreshes with same token | Grace period window exists but untested at 53.3% coverage | GAP — no test for concurrent refresh race |
| T7 | Delivery replay rate limit → replay | checkReplayLimit (deliveries.go:34) — per-org mutex | ReplayDelivery (deliveries.go:293+) | NO — check+increment atomic under mutex | Mutex-protected ✓ | Mitigated |

### TOCTOU Summary

- **3 tier gating races** (T3-T5): All tier check→create flows use check-then-act without locking. Concurrent requests at the limit can exceed it by 1. Severity: LOW — tier limit is a business rule, not a security boundary.
- **2 SSO redirect/callback windows** (T1-T2): Mitigated by re-checking connection state at callback. No test verifying the mitigation works (connection deleted mid-flow). Severity: LOW — mitigation exists, test coverage is the gap.
- **1 refresh token race** (T6): Two concurrent refreshes with the same token could both succeed if the grace period check reads stale state. Severity: MEDIUM — could allow token reuse beyond intended window.

## §4 Assertion Quality Issues (6)

1. **OAuth cookie attributes not verified** — oauth_github_test.go, oauth_google_test.go — `HttpOnly`, `Secure`, `SameSite` not checked on auth cookies in callback tests. Source: assertion.
2. **JWT claims content not verified** — auth_test.go — No test decodes JWT to verify `sub`, `exp` range, `iat` presence. Token lifetime could be set to 100 years undetected. Source: assertion.
3. **SSRF error message not verified** — channels_test.go — Tests check status 422 but not which URL was blocked. Source: assertion.
4. **CreateAlertRule boolean fields not verified** — store alert_rule tests — `HasEpssCondition`, `IsEpssOnly`, `FireOnNonMaterialChanges` not asserted. Sqlc parameter swap undetectable. Source: assertion.
5. **ChannelHasActiveBindings short-circuit not tested** — store report_channel tests — Composite function may never call second check. Source: assertion.
6. **Test helpers use only default booleans** — store helpers_test.go — All boolean fields always get defaults. Non-default paths untested. Source: assertion.

## Gap Context

| Category | Findings | Action |
|----------|----------|--------|
| Security matrix GAPs (§3) | 49 | Add security-specific tests per matrix cell |
| Cross-handler violations (§4.5A) | 3 | Fix code (add audit calls) + add tests |
| Production bugs (§4.5B) | 1 | Fix code (wrong function) + add test |
| Coverage triage gaps (§2) | 22 correctness + 8 security | Add test cases per subagent findings |
| TOCTOU windows (§4.6) | 6 | Add concurrency tests or document as accepted risk |
| Assertion quality (§4) | 6 | Strengthen existing test assertions |
| **Total unique findings** | | **~95** |

## What's Well-Covered

- **Middleware stack (100%):** `RequireAuthenticated`, `RequireOrgRole`, CSRF, security headers, body size limits, path traversal, null byte injection — all verified by dedicated tests with good assertion quality.
- **Tier package (100%):** `ResolveInt`, `ResolveBool`, `IntLimit`, `BoolFlag` — all fully covered with tests for override precedence, unlimited sentinel, and default values.
- **Store transaction helper selection:** Audit of all ~80 store methods confirmed correct helper usage — `withOrgTx` for org-scoped sqlc, `withOrgRawTx` for squirrel, `withBypassTx` for pre-context/cross-org, `WorkerTx` for workers. Zero misuse found.
- **Alert event deduplication:** `InsertAlertEvent` `ON CONFLICT DO NOTHING RETURNING id` pattern tested for both "new event" and "duplicate suppressed" paths.
- **Watchlist isolation:** `TestWatchlist_CrossOrgReadWriteIsolation` and `TestWatchlist_ViewerCannotWrite` are thorough — cross-org for all CRUD + RBAC per operation. Model test pattern.

## Production Bugs Discovered

1. **BUG-1: `getOrgTierHandler` uses wrong count function for members** — [org_tier.go:61](internal/api/org_tier.go#L61) — Source: semantic (§4.5B)
   - `CountMembersByOrg` returns active members only. The enforcement handler (`createInvitationHandler` at orgs.go:398) uses `CountMemberSlotsUsedByOrg` which includes pending invitations. Dashboard shows `used: 3 / limit: 5` but user gets 403 on invite because 2 pending invitations consume slots. Fix: change to `CountMemberSlotsUsedByOrg`.

## Security-Critical Gaps (62)

### §3 Matrix — Cross-Org Isolation (21 GAPs)

1. GET /orgs/{id}/tier — no cross-org test — [org_tier_test.go](internal/api/org_tier_test.go) — matrix
2. DELETE /invitations/{id} — not in cross-org test — [orgs_test.go](internal/api/orgs_test.go) — matrix
3. GET /channels — no cross-org test — [channels_test.go](internal/api/channels_test.go) — matrix
4. POST /channels — no cross-org test — [channels_test.go](internal/api/channels_test.go) — matrix
5. GET /channels/{cid} — no cross-org test — [channels_test.go](internal/api/channels_test.go) — matrix
6. PATCH /channels/{cid} — no cross-org test — [channels_test.go](internal/api/channels_test.go) — matrix
7. DELETE /channels/{cid} — no cross-org test — [channels_test.go](internal/api/channels_test.go) — matrix
8. POST /channels/{cid}/rotate-secret — no cross-org test — [channels_test.go](internal/api/channels_test.go) — matrix
9. POST /channels/{cid}/clear-secondary — no cross-org test — [channels_test.go](internal/api/channels_test.go) — matrix
10. POST /sso — no cross-org test — [sso_test.go](internal/api/sso_test.go) — matrix
11. GET /sso — no cross-org test — [sso_test.go](internal/api/sso_test.go) — matrix
12. PATCH /sso — no cross-org test — [sso_test.go](internal/api/sso_test.go) — matrix
13. DELETE /sso — no cross-org test — [sso_test.go](internal/api/sso_test.go) — matrix
14. PUT /sso/domains — no cross-org test — [sso_test.go](internal/api/sso_test.go) — matrix
15. GET /sso/link — no cross-org test — [sso_test.go](internal/api/sso_test.go) — matrix
16. DELETE /alert-rules/{rid}/channels/{cid} — no cross-org unbind test — [alert_rules_test.go](internal/api/alert_rules_test.go) — matrix
17. DELETE /reports/{rid}/channels/{cid} — no cross-org unbind test — [reports_test.go](internal/api/reports_test.go) — matrix
18. PATCH /groups/{gid} — no cross-org test — [groups_test.go](internal/api/groups_test.go) — matrix
19. DELETE /groups/{gid} — no cross-org test — [groups_test.go](internal/api/groups_test.go) — matrix
20. GET /groups/{gid}/members — no cross-org test — [groups_test.go](internal/api/groups_test.go) — matrix
21. POST /groups/{gid}/members — no cross-org test — [groups_test.go](internal/api/groups_test.go) — matrix

### §3 Matrix — RBAC (7 GAPs)

22. GET /channels — no RBAC test — [channels_test.go](internal/api/channels_test.go) — matrix
23. POST /channels — no RBAC test — [channels_test.go](internal/api/channels_test.go) — matrix
24. GET /channels/{cid} — no RBAC test — [channels_test.go](internal/api/channels_test.go) — matrix
25. PATCH /channels/{cid} — no RBAC test — [channels_test.go](internal/api/channels_test.go) — matrix
26. DELETE /channels/{cid} — no RBAC test — [channels_test.go](internal/api/channels_test.go) — matrix
27. POST /channels/{cid}/rotate-secret — no RBAC test — [channels_test.go](internal/api/channels_test.go) — matrix
28. POST /channels/{cid}/clear-secondary — no RBAC test — [channels_test.go](internal/api/channels_test.go) — matrix

### §3 Matrix — Audit Log (20 GAPs)

29. PATCH /orgs/{id} — no audit — [orgs.go](internal/api/orgs.go) — matrix
30. POST /invitations — no audit on create or tier-deny — [orgs.go](internal/api/orgs.go) — matrix
31. DELETE /invitations/{id} — no audit — [orgs.go](internal/api/orgs.go) — matrix
32. POST /api-keys — no audit — [apikeys.go](internal/api/apikeys.go) — matrix
33. DELETE /api-keys/{id} — no audit — [apikeys.go](internal/api/apikeys.go) — matrix
34. POST /channels/{cid}/rotate-secret — no audit — [channels.go](internal/api/channels.go) — matrix
35. POST /channels/{cid}/clear-secondary — no audit — [channels.go](internal/api/channels.go) — matrix
36. POST /deliveries/{did}/replay — no audit — [deliveries.go](internal/api/deliveries.go) — matrix
37. PUT /alert-rules/{rid}/channels/{cid} — no audit — [alert_rules.go](internal/api/alert_rules.go) — matrix
38. DELETE /alert-rules/{rid}/channels/{cid} — no audit — [alert_rules.go](internal/api/alert_rules.go) — matrix
39. POST /reports — no audit — [reports.go](internal/api/reports.go) — matrix
40. PATCH /reports/{rid} — no audit — [reports.go](internal/api/reports.go) — matrix
41. DELETE /reports/{rid} — no audit — [reports.go](internal/api/reports.go) — matrix
42. PUT /reports/{rid}/channels/{cid} — no audit — [reports.go](internal/api/reports.go) — matrix
43. DELETE /reports/{rid}/channels/{cid} — no audit — [reports.go](internal/api/reports.go) — matrix
44. POST /groups — no audit — [groups.go](internal/api/groups.go) — matrix
45. PATCH /groups/{gid} — no audit — [groups.go](internal/api/groups.go) — matrix
46. DELETE /groups/{gid} — no audit — [groups.go](internal/api/groups.go) — matrix
47. POST /groups/{gid}/members — no audit — [groups.go](internal/api/groups.go) — matrix
48. DELETE /groups/{gid}/members/{uid} — no audit — [groups.go](internal/api/groups.go) — matrix

### §3 Matrix — Fail-Closed (1 GAP)

49. POST /reports — no tier test — [reports_test.go](internal/api/reports_test.go) — matrix

### §4.5 Cross-Handler Violations (2)

50. `createInvitationHandler` tier-deny path has no audit — [orgs.go:405](internal/api/orgs.go#L405) — semantic
51. `requireEnterpriseTier` SSO tier-deny has no audit (helper lacks `srv` access) — [sso.go:93](internal/api/sso.go#L93) — semantic

### Coverage Triage — Security (8)

52. `refreshGrace` (53.3%) — grace period window, token theft detection, family ID propagation untested — [auth.go](internal/api/auth.go) — coverage
53. API key no round-trip auth test — `createAPIKeyHandler` (51%) returns `raw_key` but no test uses it to authenticate — [apikeys.go](internal/api/apikeys.go) — coverage
54. OIDC `email_verified` check untested — `oidcVerifyCallback` (48.4%) — [oauth_oidc.go](internal/api/oauth_oidc.go) — coverage
55. Login argon2 semaphore exhaustion (503 path) untested — `loginHandler` (64.9%) — [auth.go](internal/api/auth.go) — coverage
56. Invitation role escalation path untested — member inviting as admin — `createInvitationHandler` (54.5%) — [orgs.go](internal/api/orgs.go) — coverage
57. `LookupAPIKey` no expired key test — auth hot-path time-based filtering not verified — [store/apikey.go](internal/store/apikey.go) — coverage
58. `RotateSigningSecret` promotion chain — no test verifying old primary becomes new secondary — [store/notification_channel.go](internal/store/notification_channel.go) — coverage
59. `ListActiveChannelsForFanout` signing secret format not validated — [store/alert_rule_channel.go](internal/store/alert_rule_channel.go) — assertion

### Semantic / Defense-in-Depth (3)

60. No handler-level auth safety net — handlers trust `ctxUserID` from middleware with no zero-value check — [server.go](internal/api/server.go) — semantic
61. IPv6 loopback (`[::1]`) SSRF bypass path untested — `validateWebhookURL` (93.3%) — [channels.go](internal/api/channels.go) — coverage
62. Refresh token concurrent rotation race — two simultaneous refreshes could both succeed — [auth.go](internal/api/auth.go) — semantic

## Correctness Gaps (22)

1. `pgErrCode` (0%) — unique constraint detection in register/accept-invitation — [auth.go:35](internal/api/auth.go#L35) — coverage
2. `encodeDeliveryCursor` (0%) — pagination cursor encoding — [deliveries.go:88](internal/api/deliveries.go#L88) — coverage
3. `getCVEHandler` (40%) — 404, 500, nullable field rendering untested — [cves.go](internal/api/cves.go) — coverage
4. `getCVESourcesHandler` (47.6%) — 400, 500, empty array untested — [cves.go](internal/api/cves.go) — coverage
5. `listCVEsHandler` (66.7%) — cursor error, epss/kev/modified_since filters untested — [cves.go](internal/api/cves.go) — coverage
6. `updateOrgHandler` (45%) — validation, error paths untested — [orgs.go](internal/api/orgs.go) — coverage
7. `createReportHandler` (46.2%) — validation edges, channel binding untested — [reports.go](internal/api/reports.go) — coverage
8. `createAlertRuleHandler` (52.4%) — JSON error, validation edges untested — [alert_rules.go](internal/api/alert_rules.go) — coverage
9. `patchAlertRuleHandler` (67%) — invalid DSL, state transitions, 404 untested — [alert_rules.go](internal/api/alert_rules.go) — coverage
10. `createReportScheduleHandler` (59.1%) — validation, error paths untested — [reports.go](internal/api/reports.go) — coverage
11. Group handlers (42-62%) — store error paths, validation, pagination untested — [groups.go](internal/api/groups.go) — coverage
12. `withBypassTx` panic recovery path untested — [store/store.go](internal/store/store.go) — coverage
13. `withOrgRawTx` panic recovery path untested — [store/store.go](internal/store/store.go) — coverage
14. `BootstrapFirstUserOrg` `CreateOrg` failure — manual tx error propagation untested — [store/org.go](internal/store/org.go) — coverage
15. `BootstrapFirstUserOrg` `CreateOrgMember` failure — partial state rollback untested — [store/org.go](internal/store/org.go) — coverage
16. `ListCVEs` (0%) — sqlc passthrough, zero coverage — [store/cve.go](internal/store/cve.go) — coverage
17. `CompleteJob`/`FailJob` — non-existent job ID behavior undocumented — [store/jobs.go](internal/store/jobs.go) — coverage
18. `UpsertDelivery` — manual tx management lacks panic recovery — [store/notification_delivery.go](internal/store/notification_delivery.go) — coverage
19. `GetCVEDetail` — child-table query failures untested — [store/cve.go](internal/store/cve.go) — coverage
20. `acceptInvitationHandler` (66.7%) — invalid token, expired, already-accepted paths untested — [auth.go](internal/api/auth.go) — coverage
21. `issueRefreshPair` (50%) — JWT signing error, DB storage error paths — [auth.go](internal/api/auth.go) — coverage
22. Tier gating race conditions (T3-T5) — concurrent requests can exceed tier limits — [alert_rules.go](internal/api/alert_rules.go), [watchlists.go](internal/api/watchlists.go), [orgs.go](internal/api/orgs.go) — semantic

## Nice-to-Have (25)

Top 5 examples (full list: 11 from API package, 14 from store package):
1. `loginHandler` JSON decode error / missing email/password — [auth.go](internal/api/auth.go) — coverage
2. `createWatchlistHandler` empty name / JSON decode error — [watchlists.go](internal/api/watchlists.go) — coverage
3. `listDeliveriesHandler` invalid UUID filters, cursor parsing — [deliveries.go](internal/api/deliveries.go) — coverage
4. Store 87.5% pattern — outer `if err != nil` after `withOrgTx`/`withBypassTx` across ~40 functions — [store/](internal/store/) — coverage
5. `fromNullUUID` valid-UUID branch, `scanCVERow`/`encodeDSLCursor` error branches — [store/](internal/store/) — coverage

Remaining 20: Store auth wrapper error branches (6), retention outer error branches (10), miscellaneous BeginTx/SET LOCAL errors (4).

## Key Observations

### Cross-Cutting Patterns

1. **Channel security desert:** All 7 channel endpoints lack both cross-org AND RBAC tests. This is the largest single-endpoint-group security gap. The middleware provides protection, but it's unverified for this entire endpoint group.

2. **Audit logging inconsistency is systematic:** 4 of 9 handler groups have zero audit logging (reports, groups, API keys, deliveries). The pattern is clearly "early-implemented handlers audit, later-added ones don't." This suggests audit was added per-handler, not via middleware or interceptor pattern.

3. **Tier-deny audit inconsistency:** 3 of 5 tier-deny paths audit the denial. The 2 that don't (invitations, SSO) were likely added after the audit pattern was established. The SSO case is structural — `requireEnterpriseTier` is a standalone function without `srv` access.

4. **Coverage ≠ confidence mismatch:** Channels have decent coverage for some endpoints (e.g., SSRF validation at 93.3%, email validation at 94.1%) but zero security isolation tests. The coverage numbers mask the fact that the most important properties are untested.

5. **Store layer 87.5% ceiling:** ~40 store methods hit exactly 87.5% because the outer error branch after the transaction wrapper is never hit in integration tests. This is architectural, not a gap — testing it requires injecting DB failures.

6. **Refresh token security needs attention:** `refreshGrace` at 53.3% coverage means the token theft detection mechanism is effectively untested. Combined with the TOCTOU race (T6), the refresh token security surface is the weakest part of the auth system.

7. **No store-layer input validation (by design):** All validation happens at the API handler layer. This is an intentional YAGNI decision with FK constraints and RLS as safety nets. Appropriate for current stage but worth noting for security audit.

### Methodology Notes

- Subagent reports: [subagent-store-findings.md](dev/test-coverage-reports/subagent-store-findings.md), [subagent-api-findings.md](dev/test-coverage-reports/subagent-api-findings.md)
- API subagent found 0 confirmed production bugs (corrected 4 initial findings after re-reading tests)
- Store subagent found 0 production bugs
- Main agent semantic analysis found 1 production bug (BUG-1: wrong count function in org_tier.go)
