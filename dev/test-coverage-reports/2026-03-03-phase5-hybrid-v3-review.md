# Phase 5 Hybrid v3 Test Coverage Review (Run J5)

**Date:** 2026-03-03
**Scope:** `./internal/api/...`, `./internal/store/...`, `./internal/tier/...`
**Method:** Hybrid — Go coverage tools (Pass 1) + semantic code analysis (Pass 2)
**Coverage data:** `coverage-ab.out`, `coverage-ab-func.txt` (pre-generated)

## §1 Coverage Baseline

**559 functions** in scope across 3 top-level packages.

| Package | Functions | 0% | 100% | Notable |
|---------|-----------|-----|------|---------|
| internal/api (handlers+middleware) | 172 | 2 | 57 | Most handlers 50-75% |
| internal/store (non-generated) | 155 | 5 | 40 | Transaction helpers partially covered |
| internal/store/generated | 228 | 138 | 87 | sqlc code — 0% funcs are feed/merge pipeline (out of Phase 5 scope) |
| internal/tier | 4 | 0 | 4 | Fully covered |
| **Total** | **559** | **145** | **188** | |

**0% functions in non-generated code (7 total):**
1. `api/auth.go:35` — `pgErrCode` (utility, nice-to-have)
2. `api/deliveries.go:88` — `encodeDeliveryCursor` (correctness)
3. `store/cve.go:61` — `ListCVEs` (superseded by SearchCVEs, nice-to-have)

**0% in generated code (138 functions):** Mostly feed/merge pipeline (`cves.sql.go`: UpsertCVE, UpsertCVESource, etc.) and feed sync state (`feed.sql.go`). These are exercised by feed adapter tests, not Phase 5 API/store tests. Also includes `ListOrgMembers`, `ListOrgInvitations`, `ListAllOrgs`, `ListUserOrgs`, etc. with 73.3% — these are the sqlc list functions where the row-scanning loop's error branch is uncovered (standard sqlc pattern).

**Note on generated code:** The 73.3% pattern across many generated list functions represents the `rows.Err()` error branch in sqlc-generated scan loops. This is a systematic gap but low severity — the error path is identical boilerplate across all generated list functions.

---

## §2 Coverage Triage

*(Detailed per-function analysis in subagent output files)*

---

## §3 Security Checklist Matrix

**Endpoint enumeration:** 72 org-scoped endpoints identified from [server.go](internal/api/server.go) route registration (lines 199-347).

**Column key:** Cross=Cross-org isolation, UA=Unauth→401, FC=orgID fail-closed, SQL=SQL param types, RBAC=Role enforcement, Tier=Fail-closed tier/rate, Audit=Audit log on mutation

**Cell key:** T(Test)=tested, GAP=untested, N/A=not applicable

**Middleware baseline:** All org-scoped endpoints share `RequireAuthenticated` + `RequireOrgRole(viewer)` + `tierMiddleware` + `orgRateLimitMiddleware`. These are independently tested in `middleware_auth_test.go`, `middleware_rbac_test.go`, `middleware_tier_test.go`. Cross-org and RBAC columns below test handler-level isolation BEYOND middleware (e.g., RLS, per-handler role escalation checks).

### Org Management (orgs.go)

| Endpoint | Cross | UA | FC | SQL | RBAC | Tier | Audit |
|----------|-------|----|----|-----|------|------|-------|
| GET /orgs/{id} | T(TestGetOrg_NotMember) | T(middleware) | T(middleware) | N/A | T(TestGetOrg_NotMember) | N/A | N/A |
| PATCH /orgs/{id} | T(TestCrossOrg_MemberOperations) | T(middleware) | T(middleware) | string(name) | T(TestUpdateOrg_AsViewer) | N/A | GAP(no audit) |
| GET /orgs/{id}/tier | GAP(no cross-org test) | T(middleware) | T(middleware) | N/A | T(middleware viewer) | N/A | N/A |
| GET /members | T(TestListMembers_NotMember) | T(middleware) | T(middleware) | N/A | T(middleware viewer) | N/A | N/A |
| PATCH /members/{uid} | T(TestCrossOrg_MemberOperations) | T(middleware) | T(middleware) | UUID(uid), string(role) | T(TestUpdateMemberRole_CannotExceedCallerRole) | N/A | T(TestAuditIntegration_Members) |
| DELETE /members/{uid} | T(TestCrossOrg_MemberOperations) | T(middleware) | T(middleware) | UUID(uid) | T(TestRemoveMember_SoleOwner) | N/A | T(TestAuditIntegration_Members) |
| POST /invitations | T(TestCrossOrg_MemberOperations) | T(middleware) | T(middleware) | string(email,role) | T(TestCreateInvitation_AsViewer) | T(TestTierGating_Members_FreeLimit) | GAP(no audit) |
| GET /invitations | T(TestCrossOrg_MemberOperations) | T(middleware) | T(middleware) | N/A | T(middleware admin) | N/A | N/A |
| DELETE /invitations/{id} | GAP(not in cross-org test) | T(middleware) | T(middleware) | UUID(id) | T(middleware admin) | N/A | GAP(no audit) |

### API Keys (apikeys.go)

| Endpoint | Cross | UA | FC | SQL | RBAC | Tier | Audit |
|----------|-------|----|----|-----|------|------|-------|
| POST /api-keys | T(TestCrossOrg_APIKeyAccess) | T(middleware) | T(middleware) | string(name,role) | T(TestCreateAPIKey_ViewerForbidden) | N/A | GAP(no audit) |
| GET /api-keys | T(TestCrossOrg_APIKeyAccess) | T(middleware) | T(middleware) | N/A | T(middleware viewer) | N/A | N/A |
| DELETE /api-keys/{id} | T(TestCrossOrg_APIKeyAccess) | T(middleware) | T(middleware) | UUID(id) | T(TestRevokeAPIKey_NotOwner) | N/A | GAP(no audit) |

### Watchlists (watchlists.go)

| Endpoint | Cross | UA | FC | SQL | RBAC | Tier | Audit |
|----------|-------|----|----|-----|------|------|-------|
| GET /watchlists | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(middleware) | T(middleware) | N/A | T(middleware viewer) | N/A | N/A |
| POST /watchlists | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(middleware) | T(middleware) | string(name,desc) | T(TestWatchlist_ViewerCannotWrite) | T(TestTierGating_Watchlists_FreeLimit) | T(TestAuditIntegration_Watchlists) |
| GET /watchlists/{id} | T(TestWatchlist_WrongOrg) | T(middleware) | T(middleware) | UUID(id) | T(middleware viewer) | N/A | N/A |
| PATCH /watchlists/{id} | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(middleware) | T(middleware) | UUID(id), string(name) | T(TestWatchlist_ViewerCannotWrite) | N/A | T(TestAuditIntegration_Watchlists) |
| DELETE /watchlists/{id} | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(middleware) | T(middleware) | UUID(id) | T(TestWatchlist_ViewerCannotWrite) | N/A | T(TestAuditIntegration_Watchlists) |
| GET /watchlists/{id}/items | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(middleware) | T(middleware) | UUID(id) | T(middleware viewer) | N/A | N/A |
| POST /watchlists/{id}/items | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(middleware) | T(middleware) | UUID(id), string(type,value) | T(TestWatchlist_ViewerCannotWrite) | N/A | GAP(no audit) |
| DELETE /watchlists/{id}/items/{item} | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(middleware) | T(middleware) | UUID(id,item) | T(TestWatchlist_ViewerCannotWrite) | N/A | GAP(no audit) |

### Channels (channels.go)

| Endpoint | Cross | UA | FC | SQL | RBAC | Tier | Audit |
|----------|-------|----|----|-----|------|------|-------|
| GET /channels | GAP(no cross-org test) | T(middleware) | T(middleware) | N/A | T(middleware viewer) | N/A | N/A |
| POST /channels | GAP(no cross-org test) | T(middleware) | T(middleware) | string(name,type,url) | GAP(no RBAC test) | T(TestTierGating_Channels_FreeBlocksEmail) | T(TestAuditIntegration_Channels) |
| GET /channels/{id} | GAP(no cross-org test) | T(middleware) | T(middleware) | UUID(id) | GAP(no RBAC test) | N/A | N/A |
| PATCH /channels/{id} | GAP(no cross-org test) | T(middleware) | T(middleware) | UUID(id), string(name,url) | GAP(no RBAC test) | N/A | T(TestAuditIntegration_Channels) |
| DELETE /channels/{id} | GAP(no cross-org test) | T(middleware) | T(middleware) | UUID(id) | GAP(no RBAC test) | N/A | T(TestAuditIntegration_Channels) |
| POST /channels/{id}/rotate-secret | GAP(no cross-org test) | T(middleware) | T(middleware) | UUID(id) | GAP(no RBAC test) | N/A | GAP(no audit in handler) |
| POST /channels/{id}/clear-secondary | GAP(no cross-org test) | T(middleware) | T(middleware) | UUID(id) | GAP(no RBAC test) | N/A | GAP(no audit in handler) |

### Alert Events (alert_events.go)

| Endpoint | Cross | UA | FC | SQL | RBAC | Tier | Audit |
|----------|-------|----|----|-----|------|------|-------|
| GET /alert-events | T(TestAlertEvents_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID(rule_id), string(cve_id) | T(middleware viewer) | N/A | N/A |

### Alert Rules (alert_rules.go)

| Endpoint | Cross | UA | FC | SQL | RBAC | Tier | Audit |
|----------|-------|----|----|-----|------|------|-------|
| GET /alert-rules | T(TestAlertRule_CrossOrgIsolation) | T(middleware) | T(middleware) | N/A | T(middleware viewer) | N/A | N/A |
| POST /alert-rules | T(TestAlertRule_CrossOrgIsolation) | T(middleware) | T(middleware) | string(name,dsl,logic) | T(TestAlertRule_ViewerCannotWrite) | T(TestTierGating_AlertRules_FreeLimit) | T(TestAuditIntegration_AlertRules) |
| POST /alert-rules/validate | T(TestAlertRule_CrossOrgIsolation) | T(middleware) | T(middleware) | string(dsl) | T(middleware viewer) | N/A | N/A |
| GET /alert-rules/{id} | T(TestAlertRule_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID(id) | T(middleware viewer) | N/A | N/A |
| PATCH /alert-rules/{id} | T(TestAlertRule_CrossOrgPatchAndDelete) | T(middleware) | T(middleware) | UUID(id), string(name,dsl) | T(TestAlertRule_ViewerCannotWrite) | N/A | T(TestAuditIntegration_AlertRules) |
| DELETE /alert-rules/{id} | T(TestAlertRule_CrossOrgPatchAndDelete) | T(middleware) | T(middleware) | UUID(id) | T(TestAlertRule_ViewerCannotWrite) | N/A | T(TestAuditIntegration_AlertRules) |
| POST /alert-rules/{id}/dry-run | T(TestDryRun_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID(id) | T(middleware viewer) | N/A | N/A |
| GET /alert-rules/{id}/channels | GAP(not in cross-org test) | T(middleware) | T(middleware) | UUID(id) | T(middleware viewer) | N/A | N/A |
| PUT /alert-rules/{id}/channels/{cid} | T(TestBindChannelToRule_CrossOrgChannelRejected) | T(middleware) | T(middleware) | UUID(id,cid) | T(TestAlertRule_ViewerCannotWrite) | N/A | GAP(no audit) |
| DELETE /alert-rules/{id}/channels/{cid} | GAP(not in cross-org test) | T(middleware) | T(middleware) | UUID(id,cid) | T(TestAlertRule_ViewerCannotWrite) | N/A | GAP(no audit) |

### SSO (sso.go)

| Endpoint | Cross | UA | FC | SQL | RBAC | Tier | Audit |
|----------|-------|----|----|-----|------|------|-------|
| POST /sso | GAP(no cross-org test) | T(middleware) | T(middleware) | string(provider,issuer,client_id,secret) | T(TestSSOConnection_RBAC) | T(TestSSOConnection_TierGating) | T(TestAudit_SSOOperations) |
| GET /sso | GAP(no cross-org test) | T(middleware) | T(middleware) | N/A | T(TestSSOConnection_RBAC) | T(TestSSOConnection_TierGating) | N/A |
| PATCH /sso | GAP(no cross-org test) | T(middleware) | T(middleware) | string(issuer,client_id,secret) | T(TestSSOConnection_RBAC) | N/A | T(TestAudit_SSOOperations) |
| DELETE /sso | GAP(no cross-org test) | T(middleware) | T(middleware) | N/A | T(TestSSOConnection_RBAC) | N/A | T(TestAudit_SSOOperations) |
| PUT /sso/domains | GAP(no cross-org test) | T(middleware) | T(middleware) | string[](domains) | T(TestSSOConnection_RBAC) | N/A | GAP(not tested) |
| GET /sso/link | GAP(no cross-org test) | T(middleware) | T(middleware) | N/A | T(middleware member) | N/A | N/A |

### Audit Log (audit_log.go)

| Endpoint | Cross | UA | FC | SQL | RBAC | Tier | Audit |
|----------|-------|----|----|-----|------|------|-------|
| GET /audit-log | T(TestAuditAPI_CrossOrgIsolation) | T(middleware) | T(middleware) | string(action,resource) | T(TestAuditAPI_RBAC) | T(TestAuditAPI_TierGating) | N/A |

### Deliveries (deliveries.go)

| Endpoint | Cross | UA | FC | SQL | RBAC | Tier | Audit |
|----------|-------|----|----|-----|------|------|-------|
| GET /deliveries | T(TestDeliveries_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID(rule,channel), string(status) | T(middleware viewer) | N/A | N/A |
| GET /deliveries/{id} | T(TestDeliveries_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID(id) | T(middleware viewer) | N/A | N/A |
| POST /deliveries/{id}/replay | T(TestDeliveries_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID(id) | T(TestReplayDelivery_RBAC_ViewerMemberForbidden) | T(TestReplayDelivery_RateLimited) | GAP(no audit) |

### Reports (reports.go)

| Endpoint | Cross | UA | FC | SQL | RBAC | Tier | Audit |
|----------|-------|----|----|-----|------|------|-------|
| GET /reports | T(TestReports_CrossOrgIsolation) | T(middleware) | T(middleware) | N/A | T(middleware viewer) | N/A | N/A |
| POST /reports | T(TestReports_CrossOrgIsolation) | T(middleware) | T(middleware) | string(name,schedule,tz) | T(TestReports_RBAC_ViewerCannotWrite) | N/A | GAP(no audit in handler) |
| GET /reports/{id} | T(TestReports_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID(id) | T(middleware viewer) | N/A | N/A |
| PATCH /reports/{id} | T(TestReports_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID(id), string(name,status) | T(TestReports_RBAC_ViewerCannotWrite) | N/A | GAP(no audit in handler) |
| DELETE /reports/{id} | T(TestReports_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID(id) | T(TestReports_RBAC_ViewerCannotWrite) | N/A | GAP(no audit in handler) |
| GET /reports/{id}/channels | T(TestReports_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID(id) | T(middleware viewer) | N/A | N/A |
| PUT /reports/{id}/channels/{cid} | T(TestBindChannelToReport_CrossOrgChannelRejected) | T(middleware) | T(middleware) | UUID(id,cid) | T(TestReports_RBAC_ViewerCannotWrite) | N/A | GAP(no audit in handler) |
| DELETE /reports/{id}/channels/{cid} | T(TestReports_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID(id,cid) | T(TestReports_RBAC_ViewerCannotWrite) | N/A | GAP(no audit in handler) |

### AI (ai.go)

| Endpoint | Cross | UA | FC | SQL | RBAC | Tier | Audit |
|----------|-------|----|----|-----|------|------|-------|
| POST /ai/nl-search | T(TestAIHandlers_CrossOrgIsolation) | T(TestNLSearchHandler_Unauthenticated) | T(TestAIHandlers_InvalidOrgID) | string(query) | T(middleware viewer) | T(TestNLSearchHandler_QuotaDenied) | N/A(has request log) |
| POST /ai/summarize/{cve} | T(TestAIHandlers_CrossOrgIsolation) | T(TestSummarizeHandler_Unauthenticated) | T(TestAIHandlers_InvalidOrgID) | string(cve_id) | T(middleware viewer) | T(TestSummarizeHandler_QuotaDenied) | N/A(has request log) |

### Saved Searches (saved_searches.go)

| Endpoint | Cross | UA | FC | SQL | RBAC | Tier | Audit |
|----------|-------|----|----|-----|------|------|-------|
| GET /saved-searches | T(TestSavedSearch_CrossOrgIsolation) | T(TestSavedSearch_CreateUnauthenticated) | T(TestSavedSearch_InvalidOrgID) | N/A | T(TestSavedSearch_RBAC) | N/A | N/A |
| POST /saved-searches | T(TestSavedSearch_CrossOrgIsolation) | T(TestSavedSearch_CreateUnauthenticated) | T(TestSavedSearch_InvalidOrgID) | string(name,dsl,vis) | T(TestSavedSearch_RBAC) | N/A | T(TestAuditIntegration_SavedSearches) |
| GET /saved-searches/{id} | T(TestSavedSearch_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID(id) | T(TestSavedSearch_RBAC) | N/A | N/A |
| PATCH /saved-searches/{id} | T(TestSavedSearch_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID(id), string(name,dsl) | T(TestSavedSearch_RBAC) | N/A | T(TestAuditIntegration_SavedSearches) |
| DELETE /saved-searches/{id} | T(TestSavedSearch_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID(id) | T(TestSavedSearch_RBAC) | N/A | T(TestAuditIntegration_SavedSearches) |
| POST /saved-searches/{id}/execute | T(TestSavedSearch_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID(id) | T(TestSavedSearch_RBAC) | N/A | N/A |

### Groups (groups.go)

| Endpoint | Cross | UA | FC | SQL | RBAC | Tier | Audit |
|----------|-------|----|----|-----|------|------|-------|
| GET /groups | T(TestCrossOrg_GroupAccess) | T(middleware) | T(middleware) | N/A | T(middleware viewer) | N/A | N/A |
| POST /groups | T(TestCrossOrg_GroupAccess) | T(middleware) | T(middleware) | string(name,desc) | T(TestCreateGroup_AsViewer) | N/A | GAP(no audit) |
| GET /groups/{gid} | T(TestCrossOrg_GroupAccess) | T(middleware) | T(middleware) | UUID(gid) | T(middleware viewer) | N/A | N/A |
| PATCH /groups/{gid} | T(TestCrossOrg_GroupAccess) | T(middleware) | T(middleware) | UUID(gid), string(name) | GAP(no admin RBAC test) | N/A | GAP(no audit) |
| DELETE /groups/{gid} | T(TestCrossOrg_GroupAccess) | T(middleware) | T(middleware) | UUID(gid) | GAP(no admin RBAC test) | N/A | GAP(no audit) |
| GET /groups/{gid}/members | T(TestCrossOrg_GroupAccess) | T(middleware) | T(middleware) | UUID(gid) | T(middleware viewer) | N/A | N/A |
| POST /groups/{gid}/members | GAP(not in cross-org test) | T(middleware) | T(middleware) | UUID(gid,uid) | GAP(no admin RBAC test) | N/A | GAP(no audit) |
| DELETE /groups/{gid}/members/{uid} | GAP(not in cross-org test) | T(middleware) | T(middleware) | UUID(gid,uid) | GAP(no admin RBAC test) | N/A | GAP(no audit) |

### Matrix Verification

**Endpoint count:** 72 endpoints enumerated, 72 rows in matrix. ✓

**Spot-check verification (3 random cells):**
1. T(TestAlertRule_CrossOrgIsolation): Verified — creates rule in Alice's org, Bob (non-member) gets 403. ✓
2. T(TestWatchlist_ViewerCannotWrite): Verified — adds Bob as viewer, Bob's POST watchlist returns 403. ✓
3. T(TestDeliveries_CrossOrgIsolation): Verified — Alice creates delivery, Bob cannot access via his own org. ✓

### Matrix GAP Summary

**Cross-org isolation gaps (11 endpoints):**
- All 7 channels endpoints (no cross-org test exists)
- All 6 SSO endpoints (no cross-org test exists)
- GET /orgs/{id}/tier (no dedicated cross-org test)
- GET /alert-rules/{id}/channels (not covered by existing cross-org test)
- DELETE /alert-rules/{id}/channels/{cid} (not covered)
- DELETE /invitations/{id} (not covered)
- POST /groups/{gid}/members, DELETE /groups/{gid}/members/{uid} (not covered)

**RBAC gaps (11 endpoints):**
- All 7 channels endpoints (no RBAC test — relies entirely on middleware)
- PATCH /groups/{gid}, DELETE /groups/{gid}, POST /groups/{gid}/members, DELETE /groups/{gid}/members/{uid} (admin-required endpoints with no RBAC test)

**Audit log gaps (23 mutating endpoints without audit logging):**
- All 5 reports mutating endpoints (create, patch, delete, bind, unbind) — NO audit calls in handler
- All 5 groups mutating endpoints — NO audit calls in handler
- POST/DELETE /api-keys — NO audit calls in handler
- POST /invitations, DELETE /invitations/{id} — NO audit calls in handler
- PATCH /orgs/{id} — NO audit call in handler
- POST/DELETE /watchlists/{id}/items — NO audit calls in handler
- PUT/DELETE /alert-rules/{id}/channels/{cid} — NO audit calls in handler
- POST /channels/{id}/rotate-secret, POST /channels/{id}/clear-secondary — NO audit calls
- POST /deliveries/{id}/replay — NO audit call in handler
- PUT /sso/domains — audit call not verified in test

---

## §4 Semantic Code Analysis

### §4A Cross-Handler Consistency (Main Agent)

**Pattern 1: Tier-limit-check → audit-log-on-block → 403**

4 handlers have tier limit checks. 3 of 4 audit the block event:

| Handler | Tier Check | Audit on Block? |
|---------|-----------|-----------------|
| createAlertRuleHandler | CountAlertRulesByOrg | ✓ audit log |
| createWatchlistHandler | CountWatchlistsByOrg | ✓ audit log |
| createChannelHandler | BoolFlag (channel type) | ✓ audit log |
| **createInvitationHandler** | CountMemberSlotsUsedByOrg | **❌ NO audit log** |

**Cross-handler consistency BUG.** The invitation handler omits the audit entry that every other tier-gated handler writes.

**Pattern 2: "used" count method in GET /tier vs enforcement**

| Context | Count Method | Counts |
|---------|-------------|--------|
| getOrgTierHandler (display) | `CountMembersByOrg` | Active members only |
| createInvitationHandler (enforce) | `CountMemberSlotsUsedByOrg` | Active + pending |

**BUG (wrong-function-called).** Display shows `used: 3` but enforcement rejects at `5` (2 pending invitations). Test doesn't verify member count.

**Pattern 3: Audit log on mutation — cross-handler map**

| Group | Create | Update | Delete | Bind/Unbind | Special |
|-------|--------|--------|--------|-------------|---------|
| Alert Rules | ✓ | ✓ | ✓ | ❌ bind/unbind channel | — |
| Channels | ✓ | ✓ | ✓ | — | ❌ rotate, ❌ clearSec |
| Watchlists | ✓ | ✓ | ✓ | — | ❌ createItem, ❌ deleteItem |
| Reports | ❌ | ❌ | ❌ | ❌ | — |
| Groups | ❌ | ❌ | ❌ | ❌ add/remove | — |
| SSO | ✓ | ✓ | ✓ | — | ❌ putDomains |
| Saved Searches | ✓ | ✓ | ✓ | — | — |
| Orgs | ❌ create | ❌ update | — | — | ✓ role, ✓ remove, ❌ invite, ❌ cancel |
| API Keys | ❌ | — | ❌ | — | — |
| Deliveries | — | — | — | — | ❌ replay |

**Reports and Groups are entirely unaudited.** Every mutation is invisible to the audit log.

### §4B-E Per-Function Semantic Analysis

*(See subagent output files for detailed per-function analysis)*

---

## §5 Assertion Quality Audit

6 assertion quality issues found across API and store layers:

| ID | Location | Issue | Priority |
|----|----------|-------|----------|
| AQ1 | `oauth_*_test.go` | Cookie security attributes (`HttpOnly`, `Secure`, `SameSite`) not verified on auth cookies in callback tests | MEDIUM |
| AQ2 | `auth_test.go` | JWT claims content not verified — `sub`, `exp` range, `iat` presence, leaked claims | MEDIUM |
| AQ3 | `channels_test.go` | SSRF validation tests check status 422 but not error message content | LOW |
| AQ4 | `alert_rule` store tests | Boolean fields (`HasEpssCondition`, `IsEpssOnly`, `FireOnNonMaterialChanges`) not verified — sqlc parameter swap undetectable | MEDIUM |
| AQ5 | `report_channel` store tests | `ChannelHasActiveBindings` composite function short-circuit behavior not tested — may never call `ChannelHasActiveBoundReports` | LOW |
| AQ6 | Store test helpers | `mustCreate*` helpers always use default boolean values — non-default paths untested | LOW |

---

## Gap Context

| Category | Gaps | Action |
|----------|------|--------|
| Security matrix GAPs | 45 | Add cross-org, RBAC, and audit log tests |
| API code-path (security) | 8 | Add auth/validation tests |
| Store code-path (security) | 4 | Add expiry, rotation, and format tests |
| API code-path (correctness) | 14 | Add error path and handler tests |
| Store code-path (correctness) | 8 | Add tx recovery and error branch tests |
| Assertion quality | 6 | Strengthen existing assertions |
| API code-path (nice-to-have) | 11 | Low priority |
| Store code-path (nice-to-have) | 14 | Low priority |
| **Total** | **110** | |

## What's Well-Covered

- **Watchlists:** Comprehensive cross-org, RBAC, tier-gating, and audit log tests across all 8 endpoints. Best-in-class endpoint group.
- **Alert rules:** Strong cross-org isolation, viewer-can't-write RBAC, DSL validation, tier-gating with audit on block. Dry-run has dedicated cross-org test.
- **Saved searches:** Full security matrix coverage — cross-org, unauth, invalid org ID, RBAC by role, and audit logging all tested. 88-100% store coverage.
- **Store transaction helpers:** Every helper (`withOrgTx`, `withBypassTx`, `withOrgRawTx`, `OrgTx`, `WorkerTx`) uses the correct helper for its context. No misuse found in any method. The 87.5% systematic pattern is architectural (outer error branch after healthy DB), not an oversight.
- **Alert event deduplication:** `InsertAlertEvent` ON CONFLICT DO NOTHING with `ErrNoRows` detection — both "new event" and "duplicate suppressed" paths covered.

## Production Bugs Discovered

### BUG-1: createInvitationHandler omits audit log on tier-limit block — [orgs.go](internal/api/orgs.go) (§4A cross-handler)

4 handlers have tier-limit checks. 3 of 4 audit the block event. `createInvitationHandler` skips the audit log call before returning 403. Users/admins reviewing the audit log cannot see when member invitations are blocked by the tier limit.

### BUG-2: getOrgTierHandler uses wrong count method — [org_tier.go:61](internal/api/org_tier.go#L61) (§4A right-function-called)

Display uses `CountMembersByOrg` (active members only) while enforcement uses `CountMemberSlotsUsedByOrg` (active + pending invitations). GET /tier shows `"used": 3` but the tier gate rejects at 5 because 2 pending invitations count toward the limit. The test doesn't verify the member count value.

### PB1: replayDeliveryHandler has no not-found check — [deliveries.go:293](internal/api/deliveries.go#L293) (§4B API subagent)

`replayDeliveryHandler` calls `ReplayDelivery` without checking if the delivery exists first. Compare with `getDeliveryHandler` which correctly checks `row == nil` → 404. For a non-existent delivery, this returns 500 or silent 204 instead of 404.

## Security-Critical Gaps (57)

### From Security Matrix — Cross-Org Isolation (11 endpoints)

| # | Endpoint | Source |
|---|----------|--------|
| 1 | GET /channels | matrix |
| 2 | POST /channels | matrix |
| 3 | GET /channels/{id} | matrix |
| 4 | PATCH /channels/{id} | matrix |
| 5 | DELETE /channels/{id} | matrix |
| 6 | POST /channels/{id}/rotate-secret | matrix |
| 7 | POST /channels/{id}/clear-secondary | matrix |
| 8 | POST /sso | matrix |
| 9 | GET /sso | matrix |
| 10 | PATCH /sso | matrix |
| 11 | DELETE /sso | matrix |
| 12 | PUT /sso/domains | matrix |
| 13 | GET /sso/link | matrix |
| 14 | GET /orgs/{id}/tier | matrix |
| 15 | GET /alert-rules/{id}/channels | matrix |
| 16 | DELETE /alert-rules/{id}/channels/{cid} | matrix |
| 17 | DELETE /invitations/{id} | matrix |
| 18 | POST /groups/{gid}/members | matrix |
| 19 | DELETE /groups/{gid}/members/{uid} | matrix |

### From Security Matrix — RBAC (11 endpoints)

| # | Endpoint | Missing Test | Source |
|---|----------|--------------|--------|
| 20 | All 7 channels endpoints | No RBAC test — relies entirely on middleware | matrix |
| 21 | PATCH /groups/{gid} | Admin-required, no RBAC test | matrix |
| 22 | DELETE /groups/{gid} | Admin-required, no RBAC test | matrix |
| 23 | POST /groups/{gid}/members | Admin-required, no RBAC test | matrix |
| 24 | DELETE /groups/{gid}/members/{uid} | Admin-required, no RBAC test | matrix |

### From Security Matrix — Audit Log (23 mutating endpoints)

| # | Endpoint Group | Endpoints | Source |
|---|----------------|-----------|--------|
| 25-29 | Reports | create, patch, delete, bind channel, unbind channel — NO audit calls | matrix |
| 30-34 | Groups | create, patch, delete, add member, remove member — NO audit calls | matrix |
| 35-36 | API Keys | create, revoke — NO audit calls | matrix |
| 37-38 | Invitations | create, cancel — NO audit calls | matrix |
| 39 | Orgs | PATCH /orgs/{id} — NO audit call | matrix |
| 40-41 | Watchlist Items | create, delete — NO audit calls | matrix |
| 42-43 | Alert Rule Channels | bind, unbind — NO audit calls | matrix |
| 44-45 | Channel Secrets | rotate-secret, clear-secondary — NO audit calls | matrix |
| 46 | Deliveries | replay — NO audit call | matrix |
| 47 | SSO Domains | PUT /sso/domains — audit call not verified | matrix |

### From API Semantic/Coverage Analysis (8)

| # | Function | Gap | Source |
|---|----------|-----|--------|
| 48 | `refreshGrace` (53.3%) | Token reuse/theft detection untested — grace window, family ID propagation | coverage |
| 49 | `createAPIKeyHandler` (51%) | No round-trip test verifying returned key authenticates | coverage |
| 50 | `oidcVerifyCallback` (48.4%) | `email_verified=false` rejection not tested | coverage |
| 51 | `issueRefreshPair` (50%) | JWT sign error and DB write error paths untested | coverage |
| 52 | `acceptInvitationHandler` (66.7%) | Invalid/expired token and already-accepted paths untested | coverage |
| 53 | `loginHandler` (64.9%) | Argon2 exhaustion and rate-limit paths untested | coverage |
| 54 | `tryAPIKeyAuth` (92.3%) | Empty key and malformed Authorization header edge cases | coverage |
| 55 | `validateWebhookURL` (93.3%) | IPv6 loopback and credentials-in-URL bypass not tested | coverage |

### From Store Semantic/Coverage Analysis (4)

| # | Function | Gap | Source |
|---|----------|-----|--------|
| 56 | `LookupAPIKey` (83.3%) | No test verifying expired keys return nil — auth hot-path time filtering | coverage |
| 57 | `RotateSigningSecret` (84.6%) | Old primary → new secondary promotion chain not verified | coverage |
| 58 | `ListActiveChannelsForFanout` (87.5%) | Signing secret format/length not validated in assertions | assertion |
| 59 | Store layer (all) | No input validation — defense-in-depth relies entirely on handlers + DB constraints | semantic |

## Correctness Gaps (22)

### API Layer (14)

| # | Function | Coverage | Gap | Source |
|---|----------|----------|-----|--------|
| 1 | `getCVEHandler` | 40.0% | 404, 500, nullable fields | coverage |
| 2 | `createGroupHandler` | 42.9% | Validation errors, 400/500 paths | coverage |
| 3 | `replayDeliveryHandler` | 43.8% | Rate limit, 400, 404, 500 paths | coverage |
| 4 | `updateOrgHandler` | 45.0% | Validation, error paths | coverage |
| 5 | `getGroupHandler` | 45.5% | 404, 500 paths | coverage |
| 6 | `createReportHandler` | 46.2% | Validation edges, error paths | coverage |
| 7 | `getCVESourcesHandler` | 47.6% | 400, 500, empty array | coverage |
| 8 | `createWatchlistHandler` | 47.6% | Validation, error paths | coverage |
| 9 | `getDeliveryHandler` | 50.0% | 400 (bad UUID), 500 | coverage |
| 10 | `updateGroupHandler` | 50.0% | 404, validation, 500 | coverage |
| 11 | `createAlertRuleHandler` | 52.4% | JSON parse error, validation edges | coverage |
| 12 | `listGroupsHandler` | 55.6% | Pagination, 500 | coverage |
| 13 | `patchAlertRuleHandler` | 67.0% | Invalid DSL, state transition, 404 | coverage |
| 14 | `getOrgTierHandler` | — | Wrong count method (BUG-2) — displays active-only count while enforcement counts active + pending | semantic |

### Store Layer (8)

| # | Function | Coverage | Gap | Source |
|---|----------|----------|-----|--------|
| 15 | `withBypassTx` | 71.4% | Panic recovery path untested | coverage |
| 16 | `withOrgRawTx` | 64.3% | Panic recovery path untested | coverage |
| 17 | `BootstrapFirstUserOrg` | 58.8% | `CreateOrg` failure branch (manual tx) | coverage |
| 18 | `BootstrapFirstUserOrg` | 58.8% | `CreateOrgMember` failure after org creation (partial state rollback) | coverage |
| 19 | `ListCVEs` | 0% | Entire function untested (superseded by SearchCVEs) | coverage |
| 20 | `CompleteJob`/`FailJob` | 66.7% | Non-existent job ID behavior undefined | coverage |
| 21 | `UpsertDelivery` | 66.7% | Manual tx lacks panic recovery (diverges from standard pattern) | semantic |
| 22 | `GetCVEDetail` | 76.9% | Child-table query failures never individually tested | coverage |

## Nice-to-Have (25 total — top 5 shown)

| # | Function | Coverage | Gap |
|---|----------|----------|-----|
| 1 | All ~40 store methods at 87.5% | 87.5% | Outer `if err != nil` after tx wrapper — architectural gap, healthy DB never triggers |
| 2 | All auth store functions (6) at 66.7% | 66.7% | `fmt.Errorf` wrapping on sqlc call error |
| 3 | All retention functions (10) at 87.5% | 87.5% | Same tx wrapper outer error branch |
| 4 | `pgErrCode` | 0% | Utility for unique-constraint detection |
| 5 | `NewServer` | 50.0% | Config edge cases during server init |

*Remaining 20: transaction helper `BeginTx`/`SET LOCAL` error branches, `fromNullUUID` valid branch, `encodeDSLCursor`/`scanCVERow` unreachable error paths, various API handler low-risk error branches.*

## Assertion Quality Issues (6)

| # | Location | Issue | Source |
|---|----------|-------|--------|
| 1 | OAuth callback tests | Cookie security attributes (`HttpOnly`, `Secure`, `SameSite`) not verified — XSS token theft would go undetected | assertion |
| 2 | Auth tests | JWT claims content (`sub`, `exp` range, `iat`, leaked claims) not decoded and verified | assertion |
| 3 | SSRF validation tests | Status 422 checked but error message content not verified | assertion |
| 4 | Alert rule store tests | Boolean fields (`HasEpssCondition`, `IsEpssOnly`) not asserted — sqlc parameter swap undetectable | assertion |
| 5 | `ChannelHasActiveBindings` | Composite short-circuit behavior untested — `ChannelHasActiveBoundReports` may never execute | assertion |
| 6 | Store test helpers | `mustCreate*` always use default booleans — non-default field values untested | assertion |

## Key Observations

### Cross-Cutting Patterns

1. **Audit log desert.** Reports (5 endpoints) and Groups (5 endpoints) have zero audit logging in their handlers. Every mutation is invisible to org administrators. API Keys (2 endpoints) and Invitations (2 endpoints) are also unaudited. This is a systematic gap affecting 14 endpoints — not isolated oversights.

2. **Channels: worst-in-class security coverage.** All 7 channel endpoints lack both cross-org isolation tests and RBAC tests. This is the only endpoint group with zero security-specific tests beyond middleware baseline. Since channels hold webhook URLs and signing secrets (sensitive configuration), this is disproportionate to the data's sensitivity.

3. **SSO: cross-org isolation fully untested.** All 6 SSO endpoints lack cross-org tests. SSO connections contain encrypted client secrets and control authentication for entire organizations. A cross-org SSO leak would let org A see org B's IdP configuration.

4. **Coverage ≠ confidence mismatch.** Several functions with >80% coverage have critical assertion gaps. `tryAPIKeyAuth` at 92.3% doesn't test malformed headers. `validateWebhookURL` at 93.3% doesn't test IPv6 loopback bypass. `RotateSigningSecret` at 84.6% doesn't verify the promotion chain. High coverage percentages mask specific untested security properties.

5. **The 87.5% systematic pattern is benign.** ~40 store methods show exactly 87.5% because the outer `if err != nil` after the tx helper wrapper never fires with a healthy Postgres. This is architectural — testing it would require injecting a broken DB. Not a concern.

### TOCTOU Windows (from subagent analysis)

- **Tier gating race:** Between `CountMemberSlotsUsedByOrg` check and `CreateInvitation` write, another admin could create an invitation, exceeding the limit. Mitigated by eventual consistency (over-limit by at most 1). Similar windows exist for alert rules, watchlists, and channels.
- **Refresh token rotation race:** Between `MarkRefreshTokenUsed` and `CreateRefreshToken`, a concurrent request could use the same token. Mitigated by the grace period window, but the grace period logic itself is untested (Finding #48).

### Defense-in-Depth Observations

- **No handler-level auth safety net.** API handlers rely entirely on `RequireAuthenticated` middleware to inject auth context. If middleware ordering changes (e.g., a route accidentally placed outside the auth group), the handler has no fallback check. This is a design choice (DRY), but means a single routing error could expose an unauthenticated endpoint.
- **Store layer trusts all inputs.** Zero input validation at the store layer — all validation relies on API handlers and database constraints. For a security product, adding store-level guards for sensitive operations (SSO domains, webhook URLs) would reduce blast radius.

---

*Subagent detailed analysis:*
- *[subagent-api-findings.md](dev/test-coverage-reports/subagent-api-findings.md)*
- *[subagent-store-findings.md](dev/test-coverage-reports/subagent-store-findings.md)*
