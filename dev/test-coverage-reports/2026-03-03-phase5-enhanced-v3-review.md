# Phase 5 Enhanced Coverage-Tool v3 Review (Run E)

**Date:** 2026-03-03
**Scope:** `./internal/api/...`, `./internal/store/...`, `./internal/tier/...`
**Skill:** `/test-coverage-review-go` (enhanced coverage-tool v3)
**Coverage profile:** `coverage-ab.out` / `coverage-ab-func.txt`
**Overall coverage:** 73.5% (statements)

---

## Coverage Baseline

| Package | Functions | Avg Coverage | 0% Functions | Notes |
|---------|-----------|-------------|-------------|-------|
| internal/api | 181 | 74.9% | 2 | Handlers + middleware |
| internal/store | 188 | 86.2% | 1 | Repository layer (non-generated) |
| internal/store/generated | 186 | 81.5% | 23 | sqlc-generated code (Phase 1 scope, not tested here) |
| internal/tier | 4 | 100.0% | 0 | Tier resolver |
| **Overall** | **559** | **73.5%** | **26** | |

### Coverage Distribution (non-generated)

| Category | Count | % of Total |
|----------|-------|-----------|
| 0% (Uncovered) | 3 | 0.8% |
| 1–79% (Partial) | 128 | 34.3% |
| 80–99% (Well covered) | 93 | 24.9% |
| 100% (Fully covered) | 149 | 39.9% |

---

## Security Checklist Matrix

**Endpoint enumeration:** 72 org-scoped endpoints identified from [server.go:195-348](internal/api/server.go#L195-L348). All are under `/api/v1/orgs/{org_id}/...` with `RequireAuthenticated()` + `RequireOrgRole(RoleViewer)` applied at the route group level, plus `tierMiddleware` and `orgRateLimitMiddleware`.

**Auth note:** Unauth→401 is handled by `RequireAuthenticated` middleware applied at line 196 of server.go to the entire `/orgs` route group. This is tested by 8 tests in [middleware_auth_test.go](internal/api/middleware_auth_test.go) covering: no credentials, valid JWT, expired JWT, wrong secret, malformed JWT, valid API key, invalid API key, non-Bearer auth header. Individual handler tests do not redundantly test unauth→401.

**RBAC note:** `RequireOrgRole(RoleViewer)` is the base level for all org-scoped endpoints (line 200). Additional role requirements are applied per-route via `.With(srv.RequireOrgRole(...))`. The RBAC middleware is tested by 8 tests in [middleware_rbac_test.go](internal/api/middleware_rbac_test.go) covering sufficient/insufficient role, non-member, API key role capping, no user ID, invalid org ID, exact role match.

### Legend
- **T(TestName)** = Tested, citing specific test function
- **T(middleware)** = Covered by middleware-level tests (not per-endpoint)
- **GAP** = No test exists (parenthetical notes specific concern)
- **N/A** = Not applicable

### Org Management

| # | Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL params | RBAC | Fail-closed | Audit log |
|---|----------|-----------|------------|-------------------|------------|------|-------------|-----------|
| 1 | GET /orgs/{org_id} | T(TestGetOrg_NotMember) | T(middleware) | T(middleware) | UUID (path) | T(middleware: viewer) | N/A | N/A (read) |
| 2 | GET /orgs/{org_id}/tier | GAP (no cross-org test) | T(middleware) | T(middleware) | UUID (path) | T(middleware: viewer) | N/A | N/A (read) |
| 3 | PATCH /orgs/{org_id} | GAP (no cross-org test) | T(middleware) | T(middleware) | UUID, string | T(TestUpdateOrg_AsViewer) | N/A | GAP (no audit code) |
| 4 | GET /members | T(TestListMembers_NotMember) | T(middleware) | T(middleware) | UUID (path) | T(middleware: viewer) | N/A | N/A (read) |
| 5 | PATCH /members/{user_id} | T(TestCrossOrg_MemberOperations) | T(middleware) | T(middleware) | UUID, string | T(TestUpdateMemberRole_CannotExceedCallerRole) | T(TestUpdateMemberRole_CannotAssignOwner, TestUpdateMemberRole_CannotChangeExistingOwner) | T(TestAuditIntegration_Members) |
| 6 | DELETE /members/{user_id} | T(TestCrossOrg_MemberOperations) | T(middleware) | T(middleware) | UUID | T(middleware: admin) | T(TestRemoveMember_SoleOwner) | T(TestAuditIntegration_Members) |
| 7 | POST /invitations | T(TestCrossOrg_MemberOperations) | T(middleware) | T(middleware) | string (email), string (role) | T(TestCreateInvitation_AsViewer, TestCreateInvitation_MemberCannotInviteAsAdmin) | T(TestTierGating_Members_FreeLimit, TestTierGating_Members_PendingInvitationsConsumeSlots) | GAP (no audit code) |
| 8 | GET /invitations | T(TestCrossOrg_MemberOperations) | T(middleware) | T(middleware) | UUID (path) | T(middleware: admin) | N/A | N/A (read) |
| 9 | DELETE /invitations/{id} | GAP (not tested in cross-org) | T(middleware) | T(middleware) | UUID | T(middleware: admin) | N/A | GAP (no audit code) |

### API Keys

| # | Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL params | RBAC | Fail-closed | Audit log |
|---|----------|-----------|------------|-------------------|------------|------|-------------|-----------|
| 10 | POST /api-keys | T(TestCrossOrg_APIKeyAccess) | T(middleware) | T(middleware) | string (name), string (role) | T(TestCreateAPIKey_ViewerForbidden, TestCreateAPIKey_RoleEscalation) | T(TestCreateAPIKey_InvalidRole) | GAP (no audit code) |
| 11 | GET /api-keys | T(TestCrossOrg_APIKeyAccess) | T(middleware) | T(middleware) | UUID (path) | T(middleware: viewer) | N/A | N/A (read) |
| 12 | DELETE /api-keys/{id} | T(TestCrossOrg_APIKeyAccess) | T(middleware) | T(middleware) | UUID | T(middleware: viewer) | N/A | GAP (no audit code) |

### Watchlists

| # | Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL params | RBAC | Fail-closed | Audit log |
|---|----------|-----------|------------|-------------------|------------|------|-------------|-----------|
| 13 | GET /watchlists | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(middleware) | T(middleware) | UUID, cursor | T(middleware: viewer) | N/A | N/A (read) |
| 14 | POST /watchlists | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(middleware) | T(middleware) | string (name), string (description) | T(TestWatchlist_ViewerCannotWrite) | T(TestTierGating_Watchlists_FreeLimit) | T(TestAuditIntegration_Watchlists) |
| 15 | GET /watchlists/{id} | T(TestWatchlist_WrongOrg) | T(middleware) | T(middleware) | UUID | T(middleware: viewer) | N/A | N/A (read) |
| 16 | PATCH /watchlists/{id} | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(middleware) | T(middleware) | UUID, string | T(TestWatchlist_ViewerCannotWrite) | N/A | T(TestAuditIntegration_Watchlists) |
| 17 | DELETE /watchlists/{id} | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(middleware) | T(middleware) | UUID | T(TestWatchlist_ViewerCannotWrite) | N/A | T(TestAuditIntegration_Watchlists) |
| 18 | GET /watchlists/{id}/items | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(middleware) | T(middleware) | UUID, cursor | T(middleware: viewer) | N/A | N/A (read) |
| 19 | POST /watchlists/{id}/items | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(middleware) | T(middleware) | UUID, string (cve_id) | T(TestWatchlist_ViewerCannotWrite) | N/A | N/A |
| 20 | DELETE /watchlists/{id}/items/{item_id} | T(TestWatchlist_CrossOrgReadWriteIsolation) | T(middleware) | T(middleware) | UUID | T(TestWatchlist_ViewerCannotWrite) | N/A | N/A |

### Notification Channels

| # | Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL params | RBAC | Fail-closed | Audit log |
|---|----------|-----------|------------|-------------------|------------|------|-------------|-----------|
| 21 | GET /channels | **GAP** (no cross-org test) | T(middleware) | T(middleware) | UUID | T(middleware: viewer) | N/A | N/A (read) |
| 22 | POST /channels | **GAP** (no cross-org test) | T(middleware) | T(middleware) | string (name, type), JSON (config) | T(middleware: member) | T(TestTierGating_Channels_FreeBlocksEmail) | T(TestAuditIntegration_Channels) |
| 23 | GET /channels/{id} | **GAP** (no cross-org test) | T(middleware) | T(middleware) | UUID | T(middleware: viewer) | N/A | N/A (read) |
| 24 | PATCH /channels/{id} | **GAP** (no cross-org test) | T(middleware) | T(middleware) | UUID, string, JSON | T(middleware: member) | T(TestPatchChannel_WebhookSSRFBlocked) | T(TestAuditIntegration_Channels) |
| 25 | DELETE /channels/{id} | **GAP** (no cross-org test) | T(middleware) | T(middleware) | UUID | T(middleware: member) | T(TestDeleteChannel_409IfActiveRuleBound, TestDeleteChannel_409IfReportBound) | T(TestAuditIntegration_Channels) |
| 26 | POST /channels/{id}/rotate-secret | **GAP** (no cross-org test) | T(middleware) | T(middleware) | UUID | T(middleware: member) | T(TestRotateSecret_EmailChannel_Rejected) | T(TestAuditIntegration_Channels) |
| 27 | POST /channels/{id}/clear-secondary | **GAP** (no cross-org test) | T(middleware) | T(middleware) | UUID | T(middleware: member) | T(TestClearSecondary_EmailChannel_Rejected) | N/A |

### Alert Events

| # | Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL params | RBAC | Fail-closed | Audit log |
|---|----------|-----------|------------|-------------------|------------|------|-------------|-----------|
| 28 | GET /alert-events | T(TestAlertEvents_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID, cursor, filters | T(middleware: viewer) | N/A | N/A (read) |

### SSO

| # | Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL params | RBAC | Fail-closed | Audit log |
|---|----------|-----------|------------|-------------------|------------|------|-------------|-----------|
| 29 | POST /sso | T(TestOIDCFlow_CrossOrgIsolation) | T(middleware) | T(middleware) | strings (issuer, client_id, etc.) | T(TestSSOConnection_RBAC) | T(TestSSOConnection_TierGating) | T(TestAudit_SSOOperations) |
| 30 | GET /sso | T(TestOIDCFlow_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID | T(TestSSOConnection_RBAC) | T(TestSSOConnection_TierGating) | N/A (read) |
| 31 | PATCH /sso | T(TestOIDCFlow_CrossOrgIsolation) | T(middleware) | T(middleware) | strings | T(TestSSOConnection_RBAC) | T(TestSSOConnection_TierGating) | T(TestAudit_SSOOperations) |
| 32 | DELETE /sso | T(TestOIDCFlow_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID | T(TestSSOConnection_RBAC) | N/A | T(TestAudit_SSOOperations) |
| 33 | PUT /sso/domains | T(TestOIDCFlow_CrossOrgIsolation) | T(middleware) | T(middleware) | string[] (domains) | T(TestSSOConnection_RBAC) | N/A | N/A |
| 34 | GET /sso/link | T(TestOIDCFlow_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID | T(middleware: member) | N/A | N/A |

### Audit Log

| # | Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL params | RBAC | Fail-closed | Audit log |
|---|----------|-----------|------------|-------------------|------------|------|-------------|-----------|
| 35 | GET /audit-log | T(TestAuditAPI_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID, timestamps, strings | T(TestAuditAPI_RBAC) | T(TestAuditAPI_TierGating) | N/A (read) |

### Deliveries

| # | Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL params | RBAC | Fail-closed | Audit log |
|---|----------|-----------|------------|-------------------|------------|------|-------------|-----------|
| 36 | GET /deliveries | T(TestDeliveries_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID, cursor | T(middleware: viewer) | N/A | N/A (read) |
| 37 | GET /deliveries/{id} | T(TestDeliveries_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID | T(middleware: viewer) | N/A | N/A (read) |
| 38 | POST /deliveries/{id}/replay | T(TestDeliveries_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID | T(TestReplayDelivery_RBAC_ViewerMemberForbidden) | T(TestReplayDelivery_RateLimited) | **GAP** (no audit code — mutating action) |

### Alert Rules

| # | Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL params | RBAC | Fail-closed | Audit log |
|---|----------|-----------|------------|-------------------|------------|------|-------------|-----------|
| 39 | GET /alert-rules | T(TestAlertRule_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID, cursor | T(middleware: viewer) | N/A | N/A (read) |
| 40 | POST /alert-rules | T(TestAlertRule_CrossOrgIsolation) | T(middleware) | T(middleware) | strings, JSON (DSL) | T(TestAlertRule_ViewerCannotWrite) | T(TestTierGating_AlertRules_FreeLimit) | T(TestAuditIntegration_AlertRules) |
| 41 | POST /alert-rules/validate | GAP (not in cross-org test) | T(middleware) | T(middleware) | strings, JSON (DSL) | T(middleware: viewer) | N/A | N/A (read-like) |
| 42 | GET /alert-rules/{id} | T(TestAlertRule_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID | T(middleware: viewer) | N/A | N/A (read) |
| 43 | PATCH /alert-rules/{id} | T(TestAlertRule_CrossOrgPatchAndDelete) | T(middleware) | T(middleware) | UUID, strings, JSON | T(TestAlertRule_ViewerCannotWrite) | N/A | T(TestAuditIntegration_AlertRules) |
| 44 | DELETE /alert-rules/{id} | T(TestAlertRule_CrossOrgPatchAndDelete) | T(middleware) | T(middleware) | UUID | T(TestAlertRule_ViewerCannotWrite) | N/A | T(TestAuditIntegration_AlertRules) |
| 45 | POST /alert-rules/{id}/dry-run | T(TestDryRun_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID | T(middleware: viewer) | N/A | N/A (read-like) |
| 46 | GET /alert-rules/{id}/channels | T(TestAlertRule_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID | T(middleware: viewer) | N/A | N/A (read) |
| 47 | PUT /alert-rules/{id}/channels/{ch} | T(TestBindChannelToRule_CrossOrgChannelRejected) | T(middleware) | T(middleware) | UUID, UUID | T(TestAlertRule_ViewerCannotWrite) | N/A | N/A |
| 48 | DELETE /alert-rules/{id}/channels/{ch} | GAP (not in cross-org test) | T(middleware) | T(middleware) | UUID, UUID | T(TestAlertRule_ViewerCannotWrite) | N/A | N/A |

### Scheduled Reports

| # | Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL params | RBAC | Fail-closed | Audit log |
|---|----------|-----------|------------|-------------------|------------|------|-------------|-----------|
| 49 | GET /reports | T(TestReports_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID, cursor | T(middleware: viewer) | N/A | N/A (read) |
| 50 | POST /reports | T(TestReports_CrossOrgIsolation) | T(middleware) | T(middleware) | strings, UUID (rule_id) | T(TestReports_RBAC_ViewerCannotWrite) | N/A | **GAP** (no audit code) |
| 51 | GET /reports/{id} | T(TestReports_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID | T(middleware: viewer) | N/A | N/A (read) |
| 52 | PATCH /reports/{id} | T(TestReports_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID, strings | T(TestReports_RBAC_ViewerCannotWrite) | N/A | **GAP** (no audit code) |
| 53 | DELETE /reports/{id} | T(TestReports_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID | T(TestReports_RBAC_ViewerCannotWrite) | N/A | **GAP** (no audit code) |
| 54 | GET /reports/{id}/channels | T(TestReports_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID | T(middleware: viewer) | N/A | N/A (read) |
| 55 | PUT /reports/{id}/channels/{ch} | T(TestBindChannelToReport_CrossOrgChannelRejected) | T(middleware) | T(middleware) | UUID, UUID | T(TestReports_RBAC_ViewerCannotWrite) | N/A | **GAP** (no audit code) |
| 56 | DELETE /reports/{id}/channels/{ch} | GAP (not in cross-org test) | T(middleware) | T(middleware) | UUID, UUID | T(TestReports_RBAC_ViewerCannotWrite) | N/A | **GAP** (no audit code) |

### AI

| # | Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL params | RBAC | Fail-closed | Audit log |
|---|----------|-----------|------------|-------------------|------------|------|-------------|-----------|
| 57 | POST /ai/nl-search | T(TestAIHandlers_CrossOrgIsolation) | T(middleware) | T(middleware) | string (query) | T(middleware: viewer) | T (AI quota limit) | N/A |
| 58 | POST /ai/summarize/{cve_id} | T(TestAIHandlers_CrossOrgIsolation) | T(middleware) | T(middleware) | string (cve_id) | T(middleware: viewer) | T (AI quota limit) | N/A |

### Saved Searches

| # | Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL params | RBAC | Fail-closed | Audit log |
|---|----------|-----------|------------|-------------------|------------|------|-------------|-----------|
| 59 | GET /saved-searches | T(TestSavedSearch_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID, cursor | T(TestSavedSearch_RBAC) | N/A | N/A (read) |
| 60 | POST /saved-searches | T(TestSavedSearch_CrossOrgIsolation) | T(middleware) | T(middleware) | strings, JSON (DSL) | T(TestSavedSearch_RBAC) | N/A | T(TestAuditIntegration_SavedSearches) |
| 61 | GET /saved-searches/{id} | T(TestSavedSearch_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID | T(TestSavedSearch_RBAC) | N/A | N/A (read) |
| 62 | PATCH /saved-searches/{id} | T(TestSavedSearch_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID, strings, JSON | T(TestSavedSearch_RBAC) | N/A | T(TestAuditIntegration_SavedSearches) |
| 63 | DELETE /saved-searches/{id} | T(TestSavedSearch_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID | T(TestSavedSearch_RBAC) | N/A | T(TestAuditIntegration_SavedSearches) |
| 64 | POST /saved-searches/{id}/execute | T(TestSavedSearch_CrossOrgIsolation) | T(middleware) | T(middleware) | UUID | T(TestSavedSearch_RBAC) | N/A | N/A (read-like) |

### Groups

| # | Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL params | RBAC | Fail-closed | Audit log |
|---|----------|-----------|------------|-------------------|------------|------|-------------|-----------|
| 65 | GET /groups | T(TestCrossOrg_GroupAccess) | T(middleware) | T(middleware) | UUID | T(middleware: viewer) | N/A | N/A (read) |
| 66 | POST /groups | T(TestCrossOrg_GroupAccess) | T(middleware) | T(middleware) | string (name, description) | T(middleware: admin) | N/A | **GAP** (no audit code) |
| 67 | GET /groups/{group_id} | T(TestCrossOrg_GroupAccess) | T(middleware) | T(middleware) | UUID | T(middleware: viewer) | N/A | N/A (read) |
| 68 | PATCH /groups/{group_id} | T(TestCrossOrg_GroupAccess) | T(middleware) | T(middleware) | UUID, strings | T(middleware: admin) | N/A | **GAP** (no audit code) |
| 69 | DELETE /groups/{group_id} | T(TestCrossOrg_GroupAccess) | T(middleware) | T(middleware) | UUID | T(middleware: admin) | N/A | **GAP** (no audit code) |
| 70 | GET /groups/{group_id}/members | T(TestCrossOrg_GroupAccess) | T(middleware) | T(middleware) | UUID | T(middleware: viewer) | N/A | N/A (read) |
| 71 | POST /groups/{group_id}/members | GAP (not in cross-org test) | T(middleware) | T(middleware) | UUID (user_id) | T(middleware: admin) | N/A | **GAP** (no audit code) |
| 72 | DELETE /groups/{group_id}/members/{user_id} | GAP (not in cross-org test) | T(middleware) | T(middleware) | UUID | T(middleware: admin) | N/A | **GAP** (no audit code) |

### Spot-Check Verification

Three "Tested" cells verified at random:

1. **TestCrossOrg_MemberOperations** (orgs #5 cross-org): ✅ Creates two orgs with different users, verifies user A cannot list/update/remove members in org B's space. Tests GET, PATCH, DELETE.
2. **TestTierGating_Members_PendingInvitationsConsumeSlots** (invitations #7 fail-closed): ✅ Creates 4 members + 1 pending invitation = 5 slots, verifies 2nd invitation returns 403. Correctly tests CountMemberSlotsUsedByOrg behavior.
3. **TestAuditIntegration_Channels** (channels #22 audit): ✅ Creates, patches, and deletes a channel, verifies audit entries exist for each operation with correct entity_type and action.

---

## Gap Context

| Category | Gaps | Action |
|----------|------|--------|
| Cross-org isolation | 11 | Add cross-org isolation tests |
| Audit logging (missing code) | 14 | Add audit logging to handler code + tests |
| Audit logging (missing test) | 3 | Add audit integration tests |
| TOCTOU windows | 3 | Add concurrency guards or acceptance tests |
| Semantic spot-checks | 2 | Fix code bugs or add targeted tests |
| Assertion quality | 2 | Strengthen existing tests |
| **Total** | **35** | |

---

## What's Well-Covered

- **Auth middleware** is thoroughly tested with 8 tests covering JWT (valid, expired, wrong secret, malformed) and API key (valid, invalid, context values, non-Bearer) paths. RequireAuthenticated at 100% coverage.
- **RBAC middleware** has strong coverage with role hierarchy tests, API key role capping, exact role match verification, and edge cases (no user ID, invalid org ID). RequireOrgRole at 100%.
- **Tier gating** is exceptionally well tested — 13 dedicated tests in tier_gating_test.go covering free limits, enterprise unlimited, overrides, pending invitation slot consumption, and rate limiting. The `CountMemberSlotsUsedByOrg` function is correctly used (not `CountMembersByOrg`).
- **Cross-org isolation** is tested for most endpoint groups — alert rules, watchlists, orgs/members, groups, reports, deliveries, saved searches, AI, API keys, audit log, and SSO/OIDC.
- **Tier resolver** at 100% with full test coverage in internal/tier.

---

## Production Bugs Discovered

### BUG-1: Missing audit logging in groups handler (code bug)

**File:** [groups.go](internal/api/groups.go)
**Severity:** Security-critical
**Source:** semantic (§4.5A cross-handler consistency)

All other mutation handlers (channels, alert_rules, watchlists, saved_searches, orgs/members, SSO) emit audit log entries for create/update/delete operations. groups.go has zero `auditLog` calls despite having 5 mutating endpoints (create, update, delete group; add/remove member). This is a cross-handler consistency bug — the pattern is clearly established, and groups is the exception.

### BUG-2: Missing audit logging in reports handler (code bug)

**File:** [reports.go](internal/api/reports.go)
**Severity:** Security-critical
**Source:** semantic (§4.5A cross-handler consistency)

Same pattern violation as BUG-1. reports.go has zero `auditLog` calls despite 5 mutating endpoints (create, update, delete report; bind/unbind channel). Alert rule channel binding has no audit logging either, but report operations should be auditable.

### BUG-3: Missing audit logging in apikeys handler (code bug)

**File:** [apikeys.go](internal/api/apikeys.go)
**Severity:** Security-critical
**Source:** semantic (§4.5A cross-handler consistency)

API key creation and revocation are security-sensitive operations that should absolutely be audited. apikeys.go has zero `auditLog` calls. Creating an API key grants programmatic access to the org. Revoking one removes it. Both should appear in the audit log.

### BUG-4: Missing audit logging for delivery replay (code bug)

**File:** [deliveries.go](internal/api/deliveries.go)
**Severity:** Correctness
**Source:** semantic (§4.5A cross-handler consistency)

Replay is a mutating action that re-fires a notification. It should be audited for accountability.

### BUG-5: Missing audit logging for org operations (code bug)

**File:** [orgs.go](internal/api/orgs.go)
**Severity:** Correctness
**Source:** semantic (§4.5A cross-handler consistency)

`createOrgHandler`, `updateOrgHandler`, `createInvitationHandler`, and `cancelInvitationHandler` have no audit logging. Only `updateMemberRoleHandler` and `removeMemberHandler` have it. `acceptInvitationHandler` (in auth.go) does have audit logging.

---

## Security-Critical Gaps (19)

### Cross-org isolation gaps

1. **No cross-org test for GET /channels** — user from org B could potentially list org A's channels — [channels_test.go](internal/api/channels_test.go) — source: matrix
2. **No cross-org test for POST /channels** — user from org B could potentially create a channel in org A — [channels_test.go](internal/api/channels_test.go) — source: matrix
3. **No cross-org test for GET /channels/{id}** — user from org B could potentially read org A's channel — [channels_test.go](internal/api/channels_test.go) — source: matrix
4. **No cross-org test for PATCH /channels/{id}** — user from org B could potentially modify org A's channel — [channels_test.go](internal/api/channels_test.go) — source: matrix
5. **No cross-org test for DELETE /channels/{id}** — user from org B could potentially delete org A's channel — [channels_test.go](internal/api/channels_test.go) — source: matrix
6. **No cross-org test for POST /channels/{id}/rotate-secret** — user from org B could potentially rotate org A's channel secret — [channels_test.go](internal/api/channels_test.go) — source: matrix
7. **No cross-org test for POST /channels/{id}/clear-secondary** — user from org B could potentially clear org A's secondary secret — [channels_test.go](internal/api/channels_test.go) — source: matrix

### Audit logging gaps (missing code)

8. **BUG-1: groups.go has no audit logging code** — all 5 mutations unaudited — [groups.go](internal/api/groups.go) — source: semantic
9. **BUG-3: apikeys.go has no audit logging code** — create + revoke API key unaudited — [apikeys.go](internal/api/apikeys.go) — source: semantic
10. **BUG-2: reports.go has no audit logging code** — all 5 mutations unaudited — [reports.go](internal/api/reports.go) — source: semantic

### Audit logging gaps (missing code, lower impact)

11. **createOrgHandler has no audit logging** — org creation should be audited — [orgs.go:54](internal/api/orgs.go#L54) — source: semantic
12. **updateOrgHandler has no audit logging** — org name change should be audited — [orgs.go:113](internal/api/orgs.go#L113) — source: semantic
13. **createInvitationHandler has no audit logging** — invitation issuance should be audited — [orgs.go:360](internal/api/orgs.go#L360) — source: semantic
14. **cancelInvitationHandler has no audit logging** — invitation cancellation should be audited — [orgs.go:477](internal/api/orgs.go#L477) — source: semantic

### Other cross-org gaps

15. **No cross-org test for GET /orgs/{org_id}/tier** — [org_tier_test.go](internal/api/org_tier_test.go) — source: matrix
16. **No cross-org test for PATCH /orgs/{org_id}** — [orgs_test.go](internal/api/orgs_test.go) — source: matrix
17. **No cross-org test for DELETE /invitations/{id}** — [orgs_test.go](internal/api/orgs_test.go) — source: matrix
18. **No cross-org test for POST /groups/{group_id}/members** — group member add — [groups_test.go](internal/api/groups_test.go) — source: matrix
19. **No cross-org test for DELETE /groups/{group_id}/members/{user_id}** — group member remove — [groups_test.go](internal/api/groups_test.go) — source: matrix

---

## Correctness Gaps (10)

1. **No cross-org test for POST /alert-rules/validate** — [alert_rules_test.go](internal/api/alert_rules_test.go) — source: matrix
2. **No cross-org test for DELETE /alert-rules/{id}/channels/{ch}** — channel unbinding — [alert_rules_test.go](internal/api/alert_rules_test.go) — source: matrix
3. **No cross-org test for DELETE /reports/{id}/channels/{ch}** — channel unbinding — [reports_test.go](internal/api/reports_test.go) — source: matrix
4. **BUG-4: deliveries.go replay has no audit logging** — [deliveries.go:275](internal/api/deliveries.go#L275) — source: semantic
5. **BUG-5: createOrgHandler, updateOrgHandler, createInvitationHandler, cancelInvitationHandler missing audit** — [orgs.go](internal/api/orgs.go) — source: semantic
6. **store.ListCVEs at 0% coverage** — uncovered correctness function (dynamic query builder) — [store/cve.go:61](internal/store/cve.go#L61) — source: coverage
7. **store.BootstrapFirstUserOrg at 58.8%** — multi-step bootstrap logic with uncovered error branches — [store/org.go:66](internal/store/org.go#L66) — source: coverage
8. **store.withOrgRawTx at 64.3%** — RLS transaction helper with uncovered error paths — [store/store.go:78](internal/store/store.go#L78) — source: coverage
9. **store.withBypassTx at 71.4%** — bypass transaction helper with uncovered error paths — [store/store.go:50](internal/store/store.go#L50) — source: coverage
10. **api.pgErrCode at 0% coverage** — Postgres error code extraction utility — [api/auth.go:35](internal/api/auth.go#L35) — source: coverage

---

## Nice-to-Have (3)

1. **api.encodeDeliveryCursor at 0%** — cursor encoding utility — [deliveries.go:88](internal/api/deliveries.go#L88) — source: coverage
2. **store/generated: 23 functions at 0%** — sqlc-generated code for Phase 1 CVE operations (UpsertCVE, InsertAffectedCPE, etc.) — not tested in this Phase 5 scope — source: coverage
3. **store.generated.Scan/Value at 0%** — enum type scanner — source: coverage

---

## Assertion Quality Issues (2)

1. **TestTierGating_Members_FreeLimit only checks status code** — Verifies 403 but does not verify the error message contains "tier limit" — could pass if 403 is returned for a different reason (e.g., RBAC). Consider asserting on response body. — [tier_gating_test.go:329](internal/api/tier_gating_test.go#L329) — source: assertion
2. **TestCrossOrg_GroupAccess uses t.Errorf instead of t.Fatalf for early failures** — If the first cross-org check fails (which would indicate a real security breach), the test continues checking more endpoints rather than stopping immediately. A cross-org isolation failure should be a fatal failure. — [groups_test.go:476](internal/api/groups_test.go#L476) — source: assertion

---

## TOCTOU Analysis

### Multi-step flows enumerated

| Flow | State read (A) | State used (B) | External change possible? | Guard | Tested? |
|------|----------------|----------------|--------------------------|-------|---------|
| OIDC login → callback | SSO connection loaded, enabled=true | Connection re-loaded in callback | Yes (admin deletes/disables connection) | Re-load + enabled check in callback | T(TestOIDCFlow_CrossOrgIsolation) |
| OIDC link init → link callback | SSO connection loaded | Connection re-loaded in callback | Yes | Re-load + enabled check | Partially tested |
| OAuth init → callback | OAuth state/nonce set in cookie | State/nonce verified in callback | Limited (CSRF state is cryptographic) | CSRF state + nonce | Tested |
| Tier check → create invitation | CountMemberSlotsUsedByOrg < limit | INSERT invitation | Yes (concurrent request) | **None** — no lock | **GAP** |
| Tier check → create alert rule | CountAlertRulesByOrg < limit | INSERT alert_rule | Yes (concurrent request) | **None** — no lock | **GAP** |
| Tier check → create watchlist | CountWatchlistsByOrg < limit | INSERT watchlist | Yes (concurrent request) | **None** — no lock | **GAP** |
| Invitation create → accept | Tier checked at create time | No tier re-check at accept time | Yes (org fills up between invite and accept) | **None** — intentional? | Not tested |
| Channel active-binding check → delete | Check ChannelHasActiveBoundRules | DELETE channel | Yes (concurrent unbind could race) | Transaction | Not specifically tested |
| Secret rotation → clear-secondary | Rotate generates new primary, moves old to secondary | Clear removes secondary | No meaningful race (sequential operations) | N/A | N/A |

### TOCTOU Gaps

1. **Tier limit TOCTOU: concurrent requests can exceed limits** — Two concurrent `createAlertRuleHandler` requests can both pass `CountAlertRulesByOrg < limit` before either INSERT completes, resulting in one more resource than the limit allows. Same applies to watchlists and invitations. No advisory lock or UNIQUE constraint guards against this. — source: TOCTOU
2. **Invitation accept has no tier re-check** — `acceptInvitationHandler` does not verify the org is still within member limits. If 4 members exist and 2 pending invitations are accepted simultaneously, the org ends up with 6 members on a 5-member limit. — source: TOCTOU
3. **Concurrent channel delete + unbind race** — If a channel is unbound from a rule and deleted simultaneously, the delete could see stale binding state. Mitigated by transaction isolation but not explicitly tested. — source: TOCTOU

---

## Key Observations

### Cross-cutting patterns

1. **Channels are the only endpoint group with zero cross-org isolation tests.** Every other org-scoped endpoint group (watchlists, alert rules, reports, deliveries, groups, saved searches, AI, API keys, audit log, SSO) has dedicated cross-org tests. This is a systematic blind spot in channels_test.go — 7 endpoints unverified.

2. **Audit logging follows an inconsistent pattern across handlers.** Alert rules, channels, watchlists, saved searches, SSO, and members have audit logging. Groups, reports, deliveries (replay), and API keys do not. The audit integration test only covers the first set, masking the gap in the second set. This is a **cross-handler consistency violation** — 14 mutating endpoints lack audit logging.

3. **Tier limits have no concurrency protection.** The check-then-act pattern (`count < limit → INSERT`) is used consistently across alert rules, watchlists, and invitations but has no advisory lock or database-level constraint to prevent concurrent over-allocation. While this is a low-probability race in practice, it's architecturally unsound for a security product.

4. **Auth middleware coverage is strong but tested independently.** The RequireAuthenticated and RequireOrgRole middleware have excellent standalone tests, which means individual handler tests don't need to re-test unauth/RBAC. This is good architecture — but it means a routing misconfiguration (middleware not applied to a new endpoint) would not be caught by handler tests. Consider a smoke test that hits every endpoint without auth and verifies 401.

5. **Store transaction helpers (withBypassTx, withOrgRawTx, OrgTx, WorkerTx)** have partial coverage (64-78%). The error paths in these security-critical functions (RLS SET LOCAL failures, transaction rollback errors) are uncovered. Since these are the RLS enforcement layer, error path testing is important.

6. **Generated sqlc code at 0%** (23 functions) is expected — these are Phase 1 CVE operations not exercised by Phase 5 tests. Not a gap for Phase 5 scope.