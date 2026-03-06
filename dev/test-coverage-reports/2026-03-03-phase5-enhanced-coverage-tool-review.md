# Phase 5 Enhanced Coverage-Tool Test Coverage Review

**Scope:** `./internal/api/...`, `./internal/store/...`, `./internal/tier/...`
**Date:** 2026-03-03
**Skill:** `/test-coverage-review-go` (Run C of A/B test)
**Coverage files:** `coverage-ab.out`, `coverage-ab-func.txt` (pre-generated)

---

## Coverage Baseline

| Package | Coverage | Functions | Uncovered (0%) |
|---------|----------|-----------|----------------|
| internal/api | 74.9% | 181 | 2 |
| internal/store | 86.2% | 188 | 1 |
| internal/store/generated | 81.5% | 186 | 23 |
| internal/tier | 100.0% | 4 | 0 |
| **Overall** | **~80.5%** | **559** | **26** |

Coverage distribution: 26 at 0%, 188 at 1–79%, 123 at 80–99%, 222 at 100%.

**Note:** 23 of 26 uncovered functions are in `store/generated/` — feed/merge pipeline code (out of Phase 5 scope). The 3 Phase-5-relevant uncovered functions are `pgErrCode` (api), `encodeDeliveryCursor` (api), and `ListCVEs` (store).

---

## Security Checklist Matrix

### Orgs + Members + Invitations

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| GET /orgs/{id} | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested (middleware: TestRequireOrgRole_InvalidOrgID_400) | N/A | Tested (viewer+, middleware) | N/A |
| PATCH /orgs/{id} | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested (middleware) | string (name) | Tested (admin+, middleware) | N/A |
| GET /orgs/{id}/tier | GAP (no cross-org test) | Tested (middleware) | Tested (middleware) | N/A | Tested (viewer+, middleware) | N/A |
| GET /orgs/{id}/members | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested (middleware) | N/A | Tested (viewer+, inherits) | N/A |
| PATCH /orgs/{id}/members/{uid} | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested (middleware) | UUID (user_id), string (role) | Tested (admin+, route) | Tested (sole owner, escalation) |
| DELETE /orgs/{id}/members/{uid} | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested (middleware) | UUID (user_id) | Tested (admin+, route) | Tested (sole owner protection) |
| POST /orgs/{id}/invitations | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested (middleware) | string (email, role) | Tested (admin+, route) | Tested (tier limit: TestTierGating_Members_FreeLimit) |
| GET /orgs/{id}/invitations | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested (middleware) | N/A | Tested (admin+, route) | N/A |
| DELETE /orgs/{id}/invitations/{id} | GAP (no cross-org test for cancel) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (admin+, route) | N/A |

### API Keys

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| POST /orgs/{id}/api-keys | Tested (TestCrossOrg_APIKeyAccess) | Tested (middleware) | Tested (middleware) | string (name, role), int (expires_in_days) | Tested (member+, route; TestCreateAPIKey_ViewerForbidden) | Tested (role escalation: TestCreateAPIKey_RoleEscalation) |
| GET /orgs/{id}/api-keys | Tested (TestCrossOrg_APIKeyAccess) | Tested (middleware) | Tested (middleware) | N/A | Tested (viewer+, inherits) | N/A |
| DELETE /orgs/{id}/api-keys/{id} | Tested (TestCrossOrg_APIKeyAccess) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (ownership check in handler) | Tested (TestRevokeAPIKey_NotOwner) |

### Watchlists

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| GET /orgs/{id}/watchlists | Tested (TestWatchlist_WrongOrg) | Tested (middleware) | Tested (middleware) | N/A | Tested (viewer+, route) | N/A |
| POST /orgs/{id}/watchlists | Tested (TestWatchlist_WrongOrg) | Tested (middleware) | Tested (middleware) | string (name, description) | Tested (member+; TestWatchlist_ViewerCannotWrite) | Tested (tier limit: TestTierGating_Watchlists_FreeLimit) |
| GET /orgs/{id}/watchlists/{id} | Tested (TestWatchlist_CrossOrgReadWriteIsolation) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (viewer+, route) | N/A |
| PATCH /orgs/{id}/watchlists/{id} | Tested (TestWatchlist_CrossOrgReadWriteIsolation) | Tested (middleware) | Tested (middleware) | string (name), *UUID (group_id) | Tested (member+; ViewerCannotWrite) | N/A |
| DELETE /orgs/{id}/watchlists/{id} | Tested (TestWatchlist_CrossOrgReadWriteIsolation) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (member+; ViewerCannotWrite) | N/A |
| GET /orgs/{id}/watchlists/{id}/items | Tested (TestWatchlist_CrossOrgReadWriteIsolation) | Tested (middleware) | Tested (middleware) | N/A | Tested (viewer+, route) | N/A |
| POST /orgs/{id}/watchlists/{id}/items | Tested (TestWatchlist_CrossOrgReadWriteIsolation) | Tested (middleware) | Tested (middleware) | string (cve_id) | Tested (member+, route) | N/A |
| DELETE /orgs/{id}/watchlists/{id}/items/{iid} | Tested (TestWatchlist_CrossOrgReadWriteIsolation) | Tested (middleware) | Tested (middleware) | UUID (item_id) | Tested (member+, route) | N/A |

### Notification Channels

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| GET /orgs/{id}/channels | **GAP** | Tested (middleware) | Tested (middleware) | N/A | Tested (viewer+, route) | N/A |
| POST /orgs/{id}/channels | **GAP** | Tested (middleware) | Tested (middleware) | string (name, type), JSON (config) | Tested (member+, route) | Tested (tier: TestTierGating_Channels_FreeBlocksEmail) |
| GET /orgs/{id}/channels/{id} | **GAP** | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (viewer+, route) | N/A |
| PATCH /orgs/{id}/channels/{id} | **GAP** | Tested (middleware) | Tested (middleware) | string (name), JSON (config) | GAP (no viewer-write test) | N/A |
| DELETE /orgs/{id}/channels/{id} | **GAP** | Tested (middleware) | Tested (middleware) | UUID (id) | GAP (no viewer-write test) | Tested (active bindings: TestDeleteChannel_409IfActiveRuleBound) |
| POST /orgs/{id}/channels/{id}/rotate-secret | **GAP** | Tested (middleware) | Tested (middleware) | UUID (id) | GAP (no viewer-write test) | Tested (email rejected: TestRotateSecret_EmailChannel_Rejected) |
| POST /orgs/{id}/channels/{id}/clear-secondary | **GAP** | Tested (middleware) | Tested (middleware) | UUID (id) | GAP (no viewer-write test) | Tested (email rejected: TestClearSecondary_EmailChannel_Rejected) |

### Alert Rules

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| GET /orgs/{id}/alert-rules | Tested (TestAlertRule_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | N/A | Tested (viewer+, route) | N/A |
| POST /orgs/{id}/alert-rules | Tested (TestAlertRule_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | string (name, dsl), UUID[] (watchlist_ids) | Tested (member+; TestAlertRule_ViewerCannotWrite) | Tested (tier: TestTierGating_AlertRules_FreeLimit) |
| GET /orgs/{id}/alert-rules/{id} | Tested (TestAlertRule_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (viewer+, route) | N/A |
| PATCH /orgs/{id}/alert-rules/{id} | Tested (TestAlertRule_CrossOrgPatchAndDelete) | Tested (middleware) | Tested (middleware) | string (name, dsl), string (status) | Tested (member+, route) | Tested (status state machine) |
| DELETE /orgs/{id}/alert-rules/{id} | Tested (TestAlertRule_CrossOrgPatchAndDelete) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (member+; ViewerCannotWrite) | N/A |
| POST /orgs/{id}/alert-rules/validate | GAP (no cross-org test) | Tested (middleware) | Tested (middleware) | string (dsl) | Tested (viewer+, route) | N/A |
| POST /orgs/{id}/alert-rules/{id}/dry-run | Tested (TestDryRun_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (viewer+, route) | N/A |
| GET /orgs/{id}/alert-rules/{id}/channels | GAP (no cross-org test) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (viewer+, route) | N/A |
| PUT /orgs/{id}/alert-rules/{id}/channels/{cid} | Tested (TestBindChannelToRule_CrossOrgChannelRejected) | Tested (middleware) | Tested (middleware) | UUID (id, channel_id) | Tested (member+, route) | Tested (cross-org channel rejected) |
| DELETE /orgs/{id}/alert-rules/{id}/channels/{cid} | GAP (no cross-org unbind test) | Tested (middleware) | Tested (middleware) | UUID (id, channel_id) | Tested (member+, route) | N/A |

### Scheduled Reports

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| GET /orgs/{id}/reports | Tested (TestReports_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | N/A | Tested (viewer+, route) | N/A |
| POST /orgs/{id}/reports | Tested (TestReports_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | string (name, cron, tz), string (dsl) | Tested (member+; TestReports_RBAC_ViewerCannotWrite) | N/A |
| GET /orgs/{id}/reports/{id} | Tested (TestReports_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (viewer+, route) | N/A |
| PATCH /orgs/{id}/reports/{id} | Tested (TestReports_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | string (name, cron, tz, status) | Tested (member+; ViewerCannotWrite) | Tested (status state machine) |
| DELETE /orgs/{id}/reports/{id} | Tested (TestReports_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (member+; ViewerCannotWrite) | N/A |
| PUT /orgs/{id}/reports/{id}/channels/{cid} | Tested (TestBindChannelToReport_CrossOrgChannelRejected) | Tested (middleware) | Tested (middleware) | UUID (id, channel_id) | Tested (member+, route) | Tested (cross-org channel rejected) |
| DELETE /orgs/{id}/reports/{id}/channels/{cid} | GAP (no cross-org unbind test) | Tested (middleware) | Tested (middleware) | UUID (id, channel_id) | Tested (member+, route) | N/A |
| GET /orgs/{id}/reports/{id}/channels | GAP (no cross-org test) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (viewer+, route) | N/A |

### SSO Connections (Enterprise Only)

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| POST /orgs/{id}/sso | **GAP** | Tested (middleware) | Tested (middleware) | string (display_name, issuer_url, client_id, client_secret) | Tested (owner+; TestSSOConnection_RBAC) | Tested (tier: TestSSOConnection_TierGating) |
| GET /orgs/{id}/sso | **GAP** | Tested (middleware) | Tested (middleware) | N/A | Tested (owner+, route) | N/A |
| PATCH /orgs/{id}/sso | **GAP** | Tested (middleware) | Tested (middleware) | string (display_name, issuer_url, client_id, client_secret) | Tested (owner+, route) | N/A |
| DELETE /orgs/{id}/sso | **GAP** | Tested (middleware) | Tested (middleware) | N/A | Tested (owner+, route) | N/A |
| PUT /orgs/{id}/sso/domains | **GAP** | Tested (middleware) | Tested (middleware) | string[] (domains) | Tested (owner+, route) | Tested (domain validation: TestSSODomains_ValidatesFormat) |
| GET /orgs/{id}/sso/link | **GAP** | Tested (middleware) | Tested (middleware) | N/A | Tested (member+, route) | N/A |

### Groups

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| GET /orgs/{id}/groups | Tested (TestCrossOrg_GroupAccess) | Tested (middleware) | Tested (middleware) | N/A | Tested (viewer+, route) | N/A |
| POST /orgs/{id}/groups | Tested (TestCrossOrg_GroupAccess) | Tested (middleware) | Tested (middleware) | string (name, description) | Tested (member+; TestCreateGroup_AsViewer) | N/A |
| GET /orgs/{id}/groups/{id} | Tested (TestCrossOrg_GroupAccess) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (viewer+, route) | N/A |
| PATCH /orgs/{id}/groups/{id} | Tested (TestCrossOrg_GroupAccess) | Tested (middleware) | Tested (middleware) | string (name, description) | Tested (admin+, route) | N/A |
| DELETE /orgs/{id}/groups/{id} | Tested (TestCrossOrg_GroupAccess) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (admin+, route) | N/A |
| GET /orgs/{id}/groups/{id}/members | Tested (TestCrossOrg_GroupAccess) | Tested (middleware) | Tested (middleware) | N/A | Tested (viewer+, route) | N/A |
| POST /orgs/{id}/groups/{id}/members | Tested (TestCrossOrg_GroupAccess) | Tested (middleware) | Tested (middleware) | UUID (user_id) | Tested (admin+, route) | N/A |
| DELETE /orgs/{id}/groups/{id}/members/{uid} | GAP (no cross-org remove member test) | Tested (middleware) | Tested (middleware) | UUID (id, user_id) | Tested (admin+, route) | N/A |

### Deliveries

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| GET /orgs/{id}/deliveries | Tested (TestDeliveries_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | string (status, rule_id, channel_id), string (cursor) | Tested (viewer+, route) | N/A |
| GET /orgs/{id}/deliveries/{id} | Tested (TestDeliveries_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (viewer+, route) | N/A |
| POST /orgs/{id}/deliveries/{id}/replay | Tested (TestDeliveries_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (admin+; TestReplayDelivery_RBAC_ViewerMemberForbidden) | Tested (rate limit: TestReplayDelivery_RateLimited) |

### Alert Events

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| GET /orgs/{id}/alert-events | Tested (TestAlertEvents_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | string (rule_id, cve_id, cursor) | Tested (viewer+, route) | N/A |

### Saved Searches

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| GET /orgs/{id}/saved-searches | Tested (TestSavedSearch_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | N/A | Tested (viewer+, route) | N/A |
| POST /orgs/{id}/saved-searches | Tested (TestSavedSearch_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | string (name, dsl, visibility) | Tested (member+; RBAC test) | N/A |
| GET /orgs/{id}/saved-searches/{id} | Tested (TestSavedSearch_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (viewer+; private visibility) | Tested (private: creator-only access) |
| PATCH /orgs/{id}/saved-searches/{id} | Tested (TestSavedSearch_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | string (name, dsl, visibility) | Tested (member+; canModify logic) | Tested (private: TestSavedSearch_RBAC) |
| DELETE /orgs/{id}/saved-searches/{id} | Tested (TestSavedSearch_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (member+; canModify logic) | N/A |
| POST /orgs/{id}/saved-searches/{id}/execute | Tested (TestSavedSearch_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | UUID (id) | Tested (viewer+, route) | N/A |

### Audit Log

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| GET /orgs/{id}/audit-log | Tested (TestAuditAPI_CrossOrgIsolation) | Tested (middleware) | Tested (middleware) | string (entity_type, action, actor_id, after, before, cursor) | Tested (admin+; TestAuditAPI_RBAC) | Tested (tier: TestAuditAPI_TierGating) |

---

## Gap Context

| Category | Files | Gaps | Action |
|----------|-------|------|--------|
| Uncovered (0%) — Phase 5 | 3 | 3 | Create test cases |
| Uncovered (0%) — out of scope | 23 | 23 | Defer to feed/merge phase |
| Partial coverage | 188 | ~80 (mostly tx error paths) | Add targeted test cases |
| Security matrix GAPs | 5 | 28 | Add cross-org/RBAC tests |
| Assertion quality | 1 | 1 | Strengthen existing tests |
| Semantic spot-checks | 3 | 4 | Fix code or add targeted tests |
| **Total (Phase 5 scope)** | | **~36 actionable** | |

---

## What's Well-Covered

- **RLS tenant isolation is thoroughly tested.** `org_tx_test.go` contains fail-closed tests for org_members, org_invitations, api_keys, groups, and group_members using a real `NOBYPASSRLS` app role. Confirms that unset `app.org_id` returns 0 rows (not an error).
- **Cross-org isolation via middleware + RBAC is tested for most endpoints.** Orgs, watchlists, alert rules, reports, groups, deliveries, saved searches, audit log, and alert events all have dedicated cross-org tests that verify 403 is returned.
- **Tier gating is comprehensively tested.** `tier_gating_test.go` covers free limits for alert rules, watchlists, members, and channel types. Also tests override expansion and enterprise unlimited. Pending invitations correctly consume member slots (`TestTierGating_Members_PendingInvitationsConsumeSlots`).

---

## Production Bugs Discovered

### BUG-1: `org_tier.go:61` — Wrong function called for member usage display (correctness) — source: semantic

`getOrgTierHandler` calls `CountMembersByOrg` (active members only) to populate the "used" count for `max_members`. But tier enforcement in `createInvitationHandler` (orgs.go:398) correctly uses `CountMemberSlotsUsedByOrg` (members + pending invitations).

**Impact:** A user at 4/5 active members + 1 pending invitation sees "4/5 used" on the tier info page but gets 403 when trying to invite — the display is misleading. The enforcement is correct; the display is wrong.

**Fix:** Change `org_tier.go:61` from `CountMembersByOrg` to `CountMemberSlotsUsedByOrg`.

### BUG-2: `groups.go`, `reports.go`, `deliveries.go` — Missing audit logging (correctness) — source: semantic

These three handler files have zero `auditLog` calls, while channels, alert_rules, orgs, saved_searches, watchlists, and SSO all audit create/update/delete operations. This is a cross-handler pattern violation.

**Impact:** Group, report, and delivery operations (including replay, which is a security-sensitive action) produce no audit trail. An admin reviewing audit logs for compliance cannot see when groups were created/modified/deleted, when reports were configured, or when deliveries were replayed.

**Fix:** Add `srv.auditLog(r, ...)` calls to the mutating handlers in these three files.

---

## Security-Critical Gaps (17)

1. **Channels: No cross-org isolation tests (7 endpoints)** — channels_test.go — source: matrix
   - GET /channels (list), POST /channels (create), GET /channels/{id}, PATCH /channels/{id}, DELETE /channels/{id}, POST rotate-secret, POST clear-secondary — all missing cross-org tests
   - The store layer has cross-org tests for notification channels, but the HTTP handler layer does not verify that the middleware pipeline rejects cross-org requests for these endpoints
2. **SSO: No cross-org isolation tests (6 endpoints)** — sso_test.go — source: matrix
   - POST /sso, GET /sso, PATCH /sso, DELETE /sso, PUT /sso/domains, GET /sso/link — all missing cross-org tests
   - SSO manages client_secret (AES-256-GCM encrypted) and domain ownership — cross-org access here could leak secrets or hijack domain verification
3. **Channels: No RBAC viewer-denied-write tests (4 endpoints)** — channels_test.go — source: matrix
   - PATCH /channels/{id}, DELETE /channels/{id}, POST rotate-secret, POST clear-secondary — no test verifies that a viewer gets 403 on these member+ endpoints
4. **GET /orgs/{id}/tier: No cross-org test** — org_tier_test.go — source: matrix
   - Tier info may reveal org plan level and resource usage to unauthorized users
5. **DELETE /orgs/{id}/invitations/{id}: No cross-org test** — orgs_test.go — source: matrix
   - `cancelInvitationHandler` is not included in the cross-org member operations test
6. **POST /alert-rules/validate: No cross-org test** — alert_rules_test.go — source: matrix
   - Validation endpoint that could leak information about valid DSL patterns
7. **GET /alert-rules/{id}/channels: No cross-org test** — alert_rules_test.go — source: matrix
   - Listing bound channels for a rule could leak channel names/IDs across orgs
8. **DELETE /alert-rules/{id}/channels/{cid}: No cross-org unbind test** — alert_rules_test.go — source: matrix
   - Bind has cross-org test, but unbind does not
9. **DELETE /reports/{id}/channels/{cid}: No cross-org unbind test** — reports_test.go — source: matrix
   - Bind has cross-org test, but unbind does not
10. **GET /reports/{id}/channels: No cross-org test** — reports_test.go — source: matrix
    - Listing bound channels for a report could leak channel names/IDs
11. **DELETE /groups/{id}/members/{uid}: No cross-org remove member test** — groups_test.go — source: matrix
    - `TestCrossOrg_GroupAccess` covers list/get/update/delete/add-member but not remove-member
12. **Missing audit logging: replay delivery** — deliveries.go — source: semantic
    - Replay is a security-sensitive action (re-executes webhook delivery with org data) that produces no audit trail
13. **Missing audit logging: group mutations** — groups.go — source: semantic
    - Group create/update/delete/add-member/remove-member produce no audit entries
14. **Missing audit logging: report mutations** — reports.go — source: semantic
    - Report create/patch/delete/bind/unbind-channel produce no audit entries
15. **SSO RBAC: No cross-org test for non-owner member access** — sso_test.go — source: matrix
    - `TestSSOConnection_RBAC` tests member-in-same-org gets 403 (not owner), but no test verifies a user from org B cannot access org A's SSO configuration
16. **orgID fail-closed: No dedicated per-endpoint test** — multiple files — source: matrix
    - Only `saved_searches_test.go` and `ai_test.go` test invalid org_id → 400 per-endpoint. Middleware covers this globally (`TestRequireOrgRole_InvalidOrgID_400`), but no defense-in-depth at handler level for other domains. Middleware coverage is acceptable, but documented here for completeness.
17. **channels_test.go: No SSRF validation test for PATCH webhook URL changes** — channels_test.go — source: coverage
    - `TestPatchChannel_WebhookSSRFBlocked` exists (line 693) — actually this IS tested. Removing from count.

**Revised count: 16 security-critical gaps.**

---

## Correctness Gaps (8)

1. **`encodeDeliveryCursor` at 0%** — api/deliveries.go:88 — source: coverage
   - Cursor encoding for delivery pagination is untested. If broken, delivery list pagination fails.
2. **`ListCVEs` at 0%** — store/cve.go:61 — source: coverage
   - Wrapper function, 2 lines. Appears unused in Phase 5 (CVE browsing handler not yet implemented). Low risk but should be tested when used.
3. **BUG-1: `CountMembersByOrg` in org_tier.go:61** — wrong function called — source: semantic
   - Tier info shows active members instead of members + pending invitations. See Production Bugs section.
4. **BUG-2: Missing audit logging in groups/reports/deliveries** — source: semantic
   - Pattern violation: 3 handler files lack audit logging entirely. See Production Bugs section.
5. **`BootstrapFirstUserOrg` — no concurrent race test** — store/store.go — source: semantic
   - Advisory lock serialization is present in code but the test only validates single-user vs multi-user in isolation, not two goroutines racing. (Note: `concurrent_test.go` tests advisory lock for UpsertCVE, not bootstrap.)
6. **`AcceptOrgInvitation` — inner `CreateOrgMember` failure atomicity untested** — store/invitation.go — source: coverage
   - The atomicity guarantee (failed member creation rolls back invitation acceptance) is not verified.
7. **`UpsertDelivery` — lacks panic-recovery defer** — store/notification_delivery.go:38 — source: semantic
   - Hand-rolls its own transaction without the `recover()` defer that `withBypassTx` provides. Defense-in-depth gap.
8. **`encodeDeliveryCursor` and `decodeCursor` for deliveries** — deliveries.go — source: coverage
   - Cursor encode/decode pipeline is untested; keyset pagination could silently break.

---

## Nice-to-Have (76)

The vast majority (~70) are `withOrgTx`/`withBypassTx` error paths — `BeginTx` failure, `SET LOCAL` failure, `tx.Commit()` failure. These require database fault injection to test. Listed in store subagent results.

Other notable nice-to-have items:
1. `pgErrCode` at 0% — api/auth.go:35 — Postgres error code extraction utility (~5 lines)
2. `generateSigningSecret` 75% — store/notification_channel.go — `crypto/rand.Read` error (OS entropy failure)
3. All `store/generated/` 0% functions (23) — feed/merge pipeline, out of Phase 5 scope
4. `fromNullUUID` 66.7% — store/helpers.go — NULL branch exercised but not explicitly asserted
5. All `Cleanup*` retention functions at 87.5% — transaction error paths
6. Various `ListAlertRules`, `ListAlertEvents` 86-90% — `ToSql()` builder errors, `rows.Scan` errors

---

## Assertion Quality Issues (1)

1. **`channels_test.go` — No behavioral assertions on SSRF validation for PATCH** — While `TestPatchChannel_WebhookSSRFBlocked` exists and checks status 422, it only tests private IPs. No test validates that a well-formed-but-malicious URL (e.g., redirecting to localhost) is caught. The create-path SSRF test covers more cases (127.x, 10.x, 169.254.x, ::1), but the PATCH-path test only covers one pattern. — source: assertion

---

## Key Observations

### Cross-handler pattern: Audit logging inconsistency
Channels, alert rules, orgs, saved searches, watchlists, and SSO all call `srv.auditLog()` on mutating operations. Groups, reports, and deliveries do not. This is a systematic gap — not an isolated omission. All three files were likely written without the audit pattern being established or copied.

### Coverage floor from transaction helpers
~70 of 76 nice-to-have gaps follow a single pattern: the error paths within `withOrgTx`/`withBypassTx` wrappers (BeginTx failure, SET LOCAL failure, tx.Commit failure). These are database-unavailable scenarios requiring fault injection. The actual business logic branches are covered. This is a structural ceiling from the transaction-helper architecture.

### Channels and SSO: Parallel security gaps
Both `channels_test.go` and `sso_test.go` have zero cross-org isolation tests. This is the most significant security gap in the Phase 5 test suite. Both domains manage sensitive data (webhook secrets, OIDC client secrets). While the middleware pipeline (RequireOrgRole) provides the actual protection, no test verifies that these specific endpoints correctly integrate with the pipeline.

### orgID fail-closed handled at middleware level
The `RequireOrgRole` middleware validates `org_id` as UUID and performs org membership lookup. This is tested in `middleware_rbac_test.go`. Per-endpoint fail-closed tests exist only for saved-searches and AI endpoints. The middleware provides the protection; the per-endpoint tests document the contract.

### Wrong-function-called in tier info (BUG-1)
Coverage tools cannot distinguish between `CountMembersByOrg` and `CountMemberSlotsUsedByOrg` — both execute successfully, both return an int64. This is exactly the class of bug that semantic spot-checks catch but coverage tools miss. The enforcement handler uses the correct function; the display handler uses the wrong one.

### TOCTOU analysis
No TOCTOU windows detected in Phase 5 scope. Multi-step flows (`BootstrapFirstUserOrg`, `AcceptOrgInvitation`, `CreateOrgWithOwner`) all execute within single transactions. The SSO OIDC flow (redirect → callback) uses state parameter validation, eliminating TOCTOU at the protocol level. Delivery replay uses a rate limiter check-then-act, but this is rate limiting (not authorization) so TOCTOU is acceptable.
