# Phase 5 Hybrid Test Coverage Review

**Date:** 2026-03-03
**Scope:** `internal/api/...`, `internal/store/...`, `internal/tier/...`
**Method:** Hybrid — coverage-guided triage (Pass 1) + semantic code analysis (Pass 2)
**Coverage file:** `coverage-ab.out` / `coverage-ab-func.txt`

---

## Coverage Baseline

| Package | Coverage | Functions | Uncovered (0%) | Partially Covered |
|---------|----------|-----------|----------------|-------------------|
| internal/api | ~70% | 100 | 2 | ~65 |
| internal/store | ~82% | 183 | 25 | ~45 |
| internal/store/generated | ~82% | 156 | 18 | ~30 |
| internal/tier | 100% | 4 | 0 | 0 |
| **Overall** | **73.5%** | **560** | **~45** | **~140** |

**Note:** Many 0% functions in `store/generated/cves.sql.go` and `store/generated/feed.sql.go` are feed/merge pipeline code (Phase 2-3), not Phase 5 scope. These are tagged as out-of-scope below.

---

## Security Checklist Matrix

### Org Management Endpoints

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| POST /orgs | N/A (creates new) | Tested (middleware) | N/A | string (name) | N/A | N/A |
| GET /orgs/:id | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested | N/A | Tested (viewer+) | N/A |
| PATCH /orgs/:id | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested | string (name) | Tested (admin+) | N/A |
| GET /orgs/:id/members | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested | N/A | Tested (viewer+) | N/A |
| PATCH /orgs/:id/members/:uid | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested | string (role) | Tested (admin+) | GAP (last owner demotion) |
| DELETE /orgs/:id/members/:uid | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested | UUID | Tested (admin+) | Tested (last owner) |
| POST /orgs/:id/invitations | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested | string (email, role) | Tested (admin+) | **GAP (no audit log on tier block — BUG-1)** |
| GET /orgs/:id/invitations | Tested (TestCrossOrg_MemberOperations) | Tested (middleware) | Tested | N/A | Tested (admin+) | N/A |
| DELETE /orgs/:id/invitations/:id | GAP | Tested (middleware) | GAP | UUID | Tested (admin+) | N/A |
| GET /orgs/:id/tier | GAP | Tested (middleware) | Tested | N/A | Tested (viewer+) | N/A |

### Alert Rules Endpoints

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| POST /orgs/:id/alert-rules | Tested | Tested (middleware) | Tested | string (DSL), UUID[] (watchlists) | Tested (member+) | Tested (tier limit) |
| GET /orgs/:id/alert-rules/:id | Tested | Tested (middleware) | Tested | UUID | Tested (viewer+) | N/A |
| GET /orgs/:id/alert-rules | Tested | Tested (middleware) | Tested | N/A | Tested (viewer+) | N/A |
| PATCH /orgs/:id/alert-rules/:id | Tested (CrossOrgPatchAndDelete) | Tested (middleware) | Tested | string (DSL), UUID[] | Tested (member+) | N/A |
| DELETE /orgs/:id/alert-rules/:id | Tested (CrossOrgPatchAndDelete) | Tested (middleware) | Tested | UUID | Tested (member+) | N/A |
| POST /orgs/:id/alert-rules/validate | Tested | Tested (middleware) | Tested | string (DSL) | Tested (viewer+) | N/A |
| POST /orgs/:id/alert-rules/:id/dry-run | Tested (CrossOrgIsolation) | Tested (middleware) | Tested | UUID | Tested (viewer+) | Tested (candidate cap) |
| GET /orgs/:id/alert-rules/:id/channels | Tested | Tested (middleware) | Tested | UUID | Tested (viewer+) | N/A |
| POST /orgs/:id/alert-rules/:id/channels | Tested (CrossOrgChannelRejected) | Tested (middleware) | Tested | UUID | Tested (member+) | N/A |
| DELETE /orgs/:id/alert-rules/:id/channels/:cid | Tested | Tested (middleware) | Tested | UUID | Tested (member+) | N/A |

### Alert Events Endpoints

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| GET /orgs/:id/alert-events | Tested (CrossOrgIsolation) | Tested (middleware) | Tested | cursor, date, UUID | Tested (viewer+) | N/A |

### Notification Channels Endpoints

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| POST /orgs/:id/channels | **GAP** | Tested (middleware) | Tested | string (name, type, config) | Tested (admin+) | Tested (tier limit) |
| GET /orgs/:id/channels/:id | **GAP** | Tested (middleware) | Tested | UUID | Tested (viewer+) | N/A |
| GET /orgs/:id/channels | **GAP** | Tested (middleware) | Tested | N/A | Tested (viewer+) | N/A |
| PATCH /orgs/:id/channels/:id | **GAP** | Tested (middleware) | Tested | string (name, config) | Tested (admin+) | Tested (active bindings) |
| DELETE /orgs/:id/channels/:id | **GAP** | Tested (middleware) | Tested | UUID | Tested (admin+) | Tested (active bindings) |
| POST /orgs/:id/channels/:id/rotate | **GAP** | Tested (middleware) | Tested | UUID | Tested (admin+) | N/A |
| POST /orgs/:id/channels/:id/clear-secondary | **GAP** | Tested (middleware) | Tested | UUID | Tested (admin+) | N/A |

### SSO Endpoints

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| POST /orgs/:id/sso | **GAP** | Tested (middleware) | Tested | string (display, issuer, client_id, secret) | Tested (owner) | Tested (enterprise tier) |
| GET /orgs/:id/sso | **GAP** | Tested (middleware) | Tested | N/A | Tested (owner) | Tested (enterprise tier) |
| PATCH /orgs/:id/sso/:id | **GAP** | Tested (middleware) | Tested | string (display, etc.) | **GAP (admin→403 not tested)** | Tested (enterprise tier) |
| DELETE /orgs/:id/sso/:id | **GAP** | Tested (middleware) | Tested | UUID | **GAP (admin→403 not tested)** | Tested (enterprise tier) |
| PUT /orgs/:id/sso/:id/domains | **GAP** | Tested (middleware) | Tested | string[] (domains) | **GAP (admin→403 not tested)** | Tested (enterprise tier) |

### API Keys Endpoints

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| POST /orgs/:id/api-keys | Tested (CrossOrg_APIKeyAccess) | Tested (middleware) | Tested | string (name, description) | Tested (admin+) | N/A |
| GET /orgs/:id/api-keys | Tested (CrossOrg_APIKeyAccess) | Tested (middleware) | Tested | N/A | Tested (admin+) | N/A |
| DELETE /orgs/:id/api-keys/:id | Tested (CrossOrg_APIKeyAccess) | Tested (middleware) | Tested | UUID | Tested (admin+) | N/A |

### Watchlists Endpoints

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| POST /orgs/:id/watchlists | Tested (WrongOrg) | Tested (middleware) | Tested | string (name, desc) | Tested (member+) | Tested (tier limit) |
| GET /orgs/:id/watchlists/:id | Tested (CrossOrgReadWriteIsolation) | Tested (middleware) | Tested | UUID | Tested (viewer+) | N/A |
| GET /orgs/:id/watchlists | Tested | Tested (middleware) | Tested | cursor | Tested (viewer+) | N/A |
| PATCH /orgs/:id/watchlists/:id | Tested (CrossOrgReadWriteIsolation) | Tested (middleware) | Tested | string (name, desc) | Tested (member+) | N/A |
| DELETE /orgs/:id/watchlists/:id | Tested (CrossOrgReadWriteIsolation) | Tested (middleware) | Tested | UUID | Tested (member+) | N/A |
| POST /orgs/:id/watchlists/:id/items | Tested (CrossOrgReadWriteIsolation) | Tested (middleware) | Tested | string (cve_id, pattern) | Tested (member+) | N/A |
| GET /orgs/:id/watchlists/:id/items | Tested (CrossOrgReadWriteIsolation) | Tested (middleware) | Tested | UUID | Tested (viewer+) | N/A |
| DELETE /orgs/:id/watchlists/:id/items/:iid | Tested (CrossOrgReadWriteIsolation) | Tested (middleware) | Tested | UUID | Tested (member+) | N/A |

### Saved Searches Endpoints

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| POST /orgs/:id/saved-searches | Tested (CrossOrgIsolation) | Tested (middleware) | Tested | string (name, DSL, visibility) | Tested (member+) | N/A |
| GET /orgs/:id/saved-searches | Tested (CrossOrgIsolation) | Tested (middleware) | Tested | N/A | Tested (viewer+) | N/A |
| GET /orgs/:id/saved-searches/:id | Tested (CrossOrgIsolation) | Tested (middleware) | Tested | UUID | Tested (viewer+) | N/A |
| PATCH /orgs/:id/saved-searches/:id | Tested (CrossOrgIsolation) | Tested (middleware) | Tested | string (name, DSL) | Tested (member+/ownership) | N/A |
| DELETE /orgs/:id/saved-searches/:id | Tested (CrossOrgIsolation) | Tested (middleware) | Tested | UUID | Tested (member+/ownership) | N/A |
| POST /orgs/:id/saved-searches/:id/execute | Tested (CrossOrgIsolation) | Tested (middleware) | Tested | UUID | Tested (viewer+) | N/A |

### Reports Endpoints

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| POST /orgs/:id/reports | Tested | Tested (middleware) | Tested | string (name, cron, DSL), UUID[] | Tested (member+) | N/A |
| GET /orgs/:id/reports/:id | Tested (CrossOrgIsolation) | Tested (middleware) | Tested | UUID | Tested (viewer+) | N/A |
| GET /orgs/:id/reports | Tested | Tested (middleware) | Tested | N/A | Tested (viewer+) | N/A |
| PATCH /orgs/:id/reports/:id | Tested | Tested (middleware) | Tested | string (name, cron, DSL) | Tested (member+) | N/A |
| DELETE /orgs/:id/reports/:id | Tested | Tested (middleware) | Tested | UUID | Tested (member+) | N/A |
| POST /orgs/:id/reports/:id/channels | Tested (CrossOrgChannelRejected) | Tested (middleware) | Tested | UUID | Tested (member+) | N/A |
| DELETE /orgs/:id/reports/:id/channels/:cid | Tested | Tested (middleware) | Tested | UUID | Tested (member+) | N/A |
| GET /orgs/:id/reports/:id/channels | Tested | Tested (middleware) | Tested | UUID | Tested (viewer+) | N/A |

### Deliveries Endpoints

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| GET /orgs/:id/deliveries | Tested (CrossOrgIsolation) | Tested (middleware) | Tested | cursor, UUID | Tested (viewer+) | N/A |
| GET /orgs/:id/deliveries/:id | Tested (CrossOrgIsolation) | Tested (middleware) | Tested | UUID | Tested (viewer+) | N/A |
| POST /orgs/:id/deliveries/:id/replay | Tested (CrossOrgIsolation) | Tested (middleware) | Tested | UUID | Tested (admin+) | Tested (replay rate limit) |

### Groups Endpoints

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| POST /orgs/:id/groups | Tested | Tested (middleware) | Tested | string (name, desc) | Tested (admin+) | N/A |
| GET /orgs/:id/groups/:id | Tested (CrossOrg_GroupAccess) | Tested (middleware) | Tested | UUID | Tested (viewer+) | N/A |
| GET /orgs/:id/groups | Tested (CrossOrg_GroupAccess) | Tested (middleware) | Tested | N/A | Tested (viewer+) | N/A |
| PATCH /orgs/:id/groups/:id | Tested (CrossOrg_GroupAccess) | Tested (middleware) | Tested | string (name, desc) | Tested (admin+) | N/A |
| DELETE /orgs/:id/groups/:id | Tested (CrossOrg_GroupAccess) | Tested (middleware) | Tested | UUID | Tested (admin+) | N/A |
| POST /orgs/:id/groups/:id/members | Tested (CrossOrg_GroupAccess) | Tested (middleware) | Tested | UUID | Tested (admin+) | N/A |
| GET /orgs/:id/groups/:id/members | Tested (CrossOrg_GroupAccess) | Tested (middleware) | Tested | N/A | Tested (viewer+) | N/A |
| DELETE /orgs/:id/groups/:id/members/:uid | Tested | Tested (middleware) | Tested | UUID | Tested (admin+) | N/A |

### Audit Log Endpoints

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| GET /orgs/:id/audit-log | Tested (CrossOrgIsolation) | Tested (middleware) | Tested | cursor, date, string (action) | Tested (admin+) | Tested (enterprise tier) |

### AI Endpoints

| Endpoint | Cross-org | Unauth→401 | orgID fail-closed | SQL param types | RBAC | Fail-closed |
|----------|-----------|------------|-------------------|-----------------|------|-------------|
| POST /orgs/:id/ai/nl-search | Tested (CrossOrgIsolation) | Tested (middleware) | Tested | string (query) | Tested (viewer+) | Tested (AI quota) |
| POST /orgs/:id/ai/summarize | Tested (CrossOrgIsolation) | Tested (middleware) | Tested | string (cve_id) | Tested (viewer+) | Tested (AI quota) |

### Auth Endpoints (not org-scoped)

| Endpoint | Relevant checks | Tested |
|----------|----------------|--------|
| POST /auth/register | rate limit, input validation | Tested |
| POST /auth/login | rate limit, timing-safe | Tested |
| POST /auth/refresh | token rotation, grace period | Tested |
| POST /auth/logout | token invalidation | Tested |
| GET /auth/me | auth required | Tested |
| PATCH /auth/password | old password verification | Tested |

### OIDC/OAuth Endpoints (not org-scoped)

| Endpoint | Cross-org | Tested |
|----------|-----------|--------|
| GET /auth/oidc/:conn_id/login | SSO connection validation | Tested |
| GET /auth/oidc/:conn_id/callback | Identity-connection binding | Tested (CrossOrgIsolation) |
| GET /auth/oidc/:conn_id/link | Auth required + connection validation | Tested |
| GET /auth/oidc/:conn_id/link/callback | Identity ownership | Tested |

---

## Gap Context

| Category | Files | Gaps | Action |
|----------|-------|------|--------|
| Security matrix GAPs | 8 | 17 | Add security-specific tests |
| Production bugs | 2 | 2 | Fix code |
| Partially covered (security-critical paths) | 15 | 22 | Add specific test cases |
| Assertion quality | 4 | 5 | Strengthen existing tests |
| Uncovered (0%, in-scope) | 3 | 3 | Create test cases |
| Uncovered (0%, out-of-scope) | 4 | 20 | Out of Phase 5 scope |
| Semantic analysis | 6 | 8 | Fix code or add targeted tests |
| **Total** | | **77** | |

---

## What's Well-Covered

- **Middleware chain**: `RequireAuthenticated` (100%), `RequireOrgRole` (100%), `csrfProtect` (100%), `authRateLimit` (100%), `clientIPMiddleware` (100%) — the security middleware foundation is solid.
- **Tier system**: `internal/tier/` at 100%, tier cache at 100%, rate limiter implementations (`newIPRateLimiter`, `newOrgRateLimiter`) at 100%, parser/resolver fully covered.
- **Auth flow**: Cookie helpers, state/nonce validation, CSRF protection all at 100%. Registration, login, refresh flows well-exercised with cross-org tests on OIDC callback path.
- **Alert rules + events**: Comprehensive cross-org isolation tests covering CRUD, dry-run, bind/unbind channels, patch/delete across org boundaries.
- **Saved searches**: Full cross-org isolation suite (create, list, get, patch, delete, execute) — all 6 operations tested.

---

## Production Bugs Discovered

### BUG-1: Missing audit log on invitation tier block (security — source: semantic §4A)

**File:** `internal/api/orgs.go:404-407`

`createInvitationHandler` returns 403 when the member tier limit is reached but does NOT write an audit log entry. All three other tier-gated creation handlers audit-log the denial:

- `createChannelHandler` (channels.go:99-108) — audit logs with `reason: "tier_limit"`
- `createAlertRuleHandler` (alert_rules.go:189-198) — audit logs with `reason: "tier_limit"`
- `createWatchlistHandler` (watchlists.go:194-203) — audit logs with `reason: "tier_limit"`

The invitation handler is the only one that silently denies. This is a cross-handler consistency violation — 3 of 4 handlers follow the pattern, the 4th omits the audit log.

### BUG-2: Wrong function called in getOrgTierHandler (correctness — source: semantic §4B)

**File:** `internal/api/org_tier.go:61`

`getOrgTierHandler` calls `CountMembersByOrg` (counts only `org_members` rows) to display the member usage count. But the invitation tier limit check in `createInvitationHandler` (orgs.go:398) uses `CountMemberSlotsUsedByOrg` (counts members + pending unexpired invitations).

This means the tier display underreports member usage. An org with 4 members and 1 pending invitation on a 5-member limit would show `"used": 4` in the tier endpoint even though a new invitation would be denied. The two SQL queries confirm the mismatch:
- `CountMembersByOrg`: `SELECT COUNT(*) FROM org_members WHERE org_id = $1`
- `CountMemberSlotsUsedByOrg`: members + unexpired pending invitations

---

## Security-Critical Gaps (17)

1. **Channels: NO cross-org isolation test** — All 7 channel endpoints (create, get, list, patch, delete, rotate, clear-secondary) lack cross-org tests. A user from org A could potentially access org B's channels. — channels_test.go — source: matrix
2. **SSO: NO cross-org isolation test** — All 5 SSO endpoints (create, get, patch, delete, putDomains) lack cross-org tests. — sso_test.go — source: matrix
3. **SSO RBAC: admin→403 not tested** — SSO requires owner role but RBAC test only checks member→403 (sso_test.go:230-237). Admin→403 is not verified for patch, delete, or putDomains. — sso_test.go:204 — source: matrix
4. **cancelInvitation: NO cross-org test** — DELETE /orgs/:id/invitations/:id has no cross-org test. — orgs_test.go — source: matrix
5. **Org tier endpoint: NO cross-org test** — GET /orgs/:id/tier has no dedicated cross-org test (member operations test covers GET org but not the /tier sub-path). — org_tier_test.go — source: matrix
6. **createInvitationHandler: missing audit log on tier block (BUG-1)** — orgs.go:404-407 — source: semantic
7. **putSSODomainsHandler: missing audit log** — SSO domain updates have security implications (controls which email domains can use SSO) but no audit trail. All other SSO mutations (create, patch, delete) audit-log. — sso.go:426 — source: semantic
8. **createOrgHandler: missing audit log** — Org creation is a significant event without audit trail. — orgs.go:54 — source: semantic
9. **updateOrgHandler: missing audit log** — Org updates (name changes) have no audit trail. — orgs.go:113 — source: semantic
10. **cancelInvitationHandler: missing audit log** — Invitation cancellation has no audit trail. — orgs.go:477 — source: semantic
11. **withBypassTx: 71.4% coverage, no dedicated test** — This transaction helper is security-critical (bypasses RLS). Error paths (BEGIN failure, SET LOCAL failure) are untested. — store/store.go:50 — source: coverage
12. **withOrgRawTx: 64.3% coverage, no dedicated test** — Sets `app.org_id` for RLS enforcement. Error paths untested. — store/store.go:78 — source: coverage
13. **OrgTx: 77.8% coverage** — Public transaction helper for handlers. Commit failure and SET LOCAL failure paths not tested. — store/store.go:115 — source: coverage
14. **WorkerTx: 77.8% coverage** — Worker transaction helper with `bypass_rls = 'on'`. Commit failure and SET LOCAL failure paths not tested. — store/store.go:135 — source: coverage
15. **tierMiddleware: 70.6% coverage** — Error path when GetOrgTier fails, and path when orgID is missing from context (potential fail-open). — middleware_tier.go:19 — source: coverage
16. **createInvitationHandler: invitation success not audit-logged** — Even on success, creating an invitation has no audit trail. — orgs.go:430 — source: semantic
17. **TOCTOU: SSO connection deleted between OIDC redirect and callback** — User initiates OIDC login → redirect to IdP → connection deleted by admin while user is at IdP → callback arrives for deleted connection. The callback handler (oauth_oidc.go:233) loads the connection fresh, so it will get a "not found" error, but this error path has limited test coverage at 62.5%. — oauth_oidc.go:233 — source: semantic

---

## Correctness Gaps (22)

1. **getOrgTierHandler uses wrong count function (BUG-2)** — Uses `CountMembersByOrg` instead of `CountMemberSlotsUsedByOrg`. — org_tier.go:61 — source: semantic
2. **getCVEHandler: 40.0% coverage** — Multiple uncovered branches including error paths and empty-result handling. — cves.go:377 (26 lines)
3. **getCVESourcesHandler: 47.6% coverage** — Uncovered error paths for source retrieval. — cves.go:460 (21 lines)
4. **getOrgHandler: 46.2% coverage** — Error paths uncovered. — orgs.go:86 (13 lines)
5. **updateOrgHandler: 45.0% coverage** — Validation branches and error paths uncovered. — orgs.go:113 (20 lines)
6. **cancelInvitationHandler: 50.0% coverage** — Error paths and not-found case uncovered. — orgs.go:477 (18 lines)
7. **replayDeliveryHandler: 43.8% coverage** — Replay flow branches uncovered. — deliveries.go:275 (16 lines)
8. **updateGroupHandler: 42.9% coverage** — Error and validation branches uncovered. — groups.go:146 (14 lines)
9. **deleteGroupHandler: 46.2% coverage** — Error paths uncovered. — groups.go:197 (13 lines)
10. **addGroupMemberHandler: 47.6% coverage** — Error paths and duplicate member case uncovered. — groups.go:254 (21 lines)
11. **removeGroupMemberHandler: 47.1% coverage** — Error paths uncovered. — groups.go:289 (17 lines)
12. **updateWatchlistHandler: 50.0% coverage** — Validation and error branches uncovered. — watchlists.go:325 (25 lines)
13. **deleteWatchlistItemHandler: 47.1% coverage** — Error paths uncovered. — watchlists.go:589 (17 lines)
14. **bindRuleChannelHandler: 52.0% coverage** — Cross-org channel check path partially untested. — alert_rules.go:697 (25 lines)
15. **unbindRuleChannelHandler: 52.0% coverage** — Error paths uncovered. — alert_rules.go:736 (25 lines)
16. **bindChannelToReportHandler: 48.5% coverage** — Error paths uncovered. — reports.go:364 (33 lines)
17. **unbindChannelFromReportHandler: 47.1% coverage** — Error paths uncovered. — reports.go:414 (17 lines)
18. **deleteReportHandler: 46.2% coverage** — Error paths uncovered. — reports.go:344 (13 lines)
19. **patchSSOHandler: 56.1% coverage** — Several uncovered branches (partial update fields, encryption error paths). — sso.go:252 (57 lines)
20. **deleteSSOHandler: 52.6% coverage** — Error paths uncovered. — sso.go:386 (19 lines)
21. **BootstrapFirstUserOrg: 58.8% coverage** — No concurrent race test for first-user bootstrap. — store/org.go:66 (17 lines)
22. **UpsertDelivery: 66.7% coverage** — Uses manual transaction management instead of `withBypassTx`. — store/notification_delivery.go:38 (12 lines)

---

## Nice-to-Have (18)

1. **pgErrCode: 0% coverage** — Error code extraction helper. — api/auth.go:35 (8 lines)
2. **encodeDeliveryCursor: 0% coverage** — Delivery cursor encoding. — api/deliveries.go:88 (8 lines)
3. **ListCVEs (store): 0% coverage** — Thin wrapper around generated code. — store/cve.go:61 (6 lines)
4. **NewServer: 50.0% coverage** — Server initialization branches (TLS config, metrics). — server.go:54 (63 lines)
5. **healthzHandler: 68.8% coverage** — DB ping failure path. — server.go:400 (16 lines)
6. **writeJSON: 75.0% coverage** — JSON marshal error path. — orgs.go:44 (10 lines)
7. **refreshGrace: 53.3% coverage** — Edge case branches in token grace period logic. — auth.go:320 (15 lines)
8. **issueRefreshPair: 50.0% coverage** — Token generation error paths. — auth.go:345 (15 lines)
9. **generateSigningSecret: 75.0% coverage** — Crypto random error path. — store/notification_channel.go:47 (11 lines)
10. **fromNullUUID: 66.7% coverage** — Null UUID conversion. — store/audit.go:144 (8 lines)
11. **CompleteJob: 66.7% coverage** — Error path. — store/jobs.go:48 (9 lines)
12. **FailJob: 66.7% coverage** — Error path. — store/jobs.go:57 (12 lines)
13. **Scan (models.go:43): 0% coverage** — Generated scanner for enum type. — store/generated/models.go:43
14. **Value (models.go:53): 0% coverage** — Generated value converter for enum type. — store/generated/models.go:53
15. **All `store/generated/cves.sql.go` 0% functions** — Feed/merge pipeline (DeleteCVEAffectedCPEs, DeleteCVEReferences, DeleteEPSSStaging, FindCVEBySourceID, etc.) — out of Phase 5 scope
16. **All `store/generated/feed.sql.go` 0% functions** — Feed sync state management — out of Phase 5 scope
17. **GetWatchlistItem: 0% coverage** — Generated SQL function, not currently called by any handler. — store/generated/watchlist.sql.go:167
18. **Generated List* functions at 73.3%** — All sqlc-generated List functions show 73.3% due to row-scanning loop branches not fully exercised. This is a systematic pattern in the generated code and low risk.

---

## Assertion Quality Issues (5)

1. **TestGetOrgTier_FreeTier: doesn't validate member count source** — The test checks that limits are returned correctly but doesn't verify that the `used` member count matches `CountMemberSlotsUsedByOrg` (it actually uses the wrong function — BUG-2). A test asserting that pending invitations are counted would have caught this bug. — org_tier_test.go — source: assertion
2. **TestSSOConnection_RBAC: incomplete role coverage** — Only tests member→403. Should also verify admin→403 since SSO requires owner role. The test name implies comprehensive RBAC coverage but only checks one role. — sso_test.go:204 — source: assertion
3. **Store transaction helper tests: side-effect coverage only** — `withBypassTx` and `withOrgRawTx` are exercised via handler tests (which call store methods that use these helpers), but no test directly verifies their RLS-setting behavior. A test that reads `current_setting('app.org_id')` inside the transaction would verify the mechanism itself. — store/store.go:50-103 — source: assertion
4. **Channel tests: no negative ownership assertion** — Channel tests verify CRUD operations work for the owning org but never assert that another org gets 403 or 0 results. This means RLS + orgID parameter enforcement is untested for channels specifically. — channels_test.go — source: assertion
5. **Delivery replay rate limit: assertion on limit boundary** — `checkReplayLimit` at 92.3% is well-covered but the test doesn't verify the exact boundary (e.g., 10th replay succeeds, 11th fails). — deliveries.go:34 — source: assertion

---

## Key Observations

### Cross-Cutting Patterns

1. **Cross-org coverage desert: Channels + SSO** — Two entire handler families (7 channel endpoints, 5 SSO endpoints) have ZERO cross-org isolation tests. While middleware enforces orgID via `RequireOrgRole`, the absence of endpoint-level cross-org tests means any handler that incorrectly reads orgID from the URL path (instead of context) would be undetected.

2. **Audit logging inconsistency is systematic** — The missing audit logs follow a pattern: all Phase 5 additions (channels, alert rules, watchlists, SSO mutations) audit-log consistently, but the original org management handlers (createOrg, updateOrg, invitations, cancelInvitation) don't. The `putSSODomainsHandler` is an exception — it was added in Phase 5 but lacks audit logging despite its siblings having it.

3. **Transaction helper coverage gap** — The security-critical transaction helpers (`withBypassTx`, `withOrgRawTx`) have no dedicated tests. They're exercised indirectly through handler tests, but no test verifies that `SET LOCAL app.org_id = $1` actually takes effect. This is a defense-in-depth concern — the RLS layer would be silently broken if these helpers regressed.

4. **Handler coverage plateau at 45-60%** — Many handlers cluster around 45-60% coverage. The pattern: happy path + one error path tested, but validation branches, not-found cases, and secondary error paths are consistently uncovered. This is most pronounced in groups.go (42-58%), reports.go (46-66%), and sso.go (52-76%).

5. **Generated code 73.3% pattern** — All sqlc-generated List functions show exactly 73.3% coverage due to the row-scanning loop (`for rows.Next()`) not hitting the `rows.Err()` branch. This is a low-risk systematic artifact.

### TOCTOU Windows

1. **SSO redirect → callback**: Connection can be deleted/disabled between redirect and callback. Handler loads fresh, but error path has limited coverage.
2. **Invitation tier check → creation**: Member count checked, then invitation created. A concurrent invitation could exceed the limit. No advisory lock or unique constraint prevents this.
3. **Channel delete safety check → delete**: Handler checks for active bindings, then deletes. Concurrent bind could create orphan.

### Cross-Handler Pattern Violations

1. **Tier block audit logging**: 3/4 handlers audit-log (channels, alert_rules, watchlists), invitations does not (BUG-1).
2. **Mutation audit logging**: Phase 5 handlers (channels, alert_rules, watchlists, SSO CRUD) consistently audit-log all mutations. Org management handlers (createOrg, updateOrg, invitations, cancelInvitation) do not.
3. **SSO RBAC**: All SSO handlers use `RequireOrgRole(RoleOwner)` in the route definition (server.go), but the RBAC test only validates member→403. Admin→403 should be tested to confirm owner-only enforcement.