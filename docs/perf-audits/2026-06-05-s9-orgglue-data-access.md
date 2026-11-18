# S9 Org/SCIM/Admin/Tenant Glue — Data-Access Audit
**Date:** 2026-06-05
**Lane:** data-access
**Scope:** `internal/api/{orgs,groups,org_tier,org_ratelimit,scim_users,scim_groups_handler,scim_admin,scim_notif_sync,middleware_scim,admin_users,admin_orgs,admin_system,admin_doctor,audit_log,tier_cache,middleware_rbac,middleware_site_admin,middleware_tier}.go`, `internal/{audit,tier}/`, `internal/store/{org,group,scim_groups,scim_config,admin_org,admin_user,admin_delivery,admin_system,audit}.go`, plus SQL queries and DDL/indexes.

---

## Summary

Two real findings. The middleware hot paths (RBAC membership check, tier cache, rate limiter) are correctly designed and do not over-query. The problems are in the SCIM provisioning path — which bypasses the tier cache entirely and issues a redundant config re-fetch per call — and in the cross-org admin audit log query, which has no usable index for its sort order.

---

### MAJOR — SCIM provisioning path bypasses `tierCache` and re-fetches SCIM config on every call

**Location:**
- `internal/api/scim_users.go:1072–1093` (`checkSCIMMemberLimit`)
- `internal/api/scim_users.go:1097–1103` (`getSCIMDefaultRole`)
- `internal/api/server.go:473–497` (SCIM routes — no `tierMiddleware`)

**Problem:** The `/orgs/{org_id}/scim/v2/...` route group is mounted with only `requireSCIMAuth` and `scimRateLimit()` — not `tierMiddleware`. As a result, every SCIM provisioning request that needs a tier check calls `srv.store.GetOrgTier(ctx, orgID)` directly (inside `checkSCIMMemberLimit`), bypassing `tierCache` entirely. The `tierCache` TTL path used by all regular API handlers is never consulted.

Compounding this, `getSCIMDefaultRole` issues a second independent query — `srv.store.GetSCIMConfig(ctx, orgID)` — to retrieve `default_role`. This is redundant: `requireSCIMAuth` already fetched and authenticated the full `SCIMConfigRow` (including `DefaultRole`) at the start of the request. The full config is not propagated into the handler context, so handlers must re-query for the same row.

For the new-user provisioning path in `scimCreateUser` (the most common SCIM operation), this produces two avoidable DB round-trips — `GetOrgTier` and `GetSCIMConfig` — that could be eliminated by (a) reading tier from the cached SCIM config's org or a context-local cache, and (b) injecting the authenticated `SCIMConfigRow` into context instead of just the config ID.

**Impact:** SCIM routes are the write path for IdP-driven user provisioning. Enterprise IdPs (Okta, Entra ID) issue one POST per user during initial sync and again on any profile update. For an org provisioning 500 users, each provision call fires 2 uncached DB round-trips for tier/config data that does not change between calls in the same sync window. At typical SCIM sync rates (batch of hundreds per session), this is 1 000 unnecessary DB queries per sync cycle, per org. Under concurrent org onboarding, these queries hold pgxpool connections. Frequency: every SCIM create/put/patch that reaches the member-check or role-assignment branch.

**Confidence:** Strong-static

**Effort:** Contained — two changes: (1) in `requireSCIMAuth`, inject the full `SCIMConfigRow` into context (e.g. `ctxSCIMConfig`); (2) in `getSCIMDefaultRole` and `checkSCIMMemberLimit`, read `default_role` from context and bypass the tier lookup by reading `GetOrgTier` through a request-local call or through the existing `tierCache`. No signature changes to store methods required.

**Verification plan:** Allocation argument: 2 queries removed per SCIM provision call — O(1) per call constant reduction, multiplied by provisioning batch size. Correctness guard: existing `TestSCIMCreateUser*` and `TestSCIMReplaceUser*` tests must pass unchanged; add a test asserting that a SCIM create request hits `GetSCIMConfig` at most once (via middleware) and `GetOrgTier` zero times when tier is unchanged.

---

### MAJOR — `AdminListAuditEntries` has no usable index for cross-org sort; full table scan on first page

**Location:**
- `internal/store/queries/admin_system.sql:4–16` (`AdminListAuditEntries`)
- `migrations/000027_audit_log.up.sql` (only indexes: `(org_id, created_at DESC)` and `(org_id, entity_type, entity_id)`)
- `internal/api/admin_system.go:110–175` (`adminAuditLogHandler` — `org_id` is optional)

**Problem:** `AdminListAuditEntries` issues a cross-org `SELECT * FROM audit_log` with `ORDER BY created_at DESC, id DESC LIMIT N`. When called without an `org_id` filter (the common site-admin use case: view all recent activity across all tenants), neither existing index is applicable:

- `audit_log_org_created_idx` on `(org_id, created_at DESC)` requires an `org_id = $x` equality predicate to become useful; without it, the planner cannot use this index for a `ORDER BY created_at DESC` sort.
- `audit_log_entity_idx` on `(org_id, entity_type, entity_id)` is irrelevant for time-sorted pagination.

PostgreSQL must perform a full sequential scan of `audit_log` followed by an in-memory sort to return the first page. The audit log is an append-only, high-write table (every mutating API call produces an entry); at even modest scale (100 orgs × 1 000 daily mutations) it reaches millions of rows within months.

The org-scoped variant (`ListAuditEntries`) is correctly protected by `(org_id, created_at DESC)` and is not affected.

**Impact:** Every site-admin visit to the audit log page fires a seqscan + sort of the entire `audit_log` table when no `org_id` is specified. At 1M rows this is likely a multi-second query; at 10M rows it becomes untenable. Frequency: every page load of the admin audit log in the site-admin UI. Reachability: low (site admins only), but the per-occurrence cost grows unboundedly with time.

**Confidence:** Strong-static

**Effort:** Localized — add one migration: `CREATE INDEX CONCURRENTLY audit_log_created_idx ON audit_log (created_at DESC, id DESC)`. This allows the keyset pagination cursor `(created_at, id) < (cursor_ts, cursor_id)` to use an index scan. The RLS policy on `audit_log` uses `bypass_rls` for admin access, so the index is accessible via `withBypassTx`.

**Verification plan:** Allocation argument: index scan on `(created_at DESC, id DESC)` returns LIMIT N rows in O(N) index I/O instead of O(total_rows) seqscan + sort. Correctness guard: `TestAdminAuditLog*` tests must pass; add an `EXPLAIN` assertion in a test that the plan on the unfiltered query uses an index scan, not SeqScan.

---

## What was checked and found acceptable

- **`RequireOrgRole` middleware** (`middleware_rbac.go:42`): one `GetOrgMemberRoleAndStatus` PK lookup per request (`org_members` PK is `(org_id, user_id)`). No accumulation. Acceptable per-request cost.
- **`tierMiddleware`** (`middleware_tier.go`): correctly reads from `tierCache` before touching the DB; cache miss is bounded by TTL. Cache is properly invalidated on tier writes (`orgTierHandler`). No issue.
- **`orgRateLimitMiddleware`** (`middleware_tier.go:50`): in-memory token-bucket per org; no DB access. Acceptable.
- **`RequireSiteAdmin`** (`middleware_site_admin.go:22`): one `SELECT is_site_admin FROM users WHERE id = $1` PK lookup per admin request. Site-admin routes are low-traffic. Acceptable.
- **`requireSCIMAuth`** (`middleware_scim.go:45`): one `GetSCIMConfigByTokenHash` lookup via a unique index (`scim_configs_token_hash_idx`). O(1). Acceptable.
- **`listMembersHandler`** (`orgs.go:204`): returns all org members without pagination. Bounded in practice by `LimitMembers` tier cap (5/25/unlimited). For free/pro tiers this is trivially small; for enterprise the lack of pagination is the same structural issue raised in the memory lane for `scimListUsers` — not a new finding.
- **`adminListOrgsHandler` / `adminListUsersHandler`** (`admin_orgs.go`, `admin_users.go`): both use keyset pagination (`afterTime`, `afterID`). Acceptable.
- **`listAuditLogHandler`** (`audit_log.go:40`): org-scoped query uses `(org_id, created_at DESC)` index with a mandatory 30-day default window. Acceptable.
- **`scimListGroups` N+1** (`scim_groups_handler.go:169`): `ListSCIMGroupMembers` called per matching group. SCIM group counts per org are not tier-limited but are bounded by IdP configuration in practice. Already noted in memory lane as acceptable.
- **Audit log indexes for org-scoped query**: `(org_id, created_at DESC)` covers the time-range keyset pagination used by `listAuditLogHandler`. No gap for that path.
- **`scim_group_members` index coverage**: `ListSCIMGroupMembers` query (`WHERE scim_group_id = $1 AND org_id = $2`) hits the composite PK `(scim_group_id, user_id)` which leads on `scim_group_id`. `ListUserSCIMGroups` (`WHERE sgm.user_id = $1 AND sg.org_id = $2`) uses `scim_group_members_user_id_idx`. Both covered.
- **`HasPendingInvitation`** (`org.sql:69`): scans `org_invitations` filtered by `(org_id, lower(email), accepted_at IS NULL, expires_at > now())` with only an `org_id` index. A functional index on `(org_id, lower(email))` would help for high-invitation-volume orgs, but invitation tables are small and this path is invoked at human speed (admin clicking "invite"). Not a finding.

---

## Suspected Bugs (for follow-up)

- **`orgRateLimiter.Allow` resets token bucket on tier change** (`org_ratelimit.go:50–55`): when the tier changes (different `r` or `burst`), `Allow` replaces the `*rate.Limiter` with a new one, effectively resetting all accumulated tokens to the burst maximum. An org that just spent most of its burst budget could get a full refill by having its tier updated (even momentarily). Correctness issue, not a performance issue. File and location: `internal/api/org_ratelimit.go:50`.
