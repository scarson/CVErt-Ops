# S9 Org/SCIM/Admin/Tenant Glue — Memory & Allocation Audit
**Date:** 2026-06-05
**Lane:** memory
**Scope:** `internal/api/{orgs,groups,org_tier,scim_users,scim_groups_handler,scim_admin,scim_types,scim_discovery,scim_roles,scim_notif_sync,middleware_scim,admin_users,admin_orgs,admin_mfa,admin_system,admin_version,admin_reload,admin_doctor,audit_log,tier_cache,middleware_rbac,middleware_tier,role}.go`, `internal/{audit,tier}/`, `internal/store/{org,group,scim_groups,scim_config,admin_org,admin_user,admin_delivery,admin_system,audit}.go`

---

## Summary

Two real findings. The caches and middleware hot paths are well-designed (bounded, eviction-backed, no per-request growth). The problems are in SCIM bulk endpoints: one loads the entire member table into memory before filtering, and two apply per-member DB round-trips inline during administrative write operations.

---

### MAJOR — `scimListUsers` materialises all org members into memory before filtering

**Location:** `internal/api/scim_users.go:464–567` (`scimListUsers`)

**Problem:** `srv.store.ListOrgMembers(ctx, orgID)` fetches every member row for the org unconditionally. The handler then builds a second `[]scimMember` slice by iterating the full result set applying in-process filters, and only afterwards applies the SCIM `startIndex`/`count` page window. A subsequent `ListIdentitiesByProviderAndUsers` call passes the entire `[]uuid.UUID` of all members (unbounded length) to populate the external-ID map. Both allocations are proportional to the total member count, not the requested page size.

**Impact:** SCIM IdPs (Okta, Entra ID) issue periodic full-sync list requests against active enterprise orgs. An org with 5 000 members forces 5 000 `org_members` rows into the Go heap on every such request, plus a `userIDs []uuid.UUID` of equal length, plus the filtered result slice. All three live simultaneously. At ~200 bytes per row (email, display name, role, timestamps, booleans) this is ~3 MB of live allocations per concurrent sync cycle, multiplied by however many orgs are syncing simultaneously. Each completed request is GC-eligible but the allocations spike at the high-water mark of a sync. Frequency: SCIM syncs are periodic (typically every 10–60 minutes) but can be triggered ad-hoc; for SaaS use with many enterprise tenants the aggregate is non-trivial. Severity is constrained by the enterprise-tier gate on SCIM, but is real for deployments with large orgs.

**Confidence:** Strong-static

**Effort:** Contained — the fix requires pushing the filter and pagination into the store query (`ListOrgMembersFiltered(ctx, orgID, filter, startIndex, count)`) and adding a `CountOrgMembersFiltered` query for `TotalResults`. The `ListIdentitiesByProviderAndUsers` call becomes page-sized. Two new sqlc queries and a refactored handler.

**Verification plan:** Allocation argument: replacing the full-table fetch with a keyset-paginated, filter-pushed query reduces peak heap from O(total_members) to O(page_size). Correctness guard: existing SCIM list tests must pass unchanged; add a test that verifies `TotalResults` reflects pre-filter count when a username filter is active, and that `startIndex`/`count` pagination returns the correct window.

---

### MINOR — Per-member N×2 DB round-trips inline during `patchSCIMGroupMappingHandler` and `scimDeleteGroup`

**Location:**
- `internal/api/scim_admin.go:506–531` (`patchSCIMGroupMappingHandler` member loop)
- `internal/api/scim_groups_handler.go:493–504` (`scimDeleteGroup` member loop)
- `internal/api/scim_roles.go:23–83` (`recomputeSCIMRole` — called per member)

**Problem:** Both handlers iterate over every current member of a SCIM group and call `srv.recomputeSCIMRole(ctx, orgID, userID, defaultRole)` per user. `recomputeSCIMRole` issues two DB queries per call: `GetOrgMemberFull` (to fetch current role and exempt flag) and `ListUserSCIMGroups` (to find the user's highest mapped role). For a group with N members this produces 2N DB round-trips on a single HTTP request. The memory pressure from accumulating N in-flight query result structs is secondary to the query cost, but the allocations are real: each `GetOrgMemberFull` returns a struct and each `ListUserSCIMGroups` returns a `[]SomeSCIMGroup` slice, all materialised and immediately discarded.

**Impact:** This path is hit only on group mapping changes (infrequent admin action) and group deletion, not on per-user provisioning. However, a group with even 200 members produces 400 sequential DB queries on a single request, holding the pgxpool connection and blocking the response. Allocation cost is 200× the two result types. Reachability is low (admin-only, group-mapping writes), but when reached the per-occurrence cost scales linearly with group size and is entirely avoidable.

**Confidence:** Strong-static

**Effort:** Contained — introduce a single `BatchRecomputeSCIMRoles(ctx, orgID, []userID, defaultRole)` store method that fetches all member states and all SCIM group memberships in two queries (one `WHERE user_id = ANY($1)` each), then applies the same highest-rank logic in Go over the already-loaded data. The call sites become one-liners; `recomputeSCIMRole` is unchanged for single-user call sites.

**Verification plan:** Allocation argument: two queries regardless of N eliminates O(2N) sequential allocations. Correctness guard: existing `TestSCIMGroupReplace*` and `TestSCIMDeleteGroup*` tests must pass; add a test asserting that mapping a 10-member group triggers exactly 2 `store.ListXxx` calls (mock store or trace-level DB log).

---

## What was checked and found acceptable

- **`tierCache`** (`tier_cache.go`): bounded by org count, background eviction loop with `evictTTL`, `maps.Clone` on reads. No unbounded growth.
- **`orgRateLimiter`** (`org_ratelimit.go`): same pattern — bounded map with idle eviction. No issue.
- **`scimRateLimiter`** (`scim_ratelimit.go`): same. No issue.
- **`RequireOrgRole` middleware** (`middleware_rbac.go`): one `GetOrgMemberRoleAndStatus` query per request, result not retained past the handler. No accumulation.
- **`tierMiddleware`** (`middleware_tier.go`): allocates one `*tier.Resolver` per request — struct with two fields, not a concern. Cache hit avoids the DB round-trip.
- **`scimListGroups`** (`scim_groups_handler.go:147–192`): comment says "group counts are small"; performs one `ListSCIMGroupMembers` per group in the filter loop but SCIM group counts per org are administratively bounded and small in practice. Noted but not a finding.
- **All admin list endpoints** (`admin_users.go`, `admin_orgs.go`, `admin_system.go`): keyset-paginated with explicit `limit+1` fetch. No whole-table materialisation.
- **`audit.Writer.Log`**: fires a goroutine per audit entry but does so post-response (uses `context.WithoutCancel`) and serialises through the DB. Per-entry allocation is constant and small.

---

## Suspected Bugs (for follow-up)

None observed during this sweep.
