# S9 Org/SCIM/Admin Glue — Algorithmic Complexity Audit

**Lane:** algorithmic
**Date:** 2026-06-05
**Scope:** `internal/api/{orgs,groups,org_tier,org_ratelimit,scim_users,scim_groups_handler,scim_admin,scim_types,scim_discovery,scim_roles,scim_notif_sync,middleware_scim,admin_users,admin_orgs,admin_mfa,admin_system,admin_version,admin_reload,admin_doctor,audit_log,tier_cache,middleware_rbac,middleware_tier,role}.go`; `internal/{audit,tier}/**`; `internal/store/{org,group,scim_groups,scim_config,admin_org,admin_user,admin_delivery,admin_system,audit}.go`

---

## Findings

### MAJOR — `scimListGroups`: O(n) sequential DB round-trips — one `ListSCIMGroupMembers` query per group in the list

**Location:** `internal/api/scim_groups_handler.go:168–178` (`scimListGroups`)

**Problem:** `scimListGroups` calls `srv.store.ListSCIMGroups(ctx, orgID)` to fetch all groups in one query, then enters a `for` loop over the result set. Inside the loop it calls `srv.store.ListSCIMGroupMembers(ctx, orgID, g.ID)` individually for each group that passes the filter. Because each store method opens its own transaction (`withOrgTx`), this is a full separate DB round-trip per group. `ListSCIMGroups` itself already returns `member_count` via a `COUNT` aggregate, so the only use of `ListSCIMGroupMembers` here is to populate the `members[]` array in the response — UUIDs for building `$ref` links.

```go
// scim_groups_handler.go:168
for _, g := range groups {
    if matchesSCIMGroupFilter(...) {
        memberIDs, mErr := srv.store.ListSCIMGroupMembers(ctx, orgID, g.ID)  // N DB calls
        ...
    }
}
```

**Impact:** Reachability is every SCIM `GET /Groups` call. Frequency: IdPs poll this endpoint periodically (often every 5–15 minutes). Per-occurrence cost: if an org has N groups, this performs N+1 DB queries (one for the group list, then one per group). For an enterprise customer with 100 SCIM groups the sync scan alone costs 101 sequential DB round-trips. Each `withOrgTx` adds `SET LOCAL app.org_id` + transaction overhead on top of the query execution. This is O(n) sequential latency on the hot SCIM sync path.

**Confidence:** Strong-static

**Effort:** Localized — add a `ListAllSCIMGroupMembers(ctx, orgID) (map[uuid.UUID][]uuid.UUID, error)` query that returns all `(scim_group_id, user_id)` pairs for the org in one query (`SELECT scim_group_id, user_id FROM scim_group_members WHERE org_id = $1`), then build the map in-memory before the loop.

**Verification plan:** The existing member-count from `ListSCIMGroupsRow.MemberCount` proves the aggregate is already available in one query; replacing the N individual calls with a single batch query and an in-memory `map[uuid.UUID][]uuid.UUID` lookup preserves correctness and is testable by comparing `GET /Groups` response bodies before and after. Pin with the golden test for SCIM group list if one exists, or a new integration test asserting member `$ref` links are populated correctly.

---

### MAJOR — `patchSCIMGroupMappingHandler`: O(n) sequential round-trips when a group's role or notification-group mapping changes — one `recomputeSCIMRole` (3 DB queries) and/or `syncNotifGroupRemove`+`syncNotifGroupAdd` (2–3 DB queries) per member

**Location:** `internal/api/scim_admin.go:506–532` (`patchSCIMGroupMappingHandler`), `internal/api/scim_roles.go:23–83` (`recomputeSCIMRole`), `internal/api/scim_notif_sync.go` (`syncNotifGroupRemove`, `syncNotifGroupAdd`)

**Problem:** When an admin changes a SCIM group's `mapped_role` or `mapped_group_id`, the handler iterates over all current members of that group and calls `recomputeSCIMRole` and/or `syncNotifGroupRemove`/`syncNotifGroupAdd` for each user. Each call opens one or more separate DB transactions:

- `recomputeSCIMRole`: `GetOrgMemberFull` (1) + `ListUserSCIMGroups` (1) + optional `UpdateOrgMemberRole` (1) = up to 3 transactions per user
- `syncNotifGroupRemove`: `CountOtherSCIMGroupsWithSameMapping` (1) + optional `RemoveSCIMManagedGroupMember` (1)
- `syncNotifGroupAdd`: `GetGroupIfActive` (1) + `AddGroupMemberSCIMManaged` (1)

For a group with M members, the role-change path alone performs ≤ 3M sequential DB round-trips. This is a synchronous, request-scoped operation so it blocks the SCIM PUT/PATCH response. Enterprise groups with hundreds of members (a common provisioning scenario) will see proportionally high latency.

**Impact:** Reachability: every admin remapping of a SCIM group's role or notification group. These are rare admin operations but the per-occurrence cost scales with group size. An enterprise org with a 500-person department group remapping via the SCIM admin UI would perform up to 1,500 sequential DB transactions in a single HTTP request. The same loop pattern appears in `scimDeleteGroup` (role recompute per member after delete).

**Confidence:** Strong-static

**Effort:** Contained — the fix requires either (a) a batch role-recompute query that takes `(org_id, scim_group_id, default_role)` and rewrites all affected member roles in one UPDATE via a subquery, or (b) deferring the fan-out to a background job (enqueue a single job, return 202). The background-job approach is the more correct solution given the existing job queue infrastructure, and avoids holding request-scoped goroutines open during the fan-out. Either path requires changing the handler signature to return 202 for mapping changes when the member count is non-zero, or requires new store methods.

**Verification plan:** A new integration test: create a SCIM group, add N members (e.g., 10), PATCH its mapping, assert all member roles are updated correctly. The test pins behavior regardless of whether the fix is a batch query or a background job.

---

### MINOR — `tierCache.Get`/`Set`: `sync.Mutex` serializes all concurrent readers — `sync.RWMutex` would be cheaper

**Location:** `internal/api/tier_cache.go:46–72` (`Get` and `Set`)

**Problem:** `tierCache` uses a `sync.Mutex` for both reads (`Get`) and writes (`Set`/`Invalidate`/`evictExpired`). On the hot request path, every org-scoped API request acquires the write lock for `Get` even on cache hits. Under concurrent load from multiple orgs, all goroutines queue behind a single mutex for what is predominantly a read operation (`Get` is called far more than `Set`).

**Impact:** Reachability: every API request that passes through `tierMiddleware` — which is every org-scoped route. At moderate parallelism (tens of concurrent requests across active orgs) the mutex becomes a contention point. The critical section is small (a map lookup + time check), but the exclusive write lock means no two requests can read the cache simultaneously. Switching to `sync.RWMutex` with `RLock`/`RUnlock` in `Get` allows all cache-hit reads to proceed in parallel; only `Set`, `Invalidate`, and `evictExpired` need the write lock.

**Confidence:** Strong-static

**Effort:** Localized — change `mu sync.Mutex` to `mu sync.RWMutex`, change `c.mu.Lock()`/`defer c.mu.Unlock()` in `Get` to `c.mu.RLock()`/`defer c.mu.RUnlock()`. `Set`, `Invalidate`, and `evictExpired` keep the write lock. This is a one-function change with zero semantic impact.

**Verification plan:** The existing `tierCache` tests already exercise concurrent `Get`/`Set` semantics; they will continue to pass. The change is demonstrably safe because `Get` only reads `c.entries` and `c.now()`.

---

## Patterns examined with no significant findings

- **`RequireOrgRole` (RBAC middleware):** Single indexed DB lookup (`GetOrgMemberRoleAndStatus`) per request. O(1) — no scan. No finding.
- **`RequireSiteAdmin` middleware:** Single `IsSiteAdmin` lookup per request. O(1). No finding.
- **`orgRateLimitMiddleware`:** map lookup under `sync.Mutex`, consistent with `orgRateLimiter.Allow`. O(1). No finding.
- **`requireSCIMAuth` (SCIM middleware):** Single token-hash lookup + constant-time compare per request. O(1). No finding.
- **`recomputeSCIMRole` (single-user):** Loads the user's SCIM group memberships (O(number of groups user belongs to)), then linear scan over groups to find highest role. Group count per user is bounded and tiny (single digits in practice). No significant finding.
- **`checkSCIMMemberLimit`:** Bypasses the `tierCache` and calls `GetOrgTier` directly — a minor redundancy (the tier is already resolved in the request context via `tierMiddleware`), but this only fires on SCIM provisioning paths, not every request. Not significant enough to report.
- **`scimListUsers` filter loop:** Loads all members into memory and filters in Go. For typical org sizes (hundreds of members) this is acceptable. No significant finding.
- **Admin list endpoints (`adminListOrgsHandler`, `adminListUsersHandler`, `adminAuditLogHandler`):** All use keyset cursor pagination with DB-side predicates. No in-memory aggregation over large tables. No finding.
- **`parseSCIMFilter`:** `strings.Split` + `strings.SplitN` over a short string (SCIM filters are typically `attr eq "value"`). O(n) where n = filter length. No finding.
- **`roleHierarchy` map in `scim_roles.go`:** 3-element map. O(1) lookup. No finding.
- **`tierCache.evictExpired`:** Linear scan over all cached orgs under exclusive lock. Cache is bounded by active-org count; eviction runs infrequently at `evictTTL/2`. No finding.

---

## Suspected Bugs (for follow-up)

None.
