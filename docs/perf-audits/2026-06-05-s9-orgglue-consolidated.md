---
run_schema_version: 1
run_id: 2026-06-05-s9-orgglue
date: 2026-06-05T03:40:00Z
scope: "S9 — Org/SCIM/admin/tenant glue (COLD SWEEP)"
methodology: { skill: performance-audit-cycle, plugin_version: "superpowers-plus@0.2.0 (vendored; version per source repo)" }
dispatch: { model_requested: "sonnet (Claude Code Agent tool; COLD-sweep economy)", reasoning_effort: "default (harness exposes no knob)", overridden_by_user: false }
stack: [ { ecosystem: go, framework: "huma/chi + pgx + SCIM", version: "go1.26.2" } ]
currency_briefs: [ { framework: go, researched_on: null, status: "COLD — idiom-currency lane not run" } ]
lanes_run: [algorithmic, memory, data-access]
lanes_skipped: { "concurrency/idiom-currency/cost-map/payload/dynamic": "COLD SWEEP / no runtime" }
finding_counts: { by_impact: { critical: 0, major: 5, minor: 1 }, by_lane: { algorithmic: 3, memory: 2, data-access: 2 }, suspected_bugs: 1 }
regression: { prev_run_id: null, new: 6, persisting: 0, resolved: 0 }
---

# Performance Audit (COLD SWEEP, validated) — S9 Org/SCIM/admin/tenant glue

**Tier:** COLD SWEEP (3 batched lanes, sonnet). **Verification:** static-only. **Regression:** 6 new.
The sweep found that **SCIM provisioning is the genuinely hot, under-optimized part of this otherwise-cold
slice** — an external IdP polls `GET /Users` and `GET /Groups` and pushes create/put/patch in bulk, so the
N+1 patterns there scale with the customer's directory size. **Confirmed-cold non-findings (recorded):**
RBAC/tier/site-admin middleware, the three caches' correctness, and the org/admin CRUD list endpoints are
clean apart from the items below.

## Major Findings

### P1. `scimListUsers` materializes **all** org members before filtering and paginating in Go
**Lane:** memory  **Location:** `internal/api/scim_users.go:464-567`
**Fingerprint:** `memory:scim_users.go:list-materialize-all`  **Status:** new
**Problem:** `ListOrgMembers` fetches the entire member table unconditionally; a second O(N) `userIDs` slice feeds `ListIdentitiesByProviderAndUsers`; filtering + pagination happen in-process afterward — peak heap O(total_members), not O(page_size). **Impact:** every SCIM `GET /Users` poll, scaling with org size. **Confidence:** Strong-static  **Effort:** Contained — push filter + keyset pagination into the store query.

### P2. `scimListGroups` is N+1 — one member-query per group on every `GET /Groups` poll
**Lane:** algorithmic, data-access  **Location:** `internal/api/scim_groups_handler.go:168-178`
**Fingerprint:** `data-access:scim_groups_handler.go:list-groups-nplus1`  **Status:** new
**Problem:** After one groups query, a separate `withOrgTx` round-trip per group fetches member UUIDs for `$ref` links — N+1 per poll. **Impact:** every SCIM group poll. **Confidence:** Strong-static  **Effort:** Localized — one `SELECT scim_group_id, user_id … WHERE org_id=$1`, build `map[group][]user` before the loop.

### P3. SCIM group role/notif remap runs ~3 transactions **per member** (up to ~1,500 for a 500-member group)
**Lanes:** algorithmic, memory, data-access  **Location:** `internal/api/scim_admin.go:506-532`, `internal/api/scim_roles.go:23-83`, `scim_groups_handler.go:493-504`
**Fingerprint:** `data-access:scim_admin.go:group-remap-per-member-tx`  **Status:** new
**Problem:** For each of M members, `recomputeSCIMRole` opens up to 3 independent transactions (`GetOrgMemberFull` + `ListUserSCIMGroups` + update) and `syncNotifGroupRemove/Add` opens 2–3 more — a single HTTP request blocks on up to ~1,500 transactions for a large group. **Impact:** SCIM group remap/delete on enterprise groups. **Confidence:** Strong-static  **Effort:** Contained — one batched `BatchRecomputeSCIMRoles` (`WHERE user_id = ANY($1)`) or hand off to the existing job queue.

### P4. SCIM provisioning bypasses `tierCache` and re-fetches SCIM config on every create/put/patch
**Lane:** data-access  **Location:** `internal/api/scim_users.go:1072-1103`, `internal/api/server.go:473-497`
**Fingerprint:** `data-access:scim_users.go:provisioning-uncached-tier-config`  **Status:** new
**Problem:** SCIM routes are mounted **without** `tierMiddleware`, so `checkSCIMMemberLimit` calls `GetOrgTier` directly (uncached) per request; and `getSCIMDefaultRole` issues a second `GetSCIMConfig` even though `requireSCIMAuth` already fetched the full config — 2 uncached round-trips per provisioning call (~1,000 extra queries per 500-user sync). **Impact:** every SCIM write. **Confidence:** Strong-static  **Effort:** Contained — mount `tierMiddleware` on SCIM (or use the cache) and thread the already-fetched config.

### P5. `AdminListAuditEntries` cross-org global query has no usable index → full table scan + in-memory sort on the first page
**Lane:** data-access  **Location:** `internal/store/queries/admin_system.sql:4-16` + `migrations/000027_audit_log.up.sql`
**Fingerprint:** `data-access:admin_system.sql:audit-cross-org-noindex`  **Status:** new
**Problem:** The global admin audit query `ORDER BY created_at DESC, id DESC` has no `org_id` predicate, so the two `(org_id, …)`-leading indexes are useless — Postgres seq-scans the append-only `audit_log` and sorts in memory. **Same theme as S4-P1 (missing composite/keyset index).** **Impact:** admin audit views over a growing table. **Confidence:** Strong-static  **Effort:** Localized — `CREATE INDEX CONCURRENTLY audit_log_created_idx ON audit_log (created_at DESC, id DESC)`.

## Minor Findings
- **P6** `algorithmic:tier_cache.go:mutex-not-rwmutex` — `internal/api/tier_cache.go:46-57`: `tierCache.Get` uses an exclusive `sync.Mutex` on the per-request read path; every org-scoped request serializes through it for a map-read hit. Switch to `sync.RWMutex` + `RLock`. Localized.

## Suspected Bugs (for follow-up — NOT addressed here)
- **SB1.** `orgRateLimiter.Allow` (`internal/api/org_ratelimit.go:50`) resets the token bucket to burst-full whenever the tier changes — an org gets a free burst refill on any tier update. Verify intent.

---
**Disposition:** all 6 default to **FIX**. P5 joins the missing-index theme (with S4-P1); P1–P4 the
N+1/per-item-transaction theme. 1 suspected bug handed off.
