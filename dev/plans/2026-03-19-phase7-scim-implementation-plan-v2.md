# Phase 7: SCIM 2.0 Provisioning — Implementation Plan (v2)

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement SCIM 2.0 user and group provisioning so enterprise IdPs (Microsoft Entra ID, Okta) can automatically manage CVErt Ops org membership, roles, and notification groups.

**Architecture:** SCIM endpoints are implemented as chi handlers directly in `internal/api/` — no third-party SCIM library. A custom `requireSCIMAuth` middleware authenticates SCIM bearer tokens (separate from API keys/JWTs). SCIM handlers produce RFC 7644 JSON responses with `Content-Type: application/scim+json`. Admin management endpoints (SCIM config CRUD, group mapping) use the standard chi handler pattern with `RequireOrgRole` + `requireEnterpriseTier`. User deactivation (`org_members.deactivated_at`) is a general feature, not SCIM-exclusive.

**Tech Stack:** Go 1.26, chi, sqlc, testcontainers-go

**Design doc:** `dev/plans/2026-03-19-phase7-scim-provisioning-design-v2.md`

**SCIM Specification References:**
- RFC 7643 — SCIM Core Schema: https://www.rfc-editor.org/rfc/rfc7643
- RFC 7644 — SCIM Protocol: https://www.rfc-editor.org/rfc/rfc7644
- RFC 7644 §3.12 — Error Handling (our error format): https://www.rfc-editor.org/rfc/rfc7644#section-3.12
- RFC 7644 §3.4.2.2 — Filtering: https://www.rfc-editor.org/rfc/rfc7644#section-3.4.2.2
- RFC 7644 §3.5.2 — Modifying with PATCH: https://www.rfc-editor.org/rfc/rfc7644#section-3.5.2
- RFC 7643 §8.7.1 — User Schema: https://www.rfc-editor.org/rfc/rfc7643#section-8.7.1
- RFC 7643 §8.7.2 — Group Schema: https://www.rfc-editor.org/rfc/rfc7643#section-8.7.2

When in doubt about wire format, response structure, or error semantics, check the relevant RFC section rather than guessing.

**Prerequisites:** Phase 5D complete (SSO — `sso_connections` table, tier gating, audit log). Phase 6B complete (MFA tables exist).

**Context for subagents:**
- Chi handlers use `http.Error(w, msg, status)` + `return`, NOT huma error returns
- Transaction helpers: `withBypassTx` for auth lookups and global-table writes, `withOrgTx` for org-scoped queries from handlers. See `dev/implementation-pitfalls.md` §DB-17 for when to use which.
- Integration tests use `testutil.NewTestDB(t)` with testcontainers Postgres — NOT Docker Compose
- RLS isolation tests MUST use `s.AppStore` (NOBYPASSRLS) — `s.Store` (superuser) bypasses RLS. See `dev/testing-pitfalls.md` §10.
- TDD is mandatory: RED → verify fail → GREEN → verify pass → refactor → commit
- Run `sqlc generate` after any `.sql` file changes, before `go build`
- Run `golangci-lint run` before committing
- `requireEnterpriseTier(w, r)` is the existing enterprise gate helper in `internal/api/sso.go` (returns false + writes HTTP error if tier check fails)
- SCIM error format is RFC 7644 §3.12 JSON (NOT RFC 9457 Problem Details) — use `writeSCIMError()` helper
- Pointer types for PATCH fields (`*bool`, `*string`) — see pitfalls §API-2
- SCIM bearer tokens are sha256-hashed, compared via `subtle.ConstantTimeCompare` — same security pattern as API keys
- Never hold open DB tx during outbound HTTP — see pitfalls §AUTH-12
- Every migration file with `CREATE INDEX CONCURRENTLY` needs `-- migrate:no-transaction` as FIRST line of BOTH up and down files
- Every org-scoped table: denormalized `org_id` + BTREE index + ENABLE/FORCE RLS + dual-escape policy (bypass_rls OR org_id match)
- No semicolons in SQL comments — see pitfalls §DB-16 (breaks golang-migrate statement splitting)
- Context keys are defined in `internal/api/context.go` using iota — new keys must be added there, not defined locally
- To extract SCIM context in handlers: `orgID := r.Context().Value(ctxOrgID).(uuid.UUID)` and `scimConfigID := r.Context().Value(ctxSCIMConfigID).(uuid.UUID)` — same pattern as `ctxUserID` extraction in existing handlers
- `user_identities` queries already exist in `internal/store/queries/auth.sql` — reuse `UpsertUserIdentity`, `GetUserByProviderID`, `GetUserByEmail` for SCIM identity matching. Do NOT create new identity queries.
- `SCIMPatchOperation.Value` should be typed as `json.RawMessage` so handlers can type-assert based on the attribute path (booleans for `active`, strings for `userName`, arrays for `members`)
- `audit_log.entity_type` has no CHECK constraint (only `action` does) — no migration needed for new entity types, but new `action` values DO need a CHECK constraint migration
- Test setup calls MUST check errors with `require.NoError(t, err)` — never `_, _ :=`. See `dev/testing-pitfalls.md` §16.
- Every test POST/PUT/PATCH/DELETE through full HTTP stack needs `X-Requested-By: CVErt-Ops` header for CSRF. SCIM endpoints are exempt (Bearer token auth, no cookies). See `dev/testing-pitfalls.md` §16.
- Security events: use `secure.EventWriter.Write()` (async, non-blocking). New event constants go in `internal/secure/events.go` with severity mappings. See `dev/testing-pitfalls.md` §7 for "defined constants must be emitted" rule.

**DO NOT:**
- Do NOT use any third-party SCIM library. All SCIM JSON serialization/deserialization is hand-written against RFC 7643/7644.
- Do NOT use huma for SCIM endpoints. SCIM wire protocol is incompatible with huma conventions.
- Do NOT add features or filter operators beyond what the design doc specifies.
- Do NOT create an `internal/scim/` package. All SCIM handlers live in `internal/api/` alongside existing handlers.
- Do NOT modify the `groups` or `group_members` table structure beyond adding the `scim_managed` column to `group_members`.

---

## Mandatory Discipline (applies to ALL tasks with tests)

**BEFORE starting any task that includes tests:**
1. Read `dev/testing-pitfalls.md`
2. Read the TDD skill at `.claude/skills/test-driven-development/` (or invoke `/test-driven-development`)
3. For pure test additions: write the test, verify it fails for the right reason (or passes if testing already-correct behavior), then move on.
4. For code + tests: write failing test → implement code → verify green.

**BEFORE marking any task complete:**
1. Review your tests against `dev/testing-pitfalls.md`
2. Verify: are assertions checking *behavior*, not just *execution*? (e.g., assert the returned config has `enabled=true`, not just `err == nil`)
3. Verify: are negative cases tested, not just positive? (e.g., cross-org RLS isolation, not just same-org access)
4. Verify: do tests use `require.NoError(t, err)` for setup calls, never `_, _ :=`?
5. Run `go test ./...` (or relevant subset) and confirm green
6. Run `golangci-lint run` on modified packages

**After completing each wave (all tasks in the wave):**
You MUST carefully review the batch of work from multiple perspectives and revise/refine as appropriate. Repeat this review loop (minimum three rounds; if you still find substantive issues in the third review, keep going) until you're confident there aren't any more issues. Specifically check:
- Are all RLS isolation tests using `AppStore` (not `Store`)?
- Are SCIM error responses using `application/scim+json` content type (not `text/plain` or `application/json`)?
- Are admin endpoint error responses using RFC 9457 format (not SCIM format)?
- Do store tests verify returned values, not just `err == nil`?
- Are security events verified in the `security_events` table, not just assumed to fire?
Then update your private journal and continue to the next wave.

**Testing pitfall warnings (applies throughout):**
- ⚠️ §16: Test setup calls MUST use `require.NoError(t, err)` — never `_, _ :=` (nil pointer panics hide real failures)
- ⚠️ §16: Every POST/PUT/PATCH/DELETE through full HTTP stack needs `X-Requested-By: CVErt-Ops` for CSRF — EXCEPT SCIM endpoints (Bearer token auth)
- ⚠️ §10: RLS isolation tests MUST query through `db.AppStore` — `db.Store` bypasses RLS and gives false confidence
- ⚠️ §7: Every security event constant defined in `events.go` must be emitted by at least one code path — grep to verify
- ⚠️ §3: Error response format must be consistent — SCIM endpoints use `application/scim+json`, admin endpoints use `application/problem+json`
- ⚠️ §4: PATCH validation must match POST validation — if POST rejects empty `userName`, PATCH must too
- ⚠️ §1: Idempotent operations (POST /Users for existing user) must be tested under concurrent access

---

## Task 1: Migration — `org_members` deactivation + SCIM exemption columns

User deactivation is a general feature (not SCIM-exclusive). Admin-settable via member PATCH. `RequireOrgRole` middleware will check `deactivated_at IS NULL`. This migration adds the columns first so subsequent tasks can use them.

**Files:**
- Create: `migrations/000042_org_members_deactivation.up.sql`
- Create: `migrations/000042_org_members_deactivation.down.sql`

**Step 1: Write the up migration**

```sql
-- migrate:no-transaction
-- ABOUTME: Adds deactivation and SCIM exemption to org_members.
-- ABOUTME: deactivated_at is a general feature (admin-settable), scim_exempt prevents SCIM from modifying state.

ALTER TABLE org_members ADD COLUMN IF NOT EXISTS deactivated_at TIMESTAMPTZ;
ALTER TABLE org_members ADD COLUMN IF NOT EXISTS scim_exempt BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX CONCURRENTLY IF NOT EXISTS org_members_active_idx
    ON org_members (org_id) WHERE deactivated_at IS NULL;
```

**Step 2: Write the down migration**

```sql
-- migrate:no-transaction

DROP INDEX CONCURRENTLY IF EXISTS org_members_active_idx;
ALTER TABLE org_members DROP COLUMN IF EXISTS scim_exempt;
ALTER TABLE org_members DROP COLUMN IF EXISTS deactivated_at;
```

**Step 3: Run migration**

```bash
go run ./cmd/cvert-ops migrate
```

**Step 4: Regenerate sqlc**

```bash
sqlc generate
```

**Step 5: Verify it compiles**

```bash
go build ./...
```

**Step 6: Commit**

```bash
git add migrations/000042_* internal/store/generated/
git commit -m "migration(042): add org_members.deactivated_at + scim_exempt columns"
```

---

## Task 2: Migration — `group_members.scim_managed` column

Tracks whether a notification group membership was SCIM-synced. SCIM removal only deletes `scim_managed = true` rows.

**Files:**
- Create: `migrations/000043_group_members_scim_managed.up.sql`
- Create: `migrations/000043_group_members_scim_managed.down.sql`

**Step 1: Write the up migration**

```sql
-- ABOUTME: Adds scim_managed flag to group_members for SCIM notification sync tracking.
-- ABOUTME: SCIM removal only deletes scim_managed=true rows. Manual memberships preserved.

ALTER TABLE group_members ADD COLUMN IF NOT EXISTS scim_managed BOOLEAN NOT NULL DEFAULT false;
```

No `CREATE INDEX CONCURRENTLY` → no `-- migrate:no-transaction` needed.

**Step 2: Write the down migration**

```sql
ALTER TABLE group_members DROP COLUMN IF EXISTS scim_managed;
```

**Step 3: Run migration, regenerate sqlc, verify build**

```bash
go run ./cmd/cvert-ops migrate && sqlc generate && go build ./...
```

**Step 4: Commit**

```bash
git add migrations/000043_* internal/store/generated/
git commit -m "migration(043): add group_members.scim_managed column"
```

---

## Task 3: Migration — `scim_configs` table

SCIM provisioning config, 1:1 with organizations (via `sso_connections`). Token stored separately from API keys (different auth semantics). `ON DELETE RESTRICT` on `sso_connection_id` — prevents silent destruction when SSO is deleted.

**Files:**
- Create: `migrations/000044_create_scim_configs.up.sql`
- Create: `migrations/000044_create_scim_configs.down.sql`

**Step 1: Write the up migration**

Use the exact SQL from design doc §1 for `scim_configs`, but with `ON DELETE RESTRICT` (not CASCADE) on `sso_connection_id`. The migration MUST have `-- migrate:no-transaction` as the first line because it contains `CREATE INDEX CONCURRENTLY`.

**Step 2: Write the down migration**

Drop in reverse order: policy → RLS → index → table. MUST have `-- migrate:no-transaction` as the first line because it contains `DROP INDEX CONCURRENTLY`.

**Step 3: Run migration, regenerate sqlc, verify build**

```bash
go run ./cmd/cvert-ops migrate && sqlc generate && go build ./...
```

**Step 4: Commit**

```bash
git add migrations/000044_* internal/store/generated/
git commit -m "migration(044): create scim_configs table with RLS and ON DELETE RESTRICT"
```

---

## Task 4: Migration — `scim_groups` + `scim_group_members` tables

IdP groups with optional role + notification group mappings. `scim_groups` references `organizations(id)` directly (NOT `scim_configs`) so group mappings survive SCIM config deletion.

**Files:**
- Create: `migrations/000045_create_scim_groups.up.sql`
- Create: `migrations/000045_create_scim_groups.down.sql`

**Step 1: Write the up migration**

Use the exact SQL from design doc §1 for `scim_groups` and `scim_group_members`. MUST have `-- migrate:no-transaction` as the first line (contains `CREATE INDEX CONCURRENTLY`).

**Step 2: Write the down migration**

Drop `scim_group_members` first (has FK to `scim_groups`), then `scim_groups`. MUST have `-- migrate:no-transaction` as the first line.

**Step 3: Run migration, regenerate sqlc, verify build**

```bash
go run ./cmd/cvert-ops migrate && sqlc generate && go build ./...
```

**Step 4: Commit**

```bash
git add migrations/000045_* internal/store/generated/
git commit -m "migration(045): create scim_groups + scim_group_members with RLS"
```

---

## Task 5: Verify `audit_log.action` CHECK constraint (no migration needed)

The `audit_log.action` CHECK constraint (migration 000041) allows: `create`, `update`, `delete`, `revoke`, `add`, `remove`, `bind`, `unbind`, `update_domains`.

SCIM operations will use: `create`, `update`, `delete` — all already covered. No migration is needed.

The `entity_type` column has NO CHECK constraint — new entity types (`scim_config`, `scim_group`) can be used without a migration.

**Action:** No files to create. Migration number 000046 is available for the next feature. Proceed to Task 6.

---

## Task 6: Security event constants for SCIM

Add SCIM-specific event type constants and severity mappings.

**Files:**
- Modify: `internal/secure/events.go`
- Modify: `internal/secure/events_test.go` (update exhaustiveness test)

**Step 1: Add constants**

Add to `internal/secure/events.go` after the existing MFA constants:

```go
// SCIM provisioning events.
EventSCIMAuthFailed        = "scim.auth_failed"
EventSCIMAuthOrgMismatch   = "scim.auth_org_mismatch"
EventSCIMAuthDisabled      = "scim.auth_disabled"
EventSCIMTokenCreated      = "scim.token_created"      //nolint:gosec // G101 false positive: event type label, not a credential
EventSCIMTokenRotated      = "scim.token_rotated"       //nolint:gosec // G101 false positive: event type label, not a credential
EventSCIMUserProvisioned   = "scim.user_provisioned"
EventSCIMUserDeprovisioned = "scim.user_deprovisioned"
EventSCIMSoleOwnerProtected = "scim.sole_owner_protected"
EventSCIMExemptSuppressed  = "scim.exempt_suppressed"
EventSCIMRateLimited       = "scim.rate_limited"
```

**Step 2: Add severity mappings**

Add to `EventSeverity` map:
- Auth failures: `SeverityWarning`
- Token created/rotated: `SeverityInfo`
- User provisioned/deprovisioned: `SeverityInfo`
- Sole owner protected, exempt suppressed, rate limited: `SeverityWarning`

**Step 3: Update exhaustiveness test**

Add all new constants to the slice in `TestEventSeverityMapIsExhaustive`.

**Step 4: Run tests**

```bash
go test ./internal/secure/ -v -count=1
```

**Step 5: Commit**

```bash
git add internal/secure/events.go internal/secure/events_test.go
git commit -m "feat(secure): add SCIM security event type constants"
```

---

## Task 7: SCIM context key + config struct

Add the SCIM config context key and config-related types.

**Files:**
- Modify: `internal/api/context.go` — add `ctxSCIMConfigID`
- Modify: `internal/config/config.go` — add `SCIMRateLimit` field

**Step 1: Add context key**

Add `ctxSCIMConfigID` as the next iota value after `ctxTierResolver` in `internal/api/context.go`:

```go
ctxSCIMConfigID // uuid.UUID — SCIM config ID (set by requireSCIMAuth)
```

**Step 2: Add config field**

Add to `internal/config/config.go`:

```go
SCIMRateLimit int `env:"SCIM_RATE_LIMIT" envDefault:"50"` // requests per second per org
```

**Step 3: Verify build**

```bash
go build ./...
```

**Step 4: Commit**

```bash
git add internal/api/context.go internal/config/config.go
git commit -m "feat: add SCIM context key and rate limit config"
```

---

## Task 8: sqlc queries — SCIM config

**Files:**
- Create: `internal/store/queries/scim_config.sql`
- Modify: `internal/store/generated/` (regenerated)

**Step 1: Write the sqlc queries**

```sql
-- ABOUTME: sqlc queries for SCIM config CRUD.
-- ABOUTME: Token lookup uses withBypassTx (pre-org-context auth). Config CRUD uses withOrgTx.

-- name: CreateSCIMConfig :one
INSERT INTO scim_configs (org_id, sso_connection_id, enabled, token_hash, token_prefix, default_role)
VALUES ($1, $2, $3, $4, $5, $6) RETURNING *;

-- name: GetSCIMConfigByOrgID :one
SELECT * FROM scim_configs WHERE org_id = $1;

-- name: GetSCIMConfigByTokenHash :one
SELECT * FROM scim_configs WHERE token_hash = $1;

-- name: GetSCIMConfigBySSOConnectionID :one
SELECT * FROM scim_configs WHERE sso_connection_id = $1;

-- name: UpdateSCIMConfig :exec
UPDATE scim_configs SET enabled = $2, default_role = $3, updated_at = now()
WHERE org_id = $1;

-- name: UpdateSCIMConfigToken :exec
UPDATE scim_configs SET token_hash = $2, token_prefix = $3, updated_at = now()
WHERE org_id = $1;

-- name: DeleteSCIMConfig :exec
DELETE FROM scim_configs WHERE org_id = $1;
```

Note: `GetSCIMConfigBySSOConnectionID` is needed for the SSO delete pre-flight check (Task 20).

**Step 2: Regenerate sqlc and verify build**

```bash
sqlc generate && go build ./...
```

**Step 3: Commit**

```bash
git add internal/store/queries/scim_config.sql internal/store/generated/
git commit -m "sqlc: add SCIM config queries"
```

---

## Task 9: sqlc queries — SCIM groups + members

**Files:**
- Create: `internal/store/queries/scim_groups.sql`
- Modify: `internal/store/generated/` (regenerated)

**Step 1: Write the sqlc queries**

Use the exact queries from the v1 implementation plan Task 7. Add one additional query:

```sql
-- name: GetSCIMGroupByExternalID :one
SELECT * FROM scim_groups WHERE org_id = $1 AND external_id = $2;
```

This is needed for SCIM group operations that filter by `externalId`.

**Step 2: Regenerate sqlc and verify build**

```bash
sqlc generate && go build ./...
```

**Step 3: Commit**

```bash
git add internal/store/queries/scim_groups.sql internal/store/generated/
git commit -m "sqlc: add SCIM group and membership queries"
```

---

## Task 10: sqlc queries — org_members deactivation + member count

Update existing org queries for deactivation support.

**Files:**
- Modify: `internal/store/queries/org.sql`
- Modify: `internal/store/generated/` (regenerated)

**Step 1: Add new queries to org.sql**

Append these queries. Before writing, read `internal/store/queries/org.sql` to check for existing query names that might conflict — specifically `GetOrgOwnerCount` (already exists) and any `GetOrgMember` variants.

```sql
-- name: DeactivateOrgMember :exec
UPDATE org_members SET deactivated_at = now(), updated_at = now()
WHERE org_id = $1 AND user_id = $2;

-- name: ReactivateOrgMember :exec
UPDATE org_members SET deactivated_at = NULL, updated_at = now()
WHERE org_id = $1 AND user_id = $2;

-- name: GetOrgMemberFull :one
SELECT om.org_id, om.user_id, om.role, om.created_at, om.updated_at,
       om.deactivated_at, om.scim_exempt,
       u.email, u.display_name
FROM org_members om
JOIN users u ON u.id = om.user_id
WHERE om.org_id = $1 AND om.user_id = $2;

-- name: CountActiveOrgMembers :one
SELECT COUNT(*)::int FROM org_members
WHERE org_id = $1 AND deactivated_at IS NULL;

-- name: CountActiveOrgOwners :one
SELECT COUNT(*)::int FROM org_members
WHERE org_id = $1 AND role = 'owner' AND deactivated_at IS NULL;

-- name: UpdateOrgMemberSCIMExempt :exec
UPDATE org_members SET scim_exempt = $3, updated_at = now()
WHERE org_id = $1 AND user_id = $2;
```

**Important:** Check if `GetOrgOwnerCount` already exists. If it does and doesn't filter by `deactivated_at IS NULL`, you still need `CountActiveOrgOwners` as a separate query (different semantics). Do NOT modify the existing `GetOrgOwnerCount` — other code may depend on it counting ALL owners.

**Step 2: Regenerate sqlc and verify build**

```bash
sqlc generate && go build ./...
```

**Step 3: Commit**

```bash
git add internal/store/queries/org.sql internal/store/generated/
git commit -m "sqlc: add deactivation and active member count queries"
```

---

## Task 11: sqlc queries — group_members SCIM-managed operations

**Files:**
- Modify: `internal/store/queries/groups.sql`
- Modify: `internal/store/generated/` (regenerated)

**Step 1: Add queries for SCIM-managed group membership**

Read `internal/store/queries/groups.sql` first. Append:

```sql
-- name: AddGroupMemberSCIMManaged :exec
INSERT INTO group_members (group_id, user_id, org_id, scim_managed)
VALUES ($1, $2, $3, true)
ON CONFLICT (group_id, user_id) DO NOTHING;

-- name: RemoveSCIMManagedGroupMember :exec
DELETE FROM group_members
WHERE group_id = $1 AND user_id = $2 AND scim_managed = true;

-- name: IsGroupMemberSCIMManaged :one
SELECT scim_managed FROM group_members WHERE group_id = $1 AND user_id = $2;

-- name: GetGroupIfActive :one
SELECT * FROM groups WHERE id = $1 AND deleted_at IS NULL;
```

The `GetGroupIfActive` query is needed for the soft-delete guard in notification group sync (design doc §3.7). The `IsGroupMemberSCIMManaged` query is needed to check before removing.

**Step 2: Regenerate sqlc and verify build**

```bash
sqlc generate && go build ./...
```

**Step 3: Commit**

```bash
git add internal/store/queries/groups.sql internal/store/generated/
git commit -m "sqlc: add SCIM-managed group member queries"
```

---

## Task 12: Store layer — SCIM config methods

Wrap sqlc-generated queries in proper transaction helpers.

**Files:**
- Create: `internal/store/scim_config.go`
- Create: `internal/store/scim_config_test.go`

**Step 1: Write failing tests**

Write tests for SCIM config CRUD using `testutil.NewTestDB(t)`. Test cases with exact assertions:
- `TestCreateSCIMConfig` — create config → assert returned row has matching `org_id`, `sso_connection_id`, `enabled`, `token_hash`, `token_prefix`, `default_role` fields; assert `created_at` is non-zero
- `TestCreateSCIMConfig_Duplicate` — create config, then create again with same org_id → assert error contains "unique" or is a constraint violation (not a nil error)
- `TestGetSCIMConfigByTokenHash` — create config with known token hash → lookup via `LookupSCIMConfigByTokenHash` → assert returned config has matching `org_id` and `enabled` fields. Also test with non-existent hash → assert returns `nil, nil` (not error)
- `TestGetSCIMConfigByOrgID` — create config → `GetSCIMConfig(ctx, orgID)` → assert returned config matches. Also test with random UUID → assert returns `nil, nil`
- `TestGetSCIMConfigBySSOConnectionID` — create config → `LookupSCIMConfigBySSOConnectionID(ctx, ssoConnID)` → assert match. Also test non-existent → `nil, nil`
- `TestUpdateSCIMConfig` — create config with `enabled=false, default_role="viewer"` → update to `enabled=true, default_role="member"` → re-read → assert both fields changed and `updated_at > created_at`
- `TestUpdateSCIMConfigToken` — create config → rotate token hash → re-read → assert `token_hash` changed, `token_prefix` changed, `updated_at` advanced
- `TestDeleteSCIMConfig` — create config → delete → `GetSCIMConfig` returns `nil, nil`
- `TestSCIMConfig_RLSIsolation` — create config in org A and org B via superuser store → query via `AppStore` scoped to org A → assert only org A's config is returned; query scoped to org B → assert only org B's. Cross-org `GetSCIMConfigByOrgID` must return no results, not an error

Key test patterns:
- Setup: create org + SSO connection (prerequisites) via superuser store. Read `internal/store/queries/sso.sql` and `internal/store/sso.go` to find the `CreateSSOConnection` method and its required parameters (org_id, display_name, issuer_url, client_id, client_secret_enc, scopes, enabled). Use `require.NoError(t, err)` for every setup call.
- SCIM config CRUD via `AppStore` for RLS verification
- Token hash lookup via `withBypassTx` (pre-org-context, like the auth middleware will use)

**Step 2: Run tests — verify they fail**

```bash
go test ./internal/store/ -run TestSCIMConfig -v -count=1
```

Expected: compilation errors (methods don't exist yet)

**Step 3: Implement store methods**

Follow the exact method signatures from v1 plan Task 9. Key implementation notes:
- `LookupSCIMConfigByTokenHash` uses `withBypassTx` (pre-org-context auth lookup)
- `GetSCIMConfig` uses `withOrgTx`
- `CreateSCIMConfig` uses `withOrgTx`
- Return `nil, nil` (not error) for `sql.ErrNoRows` on lookup methods
- Add `LookupSCIMConfigBySSOConnectionID` using `withBypassTx` (needed for SSO delete check, which runs before org context is established)

**Step 4: Run tests — verify they pass**

```bash
go test ./internal/store/ -run TestSCIMConfig -v -count=1
```

**Step 5: Lint**

```bash
golangci-lint run ./internal/store/...
```

**Step 6: Commit**

```bash
git add internal/store/scim_config.go internal/store/scim_config_test.go
git commit -m "feat(store): SCIM config CRUD with RLS + bypass-tx token lookup"
```

---

## Task 13: Store layer — SCIM group methods

**Files:**
- Create: `internal/store/scim_groups.go`
- Create: `internal/store/scim_groups_test.go`

Follow the same TDD pattern as Task 12. Key methods:

- `CreateSCIMGroup(ctx, orgID, externalID, displayName)` — uses `withOrgTx`
- `GetSCIMGroup(ctx, orgID, id)` — uses `withOrgTx`
- `GetSCIMGroupByExternalID(ctx, orgID, externalID)` — uses `withOrgTx`
- `ListSCIMGroups(ctx, orgID)` — uses `withOrgTx`, returns member counts
- `UpdateSCIMGroup(ctx, orgID, id, displayName, externalID)` — uses `withOrgTx`
- `UpdateSCIMGroupMapping(ctx, orgID, id, mappedRole, mappedGroupID)` — uses `withOrgTx`
- `DeleteSCIMGroup(ctx, orgID, id)` — uses `withOrgTx`
- `AddSCIMGroupMember(ctx, orgID, scimGroupID, userID)` — uses `withOrgTx`
- `RemoveSCIMGroupMember(ctx, orgID, scimGroupID, userID)` — uses `withOrgTx`
- `ListSCIMGroupMembers(ctx, orgID, scimGroupID)` — uses `withOrgTx`
- `ListUserSCIMGroups(ctx, orgID, userID)` — uses `withOrgTx`
- `CountOtherSCIMGroupsWithSameMapping(ctx, orgID, userID, mappedGroupID, excludeGroupID)` — uses `withOrgTx`

**Test cases with exact assertions:**
- `TestCreateSCIMGroup` — create group → assert returned row has matching `org_id`, `display_name`, `external_id`; `mapped_role` and `mapped_group_id` are null
- `TestCreateSCIMGroup_DuplicateName` — create two groups with same `(org_id, display_name)` → assert unique constraint error
- `TestGetSCIMGroupByExternalID` — create group with external_id → lookup → assert match. Lookup non-existent → assert `sql.ErrNoRows` or nil
- `TestListSCIMGroups_WithMemberCounts` — create 2 groups, add 3 members to group A, 0 to group B → `ListSCIMGroups` → assert group A has `member_count=3`, group B has `member_count=0`
- `TestUpdateSCIMGroupMapping` — set `mapped_role="admin"` and `mapped_group_id=<uuid>` → re-read → assert both fields updated
- `TestDeleteSCIMGroup_CascadesMembers` — create group with members → delete group → assert `scim_group_members` rows are gone (query directly)
- `TestAddSCIMGroupMember_Idempotent` — add same member twice → no error (ON CONFLICT DO NOTHING), member count still 1
- `TestRemoveSCIMGroupMember` — add then remove → `ListSCIMGroupMembers` returns empty slice
- `TestListUserSCIMGroups` — user in 2 groups → assert both returned. User in 0 groups → assert empty slice (not nil, not error)
- `TestCountOtherSCIMGroupsWithSameMapping` — 2 groups both mapped to same notification group, user in both → count excluding group A → assert 1. Excluding group B → assert 1. User in only group A → excluding A → assert 0
- `TestSCIMGroups_RLSIsolation` — create group in org A, query via AppStore scoped to org B → assert zero results. `ListSCIMGroups` for org B returns empty, not org A's groups

TDD: write failing tests → implement → verify pass → lint → commit.

```bash
git commit -m "feat(store): SCIM group and membership methods with RLS"
```

---

## Task 14: Store layer — deactivation + member count methods

**Files:**
- Modify: `internal/store/org.go` — add deactivation methods
- Create: `internal/store/org_deactivation_test.go`

Key methods to add to `org.go`:

- `DeactivateOrgMember(ctx, orgID, userID)` — uses `withOrgTx`
- `ReactivateOrgMember(ctx, orgID, userID)` — uses `withOrgTx`
- `GetOrgMemberFull(ctx, orgID, userID)` — returns `org_members` joined with `users` (email, display_name, deactivated_at, scim_exempt)
- `CountActiveOrgMembers(ctx, orgID)` — uses `withOrgTx`
- `CountActiveOrgOwners(ctx, orgID)` — uses `withOrgTx`
- `UpdateOrgMemberSCIMExempt(ctx, orgID, userID, exempt bool)` — uses `withOrgTx`

**Test cases with exact assertions:**
- `TestDeactivateOrgMember` — deactivate → call `GetOrgMemberFull` → assert `DeactivatedAt.Valid == true` and `DeactivatedAt.Time` is recent (within last minute)
- `TestReactivateOrgMember` — deactivate then reactivate → `GetOrgMemberFull` → assert `DeactivatedAt.Valid == false`
- `TestCountActiveOrgMembers` — create 3 members, deactivate 1 → `CountActiveOrgMembers` → assert returns 2 (not 3)
- `TestCountActiveOrgOwners_SoleOwner` — create 1 owner + 1 member, deactivate member → `CountActiveOrgOwners` → assert 1. Then deactivate owner → assert 0
- `TestCountActiveOrgOwners_MultipleOwners` — create 2 owners, deactivate 1 → assert 1 remaining
- `TestUpdateOrgMemberSCIMExempt` — set exempt=true → `GetOrgMemberFull` → assert `ScimExempt == true`. Set back to false → assert false
- `TestDeactivation_RLSIsolation` — deactivate member in org A → query via AppStore scoped to org B → assert operation affects zero rows (not error)

TDD: write failing tests → implement → verify pass → lint → commit.

```bash
git commit -m "feat(store): org member deactivation + count methods"
```

---

## Task 15: SCIM token generation helper

**Files:**
- Create: `internal/auth/scimtoken.go`
- Create: `internal/auth/scimtoken_test.go`

**Step 1: Write failing tests**

```go
func TestGenerateSCIMToken(t *testing.T) {
    raw, hash, prefix, err := auth.GenerateSCIMToken()
    // Verify: no error, raw starts with "cvert_scim_", hash is sha256 hex (64 chars),
    // prefix is first 8 chars of raw, len(raw) == 75 (11 prefix + 64 hex from 32 bytes)
}

func TestHashSCIMToken(t *testing.T) {
    // Verify: deterministic sha256 hex
}

func TestGenerateSCIMToken_Uniqueness(t *testing.T) {
    // Generate two tokens, verify they differ
}
```

**Step 2: Implement**

```go
// ABOUTME: SCIM bearer token generation and hashing.
// ABOUTME: Tokens use "cvert_scim_" prefix (distinct from API key "cvo_" prefix).
package auth

const SCIMTokenPrefix = "cvert_scim_"

func GenerateSCIMToken() (rawToken, tokenHash, tokenPrefix string, err error) { ... }
func HashSCIMToken(rawToken string) string { ... }
```

Use `crypto/rand` for token bytes, `crypto/sha256` for hashing, `encoding/hex` for encoding. Same pattern as `internal/auth/apikey.go`.

**Step 3: Run tests, lint, commit**

```bash
git commit -m "feat(auth): SCIM bearer token generation + hashing"
```

---

## Task 16: RequireOrgRole middleware — deactivation check

Deactivated members should get 403. This is a modification to existing middleware.

**Files:**
- Modify: `internal/api/middleware_rbac.go`
- Modify: `internal/api/middleware_rbac_test.go`

**Step 1: Write failing test**

Test that a deactivated org member gets 403 with message "Your membership in this organization has been deactivated."

**Step 2: Run test — verify fail**

**Step 3: Modify RequireOrgRole**

First, read `internal/api/middleware_rbac.go` to understand the current implementation. Identify which sqlc query is called to get the member's role (likely `GetOrgMemberRole` in `internal/store/queries/org.sql`). The query needs to also return `deactivated_at`. Two options:

**Option A (recommended):** Add a new sqlc query `GetOrgMemberRoleAndStatus` that returns `role` and `deactivated_at`. Use it in the middleware instead of the existing `GetOrgMemberRole`.

**Option B:** Modify the existing `GetOrgMemberRole` query to also SELECT `deactivated_at`. This may break existing callers that don't expect the extra field — check before modifying.

After getting the member data, add the deactivation check BEFORE the role check:

```go
if member.DeactivatedAt.Valid {
    http.Error(w, "Your membership in this organization has been deactivated.", http.StatusForbidden)
    return
}
```

**Step 4: Run ALL middleware tests — verify they pass** (not just the new test)

```bash
go test ./internal/api/ -run TestRequireOrgRole -v -count=1
```

**Step 5: Lint + commit**

```bash
git commit -m "feat(api): deactivated org members get 403 in RequireOrgRole"
```

---

## Task 17: Member PATCH — deactivation + scim_exempt fields

Extend the existing member PATCH endpoint to support `active` (bool) and `scim_exempt` (bool) fields.

**Files:**
- Modify: member handler file — read `internal/api/orgs.go` first, or grep for `members/{user_id}` or `patchMemberHandler` to locate the exact file
- Modify: corresponding test file

**Step 1: Write failing tests**

Test cases:
- `TestPatchMember_Deactivate` — PATCH `{"active": false}` sets `deactivated_at`
- `TestPatchMember_Reactivate` — PATCH `{"active": true}` clears `deactivated_at`
- `TestPatchMember_SoleOwnerProtection` — cannot deactivate sole active owner → 400
- `TestPatchMember_SCIMExempt` — PATCH `{"scim_exempt": true}` sets flag
- `TestPatchMember_RequiresAdmin` — viewer/member get 403

Tests must include `X-Requested-By: CVErt-Ops` header on all requests (CSRF middleware).

**Step 2: Run tests — verify fail**

**Step 3: Implement**

Add `Active *bool` and `SCIMExempt *bool` to the patch member request struct (pointer types — see pitfalls §API-2). Semantics: `nil` = field not sent (no change), `*false` = deactivate/disable, `*true` = reactivate/enable. In the handler:
- If `Active != nil && *Active == false`: check `CountActiveOrgOwners`, if sole owner + target is owner → 400. Otherwise call `DeactivateOrgMember`.
- If `Active != nil && *Active == true`: call `ReactivateOrgMember`.
- If `SCIMExempt != nil`: call `UpdateOrgMemberSCIMExempt`.
- Audit log the changes with entity_type `member`.

**Step 4: Also update `GET /members` response** to include `active`, `deactivated_at`, `scim_exempt` fields.

**⚠️ Pitfall warnings for this task:**
- API-2: `Active *bool` and `SCIMExempt *bool` MUST be pointer types. If you use `bool` with `omitempty`, sending `{"active": false}` will be silently ignored (Go's zero value for bool is false, omitempty drops it)
- API-9: The same validation rules that apply to admin manual deactivation (sole-owner check) must also apply when SCIM triggers deactivation later — this task establishes the handler logic that SCIM reuses
- Testing §4: Test PATCH with `{"active": false}` explicitly — this is the critical case that breaks with non-pointer types

**Step 5: Run tests, lint, commit**

```bash
git commit -m "feat(api): member PATCH supports active + scim_exempt fields"
```

---

## Task 18: SCIM error helper + response types

Shared SCIM JSON helpers used by all SCIM handlers.

**Files:**
- Create: `internal/api/scim_types.go`
- Create: `internal/api/scim_types_test.go`

**Step 1: Implement SCIM response types**

```go
// ABOUTME: SCIM 2.0 request/response types and JSON helpers (RFC 7643/7644).
// ABOUTME: Used by all SCIM chi handlers. Separate from huma types.
package api
```

Types to define:
- `SCIMError` struct: `Schemas []string`, `Status string`, `SCIMType string`, `Detail string`
- `SCIMUser` struct: `Schemas []string`, `ID string`, `ExternalID string`, `UserName string`, `DisplayName string`, `Active bool`, `Meta SCIMMeta`
- `SCIMGroup` struct: similar
- `SCIMListResponse` struct: `Schemas []string`, `TotalResults int`, `ItemsPerPage int`, `StartIndex int`, `Resources []any`
- `SCIMMeta` struct: `ResourceType string`, `Created string`, `LastModified string`, `Location string`
- `SCIMPatchOp` struct: `Schemas []string`, `Operations []SCIMPatchOperation`
- `SCIMPatchOperation` struct: `Op string`, `Path string`, `Value any`
- `writeSCIMError(w, status, scimType, detail)` helper
- `writeSCIMJSON(w, status, body)` helper — sets `Content-Type: application/scim+json`
- `parseSCIMBool(v any) (bool, error)` — handles both JSON booleans and string `"True"`/`"False"`
- `parseSCIMFilter(filter string) ([]SCIMFilterExpr, error)` — parses the minimal filter grammar: `attr SP "eq" SP quotedValue` and compound `expr SP "and" SP expr`. Split on ` and ` (space-surrounded) first, then parse each part as `attr SP op SP value`. Only `eq` operator is supported; any other operator returns error with `scimType: "invalidFilter"`. No nested expressions, no `or`, no parentheses, no `not`.

**Step 2: Write tests**

Test `writeSCIMError`, `parseSCIMBool` (with string booleans from Entra ID), `parseSCIMFilter` (eq, and, unsupported operators → error), and JSON serialization of response types. Verify `Content-Type: application/scim+json` header.

**Step 3: Lint + commit**

```bash
git commit -m "feat(api): SCIM 2.0 response types, error helper, filter parser"
```

---

## Task 19: SCIM auth middleware (`requireSCIMAuth`)

**Files:**
- Create: `internal/api/middleware_scim.go`
- Create: `internal/api/middleware_scim_test.go`

**Step 1: Write failing tests**

Test cases (from design §2):
- `TestSCIMAuth_ValidToken` — bearer token accepted, org_id + scim_config_id in context
- `TestSCIMAuth_InvalidToken` — wrong token → 401, SCIM error JSON format
- `TestSCIMAuth_OrgMismatch` — token for org A used on org B → 401
- `TestSCIMAuth_Disabled` — disabled config → 403
- `TestSCIMAuth_MissingHeader` — no Authorization header → 401
- `TestSCIMAuth_ErrorFormat` — all auth failures return `Content-Type: application/scim+json` with RFC 7644 error body
- `TestSCIMAuth_SecurityEvent` — auth failures fire security events (verify in `security_events` table)

Tests must NOT include `X-Requested-By` header — SCIM endpoints use Bearer token auth, not cookies, so CSRF middleware should not apply. This also verifies that SCIM routes are properly exempt from CSRF middleware (if they weren't exempt, requests without this header would get 403).

**Step 2: Implement**

Follow design doc §2 auth flow steps 1-9 exactly. Use `writeSCIMError()` from Task 18 for error responses. Fire `secure.EventWriter.Write()` for auth failures:
- Invalid/missing token → `EventSCIMAuthFailed`
- Org mismatch → `EventSCIMAuthOrgMismatch`
- Disabled config → `EventSCIMAuthDisabled`

The middleware needs access to `*store.Store` and `*secure.EventWriter`. Get them from the `*Server` receiver.

**⚠️ Pitfall warnings for this task:**
- AUTH-10: Token hash comparison MUST use `subtle.ConstantTimeCompare` — never `==` or `bytes.Equal`
- Testing §3: Auth failure error responses MUST return `Content-Type: application/scim+json` — test that the Content-Type header is correct on ALL error paths (missing header, invalid token, org mismatch, disabled)
- Testing §11: Test with a well-formed-but-wrong token (same prefix, correct length, different random bytes) — not just `"invalid"` string

**Step 3: Run tests, lint, commit**

```bash
git commit -m "feat(api): SCIM bearer token auth middleware with security events"
```

---

## Task 20: SSO delete handler — SCIM pre-flight check

**Depends on:** Task 12 (provides `LookupSCIMConfigBySSOConnectionID` store method).

Modify the existing SSO delete handler to check for attached SCIM config.

**Files:**
- Modify: `internal/api/sso.go`
- Modify: `internal/api/sso_test.go`

**Step 1: Write failing test**

- `TestSSODelete_BlockedBySCIM` — SSO delete when SCIM config exists → 409 with actionable message

**Step 2: Implement**

In the SSO delete handler, before deleting:
1. Get the SSO connection ID from the request
2. Call `store.LookupSCIMConfigBySSOConnectionID(ctx, ssoConnID)` (uses `withBypassTx`)
3. If config exists → return 409 with RFC 9457 error (this is an admin endpoint, not SCIM, so use standard error format):
   ```go
   writeProblem(w, http.StatusConflict, "SSO connection has active SCIM provisioning",
       "Disable and delete the SCIM configuration before removing SSO, or update the SSO connection in place.")
   ```

**Step 3: Run existing SSO tests to ensure no regressions**

```bash
go test ./internal/api/ -run TestSSO -v -count=1
```

**Step 4: Lint + commit**

```bash
git commit -m "feat(api): block SSO delete when SCIM config exists (409)"
```

---

## Task 21: SCIM rate limiter

Separate rate limiter for SCIM endpoints.

**Files:**
- Create: `internal/api/scim_ratelimit.go`
- Create: `internal/api/scim_ratelimit_test.go`

**Step 1: Write failing test**

- `TestSCIMRateLimit_EnforcesLimit` — exceeding the limit returns 429 with SCIM error format
- `TestSCIMRateLimit_PerOrg` — different orgs have independent limits

**Step 2: Implement**

Create a `scimRateLimiter` using `golang.org/x/time/rate` (same dependency already in use for API rate limiting). The limiter is keyed by org_id (UUID string). Rate is configured from `srv.cfg.SCIMRateLimit`. Mount as middleware after `requireSCIMAuth`.

On rate limit exceeded, return SCIM error format:
```go
writeSCIMError(w, http.StatusTooManyRequests, "", "Rate limit exceeded")
```

Also fire `EventSCIMRateLimited` security event.

**Step 3: Lint + commit**

```bash
git commit -m "feat(api): dedicated SCIM rate limiter (configurable per org)"
```

---

## Task 22: Role recomputation function

**Depends on:** Task 14 (provides `GetOrgMemberFull`, `UpdateOrgMemberRole` store methods) and Task 13 (provides `ListUserSCIMGroups`).

Shared function called from SCIM handlers and admin mapping endpoints.

**Files:**
- Create: `internal/api/scim_roles.go`
- Create: `internal/api/scim_roles_test.go`

**Step 1: Write failing tests**

Test cases (from design §3.6) with exact assertions:
- `TestRoleRecompute_SingleGroup` — user in group with `mapped_role="admin"` → recompute → `GetOrgMemberFull` → assert `role == "admin"`
- `TestRoleRecompute_MultipleGroups_HighestWins` — user in group A (`mapped_role="member"`) and group B (`mapped_role="admin"`) → recompute → assert `role == "admin"` (not "member")
- `TestRoleRecompute_NoMappedGroups` — user in group with `mapped_role=NULL`, `default_role="viewer"` → recompute → assert `role == "viewer"`
- `TestRoleRecompute_NeverSetsOwner` — user in group with `mapped_role="admin"` → recompute → assert `role == "admin"` (never "owner", even if somehow mapped)
- `TestRoleRecompute_SCIMExempt_Skipped` — user has `scim_exempt=true`, current `role="viewer"`, in group with `mapped_role="admin"` → recompute → assert `role` is still "viewer" (unchanged)
- `TestRoleRecompute_OwnerNotDowngraded` — user with `role="owner"` in group with `mapped_role="viewer"` → recompute → assert `role` is still "owner"
- `TestRoleRecompute_RemovedFromAllGroups` — user was in a group with `mapped_role="admin"`, remove from group → recompute → assert `role` falls back to `default_role` (e.g., "viewer")

These are integration tests using `testutil.NewTestDB(t)`. Each test must set up a complete environment: org (enterprise tier) + SSO connection + SCIM config + user + org_member + SCIM group + SCIM group membership.

**Step 2: Implement**

Follow design doc §3.6 exactly. The function signature:

```go
func (srv *Server) recomputeSCIMRole(ctx context.Context, orgID, userID uuid.UUID, defaultRole string) error
```

Use `srv.store.GetOrgMemberFull()` to check current role and scim_exempt. Use `srv.store.ListUserSCIMGroups()` to get group mappings. Use `srv.store.UpdateOrgMemberRole()` to write the new role.

Role hierarchy map: `map[string]int{"viewer": 1, "member": 2, "admin": 3}`.

**Step 3: Run tests, lint, commit**

```bash
git commit -m "feat(api): SCIM role recomputation from group mappings"
```

---

## Task 23: Notification group sync function

**Files:**
- Create: `internal/api/scim_notif_sync.go`
- Create: `internal/api/scim_notif_sync_test.go`

**Step 1: Write failing tests**

Test cases (from design §3.7) with exact assertions:
- `TestNotifSync_Add_NewMember` — call `syncNotifGroupAdd` → query `group_members` → assert row exists with `scim_managed=true`
- `TestNotifSync_Add_AlreadyManualMember` — manually add member with `scim_managed=false` → call `syncNotifGroupAdd` → assert `scim_managed` is still `false` (ON CONFLICT DO NOTHING preserves manual flag)
- `TestNotifSync_Remove_SCIMManaged` — add member with `scim_managed=true` → call `syncNotifGroupRemove` → query `group_members` → assert row is gone
- `TestNotifSync_Remove_ManualMember` — add member with `scim_managed=false` → call `syncNotifGroupRemove` → assert row still exists (admin owns it)
- `TestNotifSync_Remove_MultiMapping` — user in SCIM group A and B, both mapped to same notification group → remove from group A → assert `group_members` row still exists (group B still maps). Then remove from group B → assert row is gone
- `TestNotifSync_GroupDelete_NoRemoval` — add via SCIM sync → delete the SCIM group → assert `group_members` row in notification group is STILL present
- `TestNotifSync_ExemptUser_Skipped` — user has `scim_exempt=true` → call `syncNotifGroupAdd` → assert NO row created in `group_members`
- `TestNotifSync_SoftDeletedTargetGroup` — soft-delete the notification group (`deleted_at=now()`) → call `syncNotifGroupAdd` → assert NO row created (no-op, no error)

**Step 2: Implement**

Two functions:
- `syncNotifGroupAdd(ctx, orgID, userID, mappedGroupID, scimGroupID)` — first calls `GetGroupIfActive` to verify target group exists and `deleted_at IS NULL`. If soft-deleted, return nil (no-op). Otherwise, call `AddGroupMemberSCIMManaged`.
- `syncNotifGroupRemove(ctx, orgID, userID, mappedGroupID, scimGroupID)` — calls `CountOtherSCIMGroupsWithSameMapping`. If count > 0, return nil. Otherwise, call `RemoveSCIMManagedGroupMember`.

**Step 3: Run tests, lint, commit**

```bash
git commit -m "feat(api): notification group sync from SCIM group mappings"
```

---

## Task 24: SCIM User handlers

**Depends on:** Tasks 12, 14 (store methods), Task 15 (token generation), Task 18 (SCIM types), Task 19 (auth middleware).

The core SCIM user CRUD handlers.

**Files:**
- Create: `internal/api/scim_users.go`
- Create: `internal/api/scim_users_test.go`

**Step 1: Write failing tests**

Integration tests using `testutil.NewTestDB(t)` + `httptest.Server`. Test cases from design doc §7 — User Provisioning, User Read/List, User Update, User Deprovision sections.

Key test patterns:
- Setup: create org (enterprise tier) + SSO connection + SCIM config via store. Create users as needed.
- Each test makes HTTP requests with Bearer token auth through the full middleware stack.
- Verify SCIM JSON response format (schemas array, Content-Type header).
- Verify audit log entries are created.
- Verify security events for provisioning operations.

**Step 2: Implement handlers**

Implement as chi `HandlerFunc` methods on `*Server`:
- `scimCreateUser(w, r)` — POST /Users (design doc §3.3)
- `scimGetUser(w, r)` — GET /Users/{id}
- `scimListUsers(w, r)` — GET /Users (with filter parsing)
- `scimReplaceUser(w, r)` — PUT /Users/{id}
- `scimPatchUser(w, r)` — PATCH /Users/{id}
- `scimDeleteUser(w, r)` — DELETE /Users/{id}

Each handler:
1. Extracts `orgID` and `scimConfigID` from context (set by `requireSCIMAuth`)
2. Reads request body and parses JSON
3. Performs business logic using store methods
4. Writes SCIM JSON response using `writeSCIMJSON`
5. Fires audit log entry
6. Fires security events where applicable
7. Emits slog with standard attributes (`org_id`, `scim_config_id`, operation-specific fields)

Identity matching in POST /Users follows design doc §3.2-3.3 exactly:
1. Check `user_identities` for `provider='scim:{config_id}'`, `provider_user_id=externalId`
2. If not found, check `users` by email
3. If not found, create new user

Transaction splitting: `users`/`user_identities` writes use `withBypassTx` (global tables, no RLS). `org_members` writes use `withOrgTx` (org-scoped, RLS). This is NOT a pitfall violation (AUTH-12) — `withBypassTx` is correct here because `users` and `user_identities` are global tables that cannot be written through `withOrgTx`. See design doc §3.3 transaction note.

**⚠️ Pitfall warnings for this task:**
- API-2: PATCH `active` field MUST be `*bool` pointer — `omitempty` on non-pointer bool silently drops `false` values
- API-9: PUT/PATCH userName validation must reject empty/whitespace strings the same way POST does
- Testing §4: Test PATCH with explicit `false` value for `active` — not just `true`. `false` via pointer is different from absent
- Testing §1: `TestSCIMCreateUser_ConcurrentDuplicate` must use barrier pattern (`close(ready)`) to ensure goroutines hit the critical section simultaneously
- Testing §3: Error responses for 404, 409, 400 must all return `Content-Type: application/scim+json` — assert Content-Type on EVERY error test case
- DB-17: Store method selection matters — read `dev/implementation-pitfalls.md` §DB-17 before choosing transaction helpers

**Step 3: Run tests, lint, commit**

```bash
git commit -m "feat(api): SCIM user handlers (create, get, list, put, patch, delete)"
```

---

## Task 25: SCIM Group handlers

**Files:**
- Create: `internal/api/scim_groups.go`
- Create: `internal/api/scim_groups_test.go`

**Step 1: Write failing tests**

Test cases from design doc §7 — Group Operations section.

**Step 2: Implement handlers**

- `scimCreateGroup(w, r)` — POST /Groups
- `scimGetGroup(w, r)` — GET /Groups/{id}
- `scimListGroups(w, r)` — GET /Groups
- `scimReplaceGroup(w, r)` — PUT /Groups/{id}
- `scimPatchGroup(w, r)` — PATCH /Groups/{id}
- `scimDeleteGroup(w, r)` — DELETE /Groups/{id}

**PATCH member removal must handle both formats** (design doc §4.2):
- Standard: `op: "remove", path: "members[value eq \"user-uuid\"]"` — extract user UUID from path filter using regex `members\[value eq "(.+)"\]` or string parsing
- Entra ID: `op: "remove", path: "members", value: [{value: "user-uuid"}]` — type-assert `Value` to `[]any`, then extract `value` field from each map element

Each membership change triggers `recomputeSCIMRole()` + `syncNotifGroupAdd/Remove()` for the affected user (if not exempt and if mappings are configured).

**Step 3: Run tests, lint, commit**

```bash
git commit -m "feat(api): SCIM group handlers (create, get, list, put, patch, delete)"
```

---

## Task 26: SCIM route mounting + discovery endpoints

Wire SCIM handlers into the chi router.

**Files:**
- Modify: `internal/api/server.go` — add SCIM route mount
- Create: `internal/api/scim_discovery.go` — static discovery responses
- Create: `internal/api/scim_routes_test.go`

**Step 1: Write failing tests**

- `TestSCIMRoutes_UsersAccessible` — `GET /api/v1/orgs/{org_id}/scim/v2/Users` returns 401 (not 404)
- `TestSCIMRoutes_GroupsAccessible` — same for Groups
- `TestSCIMRoutes_ServiceProviderConfig` — returns correct JSON with `patch: true`, `bulk: false`
- `TestSCIMRoutes_Schemas` — returns User + Group schema definitions
- `TestSCIMRoutes_ResourceTypes` — returns User + Group resource type metadata

**Step 2: Implement route mounting**

In the server's route setup, add SCIM routes under the org path:

```go
r.Route("/scim/v2", func(r chi.Router) {
    r.Use(srv.requireSCIMAuth)
    r.Use(srv.scimRateLimitMiddleware)

    // Discovery endpoints (no auth — but still behind requireSCIMAuth since
    // they're org-scoped and IdPs use the same token for discovery)
    r.Get("/ServiceProviderConfig", srv.scimServiceProviderConfig)
    r.Get("/Schemas", srv.scimSchemas)
    r.Get("/ResourceTypes", srv.scimResourceTypes)

    // User endpoints
    r.Get("/Users", srv.scimListUsers)
    r.Post("/Users", srv.scimCreateUser)
    r.Get("/Users/{id}", srv.scimGetUser)
    r.Put("/Users/{id}", srv.scimReplaceUser)
    r.Patch("/Users/{id}", srv.scimPatchUser)
    r.Delete("/Users/{id}", srv.scimDeleteUser)

    // Group endpoints
    r.Get("/Groups", srv.scimListGroups)
    r.Post("/Groups", srv.scimCreateGroup)
    r.Get("/Groups/{id}", srv.scimGetGroup)
    r.Put("/Groups/{id}", srv.scimReplaceGroup)
    r.Patch("/Groups/{id}", srv.scimPatchGroup)
    r.Delete("/Groups/{id}", srv.scimDeleteGroup)
})
```

**Important:** Read `internal/api/server.go` to understand the route structure. Key considerations:
1. SCIM routes must be OUTSIDE the `RequireAuthenticated` middleware group — they use their own `requireSCIMAuth` middleware. Look at how SSO callback routes are mounted (likely in a separate route group without RequireAuthenticated) and follow the same pattern.
2. SCIM routes must be AFTER request ID middleware in the chain so slog output includes correlation IDs.
3. SCIM routes should be under the org path: `/api/v1/orgs/{org_id}/scim/v2/...`
4. The SCIM route group needs its own middleware stack: `requireSCIMAuth` → `scimRateLimitMiddleware` → handlers.
5. SCIM routes should also be exempt from CSRF middleware (Bearer token auth, not cookie auth).

**Step 3: Implement discovery endpoints**

Static JSON responses from design doc §3.5. Served with `Content-Type: application/scim+json`.

**Step 4: Run tests, lint, commit**

```bash
git commit -m "feat(api): mount SCIM routes + discovery endpoints"
```

---

## Task 27: Admin endpoints — SCIM config CRUD

Standard chi handlers for managing SCIM config. Enterprise-only, owner-only.

**Files:**
- Create: `internal/api/scim_admin.go`
- Create: `internal/api/scim_admin_test.go`

**Step 1: Write failing tests**

Test cases from design doc §7 — SCIM Config Management section. All requests need `X-Requested-By: CVErt-Ops` header (these are standard auth endpoints, not SCIM protocol).

**Step 2: Implement handlers**

Follow the SSO handler pattern in `internal/api/sso.go`:
- Extract `orgID` from context
- Call `requireEnterpriseTier(w, r)` — returns false if tier check fails
- Validate input
- Call store methods
- Return JSON response (NOT SCIM format — these are admin endpoints using standard RFC 9457 errors)
- Audit log with entity_type `scim_config`
- Fire security events for token create/rotate

Register routes under the existing org route group:

```go
r.Route("/sso/scim", func(r chi.Router) {
    r.With(srv.RequireOrgRole(RoleOwner)).Post("/", srv.createSCIMConfigHandler)
    r.With(srv.RequireOrgRole(RoleAdmin)).Get("/", srv.getSCIMConfigHandler)
    r.With(srv.RequireOrgRole(RoleOwner)).Patch("/", srv.patchSCIMConfigHandler)
    r.With(srv.RequireOrgRole(RoleOwner)).Delete("/", srv.deleteSCIMConfigHandler)
    r.With(srv.RequireOrgRole(RoleOwner)).Post("/rotate-token", srv.rotateSCIMTokenHandler)
    r.With(srv.RequireOrgRole(RoleAdmin)).Get("/groups", srv.listSCIMGroupsHandler)
    r.Route("/groups/{id}/mapping", func(r chi.Router) {
        r.With(srv.RequireOrgRole(RoleAdmin)).Patch("/", srv.patchSCIMGroupMappingHandler)
    })
})
```

**Step 3: Run tests, lint, commit**

```bash
git commit -m "feat(api): SCIM config admin endpoints (CRUD, token rotation, group mapping)"
```

---

## Task 28: Group mapping with immediate effect

When a group's `mapped_role` or `mapped_group_id` changes, recompute roles / sync notification groups for all current members immediately.

**Files:**
- Modify: `internal/api/scim_admin.go` (already created in Task 27)
- Add tests to `internal/api/scim_admin_test.go`

**Step 1: Write failing tests**

- `TestGroupMapping_SetRole` — mapped_role applied immediately to existing members
- `TestGroupMapping_SetNotificationGroup` — mapped_group_id triggers immediate sync
- `TestGroupMapping_ClearMapping` — null mapped_role → roles recomputed to default
- `TestGroupMapping_CrossOrgGroupId` — mapped_group_id from different org → 400
- `TestGroupMapping_SoftDeletedGroupId` — mapped_group_id to soft-deleted group → 400
- `TestGroupMapping_MappingChanged_OldGroupCleanedUp` — old notification group members cleaned up

**Step 2: Implement**

In `patchSCIMGroupMappingHandler`:
1. Update `scim_groups.mapped_role` and/or `mapped_group_id`
2. If `mapped_group_id` is set, validate it belongs to the same org AND `deleted_at IS NULL` (call `GetGroupIfActive` — FK bypasses RLS, soft-delete not visible to FK)
3. List all current members of the SCIM group
4. For each non-exempt member: `recomputeSCIMRole()` if mapped_role changed, `syncNotifGroupAdd/Remove()` if mapped_group_id changed
5. If mapped_group_id changed from a previous value: clean up scim_managed memberships in the old notification group

**Step 3: Run tests, lint, commit**

```bash
git commit -m "feat(api): SCIM group mapping with immediate role/notif recomputation"
```

---

## Task 29: End-to-end SCIM integration tests

Full workflow tests simulating IdP provisioning flows.

**Files:**
- Create: `internal/api/scim_e2e_test.go`

Test scenarios:
1. **Full provisioning lifecycle:** Create SCIM config → provision user → deactivate → reactivate → deprovision
2. **Group role mapping:** Create group with mapping → add member → verify role applied → remove member → verify role reverted to default
3. **Notification group sync:** Create group with mapped_group_id → add member → verify notification group membership → remove → verify cleanup
4. **Entra ID compatibility:** Capitalized op names, string booleans, value-array member removal
5. **Okta compatibility:** PUT for attribute updates, PATCH only for activation
6. **Test connection patterns:** Entra ID `GET /Users?filter=id eq "{random-guid}"`, Okta `GET /Users?startIndex=1&count=1`
7. **Cross-org isolation:** Provision user in org A → verify invisible from org B's SCIM endpoint
8. **SCIM exempt user:** All operations return success but no modifications
9. **Sole-owner protection:** Attempt to deactivate sole owner via SCIM → verify 400
10. **Token rotation:** Rotate token → old token rejected → new token works
11. **Error Content-Type consistency:** All error responses (auth, validation, not-found) return `Content-Type: application/scim+json` — never `text/plain` from middleware layers (testing-pitfalls §3)

These tests use `testutil.NewTestDB(t)` and make HTTP requests through `httptest.Server` to test the full middleware → handler → store stack.

```bash
git commit -m "test(scim): end-to-end SCIM provisioning integration tests"
```

---

## Task 30: Audit + security event verification pass

Ensure all SCIM operations produce correct audit log entries and security events.

**Files:**
- Modify: SCIM handler files (add any missing audit/security event calls)
- Modify: existing SCIM test files (add audit/security event assertions)

**Step 1: Verify audit logging**

For each SCIM operation, verify in existing tests that:
- Audit log entry is created with correct `entity_type` (`scim_config`, `scim_group`, or `member`)
- Audit log entry has correct `action` (`create`, `update`, `delete`)
- SCIM protocol operations have `metadata: {"source": "scim", "scim_config_id": "<uuid>"}`
- Exempt user operations have `metadata: {"source": "scim", "suppressed": true, "reason": "scim_exempt"}`

**Step 2: Verify security events**

Verify that all event constants defined in Task 6 are actually emitted somewhere (testing-pitfalls §7). For each constant, grep for its usage outside `events.go`. If a constant is defined but never emitted, either add the emit call or remove the constant.

**Step 3: Verify slog attributes**

Verify that all SCIM log lines include `org_id` and `scim_config_id` standard attributes.

```bash
git commit -m "feat(scim): complete audit logging + security event verification"
```

---

## Task 31: Final review and cleanup

**Files:**
- All files created/modified in this phase

**Step 1: Run full test suite**

```bash
go test ./... -count=1 -timeout=600s
```

If Docker Desktop is unavailable, this is a HARD BLOCKER. Do not proceed. Escalate to Sam.

**Step 2: Run with race detector**

```bash
go test ./... -count=1 -race -timeout=600s
```

**Step 3: Lint**

```bash
golangci-lint run
```

**Step 4: Verify ABOUTME comments**

Every new Go file must start with two `// ABOUTME:` comment lines.

**Step 5: Update implementation log**

Invoke the `implementation-log` skill to add Phase 7 summary.

**Step 6: Run /pitfall-check**

Invoke the `pitfall-check` skill on the SCIM code.

**Step 7: Run /security-review**

Invoke the `security-review` skill on SCIM auth, token handling, and tenant isolation code.

**Step 8: Run /plan-check**

Invoke the `plan-check` skill against PLAN.md §7.2.

**Step 9: Commit**

```bash
git commit -m "chore(scim): Phase 7 final review, cleanup, and verification"
```

---

## Execution Waves (Subagent-Driven)

Each wave completes fully (tests green, lint clean, committed) before the next wave starts. Within a wave, parallel lanes run as independent subagents in worktrees. **Review checkpoint** after each wave — merge results, verify integration, course-correct before proceeding.

### Wave 1: Foundation (sequential — main agent)
**Tasks:** 1, 2, 3, 4, 5, 6, 7
**Why sequential:** Migrations depend on each other. Security events and config must exist first. These are small, mechanical tasks.
**Deliverable:** All migrations applied, security event constants defined, sqlc regenerated, `go build ./...` passes.
**Review checkpoint:** Run 3-round review. Verify: all migrations have `-- migrate:no-transaction` where needed (CONCURRENTLY indexes). All RLS policies use dual-escape pattern. Security event exhaustiveness test passes. `go build ./...` clean.

### Wave 2: Data Layer (3 parallel subagents)
| Lane A | Lane B | Lane C |
|--------|--------|--------|
| Task 8: sqlc — SCIM config queries | Task 9: sqlc — SCIM group queries | Task 10: sqlc — org deactivation queries |
| Task 12: Store — SCIM config methods + tests | Task 13: Store — SCIM group methods + tests | Task 11: sqlc — group_members SCIM queries |
| | | Task 14: Store — deactivation methods + tests |

**Why parallel:** Each lane touches independent query files and store files.
**Deliverable:** Complete store layer with passing RLS isolation tests.
**Review checkpoint:** Run 3-round review. Verify: sqlc generation is clean after merging all three lanes. ALL store tests use `AppStore` for RLS verification (not `Store`). Every store method test verifies the returned VALUE, not just `err == nil`. `go test ./internal/store/ -count=1` passes.

### Wave 3: Cross-Cutting Utilities (3 parallel subagents)
| Lane A | Lane B | Lane C |
|--------|--------|--------|
| Task 15: SCIM token generation | Task 16: RequireOrgRole deactivation check | Task 18: SCIM error helper + response types |
| Task 19: SCIM auth middleware | Task 17: Member PATCH deactivation + scim_exempt | Task 22: Role recomputation function |
| Task 21: SCIM rate limiter | Task 20: SSO delete SCIM pre-flight check | Task 23: Notification group sync function |

**Lane A:** SCIM auth stack (token → middleware → rate limiter), sequential within.
**Lane B:** General deactivation feature (middleware → API → SSO guard), sequential within.
**Lane C:** SCIM types and business logic (types → roles → notif sync), sequential within.
**Deliverable:** SCIM auth tested, deactivation works, role recompute + notif sync tested.
**Review checkpoint:** Run 3-round review. Verify: SCIM error format (not RFC 9457). Deactivation returns 403 (not 401). Role hierarchy correct (admin > member > viewer). Auth middleware uses `subtle.ConstantTimeCompare`. Security events fire on auth failures. `go test ./internal/api/ ./internal/auth/ -count=1` passes.

### Wave 4: SCIM Handlers + Admin (3 parallel subagents)
| Lane A | Lane B | Lane C |
|--------|--------|--------|
| Task 24: SCIM User handlers | Task 25: SCIM Group handlers | Task 27: Admin SCIM config endpoints |
| | | Task 28: Group mapping with immediate effect |

**Lane A:** User CRUD — the largest single task.
**Lane B:** Group CRUD — depends on role recompute + notif sync from Wave 3.
**Lane C:** Admin endpoints — standard chi handlers.
**Deliverable:** All SCIM and admin handlers working.
**Review checkpoint:** Run 3-round review. Verify: Entra ID quirks handled (case-insensitive ops, string booleans, value-array member removal). PUT is a full implementation (not PATCH wrapper) — critical for Okta. Content-Type is `application/scim+json` on ALL responses. Admin endpoints use RFC 9457 errors (not SCIM format). SCIM `schemas` array is included in every response. `go test ./internal/api/ -count=1 -run SCIM` passes.

### Wave 5: Integration (sequential — main agent)
**Task:** 26
**Why sequential:** Route mounting is the riskiest integration point — tight feedback loop needed.
**Deliverable:** Full SCIM endpoint stack accessible at `/api/v1/orgs/{org_id}/scim/v2/*`.

### Wave 6: Verification (2 parallel subagents)
| Lane A | Lane B |
|--------|--------|
| Task 29: E2E integration tests | Task 30: Audit + security event verification |

**Deliverable:** All SCIM flows tested E2E. Audit + security events verified.
**Review checkpoint:** Run 3-round review. Verify: all 10 security event constants from Task 6 are emitted in at least one code path (grep). All audit log entries have correct `entity_type` and `metadata.source`. E2E tests cover both Entra ID and Okta compatibility scenarios. `go test ./internal/api/ -count=1 -timeout=300s` passes.

### Wave 7: Final Review (sequential — main agent)
**Task:** 31
Runs full test suite, race detector, lint, pitfall-check, security-review, plan-check.

---

## Dependency Graph (reference)

```
Wave 1:  [1] → [2] → [3] → [4] → [5] → [6] → [7]
              ↓
Wave 2:  [8→12]  ||  [9→13]  ||  [10→11→14]
              ↓
Wave 3:  [15→19→21]  ||  [16→17→20]  ||  [18→22→23]
              ↓
Wave 4:  [24]  ||  [25]  ||  [27→28]
              ↓
Wave 5:  [26]
              ↓
Wave 6:  [29]  ||  [30]
              ↓
Wave 7:  [31]
```

---

## Appendix: Autonomous Decisions Made During Execution

These decisions were made by Claude during overnight execution (Sam asleep) per the instruction "make a reasonable decision yourself and clearly document the decision point."

### D1: `SCIMRateLimit` config type — `float64` vs `int`

**Context:** Wave 1 defined `SCIMRateLimit int`, Wave 3 Lane A defined `SCIMRateLimit float64`.
**Decision:** Kept `float64` because `golang.org/x/time/rate.Limit` is typed `float64`. Using `int` would require a cast at every usage site.
**Risk:** None — both parse from the same env var, and the default `50` works for both types.

### D2: `withBypassTx` for SCIM group methods without `orgID` parameter

**Context:** Wave 2 Lane B noted that `GetSCIMGroup(id)`, `DeleteSCIMGroup(id)`, and similar methods don't take `orgID` as a parameter, making `withOrgTx` impossible.
**Decision:** Used `withBypassTx` for these methods, matching the existing `GetSSOConnectionByID` pattern. RLS still protects at the DB level since queries filter by `id` (UUID PK).
**Risk:** Low — the SCIM auth middleware verifies org ownership before these methods are called.

### D3: `writeSCIMError` duplicate resolution

**Context:** Wave 3 Lane A (middleware_scim.go) and Lane C (scim_types.go) independently implemented `writeSCIMError`.
**Decision:** Kept the scim_types.go version (canonical location for SCIM response helpers). Removed the duplicate from middleware_scim.go.
**Risk:** None — both implementations were identical.

### D4: Wave 6 worktree isolation failure

**Context:** Wave 6 agents were launched in worktrees that branched from `origin/dev`, which only had Wave 1 code. Waves 2-5 were on local `dev` but not pushed.
**Decision:** After Sam pushed dev to origin, relaunched the E2E test agent without worktree isolation (directly on dev). Handled Task 30 (audit verification) directly as orchestrator.
**Risk:** Non-worktree agents can't be rolled back as cleanly, but test-only changes are safe.

### D5: Suppressed audit entries for exempt users

**Context:** Wave 6 Lane B added `scimAuditLog` calls at exempt-user skip points with `metadata: {"source": "scim", "suppressed": true, "reason": "scim_exempt"}`. This wasn't in the original plan.
**Decision:** Accepted — provides audit trail visibility for suppressed operations, which is valuable for compliance. Design doc §2 already specified this metadata pattern.
**Risk:** None — purely additive audit entries.
