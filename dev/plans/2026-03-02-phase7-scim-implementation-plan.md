# Phase 7: SCIM 2.0 Provisioning — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement SCIM 2.0 user and group provisioning so enterprise IdPs (Microsoft Entra ID, Okta) can automatically manage CVErt Ops org membership, roles, and notification groups.

**Architecture:** SCIM endpoints are mounted as a raw `http.Handler` via `marcelom97/scimgateway` — outside huma's OpenAPI spec. A custom `requireSCIMAuth` middleware authenticates SCIM bearer tokens (separate from API keys/JWTs). The scimgateway plugin interface receives typed Go structs and returns typed Go structs — no HTTP handling in our code. Admin management endpoints (SCIM config CRUD, group mapping) use the standard chi handler pattern with `RequireOrgRole` + `requireEnterpriseTier`. User deactivation (`org_members.deactivated_at`) is a general feature, not SCIM-exclusive.

**Tech Stack:** Go 1.26, `marcelom97/scimgateway` v1.0.0, chi, sqlc, testcontainers-go

**Design doc:** `dev/plans/2026-03-01-phase7-scim-provisioning-design.md`

**Prerequisites:** Phase 5D complete (SSO — `sso_connections` table, tier gating, audit log).

**Context for subagents:**
- Chi handlers use `http.Error(w, msg, status)` + `return`, NOT huma error returns
- Transaction helpers: `withBypassTx` for auth lookups and global-table writes, `withOrgTx` for org-scoped queries from handlers
- Integration tests use `testutil.NewTestDB(t)` with testcontainers Postgres — NOT Docker Compose
- RLS isolation tests MUST use `s.AppStore` (NOBYPASSRLS) — `s.Store` (superuser) bypasses RLS
- TDD is mandatory: RED → verify fail → GREEN → verify pass → refactor → commit
- Run `sqlc generate` after any `.sql` file changes, before `go build`
- Run `golangci-lint run` before committing
- `requireEnterpriseTier(w, r)` is the existing enterprise gate helper (returns false + writes HTTP error)
- SCIM error format is RFC 7644 §3.12 JSON (NOT RFC 9457 Problem Details)
- Pointer types for PATCH fields (`*bool`, `*string`) — see pitfalls §1.11
- SCIM bearer tokens are sha256-hashed, compared via `subtle.ConstantTimeCompare` — same security pattern as API keys
- Never hold open DB tx during outbound HTTP; use `context.WithoutCancel(r.Context())` for background goroutines
- Every migration file with `CREATE INDEX CONCURRENTLY` needs `-- migrate:no-transaction` as FIRST line
- Every org-scoped table: denormalized `org_id` + BTREE index + ENABLE/FORCE RLS + dual-escape policy
- No semicolons in SQL comments (pitfalls §2.16 — breaks golang-migrate statement splitting)

---

## Task 1: Add `go get marcelom97/scimgateway`

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

**Step 1: Add the dependency**

Run:
```bash
cd /c/Users/Sam/Code/CVErt-Ops && go get github.com/marcelom97/scimgateway@v1.0.0
```

**Step 2: Verify import resolves**

Create a temporary file to verify the import works:
```bash
echo 'package main; import _ "github.com/marcelom97/scimgateway"' > /tmp/scimcheck.go && go build /tmp/scimcheck.go && rm /tmp/scimcheck.go
```

If the library's module path or version differs from what's documented, adjust accordingly. The library was released Feb 2026 — verify the exact import path from `go.dev`.

**Step 3: Tidy**

Run:
```bash
go mod tidy
```

**Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "deps: add marcelom97/scimgateway v1.0.0 for SCIM provisioning"
```

---

## Task 2: Migration — `org_members` deactivation + SCIM exemption columns

User deactivation is a general feature (not SCIM-exclusive). Admin-settable via member PATCH. `RequireOrgRole` middleware will check `deactivated_at IS NULL`. This migration adds the columns first so subsequent tasks can use them.

**Files:**
- Create: `migrations/000029_org_members_deactivation.up.sql`
- Create: `migrations/000029_org_members_deactivation.down.sql`

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
git add migrations/000029_* internal/store/generated/
git commit -m "migration(029): add org_members.deactivated_at + scim_exempt columns"
```

---

## Task 3: Migration — `group_members.scim_managed` column

Tracks whether a notification group membership was SCIM-synced. SCIM removal only deletes `scim_managed = true` rows.

**Files:**
- Create: `migrations/000030_group_members_scim_managed.up.sql`
- Create: `migrations/000030_group_members_scim_managed.down.sql`

**Step 1: Write the up migration**

```sql
-- ABOUTME: Adds scim_managed flag to group_members for SCIM notification sync tracking.
-- ABOUTME: SCIM removal only deletes scim_managed=true rows. Manual memberships preserved.

ALTER TABLE group_members ADD COLUMN IF NOT EXISTS scim_managed BOOLEAN NOT NULL DEFAULT false;
```

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
git add migrations/000030_* internal/store/generated/
git commit -m "migration(030): add group_members.scim_managed column"
```

---

## Task 4: Migration — `scim_configs` table

SCIM provisioning config, 1:1 with organizations (via `sso_connections`). Token stored separately from API keys (different auth semantics).

**Files:**
- Create: `migrations/000031_create_scim_configs.up.sql`
- Create: `migrations/000031_create_scim_configs.down.sql`

**Step 1: Write the up migration**

```sql
-- migrate:no-transaction
-- ABOUTME: SCIM provisioning config table (1:1 with orgs via sso_connections).
-- ABOUTME: Bearer token stored as sha256 hash. Separate from API key infrastructure.

CREATE TABLE IF NOT EXISTS scim_configs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    sso_connection_id UUID NOT NULL UNIQUE REFERENCES sso_connections(id) ON DELETE CASCADE,
    enabled           BOOLEAN NOT NULL DEFAULT false,
    token_hash        TEXT NOT NULL,
    token_prefix      TEXT NOT NULL,
    default_role      TEXT NOT NULL DEFAULT 'viewer'
                      CHECK (default_role IN ('viewer', 'member')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS scim_configs_token_hash_idx
    ON scim_configs (token_hash);

ALTER TABLE scim_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_configs FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON scim_configs
    USING (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid)
    WITH CHECK (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON scim_configs TO cvert_ops_app;
```

**Step 2: Write the down migration**

```sql
-- migrate:no-transaction

DROP POLICY IF EXISTS org_isolation ON scim_configs;
ALTER TABLE scim_configs DISABLE ROW LEVEL SECURITY;
DROP INDEX CONCURRENTLY IF EXISTS scim_configs_token_hash_idx;
DROP TABLE IF EXISTS scim_configs;
```

**Step 3: Run migration, regenerate sqlc, verify build**

```bash
go run ./cmd/cvert-ops migrate && sqlc generate && go build ./...
```

**Step 4: Commit**

```bash
git add migrations/000031_* internal/store/generated/
git commit -m "migration(031): create scim_configs table with RLS"
```

---

## Task 5: Migration — `scim_groups` + `scim_group_members` tables

IdP groups with optional role + notification group mappings. `scim_groups` references `organizations(id)` directly (NOT `scim_configs`) so group mappings survive SCIM config deletion.

**Files:**
- Create: `migrations/000032_create_scim_groups.up.sql`
- Create: `migrations/000032_create_scim_groups.down.sql`

**Step 1: Write the up migration**

```sql
-- migrate:no-transaction
-- ABOUTME: SCIM group and membership tables for IdP group sync.
-- ABOUTME: scim_groups references organizations directly (survives scim_config deletion).

CREATE TABLE IF NOT EXISTS scim_groups (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    external_id      TEXT,
    display_name     TEXT NOT NULL,
    mapped_role      TEXT CHECK (mapped_role IN ('viewer', 'member', 'admin')),
    mapped_group_id  UUID REFERENCES groups(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, display_name)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_groups_org_id_idx
    ON scim_groups (org_id);
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS scim_groups_org_external_id_idx
    ON scim_groups (org_id, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_groups_mapped_group_id_idx
    ON scim_groups (mapped_group_id);

ALTER TABLE scim_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_groups FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON scim_groups
    USING (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid)
    WITH CHECK (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON scim_groups TO cvert_ops_app;

-- SCIM group membership (denormalized org_id for RLS)
CREATE TABLE IF NOT EXISTS scim_group_members (
    scim_group_id UUID NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scim_group_id, user_id)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_group_members_org_id_idx
    ON scim_group_members (org_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_group_members_user_id_idx
    ON scim_group_members (user_id);

ALTER TABLE scim_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_group_members FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON scim_group_members
    USING (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid)
    WITH CHECK (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid);

GRANT SELECT, INSERT, DELETE ON scim_group_members TO cvert_ops_app;
```

**Step 2: Write the down migration**

```sql
-- migrate:no-transaction

DROP POLICY IF EXISTS org_isolation ON scim_group_members;
ALTER TABLE scim_group_members DISABLE ROW LEVEL SECURITY;
DROP INDEX CONCURRENTLY IF EXISTS scim_group_members_user_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS scim_group_members_org_id_idx;
DROP TABLE IF EXISTS scim_group_members;

DROP POLICY IF EXISTS org_isolation ON scim_groups;
ALTER TABLE scim_groups DISABLE ROW LEVEL SECURITY;
DROP INDEX CONCURRENTLY IF EXISTS scim_groups_mapped_group_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS scim_groups_org_external_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS scim_groups_org_id_idx;
DROP TABLE IF EXISTS scim_groups;
```

**Step 3: Run migration, regenerate sqlc, verify build**

```bash
go run ./cmd/cvert-ops migrate && sqlc generate && go build ./...
```

**Step 4: Commit**

```bash
git add migrations/000032_* internal/store/generated/
git commit -m "migration(032): create scim_groups + scim_group_members with RLS"
```

---

## Task 6: sqlc queries — SCIM config

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

-- name: UpdateSCIMConfig :exec
UPDATE scim_configs SET enabled = $2, default_role = $3, updated_at = now()
WHERE org_id = $1;

-- name: UpdateSCIMConfigToken :exec
UPDATE scim_configs SET token_hash = $2, token_prefix = $3, updated_at = now()
WHERE org_id = $1;

-- name: DeleteSCIMConfig :exec
DELETE FROM scim_configs WHERE org_id = $1;
```

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

## Task 7: sqlc queries — SCIM groups + members

**Files:**
- Create: `internal/store/queries/scim_groups.sql`
- Modify: `internal/store/generated/` (regenerated)

**Step 1: Write the sqlc queries**

```sql
-- ABOUTME: sqlc queries for SCIM group and membership management.
-- ABOUTME: All queries are org-scoped via RLS. scim_group_members denormalize org_id.

-- name: CreateSCIMGroup :one
INSERT INTO scim_groups (org_id, external_id, display_name)
VALUES ($1, $2, $3) RETURNING *;

-- name: GetSCIMGroupByID :one
SELECT * FROM scim_groups WHERE id = $1;

-- name: GetSCIMGroupByDisplayName :one
SELECT * FROM scim_groups WHERE org_id = $1 AND display_name = $2;

-- name: ListSCIMGroups :many
SELECT sg.*, COUNT(sgm.user_id)::int AS member_count
FROM scim_groups sg
LEFT JOIN scim_group_members sgm ON sgm.scim_group_id = sg.id
WHERE sg.org_id = $1
GROUP BY sg.id
ORDER BY sg.display_name;

-- name: UpdateSCIMGroup :exec
UPDATE scim_groups SET display_name = $2, external_id = $3, updated_at = now()
WHERE id = $1;

-- name: UpdateSCIMGroupMapping :exec
UPDATE scim_groups SET mapped_role = $2, mapped_group_id = $3, updated_at = now()
WHERE id = $1;

-- name: DeleteSCIMGroup :exec
DELETE FROM scim_groups WHERE id = $1;

-- name: AddSCIMGroupMember :exec
INSERT INTO scim_group_members (scim_group_id, user_id, org_id)
VALUES ($1, $2, $3)
ON CONFLICT (scim_group_id, user_id) DO NOTHING;

-- name: RemoveSCIMGroupMember :exec
DELETE FROM scim_group_members WHERE scim_group_id = $1 AND user_id = $2;

-- name: ListSCIMGroupMembers :many
SELECT user_id FROM scim_group_members WHERE scim_group_id = $1;

-- name: ListUserSCIMGroups :many
SELECT sg.* FROM scim_groups sg
JOIN scim_group_members sgm ON sgm.scim_group_id = sg.id
WHERE sgm.user_id = $1 AND sg.org_id = $2;

-- name: SetSCIMGroupMembers_Delete :exec
DELETE FROM scim_group_members WHERE scim_group_id = $1;

-- name: CountOtherSCIMGroupsWithSameMapping :one
SELECT COUNT(*)::int FROM scim_group_members sgm
JOIN scim_groups sg ON sgm.scim_group_id = sg.id
WHERE sgm.user_id = $1
  AND sg.mapped_group_id = $2
  AND sg.id != $3;
```

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

## Task 8: sqlc queries — org_members deactivation + member count

Update existing org queries for deactivation support.

**Files:**
- Modify: `internal/store/queries/org.sql`
- Modify: `internal/store/generated/` (regenerated)

**Step 1: Add new queries to org.sql**

Append these queries to the existing file:

```sql
-- name: DeactivateOrgMember :exec
UPDATE org_members SET deactivated_at = now(), updated_at = now()
WHERE org_id = $1 AND user_id = $2;

-- name: ReactivateOrgMember :exec
UPDATE org_members SET deactivated_at = NULL, updated_at = now()
WHERE org_id = $1 AND user_id = $2;

-- name: GetOrgMember :one
SELECT om.*, u.email, u.display_name FROM org_members om
JOIN users u ON u.id = om.user_id
WHERE om.org_id = $1 AND om.user_id = $2;

-- name: CountActiveOrgMembers :one
SELECT COUNT(*)::int FROM org_members
WHERE org_id = $1 AND deactivated_at IS NULL;

-- name: CountActiveOrgOwners :one
SELECT COUNT(*)::int FROM org_members
WHERE org_id = $1 AND role = 'owner' AND deactivated_at IS NULL;

-- name: UpdateOrgMemberDeactivation :exec
UPDATE org_members SET deactivated_at = $3, updated_at = now()
WHERE org_id = $1 AND user_id = $2;

-- name: UpdateOrgMemberSCIMExempt :exec
UPDATE org_members SET scim_exempt = $3, updated_at = now()
WHERE org_id = $1 AND user_id = $2;
```

**Step 2: Regenerate sqlc and verify build**

```bash
sqlc generate && go build ./...
```

**Step 3: Commit**

```bash
git add internal/store/queries/org.sql internal/store/generated/
git commit -m "sqlc: add deactivation, member count, and SCIM-exempt queries"
```

---

## Task 9: Store layer — SCIM config methods

Wrap sqlc-generated queries in proper transaction helpers.

**Files:**
- Create: `internal/store/scim_config.go`
- Create: `internal/store/scim_config_test.go`

**Step 1: Write failing tests**

Write tests for SCIM config CRUD using `testutil.NewTestDB(t)`. Test cases:
- `TestCreateSCIMConfig` — creates config, verifies all fields returned
- `TestCreateSCIMConfig_Duplicate` — second create returns uniqueness error
- `TestGetSCIMConfigByTokenHash` — lookup by token hash (uses `withBypassTx`)
- `TestGetSCIMConfigByOrgID` — org-scoped lookup
- `TestUpdateSCIMConfig` — update enabled + default_role
- `TestUpdateSCIMConfigToken` — token rotation
- `TestDeleteSCIMConfig` — delete + verify gone
- `TestSCIMConfig_RLSIsolation` — config from org A not visible to org B via `AppStore`

Key test patterns:
- Setup: create org + SSO connection (prerequisites) via superuser store
- SCIM config CRUD via `AppStore` for RLS verification
- Token hash lookup via `withBypassTx` (pre-org-context, like the auth middleware will use)

**Step 2: Run tests — verify they fail**

```bash
go test ./internal/store/ -run TestSCIMConfig -v -count=1
```

Expected: compilation errors (methods don't exist yet)

**Step 3: Implement store methods**

```go
// ABOUTME: Store methods for SCIM provisioning config CRUD.
// ABOUTME: Token lookup uses withBypassTx (auth middleware context). Config CRUD uses withOrgTx.
package store

// CreateSCIMConfig creates a SCIM config for an org.
// Must be called within org context (withOrgTx).
func (s *Store) CreateSCIMConfig(ctx context.Context, orgID, ssoConnID uuid.UUID, enabled bool, tokenHash, tokenPrefix, defaultRole string) (*generated.ScimConfig, error) {
    var row generated.ScimConfig
    err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
        var err error
        row, err = q.CreateSCIMConfig(ctx, generated.CreateSCIMConfigParams{
            OrgID:           orgID,
            SsoConnectionID: ssoConnID,
            Enabled:         enabled,
            TokenHash:       tokenHash,
            TokenPrefix:     tokenPrefix,
            DefaultRole:     defaultRole,
        })
        return err
    })
    if err != nil {
        return nil, fmt.Errorf("create scim config: %w", err)
    }
    return &row, nil
}

// LookupSCIMConfigByTokenHash finds a SCIM config by bearer token hash.
// Uses withBypassTx — called from SCIM auth middleware (pre-org-context).
func (s *Store) LookupSCIMConfigByTokenHash(ctx context.Context, tokenHash string) (*generated.ScimConfig, error) {
    var row generated.ScimConfig
    err := s.withBypassTx(ctx, func(q *generated.Queries) error {
        var err error
        row, err = q.GetSCIMConfigByTokenHash(ctx, tokenHash)
        return err
    })
    if errors.Is(err, sql.ErrNoRows) {
        return nil, nil
    }
    if err != nil {
        return nil, fmt.Errorf("lookup scim config by token: %w", err)
    }
    return &row, nil
}

// GetSCIMConfig gets the SCIM config for an org. Returns nil if none exists.
func (s *Store) GetSCIMConfig(ctx context.Context, orgID uuid.UUID) (*generated.ScimConfig, error) {
    var row generated.ScimConfig
    err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
        var err error
        row, err = q.GetSCIMConfigByOrgID(ctx, orgID)
        return err
    })
    if errors.Is(err, sql.ErrNoRows) {
        return nil, nil
    }
    if err != nil {
        return nil, fmt.Errorf("get scim config: %w", err)
    }
    return &row, nil
}

// UpdateSCIMConfig updates enabled + default_role.
func (s *Store) UpdateSCIMConfig(ctx context.Context, orgID uuid.UUID, enabled bool, defaultRole string) error {
    return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
        return q.UpdateSCIMConfig(ctx, generated.UpdateSCIMConfigParams{
            OrgID:       orgID,
            Enabled:     enabled,
            DefaultRole: defaultRole,
        })
    })
}

// RotateSCIMToken replaces the token hash and prefix.
func (s *Store) RotateSCIMToken(ctx context.Context, orgID uuid.UUID, tokenHash, tokenPrefix string) error {
    return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
        return q.UpdateSCIMConfigToken(ctx, generated.UpdateSCIMConfigTokenParams{
            OrgID:       orgID,
            TokenHash:   tokenHash,
            TokenPrefix: tokenPrefix,
        })
    })
}

// DeleteSCIMConfig deletes the SCIM config for an org.
func (s *Store) DeleteSCIMConfig(ctx context.Context, orgID uuid.UUID) error {
    return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
        return q.DeleteSCIMConfig(ctx, orgID)
    })
}
```

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

## Task 10: Store layer — SCIM group methods

**Files:**
- Create: `internal/store/scim_groups.go`
- Create: `internal/store/scim_groups_test.go`

Follow the same TDD pattern as Task 9. Key methods:

- `CreateSCIMGroup(ctx, orgID, externalID, displayName)` — uses `withOrgTx`
- `GetSCIMGroup(ctx, orgID, id)` — uses `withOrgTx`
- `ListSCIMGroups(ctx, orgID)` — uses `withOrgTx`, returns member counts
- `UpdateSCIMGroup(ctx, orgID, id, displayName, externalID)` — uses `withOrgTx`
- `UpdateSCIMGroupMapping(ctx, orgID, id, mappedRole, mappedGroupID)` — uses `withOrgTx`
- `DeleteSCIMGroup(ctx, orgID, id)` — uses `withOrgTx`
- `AddSCIMGroupMember(ctx, orgID, scimGroupID, userID)` — uses `withOrgTx`
- `RemoveSCIMGroupMember(ctx, orgID, scimGroupID, userID)` — uses `withOrgTx`
- `ListSCIMGroupMembers(ctx, orgID, scimGroupID)` — uses `withOrgTx`
- `ListUserSCIMGroups(ctx, orgID, userID)` — uses `withOrgTx`
- `CountOtherSCIMGroupsWithSameMapping(ctx, orgID, userID, mappedGroupID, excludeGroupID)` — uses `withOrgTx`

**Test cases must include RLS isolation** — create groups in org A and org B, verify AppStore for org A cannot see org B's groups.

TDD: write failing tests → implement → verify pass → lint → commit.

```bash
git commit -m "feat(store): SCIM group and membership methods with RLS"
```

---

## Task 11: Store layer — deactivation + member count methods

**Files:**
- Modify: `internal/store/org.go` — add deactivation methods
- Create: `internal/store/org_deactivation_test.go`

Key methods to add to `org.go`:

- `DeactivateOrgMember(ctx, orgID, userID)` — uses `withOrgTx`
- `ReactivateOrgMember(ctx, orgID, userID)` — uses `withOrgTx`
- `GetOrgMemberFull(ctx, orgID, userID)` — returns `org_members` joined with `users` (email, display_name, deactivated_at, scim_exempt)
- `CountActiveOrgMembers(ctx, orgID)` — uses `withOrgTx` for tier member limit checks
- `CountActiveOrgOwners(ctx, orgID)` — uses `withOrgTx` for sole-owner protection
- `UpdateOrgMemberSCIMExempt(ctx, orgID, userID, exempt bool)` — uses `withOrgTx`

**Test cases:**
- Deactivate → verify `deactivated_at` is set
- Reactivate → verify `deactivated_at` is NULL
- CountActiveOrgMembers excludes deactivated
- CountActiveOrgOwners — sole-owner scenarios
- scim_exempt flag update
- RLS isolation for all methods

TDD: write failing tests → implement → verify pass → lint → commit.

```bash
git commit -m "feat(store): org member deactivation + count methods"
```

---

## Task 12: SCIM token generation helper

**Files:**
- Create: `internal/auth/scimtoken.go`
- Create: `internal/auth/scimtoken_test.go`

**Step 1: Write failing tests**

```go
func TestGenerateSCIMToken(t *testing.T) {
    raw, hash, prefix, err := auth.GenerateSCIMToken()
    // Verify: no error, raw starts with "cvert_scim_", hash is sha256 hex,
    // prefix is first 8 chars of raw, raw is 32 random bytes hex-encoded after prefix
}

func TestHashSCIMToken(t *testing.T) {
    raw := "cvert_scim_abcdef1234567890abcdef1234567890abcdef1234567890abcdef12"
    hash := auth.HashSCIMToken(raw)
    // Verify: hash is deterministic sha256 hex
}
```

**Step 2: Run tests — verify fail**

**Step 3: Implement**

```go
// ABOUTME: SCIM bearer token generation and hashing.
// ABOUTME: Tokens use "cvert_scim_" prefix (distinct from API key "cvo_" prefix).
package auth

const SCIMTokenPrefix = "cvert_scim_"

// GenerateSCIMToken creates a new SCIM bearer token.
// Returns raw token (shown once), sha256 hex hash (stored), and display prefix (first 8 chars).
func GenerateSCIMToken() (rawToken, tokenHash, tokenPrefix string, err error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", "", "", fmt.Errorf("generate scim token: %w", err)
    }
    rawToken = SCIMTokenPrefix + hex.EncodeToString(b)
    tokenHash = HashSCIMToken(rawToken)
    tokenPrefix = rawToken[:8]
    return rawToken, tokenHash, tokenPrefix, nil
}

// HashSCIMToken returns the sha256 hex hash of a raw SCIM token.
func HashSCIMToken(rawToken string) string {
    sum := sha256.Sum256([]byte(rawToken))
    return hex.EncodeToString(sum[:])
}
```

**Step 4: Run tests — verify pass**

**Step 5: Lint + commit**

```bash
git commit -m "feat(auth): SCIM bearer token generation + hashing"
```

---

## Task 13: RequireOrgRole middleware — deactivation check

Deactivated members should get 403. This is a modification to existing middleware.

**Files:**
- Modify: `internal/api/middleware_rbac.go`
- Modify: `internal/api/middleware_rbac_test.go` (or create if needed)

**Step 1: Write failing test**

Test that a deactivated org member gets 403 with message "Your membership in this organization has been deactivated."

**Step 2: Run test — verify fail**

**Step 3: Modify RequireOrgRole**

After the role lookup (`GetOrgMemberRole`), the middleware needs to also check deactivation status. There are two approaches:

**Option A (recommended):** Change `GetOrgMemberRole` query to also return `deactivated_at`, or add a new query `GetOrgMemberStatus` that returns `role` + `deactivated_at`. Then check:

```go
if member.DeactivatedAt.Valid {
    http.Error(w, "Your membership in this organization has been deactivated.", http.StatusForbidden)
    return
}
```

**Option B:** Use the existing `GetOrgMember` (from Task 8/11) which returns full member data including `deactivated_at`.

Choose whichever integrates cleanest with the existing middleware. The sqlc query may need updating — if so, regenerate sqlc.

**Step 4: Run tests — verify pass**

**Step 5: Lint + commit**

```bash
git commit -m "feat(api): deactivated org members get 403 in RequireOrgRole"
```

---

## Task 14: Member PATCH — deactivation + scim_exempt fields

Extend the existing member PATCH endpoint to support `active` (bool) and `scim_exempt` (bool) fields.

**Files:**
- Modify: `internal/api/orgs.go` (or the member handler file)
- Modify: corresponding test file

**Step 1: Write failing tests**

Test cases:
- `TestPatchMember_Deactivate` — PATCH `{"active": false}` sets `deactivated_at`
- `TestPatchMember_Reactivate` — PATCH `{"active": true}` clears `deactivated_at`
- `TestPatchMember_SoleOwnerProtection` — cannot deactivate sole active owner → 400
- `TestPatchMember_SCIMExempt` — PATCH `{"scim_exempt": true}` sets flag
- `TestPatchMember_RequiresAdmin` — viewer/member get 403

**Step 2: Run tests — verify fail**

**Step 3: Implement**

Add `Active *bool` and `SCIMExempt *bool` to the patch member request struct. In the handler:
- If `Active != nil && *Active == false`: check sole-owner → `CountActiveOrgOwners`, if sole owner → 400. Otherwise deactivate.
- If `Active != nil && *Active == true`: reactivate.
- If `SCIMExempt != nil`: update flag.
- Audit log the changes.

**Step 4: Run tests — verify pass**

**Step 5: Also update `GET /members` response** to include `active`, `deactivated_at`, `scim_exempt` fields. Add test.

**Step 6: Lint + commit**

```bash
git commit -m "feat(api): member PATCH supports active + scim_exempt fields"
```

---

## Task 15: SCIM auth middleware (`requireSCIMAuth`)

Separate auth middleware for SCIM endpoints. No human actor, no `ctxUserID`, no RBAC role. Machine-to-machine provisioning.

**Files:**
- Create: `internal/api/middleware_scim.go`
- Create: `internal/api/middleware_scim_test.go`

**Step 1: Write failing tests**

Test cases (from design §7):
- `TestSCIMAuth_ValidToken` — bearer token accepted, org_id + scim_config_id in context
- `TestSCIMAuth_InvalidToken` — wrong token → 401
- `TestSCIMAuth_OrgMismatch` — token for org A used on org B endpoint → 401
- `TestSCIMAuth_Disabled` — disabled config → 403
- `TestSCIMAuth_MissingHeader` — no Authorization header → 401
- `TestSCIMAuth_ErrorFormat` — auth failures return SCIM error JSON, not RFC 9457

**Step 2: Run tests — verify fail**

**Step 3: Implement**

```go
// ABOUTME: SCIM bearer token authentication middleware.
// ABOUTME: Mounted on /scim/v2/* only. Separate from RequireAuthenticated (no human actor).

// New context keys for SCIM
const (
    ctxSCIMConfigID contextKey = iota + 100 // uuid.UUID — SCIM config ID
    // ctxOrgID is reused from the standard context (set by this middleware for SCIM routes)
)

func (srv *Server) requireSCIMAuth(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // 1. Extract org_id from URL path
        orgIDStr := chi.URLParam(r, "org_id")
        orgID, err := uuid.Parse(orgIDStr)
        if err != nil {
            writeSCIMError(w, http.StatusBadRequest, "", "invalid org_id")
            return
        }

        // 2. Extract Bearer token
        authHeader := r.Header.Get("Authorization")
        if !strings.HasPrefix(authHeader, "Bearer ") {
            writeSCIMError(w, http.StatusUnauthorized, "", "missing or invalid Authorization header")
            return
        }
        rawToken := strings.TrimPrefix(authHeader, "Bearer ")

        // 3. Hash token
        tokenHash := auth.HashSCIMToken(rawToken)

        // 4. Lookup config (withBypassTx — pre-context)
        config, err := srv.store.LookupSCIMConfigByTokenHash(r.Context(), tokenHash)
        if err != nil {
            slog.ErrorContext(r.Context(), "scim auth: lookup", "error", err)
            writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
            return
        }

        // 5. Constant-time compare (defense-in-depth against timing)
        if config == nil || subtle.ConstantTimeCompare([]byte(config.TokenHash), []byte(tokenHash)) != 1 {
            slog.WarnContext(r.Context(), "scim auth failed", "org_id", orgID, "reason", "invalid_token")
            writeSCIMError(w, http.StatusUnauthorized, "", "invalid or missing bearer token")
            return
        }

        // 6. Verify org_id match (defense-in-depth)
        if config.OrgID != orgID {
            slog.WarnContext(r.Context(), "scim auth failed", "org_id", orgID, "reason", "org_mismatch")
            writeSCIMError(w, http.StatusUnauthorized, "", "invalid or missing bearer token")
            return
        }

        // 7. Check enabled
        if !config.Enabled {
            slog.WarnContext(r.Context(), "scim auth failed", "org_id", orgID, "reason", "disabled")
            writeSCIMError(w, http.StatusForbidden, "", "SCIM provisioning is disabled for this organization")
            return
        }

        // 8. Inject context
        ctx := context.WithValue(r.Context(), ctxOrgID, orgID)
        ctx = context.WithValue(ctx, ctxSCIMConfigID, config.ID)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// writeSCIMError writes a SCIM-formatted error response (RFC 7644 §3.12).
func writeSCIMError(w http.ResponseWriter, status int, scimType, detail string) {
    w.Header().Set("Content-Type", "application/scim+json")
    w.WriteHeader(status)
    resp := map[string]any{
        "schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
        "status":  fmt.Sprintf("%d", status),
        "detail":  detail,
    }
    if scimType != "" {
        resp["scimType"] = scimType
    }
    json.NewEncoder(w).Encode(resp)
}
```

**Step 4: Run tests — verify pass**

**Step 5: Lint + commit**

```bash
git commit -m "feat(api): SCIM bearer token auth middleware with SCIM error format"
```

---

## Task 16: SCIM rate limiter

Separate rate limiter for SCIM: 50 req/sec per org. Not shared with per-org API rate limiter.

**Files:**
- Modify: `internal/api/middleware_scim.go` (or create `internal/api/scim_ratelimit.go`)
- Add tests

**Step 1: Write failing test**

- `TestSCIMRateLimit_IndependentOfOrgRL` — SCIM rate limit is separate from API rate limit

**Step 2: Implement**

Create a dedicated `scimRateLimiter` (same pattern as `orgRateLimiter`) with a fixed 50 req/sec burst. Mount it after `requireSCIMAuth`. Add the limiter as a field on `Server`.

**Step 3: Run tests — verify pass**

**Step 4: Lint + commit**

```bash
git commit -m "feat(api): dedicated SCIM rate limiter (50 req/sec per org)"
```

---

## Task 17: Role recomputation function

Shared function called from SCIM operations and admin mapping endpoints.

**Files:**
- Create: `internal/api/scim_roles.go`
- Create: `internal/api/scim_roles_test.go`

**Step 1: Write failing tests**

Test cases (from design §7):
- `TestRoleRecompute_SingleGroup` — user gets mapped_role
- `TestRoleRecompute_MultipleGroups_HighestWins` — admin > member > viewer
- `TestRoleRecompute_NoMappedGroups` — falls back to scim_configs.default_role
- `TestRoleRecompute_NeverSetsOwner` — owner role never assigned by SCIM
- `TestRoleRecompute_SCIMExempt_Skipped` — exempt user's role unchanged
- `TestRoleRecompute_OwnerNotDowngraded` — existing owner preserved

**Step 2: Run tests — verify fail**

**Step 3: Implement**

```go
// ABOUTME: Role recomputation from SCIM group mappings.
// ABOUTME: Called on group membership change and group mapping change. Apply-on-write.

// recomputeRole calculates the effective role for a user based on their SCIM group
// memberships and writes it to org_members. Skips owners and exempt users.
func (srv *Server) recomputeRole(ctx context.Context, orgID, userID uuid.UUID, defaultRole string) error {
    // 1. Get current org_members row
    member, err := srv.store.GetOrgMemberFull(ctx, orgID, userID)
    if err != nil {
        return fmt.Errorf("get org member: %w", err)
    }
    if member == nil {
        return nil // not a member (edge case)
    }

    // Skip owners — owner is always manual
    if member.Role == "owner" {
        return nil
    }

    // Skip exempt users
    if member.ScimExempt {
        return nil
    }

    // 2. Load all SCIM groups the user belongs to
    groups, err := srv.store.ListUserSCIMGroups(ctx, orgID, userID)
    if err != nil {
        return fmt.Errorf("list user scim groups: %w", err)
    }

    // 3. Collect mapped roles, find highest
    effectiveRole := defaultRole
    roleRank := map[string]int{"viewer": 1, "member": 2, "admin": 3}
    for _, g := range groups {
        if g.MappedRole.Valid && roleRank[g.MappedRole.String] > roleRank[effectiveRole] {
            effectiveRole = g.MappedRole.String
        }
    }

    // 4. Update if changed
    if effectiveRole != member.Role {
        oldRole := member.Role
        if err := srv.store.UpdateOrgMemberRole(ctx, orgID, userID, effectiveRole); err != nil {
            return fmt.Errorf("update member role: %w", err)
        }
        slog.InfoContext(ctx, "role recomputed from SCIM groups",
            "org_id", orgID, "user_id", userID, "old_role", oldRole, "new_role", effectiveRole)
    }

    return nil
}
```

**Step 4: Run tests — verify pass**

**Step 5: Lint + commit**

```bash
git commit -m "feat(api): SCIM role recomputation from group mappings"
```

---

## Task 18: Notification group sync function

Shared function for syncing SCIM group membership to notification groups.

**Files:**
- Create: `internal/api/scim_notif_sync.go`
- Create: `internal/api/scim_notif_sync_test.go`

**Step 1: Write failing tests**

Test cases (from design §7):
- `TestNotifSync_Add_NewMember` — inserts with scim_managed=true
- `TestNotifSync_Add_AlreadyManualMember` — no change
- `TestNotifSync_Remove_SCIMManaged` — deletes scim_managed=true row
- `TestNotifSync_Remove_ManualMember` — no-op
- `TestNotifSync_Remove_MultiMapping` — keeps if other SCIM group maps same
- `TestNotifSync_GroupDelete_NoRemoval` — SCIM group delete does not remove notification members
- `TestNotifSync_ExemptUser_Skipped` — exempt user not synced

**Step 2: Implement**

Two functions:
- `syncNotifGroupAdd(ctx, orgID, userID, mappedGroupID, scimGroupID)` — adds user to notification group with `scim_managed=true` if not already present
- `syncNotifGroupRemove(ctx, orgID, userID, mappedGroupID, scimGroupID)` — removes only if `scim_managed=true` AND no other SCIM group with same mapping

These require new sqlc queries for `group_members` that check `scim_managed`. Add them to `internal/store/queries/groups.sql`:

```sql
-- name: AddGroupMemberSCIMManaged :exec
INSERT INTO group_members (group_id, user_id, org_id, scim_managed)
VALUES ($1, $2, $3, true)
ON CONFLICT (group_id, user_id) DO NOTHING;

-- name: RemoveSCIMManagedGroupMember :exec
DELETE FROM group_members
WHERE group_id = $1 AND user_id = $2 AND scim_managed = true;

-- name: IsGroupMember :one
SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2) AS is_member;
```

**Step 3: Run tests — verify pass**

**Step 4: Lint + commit**

```bash
git commit -m "feat(api): notification group sync from SCIM group mappings"
```

---

## Task 19: scimgateway plugin — User operations

The core SCIM plugin implementing `plugin.Plugin` for user CRUD.

**Files:**
- Create: `internal/scim/plugin.go` — Plugin struct + Name() + constructor
- Create: `internal/scim/users.go` — User operation implementations
- Create: `internal/scim/users_test.go`

**Step 1: Write failing tests**

Integration tests using `testutil.NewTestDB(t)`. Test cases (from design §7):

User provisioning:
- `TestSCIMCreateUser_NewUser` — creates user + identity + membership (201)
- `TestSCIMCreateUser_ExistingByExternalId_Active` — returns existing (200, idempotent)
- `TestSCIMCreateUser_ExistingByExternalId_Deactivated` — reactivates (200)
- `TestSCIMCreateUser_ExistingByEmail_OrgMember` — links SCIM identity (200)
- `TestSCIMCreateUser_ExistingByEmail_NotMember` — links + creates membership (201)
- `TestSCIMCreateUser_TierMemberLimit` — exceeds → 403
- `TestSCIMCreateUser_SCIMExempt_Deactivated` — exempt not reactivated (200)
- `TestSCIMCreateUser_DefaultRole` — new user gets default_role

User read/list:
- `TestSCIMGetUser_Found` — correct attributes
- `TestSCIMGetUser_NotFound` — 404
- `TestSCIMListUsers_FilterByUserName` — eq filter
- `TestSCIMListUsers_FilterByExternalId` — eq filter
- `TestSCIMListUsers_EmptyResult` — 200 with empty Resources[]

User update:
- `TestSCIMReplaceUser_Success` — PUT updates all
- `TestSCIMReplaceUser_SCIMExempt` — returns current, no mod
- `TestSCIMReplaceUser_SoleOwner` — deactivate sole owner → 400
- `TestSCIMPatchUser_ReplaceActive` — PATCH active=false
- `TestSCIMPatchUser_CaseInsensitiveOp` — "Replace" and "replace"
- `TestSCIMPatchUser_StringBoolean` — "False" coerced

User deprovision:
- `TestSCIMDeleteUser_Success` — sets deactivated_at (204)
- `TestSCIMDeleteUser_NotFound` — 204 (idempotent)
- `TestSCIMDeleteUser_SCIMExempt` — 204, no modification

**Step 2: Implement plugin struct**

```go
// ABOUTME: SCIM 2.0 plugin implementing marcelom97/scimgateway plugin.Plugin interface.
// ABOUTME: Bridges IdP provisioning to CVErt Ops user/group management via store layer.
package scim

// Plugin implements the scimgateway plugin.Plugin interface for CVErt Ops.
type Plugin struct {
    store       *store.Store
    auditWriter *audit.Writer
    server      *api.Server // for role recomputation + notif sync (or extract those as standalone funcs)
}
```

The plugin receives `org_id` and `scim_config_id` from the request context (set by `requireSCIMAuth`).

**Key implementation detail:** The scimgateway plugin methods receive a `context.Context`. The SCIM auth middleware injects `ctxOrgID` and `ctxSCIMConfigID` into this context. The plugin extracts them:

```go
func orgIDFromCtx(ctx context.Context) uuid.UUID {
    return ctx.Value(api.CtxOrgID).(uuid.UUID)
}
func scimConfigIDFromCtx(ctx context.Context) uuid.UUID {
    return ctx.Value(api.CtxSCIMConfigID).(uuid.UUID)
}
```

**Identity matching** (POST /Users):
1. Check `user_identities` for `provider='scim:{config_id}'`, `provider_user_id=externalId`
2. If not found, check `users` by email
3. If not found, create new user

Use `withBypassTx` for global-table writes (`users`, `user_identities`), `withOrgTx` for org-scoped writes (`org_members`). See design §3.3 transaction note.

Return `*scim.SCIMError` for error conditions (the library maps these to proper SCIM JSON responses).

**Step 3: Run tests — verify pass**

**Step 4: Lint + commit**

```bash
git commit -m "feat(scim): user provisioning plugin (create, get, list, patch, put, delete)"
```

---

## Task 20: scimgateway plugin — Group operations

**Files:**
- Create: `internal/scim/groups.go`
- Create: `internal/scim/groups_test.go`

**Step 1: Write failing tests**

Test cases (from design §7):
- `TestSCIMCreateGroup_Basic` — creates group (201)
- `TestSCIMCreateGroup_WithMembers` — creates + memberships, roles recomputed
- `TestSCIMGetGroup_WithMembers` — returns group with member list
- `TestSCIMListGroups_FilterByDisplayName` — eq filter
- `TestSCIMPatchGroup_AddMembers` — adds members, recomputes roles
- `TestSCIMPatchGroup_RemoveMembers` — removes, recomputes
- `TestSCIMPatchGroup_EntraIdMemberRemoveFormat` — value array format
- `TestSCIMReplaceGroup_MemberDiff` — correctly diffs membership
- `TestSCIMDeleteGroup_CascadesMembers` — scim_group_members deleted
- `TestSCIMDeleteGroup_RecomputesRoles` — affected users' roles recomputed

**Step 2: Implement**

Group operations are simpler than user operations — direct CRUD on `scim_groups` and `scim_group_members`. Each membership change triggers `recomputeRole` + `syncNotifGroup` for the affected user (if not exempt and if mappings are configured).

**PATCH member removal must handle both formats** (design §3.4, §4.2):
- Standard: `op: "remove", path: "members[value eq \"user-uuid\"]"` — parse user ID from filter expression
- Entra ID: `op: "remove", path: "members", value: [{value: "user-uuid"}]` — parse user IDs from value array

The scimgateway library parses `PatchOperation.Value` as `any`. Type-assert to handle both cases.

**Step 3: Run tests — verify pass**

**Step 4: Lint + commit**

```bash
git commit -m "feat(scim): group provisioning plugin (create, get, list, patch, put, delete)"
```

---

## Task 21: Mount SCIM gateway as http.Handler

Wire the scimgateway into the chi router.

**Files:**
- Modify: `internal/api/server.go` — add SCIM route mount
- Create: `internal/api/scim_mount.go` — gateway initialization
- Create: `internal/api/scim_mount_test.go`

**Step 1: Write failing test**

Test that SCIM endpoints are accessible at the expected paths (e.g., `GET /api/v1/orgs/{org_id}/scim/v2/Users` returns 401 without auth, not 404).

**Step 2: Implement gateway mount**

```go
// ABOUTME: Initializes and mounts the scimgateway http.Handler on the chi router.
// ABOUTME: SCIM routes live outside huma - raw http.Handler via scimgateway.

func (srv *Server) initSCIMGateway() (http.Handler, error) {
    p := scim.NewPlugin(srv.store, srv.auditWriter, /* role recompute + notif sync deps */)

    cfg := scimgateway.Config{
        // Configure as needed
    }
    gw := scimgateway.New(cfg)
    gw.SetLogger(slog.Default())
    gw.RegisterPlugin(p)
    if err := gw.Initialize(); err != nil {
        return nil, fmt.Errorf("scim gateway init: %w", err)
    }
    return gw.Handler()
}
```

In `Handler()` route setup, after the SSO routes:

```go
// SCIM provisioning (scimgateway http.Handler, separate auth)
r.Route("/scim/v2", func(r chi.Router) {
    r.Use(srv.requireSCIMAuth)
    r.Use(srv.scimRateLimitMiddleware)
    // Mount scimgateway handler
    // The plugin is registered with name "v2", so scimgateway routes are:
    //   /{plugin}/Users, /{plugin}/Groups, etc.
    // We need to strip the prefix and let scimgateway handle routing.
    r.Handle("/*", scimHandler)
})
```

**Important:** The exact mounting pattern depends on how scimgateway routes its internal paths. The plugin name becomes part of the URL. If the plugin is named `"v2"`, the internal routes are `/v2/Users`, etc. Since we've already mounted at `/scim/v2`, we need `http.StripPrefix` or configure the plugin name to be empty/match. Test this carefully.

**Step 3: Run tests — verify pass**

**Step 4: Lint + commit**

```bash
git commit -m "feat(api): mount scimgateway http.Handler with SCIM auth middleware"
```

---

## Task 22: Admin endpoints — SCIM config CRUD

Standard chi handlers for managing SCIM config. Enterprise-only, owner-only.

**Files:**
- Create: `internal/api/scim_admin.go`
- Create: `internal/api/scim_admin_test.go`

**Step 1: Write failing tests**

Test cases (from design §7):
- `TestSCIMConfig_Create` — owner creates, token returned once (201)
- `TestSCIMConfig_Create_RequiresSSO` — fails without sso_connection (400)
- `TestSCIMConfig_Create_EnterpriseOnly` — non-Enterprise → 403
- `TestSCIMConfig_Get_TokenMasked` — token not in GET response
- `TestSCIMConfig_Enable_Disable` — PATCH enabled flag
- `TestSCIMConfig_Delete` — removes config (204)
- `TestSCIMConfig_Delete_GroupsSurvive` — scim_groups not cascade-deleted
- `TestSCIMConfig_RotateToken` — new token works, old rejected
- `TestSCIMConfig_RBAC` — non-owner → 403 for mutation; admin can GET
- `TestSCIMConfig_Create_Duplicate` — second POST → 409

**Step 2: Implement handlers**

Follow the SSO handler pattern in `internal/api/sso.go`:
- Extract `orgID` from context
- Call `requireEnterpriseTier(w, r)`
- Validate input
- Call store methods
- Return JSON response (not SCIM format — these are admin endpoints, not SCIM protocol)
- Audit log

Response types (from design §5):
- POST returns `{id, org_id, enabled, default_role, token_prefix, token, created_at}` — `token` in cleartext once
- GET returns same without `token` field
- PATCH returns updated config
- DELETE returns 204

**Step 3: Register routes in server.go**

Under the existing SSO route group or as a sibling:

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

**Step 4: Run tests — verify pass**

**Step 5: Lint + commit**

```bash
git commit -m "feat(api): SCIM config admin endpoints (CRUD, token rotation, group mapping)"
```

---

## Task 23: Admin endpoint — group mapping with immediate effect

When a group's `mapped_role` or `mapped_group_id` changes, recompute roles / sync notification groups for all current members immediately.

**Files:**
- Modify: `internal/api/scim_admin.go` (already created in Task 22)
- Add tests to `internal/api/scim_admin_test.go`

**Step 1: Write failing tests**

- `TestGroupMapping_SetRole` — mapped_role applied immediately to existing members
- `TestGroupMapping_SetNotificationGroup` — mapped_group_id triggers immediate sync
- `TestGroupMapping_ClearMapping` — null mapped_role → roles recomputed to default
- `TestGroupMapping_CrossOrgGroupId` — mapped_group_id from different org → 400
- `TestGroupMapping_MappingChanged_OldGroupCleanedUp` — old notification group members cleaned up

**Step 2: Implement**

The `patchSCIMGroupMappingHandler` should:
1. Update `scim_groups.mapped_role` and/or `mapped_group_id`
2. If `mapped_group_id` is set, validate it belongs to the same org (app-layer — FK bypasses RLS)
3. List all current members of the SCIM group
4. For each non-exempt member: `recomputeRole()` if mapped_role changed, `syncNotifGroup()` if mapped_group_id changed
5. If mapped_group_id changed from a previous value: clean up scim_managed memberships in the old notification group

**Step 3: Run tests — verify pass**

**Step 4: Lint + commit**

```bash
git commit -m "feat(api): SCIM group mapping with immediate role/notif recomputation"
```

---

## Task 24: Discovery endpoints (ServiceProviderConfig, Schemas, ResourceTypes)

The scimgateway library provides built-in discovery endpoints, but they report capabilities we don't support (bulk, sort, etag, changePassword). We have two options:

**Option A:** Use the library's built-in discovery and accept the inaccuracy (IdPs generally ignore these capabilities and only use what they need).

**Option B:** Override with custom static responses that match our design §3.5.

Check what the library returns. If it's close enough, use Option A. If it reports misleading capabilities (like `bulk: true`), implement Option B by adding static handler overrides before the scimgateway mount.

**Files:**
- May modify: `internal/api/scim_mount.go`
- May create: `internal/api/scim_discovery.go`
- Add test verifying ServiceProviderConfig returns expected values

TDD: write test → implement → verify → commit.

```bash
git commit -m "feat(api): SCIM discovery endpoints (ServiceProviderConfig, Schemas, ResourceTypes)"
```

---

## Task 25: End-to-end SCIM integration tests

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
8. **SCIM exempt user:** Provision exempt user → verify all operations return success but no modifications
9. **Sole-owner protection:** Attempt to deactivate sole owner via SCIM → verify 400
10. **Token rotation:** Rotate token → old token rejected → new token works

These tests use `testutil.NewTestDB(t)` and make HTTP requests through `httptest.Server` to test the full middleware → plugin → store stack.

TDD: write tests → verify they exercise the full stack → commit.

```bash
git commit -m "test(scim): end-to-end SCIM provisioning integration tests"
```

---

## Task 26: Audit logging for SCIM operations

Ensure all SCIM operations produce audit log entries per design §6.

**Files:**
- Modify: `internal/scim/users.go` — add audit logging
- Modify: `internal/scim/groups.go` — add audit logging
- Add audit log verification to existing tests

SCIM protocol operations use `ActorID = nil`, `ActorEmail = ""` (system action), with `Metadata: {"source": "scim", "scim_config_id": "<uuid>"}`.

For exempt user suppression: `Metadata` includes `{"source": "scim", "suppressed": true, "reason": "scim_exempt"}`.

Admin management actions (already in Task 22 handlers) use the authenticated user's `ActorID`.

Verify in tests that audit log entries are created with correct metadata.

```bash
git commit -m "feat(scim): audit logging for all SCIM protocol operations"
```

---

## Task 27: Structured logging (slog)

Ensure all slog events from design §6 are emitted at the correct levels.

**Files:**
- Review and update: `internal/scim/users.go`, `internal/scim/groups.go`, `internal/api/scim_admin.go`, `internal/api/middleware_scim.go`

Events to verify (from design §6):
- Info: user provisioned, deactivated, reactivated, attributes updated, deprovisioned
- Info: group created, deleted, membership changed
- Info: role recomputed, notification group synced
- Info: SCIM config created/enabled/disabled/updated/deleted, token rotated, mapping updated
- Warn: operation suppressed (exempt), sole-owner protection, auth failed
- Debug: SCIM request received

Add test helpers that capture slog output and verify expected log entries. Use `slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))` in tests.

```bash
git commit -m "feat(scim): structured slog events per design specification"
```

---

## Task 28: Final review and cleanup

**Files:**
- All files created/modified in this phase

**Step 1: Run full test suite**

```bash
go test ./... -count=1 -race
```

**Step 2: Lint**

```bash
golangci-lint run
```

**Step 3: Verify ABOUTME comments**

Every new Go file must start with two `// ABOUTME:` comment lines.

**Step 4: Update implementation log**

Add Phase 7 summary to `dev/implementation-log.md`.

**Step 5: Run /pitfall-check**

Invoke the `pitfall-check` skill on the SCIM code to catch documented mistakes.

**Step 6: Run /security-review**

Invoke the `security-review` skill on SCIM auth, token handling, and tenant isolation code.

**Step 7: Run /plan-check**

Invoke the `plan-check` skill against PLAN.md §7.2 to verify requirements coverage.

**Step 8: Commit**

```bash
git commit -m "chore(scim): Phase 7 final review, cleanup, and verification"
```

---

## Dependency Graph

```
Task 1: go get scimgateway
  ↓
Tasks 2-5: Migrations (can run in sequence, each depends on prior)
  ↓
Tasks 6-8: sqlc queries (depend on migrations, can run in parallel)
  ↓
Tasks 9-11: Store layer (depend on sqlc, can run in parallel)
  ↓
Task 12: SCIM token helper (independent, can run in parallel with store tasks)
  ↓
Task 13: RequireOrgRole deactivation check (depends on Task 11 store methods)
Task 14: Member PATCH extensions (depends on Task 11 + 13)
  ↓
Task 15: SCIM auth middleware (depends on Task 9 store + Task 12 token)
Task 16: SCIM rate limiter (depends on Task 15)
  ↓
Task 17: Role recomputation (depends on Tasks 10-11 store)
Task 18: Notification group sync (depends on Tasks 10-11 store)
  ↓
Task 19: Plugin — User operations (depends on Tasks 15, 17, 18)
Task 20: Plugin — Group operations (depends on Tasks 15, 17, 18)
  ↓
Task 21: Mount gateway (depends on Tasks 19-20)
  ↓
Task 22: Admin endpoints (depends on Tasks 9, 12, can start after Task 15)
Task 23: Group mapping admin (depends on Tasks 17, 18, 22)
  ↓
Task 24: Discovery endpoints (depends on Task 21)
  ↓
Task 25: E2E tests (depends on all above)
Task 26: Audit logging (can start after Tasks 19-20)
Task 27: Structured logging (can start after Tasks 19-20)
  ↓
Task 28: Final review (depends on all above)
```

**Parallelization opportunities for subagents:**
- Tasks 6, 7, 8 can run in parallel (independent sqlc query files)
- Tasks 9, 10, 11 can run in parallel (independent store files)
- Tasks 13, 14 are sequential but independent of Tasks 15-16
- Tasks 17, 18 can run in parallel
- Tasks 19, 20 can run in parallel
- Tasks 22, 23 can start as soon as their store dependencies are ready
- Tasks 26, 27 can run in parallel after the plugin tasks
