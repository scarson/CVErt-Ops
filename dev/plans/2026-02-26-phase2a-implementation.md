# Phase 2a: Org Model + Auth + RBAC + RLS — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Implement the org model, user authentication (native email/password + GitHub OAuth + Google OIDC), JWT + refresh tokens, API keys, RBAC middleware, and Postgres RLS on all org-scoped tables.

**Architecture:** `internal/auth/` package for pure crypto functions; `api.Server` struct replaces `NewRouter`; chi middleware for authentication + RBAC; `store.OrgTx()` helper for `SET LOCAL app.org_id`; dual-layer isolation (app `orgID` params + Postgres RLS fail-closed).

**Tech Stack:** `github.com/golang-jwt/jwt/v5` (new), `golang.org/x/oauth2` (new), `github.com/coreos/go-oidc/v3` (new), `golang.org/x/crypto/argon2` (already in go.mod via `golang.org/x/crypto`), `golang.org/x/time/rate` (already in go.mod), `github.com/google/uuid` (already in go.mod), testcontainers-go (already in go.mod).

**Reference:** Design doc at `dev/plans/2026-02-26-phase2a-auth-rbac-design.md`. See PLAN.md §6 + §7 for full spec.

**Module path:** `github.com/scarson/cvert-ops`

---

## Before starting

Read these files to understand the existing codebase patterns:
- `internal/api/server.go` — existing `NewRouter`, middleware chain, huma wiring
- `internal/api/smoke_test.go` — test pattern (testcontainers, httptest.Server)
- `internal/store/store.go` — Store struct, `withTx` helper
- `internal/store/cve.go` — store method patterns (sqlc + squirrel)
- `internal/store/queries/cves.sql` — sqlc query syntax
- `cmd/cvert-ops/main.go` — `newPool` retry pattern, `expectedSchemaVersion`
- `docker/compose.yml` — existing compose structure
- `dev/plans/2026-02-26-phase2a-auth-rbac-design.md` — full design doc

**Key conventions:**
- Every file starts with a 2-line `// ABOUTME:` comment
- Migrations use `-- migrate:no-transaction` as first line (all have CONCURRENTLY indexes)
- Each migration has both `.up.sql` and `.down.sql`
- sqlc queries: write in `internal/store/queries/`, run `sqlc generate` after changes
- Tests: use `t.Parallel()`, testcontainers-go for postgres integration tests
- `//nolint:gosec // G704 false positive: srv.URL is httptest.Server` on `srv.Client().Do()` calls

---

## Task 1: Add new Go dependencies

**Files:**
- Modify: `go.mod` (via `go get`)

**Step 1:** Add required packages.

```bash
cd /path/to/cvert-ops
go get github.com/golang-jwt/jwt/v5
go get golang.org/x/oauth2
go get github.com/coreos/go-oidc/v3/oidc
go mod tidy
```

**Step 2:** Verify.

```bash
go build ./...
```
Expected: builds cleanly.

**Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add jwt/v5, oauth2, go-oidc/v3 dependencies"
```

---

## Task 2: Split DATABASE_URL_MIGRATE in config

**Files:**
- Modify: `internal/config/config.go`
- Modify: `.env.example`

**Step 1:** Add `DatabaseURLMigrate` field to `Config` after `DatabaseURL`:

```go
// DatabaseURLMigrate is the connection string used by `cvert-ops migrate`.
// Should use a superuser/DDL role. Falls back to DatabaseURL if unset.
DatabaseURLMigrate string `env:"DATABASE_URL_MIGRATE"`
```

**Step 2:** Update migrate command in `cmd/cvert-ops/main.go` to prefer `cfg.DatabaseURLMigrate`:

In `runMigrate`, replace:
```go
connCfg, err := pgx.ParseConfig(cfg.DatabaseURL)
```
with:
```go
migrateURL := cfg.DatabaseURL
if cfg.DatabaseURLMigrate != "" {
    migrateURL = cfg.DatabaseURLMigrate
}
connCfg, err := pgx.ParseConfig(migrateURL)
```

**Step 3:** Update `.env.example` — add after `DATABASE_URL`:

```
# DATABASE_URL_MIGRATE is used by `cvert-ops migrate` (superuser/DDL role).
# Falls back to DATABASE_URL if unset. Set this if your app DB role lacks DDL privs.
# DATABASE_URL_MIGRATE=postgres://superuser:password@localhost:5432/cvert_ops?sslmode=disable
```

**Step 4:** Build to verify.

```bash
go build ./...
```

**Step 5: Commit**

```bash
git add internal/config/config.go cmd/cvert-ops/main.go .env.example
git commit -m "feat(config): add DATABASE_URL_MIGRATE for split DDL/app DB roles"
```

---

## Task 3: docker/init.sql — app DB role with NOBYPASSRLS

**Files:**
- Modify: `docker/compose.yml` (mount init.sql)
- Create: `docker/init.sql`

**Step 1:** Check the existing compose file structure:

```bash
cat docker/compose.yml
```

**Step 2:** Create `docker/init.sql`. This creates the restricted app role.

```sql
-- ABOUTME: Creates the cvert_ops_app database role with NOBYPASSRLS.
-- ABOUTME: Run once at initial DB creation via docker-entrypoint-initdb.d.

-- Create the restricted application role if it does not already exist.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cvert_ops_app') THEN
        CREATE ROLE cvert_ops_app
            LOGIN
            NOBYPASSRLS
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE;
    END IF;
END
$$;

-- Set the password. In production, use a secrets manager instead.
-- ALTER ROLE cvert_ops_app WITH PASSWORD 'changeme';

-- Grant the app role access to the database.
GRANT CONNECT ON DATABASE cvert_ops TO cvert_ops_app;

-- Grant schema usage. Tables will be granted per-migration.
GRANT USAGE ON SCHEMA public TO cvert_ops_app;
```

**Step 3:** Mount init.sql in docker compose postgres service. Add to the `volumes` section of the postgres service:

```yaml
- ./init.sql:/docker-entrypoint-initdb.d/init.sql:ro
```

**Step 4:** Update `.env.example` with note about DATABASE_URL variants:

```
# For local dev with split roles:
# DATABASE_URL=postgres://cvert_ops_app:changeme@localhost:5432/cvert_ops?sslmode=disable
# DATABASE_URL_MIGRATE=postgres://postgres:postgres@localhost:5432/cvert_ops?sslmode=disable
```

**Step 5: Commit**

```bash
git add docker/init.sql docker/compose.yml .env.example
git commit -m "infra: docker init.sql creates cvert_ops_app role with NOBYPASSRLS"
```

---

## Task 4: Migration 000004 — `organizations` table

**Files:**
- Create: `migrations/000004_create_organizations.up.sql`
- Create: `migrations/000004_create_organizations.down.sql`

**Step 1:** Write the up migration:

```sql
-- migrate:no-transaction
-- ABOUTME: Creates the organizations table (tenant containers).
-- ABOUTME: Global table — no RLS (orgs are the tenants, not org-scoped rows).

CREATE TABLE organizations (
    id          uuid        NOT NULL DEFAULT gen_random_uuid(),
    name        text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz NULL,
    CONSTRAINT organizations_pkey PRIMARY KEY (id)
);

CREATE INDEX CONCURRENTLY organizations_name_idx
    ON organizations (name);

GRANT SELECT, INSERT, UPDATE ON organizations TO cvert_ops_app;
```

**Step 2:** Write the down migration:

```sql
-- migrate:no-transaction
-- ABOUTME: Drops the organizations table.
-- ABOUTME: Down migration for 000004_create_organizations.

DROP INDEX CONCURRENTLY IF EXISTS organizations_name_idx;
DROP TABLE IF EXISTS organizations;
```

**Step 3:** Run the migration to verify it applies cleanly:

```bash
migrate -path migrations -database "$DATABASE_URL" up 1
migrate -path migrations -database "$DATABASE_URL" version
```
Expected: version 4.

**Step 4:** Update `expectedSchemaVersion` in `cmd/cvert-ops/main.go` to `4`.

**Step 5: Commit**

```bash
git add migrations/000004_create_organizations.up.sql \
        migrations/000004_create_organizations.down.sql \
        cmd/cvert-ops/main.go
git commit -m "feat(migration): organizations table"
```

---

## Task 5: Migration 000005 — `users` + `user_identities`

**Files:**
- Create: `migrations/000005_create_users.up.sql`
- Create: `migrations/000005_create_users.down.sql`

**Step 1:** Write the up migration:

```sql
-- migrate:no-transaction
-- ABOUTME: Creates users and user_identities tables.
-- ABOUTME: Global tables — no RLS (not org-scoped).

CREATE TABLE users (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    email                 text        NOT NULL,
    display_name          text        NOT NULL DEFAULT '',
    password_hash         text        NULL,     -- NULL for OAuth-only accounts
    password_hash_version int         NOT NULL DEFAULT 2, -- 2=argon2id
    token_version         int         NOT NULL DEFAULT 1,
    created_at            timestamptz NOT NULL DEFAULT now(),
    last_login_at         timestamptz NULL,
    CONSTRAINT users_pkey PRIMARY KEY (id)
);

-- Unique email index (partial: excludes deleted users if soft-delete is added later).
CREATE UNIQUE INDEX CONCURRENTLY users_email_uq ON users (email);

-- user_identities links users to OAuth providers (or native auth).
-- Matched on (provider, provider_user_id) — NEVER by email alone.
CREATE TABLE user_identities (
    id               uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id          uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider         text        NOT NULL,  -- 'github', 'google', 'native'
    provider_user_id text        NOT NULL,  -- immutable: GitHub numeric ID, Google sub
    email            text        NOT NULL,  -- mutable display attribute only
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_identities_pkey PRIMARY KEY (id)
);

-- The authoritative identity key: (provider, provider_user_id).
CREATE UNIQUE INDEX CONCURRENTLY user_identities_provider_uq
    ON user_identities (provider, provider_user_id);

CREATE INDEX CONCURRENTLY user_identities_user_idx
    ON user_identities (user_id);

GRANT SELECT, INSERT, UPDATE ON users TO cvert_ops_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON user_identities TO cvert_ops_app;
```

**Step 2:** Write the down migration:

```sql
-- migrate:no-transaction
-- ABOUTME: Drops users and user_identities tables.
-- ABOUTME: Down migration for 000005_create_users.

DROP INDEX CONCURRENTLY IF EXISTS user_identities_provider_uq;
DROP INDEX CONCURRENTLY IF EXISTS user_identities_user_idx;
DROP TABLE IF EXISTS user_identities;
DROP INDEX CONCURRENTLY IF EXISTS users_email_uq;
DROP TABLE IF EXISTS users;
```

**Step 3:** Run and verify. Update `expectedSchemaVersion` to `5`.

**Step 4: Commit**

```bash
git add migrations/000005_create_users.up.sql \
        migrations/000005_create_users.down.sql \
        cmd/cvert-ops/main.go
git commit -m "feat(migration): users + user_identities tables"
```

---

## Task 6: Migration 000006 — `refresh_tokens`

**Files:**
- Create: `migrations/000006_create_refresh_tokens.up.sql`
- Create: `migrations/000006_create_refresh_tokens.down.sql`

**Step 1:** Write the up migration (per PLAN.md §7.1 JTI tracking spec):

```sql
-- migrate:no-transaction
-- ABOUTME: Creates the refresh_tokens table for stateful JTI-based token tracking.
-- ABOUTME: Enables theft detection via the reuse + grace-window pattern (PLAN.md §7.1).

CREATE TABLE refresh_tokens (
    jti              uuid        NOT NULL,
    user_id          uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_version    int         NOT NULL,   -- must match users.token_version at validation
    expires_at       timestamptz NOT NULL,
    used_at          timestamptz NULL,       -- non-null = already consumed
    replaced_by_jti  uuid        NULL REFERENCES refresh_tokens(jti),
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT refresh_tokens_pkey PRIMARY KEY (jti)
);

-- For cleanup and per-user lookup.
CREATE INDEX CONCURRENTLY refresh_tokens_user_idx
    ON refresh_tokens (user_id, expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON refresh_tokens TO cvert_ops_app;
```

**Step 2:** Down migration:

```sql
-- migrate:no-transaction
-- ABOUTME: Drops refresh_tokens table.
-- ABOUTME: Down migration for 000006_create_refresh_tokens.

DROP INDEX CONCURRENTLY IF EXISTS refresh_tokens_user_idx;
DROP TABLE IF EXISTS refresh_tokens;
```

**Step 3:** Run, verify, update `expectedSchemaVersion` to `6`. Commit.

```bash
git commit -m "feat(migration): refresh_tokens table"
```

---

## Task 7: Migration 000007 — `org_members` + RLS

**Files:**
- Create: `migrations/000007_create_org_members.up.sql`
- Create: `migrations/000007_create_org_members.down.sql`

**Step 1:** Up migration — first org-scoped table with RLS:

```sql
-- migrate:no-transaction
-- ABOUTME: Creates org_members join table (user ↔ org role assignments).
-- ABOUTME: First org-scoped table: includes full RLS policy (PLAN.md §6.2).

CREATE TABLE org_members (
    org_id     uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       text        NOT NULL,  -- 'owner', 'admin', 'member', 'viewer'
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT org_members_pkey PRIMARY KEY (org_id, user_id)
);

CREATE INDEX CONCURRENTLY org_members_org_idx  ON org_members (org_id);
CREATE INDEX CONCURRENTLY org_members_user_idx ON org_members (user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON org_members TO cvert_ops_app;

-- ── RLS (PLAN.md §6.2) ────────────────────────────────────────────────────
ALTER TABLE org_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_members FORCE ROW LEVEL SECURITY;

-- Policy: visible only when app.org_id matches, or worker bypass is set.
-- Both settings use missing_ok=TRUE so an unset variable returns NULL,
-- which evaluates to FALSE in USING — fail-closed by design.
CREATE POLICY org_isolation ON org_members
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );
```

**Step 2:** Down migration:

```sql
-- migrate:no-transaction
-- ABOUTME: Drops org_members table and RLS policies.
-- ABOUTME: Down migration for 000007_create_org_members.

DROP POLICY IF EXISTS org_isolation ON org_members;
ALTER TABLE IF EXISTS org_members DISABLE ROW LEVEL SECURITY;
DROP INDEX CONCURRENTLY IF EXISTS org_members_org_idx;
DROP INDEX CONCURRENTLY IF EXISTS org_members_user_idx;
DROP TABLE IF EXISTS org_members;
```

**Step 3:** Verify RLS is working. Run the migration, then:

```sql
-- As cvert_ops_app with no app.org_id set:
SET ROLE cvert_ops_app;
SELECT COUNT(*) FROM org_members;  -- should return 0 (fail-closed)
```

**Step 4:** Update `expectedSchemaVersion` to `7`. Commit.

```bash
git commit -m "feat(migration): org_members table + RLS"
```

---

## Task 8: Migration 000008 — `api_keys` + RLS

**Files:**
- Create: `migrations/000008_create_api_keys.up.sql`
- Create: `migrations/000008_create_api_keys.down.sql`

**Step 1:** Up migration:

```sql
-- migrate:no-transaction
-- ABOUTME: Creates api_keys table for machine-to-machine authentication.
-- ABOUTME: Stores only sha256(raw_key) — never the raw key. RLS on org_id.

CREATE TABLE api_keys (
    id                  uuid        NOT NULL DEFAULT gen_random_uuid(),
    org_id              uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by_user_id  uuid        NOT NULL REFERENCES users(id),
    key_hash            text        NOT NULL,   -- sha256(raw_key), hex-encoded
    name                text        NOT NULL,   -- user-visible label
    role                text        NOT NULL,   -- role ≤ creator's role at time of creation
    expires_at          timestamptz NULL,       -- NULL = never expires
    last_used_at        timestamptz NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    revoked_at          timestamptz NULL,
    CONSTRAINT api_keys_pkey PRIMARY KEY (id)
);

-- O(1) lookup by hash. No prefix stored — hash is sufficient with UNIQUE index.
CREATE UNIQUE INDEX CONCURRENTLY api_keys_hash_uq ON api_keys (key_hash);
CREATE INDEX CONCURRENTLY api_keys_org_idx ON api_keys (org_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys TO cvert_ops_app;

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON api_keys
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );
```

**Step 2:** Down migration (same pattern as org_members). Update `expectedSchemaVersion` to `8`. Commit.

```bash
git commit -m "feat(migration): api_keys table + RLS"
```

---

## Task 9: Migration 000009 — `org_invitations`

**Files:**
- Create: `migrations/000009_create_org_invitations.up.sql`
- Create: `migrations/000009_create_org_invitations.down.sql`

**Step 1:** Up migration. Note: no RLS — the accept endpoint is public (no org context), and admin endpoints enforce RBAC at handler level.

```sql
-- migrate:no-transaction
-- ABOUTME: Creates org_invitations for email-based member invitation flow.
-- ABOUTME: No RLS — accept endpoint is public; admin endpoints enforce RBAC at handler level.

CREATE TABLE org_invitations (
    id          uuid        NOT NULL DEFAULT gen_random_uuid(),
    org_id      uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email       text        NOT NULL,
    role        text        NOT NULL DEFAULT 'member',
    token       text        NOT NULL,           -- 32 random bytes, hex-encoded; used in link
    created_by  uuid        NOT NULL REFERENCES users(id),
    expires_at  timestamptz NOT NULL,
    accepted_at timestamptz NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT org_invitations_pkey PRIMARY KEY (id)
);

CREATE UNIQUE INDEX CONCURRENTLY org_invitations_token_uq ON org_invitations (token);
CREATE INDEX CONCURRENTLY org_invitations_org_idx ON org_invitations (org_id);

GRANT SELECT, INSERT, UPDATE ON org_invitations TO cvert_ops_app;
```

**Step 2:** Down migration. Update `expectedSchemaVersion` to `9`. Commit.

```bash
git commit -m "feat(migration): org_invitations table"
```

---

## Task 10: Migration 000010 — `groups` + RLS

**Files:**
- Create: `migrations/000010_create_groups.up.sql`
- Create: `migrations/000010_create_groups.down.sql`

**Step 1:** Up migration. Note the partial unique index for soft-delete support (PLAN.md Appendix A).

```sql
-- migrate:no-transaction
-- ABOUTME: Creates the groups table for org-scoped user collections.
-- ABOUTME: Used for notification routing and watchlist ownership. Soft-deletable.

CREATE TABLE groups (
    id          uuid        NOT NULL DEFAULT gen_random_uuid(),
    org_id      uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz NULL,
    CONSTRAINT groups_pkey PRIMARY KEY (id)
);

-- Partial unique index: allows name reuse after soft-delete (PLAN.md Appendix A).
CREATE UNIQUE INDEX CONCURRENTLY groups_name_uq
    ON groups (org_id, name)
    WHERE deleted_at IS NULL;

CREATE INDEX CONCURRENTLY groups_org_idx ON groups (org_id);

GRANT SELECT, INSERT, UPDATE ON groups TO cvert_ops_app;

ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON groups
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );
```

**Step 2:** Down migration. Update `expectedSchemaVersion` to `10`. Commit.

```bash
git commit -m "feat(migration): groups table + RLS"
```

---

## Task 11: Migration 000011 — `group_members` + RLS

**Files:**
- Create: `migrations/000011_create_group_members.up.sql`
- Create: `migrations/000011_create_group_members.down.sql`

**Step 1:** Up migration. `org_id` is DENORMALIZED (PLAN.md §6.2 — RLS on parent does NOT protect children).

```sql
-- migrate:no-transaction
-- ABOUTME: Creates group_members join table with denormalized org_id for RLS.
-- ABOUTME: org_id must be denormalized — RLS on groups does NOT protect group_members.

CREATE TABLE group_members (
    id         uuid        NOT NULL DEFAULT gen_random_uuid(),
    org_id     uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    group_id   uuid        NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT group_members_pkey PRIMARY KEY (id),
    CONSTRAINT group_members_unique UNIQUE (group_id, user_id)
);

CREATE INDEX CONCURRENTLY group_members_org_idx   ON group_members (org_id);
CREATE INDEX CONCURRENTLY group_members_group_idx ON group_members (group_id);

GRANT SELECT, INSERT, DELETE ON group_members TO cvert_ops_app;

ALTER TABLE group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_members FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON group_members
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );
```

**Step 2:** Down migration. Update `expectedSchemaVersion` to `11`. Commit.

```bash
git commit -m "feat(migration): group_members table + org_id denormalization + RLS"
```

---

## Task 12: Shared test helper for integration tests

Create a reusable postgres test helper so Phase 2a store tests don't each start their own container.

**Files:**
- Create: `internal/testutil/postgres.go`

**Step 1:** Write the helper:

```go
// ABOUTME: Test helper that starts a Postgres testcontainer with migrations applied.
// ABOUTME: Use NewTestDB(t) in integration tests that need a real database.
package testutil

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/migrations"
	// migration runner imports
	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/stdlib"
)

// NewTestDB starts a Postgres testcontainer, runs all migrations, and returns
// a Store backed by the test DB. The container and pool are cleaned up via t.Cleanup.
func NewTestDB(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()

	pgCtr, err := tcpostgres.Run(ctx,
		"postgres:18-alpine",
		tcpostgres.WithDatabase("cvert_ops_test"),
		tcpostgres.WithUsername("cvert_ops_test"),
		tcpostgres.WithPassword("testpassword"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() {
		if err := pgCtr.Terminate(ctx); err != nil {
			t.Logf("terminate postgres container: %v", err)
		}
	})

	connStr, err := pgCtr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	// Run migrations.
	connCfg, err := stdlib.OpenDB(*pgxMustParse(t, connStr)).Stats(), // get the db
	// Actually use stdlib directly:
	db, err := stdlib.Open(connStr) // use pgx stdlib
	// ... run migrations using iofs source and migratepg driver
	src, err := iofs.New(migrations.FS, ".")
	if err != nil { t.Fatalf("migration source: %v", err) }
	driver, err := migratepg.WithInstance(db, &migratepg.Config{})
	if err != nil { t.Fatalf("migration driver: %v", err) }
	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil { t.Fatalf("migrate init: %v", err) }
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("migrate up: %v", err)
	}

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil { t.Fatalf("pgxpool: %v", err) }
	t.Cleanup(pool.Close)

	return store.New(pool)
}
```

**IMPORTANT:** The above is a skeleton. Look at `internal/api/smoke_test.go` for the exact testcontainers pattern used in this codebase. Follow the same pattern. The key parts:
1. `tcpostgres.Run(ctx, "postgres:18-alpine", ...)`
2. `pgCtr.ConnectionString(ctx, "sslmode=disable")`
3. Then run migrations using the `migrations.FS` embed (same as in `cmd/cvert-ops/main.go` `runMigrate` function)
4. Create `pgxpool.New(ctx, connStr)`
5. Return `store.New(pool)`

**Step 2:** Run existing tests to make sure nothing breaks:

```bash
go test ./... -count=1 -timeout 120s
```

**Step 3: Commit**

```bash
git add internal/testutil/
git commit -m "feat(testutil): shared postgres test helper with migrations"
```

---

## Task 13: `internal/auth` — JWT package

**Files:**
- Create: `internal/auth/jwt.go`
- Create: `internal/auth/jwt_test.go`

**Step 1:** Write the failing tests first:

```go
// ABOUTME: Tests for JWT issuance and parsing with required security constraints.
// ABOUTME: Covers algorithm pinning, expiry enforcement, and token_version embedding.
package auth_test

import (
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/auth"
)

func TestJWTRoundTrip(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssueAccessToken(secret, userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	claims, err := auth.ParseAccessToken(tokenStr, secret)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.TokenVersion != 1 {
		t.Errorf("TokenVersion = %d, want 1", claims.TokenVersion)
	}
}

func TestJWTRejectsExpired(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssueAccessToken(secret, userID, 1, -1*time.Second) // already expired
	if err != nil { t.Fatalf("issue: %v", err) }

	_, err = auth.ParseAccessToken(tokenStr, secret)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestJWTRejectsWrongAlgorithm(t *testing.T) {
	// Test that a token signed with HMAC but claiming RS256 is rejected.
	// This tests the WithValidMethods guard.
	// ... (craft a token with alg=RS256 header manually and verify rejection)
}
```

**Step 2:** Run tests:

```bash
go test ./internal/auth/... -run TestJWT -v
```
Expected: FAIL (package doesn't exist yet).

**Step 3:** Implement `internal/auth/jwt.go`:

```go
// ABOUTME: JWT issuance and parsing for CVErt Ops access and refresh tokens.
// ABOUTME: Always enforces HS256 algorithm and expiration — never call jwt.Parse directly.
package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AccessClaims holds the claims embedded in an access token.
type AccessClaims struct {
	jwt.RegisteredClaims
	// UserID is the authenticated user's UUID (sub claim).
	UserID       uuid.UUID `json:"sub"`
	// TokenVersion must match users.token_version for the refresh flow to succeed.
	TokenVersion int       `json:"tv"`
}

// IssueAccessToken creates a signed HS256 JWT access token.
// ttl should be ≤15 minutes per PLAN.md §7.1.
func IssueAccessToken(secret []byte, userID uuid.UUID, tokenVersion int, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		TokenVersion: tokenVersion,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return signed, nil
}

// ParseAccessToken validates and parses an HS256 access token.
// Returns an error if the token is expired, uses a wrong algorithm, or is invalid.
// PLAN.md §7.1: WithValidMethods and WithExpirationRequired are MANDATORY.
func ParseAccessToken(tokenStr string, secret []byte) (*AccessClaims, error) {
	claims := &AccessClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		return secret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("parse access token: %w", err)
	}
	return claims, nil
}

// RefreshClaims holds the claims embedded in a refresh token.
type RefreshClaims struct {
	jwt.RegisteredClaims
	UserID       uuid.UUID `json:"sub"`
	TokenVersion int       `json:"tv"`
	JTI          uuid.UUID `json:"jti_id"` // also in RegisteredClaims.ID but typed here
}

// IssueRefreshToken creates a signed HS256 refresh token with a unique JTI.
func IssueRefreshToken(secret []byte, userID uuid.UUID, tokenVersion int, jti uuid.UUID, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := RefreshClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ID:        jti.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		TokenVersion: tokenVersion,
		JTI:          jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("sign refresh token: %w", err)
	}
	return signed, nil
}

// ParseRefreshToken validates and parses an HS256 refresh token.
func ParseRefreshToken(tokenStr string, secret []byte) (*RefreshClaims, error) {
	claims := &RefreshClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		return secret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("parse refresh token: %w", err)
	}
	return claims, nil
}
```

**Step 4:** Run tests — should pass. Then run lint:

```bash
go test ./internal/auth/... -v
golangci-lint run ./internal/auth/...
```

**Step 5: Commit**

```bash
git add internal/auth/jwt.go internal/auth/jwt_test.go
git commit -m "feat(auth): JWT Claims, IssueAccessToken, ParseAccessToken + tests"
```

---

## Task 14: `internal/auth` — argon2id password hashing

**Files:**
- Create: `internal/auth/hash.go`
- Create: `internal/auth/hash_test.go`

**Step 1:** Write failing tests:

```go
func TestHashPassword(t *testing.T) {
	t.Parallel()
	hash, err := auth.HashPassword("correct-horse-battery-staple")
	if err != nil { t.Fatalf("hash: %v", err) }
	if hash == "" { t.Error("hash is empty") }

	ok, err := auth.VerifyPassword("correct-horse-battery-staple", hash)
	if err != nil { t.Fatalf("verify: %v", err) }
	if !ok { t.Error("correct password should verify") }
}

func TestHashPasswordWrongPassword(t *testing.T) {
	t.Parallel()
	hash, _ := auth.HashPassword("real-password")
	ok, err := auth.VerifyPassword("wrong-password", hash)
	if err != nil { t.Fatalf("verify: %v", err) }
	if ok { t.Error("wrong password should not verify") }
}
```

**Step 2:** Run tests (FAIL).

**Step 3:** Implement `internal/auth/hash.go`. Use `golang.org/x/crypto/argon2` directly (already in go.mod).

Parameters from PLAN.md §7.1: memory=19456 KiB, iterations=2, parallelism=1, salt=16 bytes, key=32 bytes.

Storage format: `$argon2id$v=19$m=19456,t=2,p=1$<base64(salt)>$<base64(key)>`

```go
// ABOUTME: Argon2id password hashing per PLAN.md §7.1 OWASP parameters.
// ABOUTME: Callers must acquire the argon2 semaphore (on api.Server) before calling.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Memory      = 19456 // KiB (19 MiB)
	argon2Iterations  = 2
	argon2Parallelism = 1
	argon2SaltLen     = 16
	argon2KeyLen      = 32
)

// HashPassword hashes password using argon2id. Returns a PHC-format string.
// The caller is responsible for acquiring the argon2 concurrency semaphore.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argon2Iterations, argon2Memory, argon2Parallelism, argon2KeyLen)
	hash := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory, argon2Iterations, argon2Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
	return hash, nil
}

// VerifyPassword checks password against a PHC-format argon2id hash.
// Returns (false, nil) for wrong password — never returns an error for a valid hash.
func VerifyPassword(password, hash string) (bool, error) {
	// Parse: $argon2id$v=19$m=M,t=T,p=P$salt$key
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid hash format")
	}
	var m, t, p uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, fmt.Errorf("parse params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil { return false, fmt.Errorf("decode salt: %w", err) }
	expectedKey, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil { return false, fmt.Errorf("decode key: %w", err) }

	actualKey := argon2.IDKey([]byte(password), salt, t, m, uint8(p), uint32(len(expectedKey)))
	return subtle.ConstantTimeCompare(expectedKey, actualKey) == 1, nil
}
```

**Step 4:** Run tests (PASS). Commit.

```bash
git commit -m "feat(auth): argon2id HashPassword, VerifyPassword + tests"
```

---

## Task 15: `internal/auth` — API key generation

**Files:**
- Create: `internal/auth/apikey.go`
- Create: `internal/auth/apikey_test.go`

**Step 1:** Write failing tests:

```go
func TestGenerateKey(t *testing.T) {
	t.Parallel()
	rawKey, hash, err := auth.GenerateAPIKey()
	if err != nil { t.Fatalf("generate: %v", err) }
	if !strings.HasPrefix(rawKey, "cvo_") { t.Errorf("key missing cvo_ prefix") }
	if len(hash) != 64 { t.Errorf("hash should be 64 hex chars (sha256), got %d", len(hash)) }
}

func TestHashAPIKey(t *testing.T) {
	t.Parallel()
	rawKey, hash1, _ := auth.GenerateAPIKey()
	hash2 := auth.HashAPIKey(rawKey)
	if hash1 != hash2 { t.Error("HashAPIKey(rawKey) should match hash from GenerateAPIKey") }
}
```

**Step 2:** Implement `internal/auth/apikey.go`:

```go
// ABOUTME: API key generation and hashing for machine-to-machine authentication.
// ABOUTME: Keys are opaque strings (cvo_ prefix + random bytes). Only sha256 stored.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// APIKeyPrefix is the human-readable prefix on all CVErt Ops API keys.
const APIKeyPrefix = "cvo_"

// GenerateAPIKey creates a new API key. Returns the raw key (shown to user once),
// the sha256 hex hash (stored in DB), and any error.
func GenerateAPIKey() (rawKey, keyHash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate api key: %w", err)
	}
	rawKey = APIKeyPrefix + hex.EncodeToString(b)
	keyHash = HashAPIKey(rawKey)
	return rawKey, keyHash, nil
}

// HashAPIKey returns the sha256 hex hash of rawKey.
// Use subtle.ConstantTimeCompare when comparing against stored hashes.
func HashAPIKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])
}
```

**Step 3:** Run tests (PASS). Commit.

```bash
git commit -m "feat(auth): API key GenerateAPIKey, HashAPIKey + tests"
```

---

## Task 16: sqlc queries for auth + store method for users

**Files:**
- Create: `internal/store/queries/auth.sql`
- Run: `sqlc generate`
- Create: `internal/store/auth.go`
- Create: `internal/store/auth_test.go`

**Step 1:** Write sqlc queries in `internal/store/queries/auth.sql`:

```sql
-- ABOUTME: sqlc queries for user authentication operations.
-- ABOUTME: Used by store/auth.go — static CRUD only. No RLS (users is global table).

-- name: CreateUser :one
INSERT INTO users (email, display_name, password_hash, password_hash_version)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1 LIMIT 1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 LIMIT 1;

-- name: UpdateLastLogin :exec
UPDATE users SET last_login_at = now() WHERE id = $1;

-- name: IncrementTokenVersion :one
UPDATE users SET token_version = token_version + 1 WHERE id = $1
RETURNING token_version;

-- name: UpdatePasswordHash :exec
UPDATE users
SET password_hash = $2, password_hash_version = $3, token_version = token_version + 1
WHERE id = $1;

-- name: UpsertUserIdentity :exec
INSERT INTO user_identities (user_id, provider, provider_user_id, email)
VALUES ($1, $2, $3, $4)
ON CONFLICT (provider, provider_user_id)
DO UPDATE SET email = EXCLUDED.email;

-- name: GetUserByProviderID :one
SELECT u.* FROM users u
JOIN user_identities ui ON ui.user_id = u.id
WHERE ui.provider = $1 AND ui.provider_user_id = $2
LIMIT 1;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (jti, user_id, token_version, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens WHERE jti = $1 LIMIT 1;

-- name: MarkRefreshTokenUsed :exec
UPDATE refresh_tokens
SET used_at = now(), replaced_by_jti = $2
WHERE jti = $1;

-- name: DeleteExpiredRefreshTokens :execrows
DELETE FROM refresh_tokens
WHERE expires_at < now() - interval '60 seconds';
```

**Step 2:** Run `sqlc generate`:

```bash
sqlc generate
```
Expected: new file generated in `internal/store/generated/auth.sql.go`.

**Step 3:** Write failing tests for `store/auth.go`:

```go
// internal/store/auth_test.go
func TestCreateAndGetUser(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "alice@example.com", "Alice", "$argon2id$...", 2)
	if err != nil { t.Fatalf("CreateUser: %v", err) }
	if user.Email != "alice@example.com" { t.Errorf("email mismatch") }

	got, err := s.GetUserByEmail(ctx, "alice@example.com")
	if err != nil { t.Fatalf("GetUserByEmail: %v", err) }
	if got.ID != user.ID { t.Errorf("ID mismatch") }
}

func TestIncrementTokenVersion(t *testing.T) { ... }
func TestUpsertUserIdentity(t *testing.T) { ... }
func TestRefreshTokenCRUD(t *testing.T) { ... }
```

**Step 4:** Implement `internal/store/auth.go` — thin wrappers around sqlc-generated functions:

```go
// ABOUTME: Store methods for user authentication: creation, lookup, token versioning.
// ABOUTME: These are global-table operations — no orgID parameter, no RLS.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// CreateUser inserts a new user row. Returns the created user.
func (s *Store) CreateUser(ctx context.Context, email, displayName, passwordHash string, hashVersion int) (*generated.User, error) {
	row, err := s.q.CreateUser(ctx, generated.CreateUserParams{
		Email:               email,
		DisplayName:         displayName,
		PasswordHash:        sql.NullString{String: passwordHash, Valid: passwordHash != ""},
		PasswordHashVersion: int32(hashVersion),
	})
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return &row, nil
}

// GetUserByEmail returns the user with the given email, or (nil, nil) if not found.
// SECURITY: only call from auth flows (login, OAuth callback) — not from org-admin endpoints.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*generated.User, error) {
	row, err := s.q.GetUserByEmail(ctx, email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return &row, nil
}

// ... GetUserByID, IncrementTokenVersion, UpsertUserIdentity, GetUserByProviderID,
// CreateRefreshToken, GetRefreshToken, MarkRefreshTokenUsed, DeleteExpiredRefreshTokens
```

**Step 5:** Run tests (PASS). Commit.

```bash
git commit -m "feat(store): user CRUD + GetUserByProviderID + refresh token CRUD + tests"
```

---

## Task 17: sqlc queries + store methods for orgs and members

**Files:**
- Create: `internal/store/queries/org.sql`
- Run: `sqlc generate`
- Create: `internal/store/org.go`
- Create: `internal/store/org_test.go`

**Step 1:** Write sqlc queries in `internal/store/queries/org.sql`:

```sql
-- ABOUTME: sqlc queries for organization and membership management.
-- ABOUTME: Org-scoped methods take org_id as a parameter (Layer 1 isolation).

-- name: CreateOrg :one
INSERT INTO organizations (name) VALUES ($1) RETURNING *;

-- name: GetOrgByID :one
SELECT * FROM organizations WHERE id = $1 AND deleted_at IS NULL LIMIT 1;

-- name: CreateOrgMember :exec
INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3);

-- name: GetOrgMemberRole :one
SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2 LIMIT 1;

-- name: ListOrgMembers :many
SELECT om.*, u.email, u.display_name FROM org_members om
JOIN users u ON u.id = om.user_id
WHERE om.org_id = $1
ORDER BY om.created_at;

-- name: UpdateOrgMemberRole :exec
UPDATE org_members SET role = $3, updated_at = now()
WHERE org_id = $1 AND user_id = $2;

-- name: DeleteOrgMember :exec
DELETE FROM org_members WHERE org_id = $1 AND user_id = $2;

-- name: ListUserOrgs :many
SELECT om.org_id, om.role, o.name FROM org_members om
JOIN organizations o ON o.id = om.org_id
WHERE om.user_id = $1 AND o.deleted_at IS NULL
ORDER BY o.name;

-- name: CreateOrgInvitation :exec
INSERT INTO org_invitations (org_id, email, role, token, created_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetInvitationByToken :one
SELECT * FROM org_invitations WHERE token = $1 LIMIT 1;

-- name: AcceptInvitation :exec
UPDATE org_invitations SET accepted_at = now() WHERE id = $1;

-- name: ListOrgInvitations :many
SELECT * FROM org_invitations
WHERE org_id = $1 AND accepted_at IS NULL AND expires_at > now()
ORDER BY created_at DESC;

-- name: DeleteOrgInvitation :exec
DELETE FROM org_invitations WHERE id = $1 AND org_id = $2;

-- name: GetOrgMemberCount :one
SELECT COUNT(*) FROM org_members WHERE org_id = $1 AND role = 'owner';
```

**Step 2:** Run `sqlc generate`.

**Step 3:** Write failing tests in `internal/store/org_test.go` BEFORE implementing:

```go
func TestCreateAndGetOrg(t *testing.T) { ... }

func TestGetOrgMemberRole_NonMember(t *testing.T) {
    // Create org + one member. Query role for a different user.
    // Expect: (nil, nil) — user is not a member, not an error.
}

func TestGetOrgMemberRole_Member(t *testing.T) {
    // Create org, add user as admin. Query role.
    // Expect: "admin", nil.
}

func TestListOrgMembers_OnlyShowsOwnOrg(t *testing.T) {
    // Create two orgs, one member each.
    // ListOrgMembers(org1) should return only org1's member.
}

func TestListUserOrgs_MultipleOrgs(t *testing.T) {
    // Add user to two orgs with different roles.
    // ListUserOrgs should return both, ordered by name.
}

func TestCreateOrgInvitation_AcceptFlow(t *testing.T) {
    // Create invitation, accept it, verify accepted_at is set.
}

func TestGetInvitationByToken_ExpiredNotReturned(t *testing.T) {
    // Insert invitation with expires_at in the past.
    // GetInvitationByToken should still return it (expiry checked at handler level).
    // ListOrgInvitations should NOT return it (query filters expires_at > now()).
}
```

**Step 4:** Implement `internal/store/org.go` following the thin-wrapper pattern as `store/auth.go`. Key methods: `CreateOrg`, `GetOrgByID`, `CreateOrgMember`, `GetOrgMemberRole`, `ListOrgMembers`, `UpdateOrgMemberRole`, `RemoveOrgMember`, `ListUserOrgs`, `CreateOrgInvitation`, `GetInvitationByToken`, `AcceptInvitation`, `ListOrgInvitations`, `CancelInvitation`.

**Step 5:** Run tests. Commit.

```bash
git commit -m "feat(store): org + org_member CRUD + invitation CRUD + tests"
```

---

## Task 18: sqlc queries + store methods for API keys

**Files:**
- Append to: `internal/store/queries/org.sql` (or create `internal/store/queries/apikeys.sql`)
- Run: `sqlc generate`
- Create: `internal/store/apikey.go`

**Step 1:** Add API key queries to the org queries file (or a new file):

```sql
-- name: CreateAPIKey :one
INSERT INTO api_keys (org_id, created_by_user_id, key_hash, name, role, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: LookupAPIKey :one
-- Used for authentication — checks revocation + expiry.
SELECT * FROM api_keys
WHERE key_hash = $1
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now())
LIMIT 1;

-- name: ListOrgAPIKeys :many
SELECT id, name, role, expires_at, last_used_at, created_at, revoked_at
FROM api_keys
WHERE org_id = $1
ORDER BY created_at DESC;

-- name: RevokeAPIKey :exec
UPDATE api_keys SET revoked_at = now()
WHERE id = $1 AND org_id = $2;

-- name: UpdateAPIKeyLastUsed :exec
UPDATE api_keys SET last_used_at = now() WHERE id = $1;
```

**Step 2:** `sqlc generate`.

**Step 3:** Write failing tests in `internal/store/apikey_test.go` BEFORE implementing:

```go
func TestLookupAPIKey_ValidKey(t *testing.T) {
    // Insert a key. LookupAPIKey(hash) should return it.
}

func TestLookupAPIKey_RevokedKey(t *testing.T) {
    // Insert a key, revoke it. LookupAPIKey should return nil (query filters revoked_at IS NULL).
}

func TestLookupAPIKey_ExpiredKey(t *testing.T) {
    // Insert a key with expires_at in the past. LookupAPIKey should return nil.
}

func TestLookupAPIKey_NeverExpiresKey(t *testing.T) {
    // Insert a key with expires_at = NULL. LookupAPIKey should return it.
}

func TestCreateAndListAPIKeys(t *testing.T) {
    // Create two keys for an org. ListOrgAPIKeys should return both, newest first.
    // Verify key_hash is NOT returned in ListOrgAPIKeys (select excludes it).
}

func TestRevokeAPIKey_WrongOrg(t *testing.T) {
    // Create key for org1. RevokeAPIKey with org2 should be a no-op (0 rows affected is OK).
}
```

**Step 4:** Implement `internal/store/apikey.go`. Note: `LookupAPIKey` does NOT take `orgID` — the hash lookup finds the key, then the RBAC check validates org membership separately.

**Step 5:** Run tests. Commit.

```bash
git commit -m "feat(store): API key CRUD + tests"
```

---

## Task 19: Store methods for groups

**Files:**
- Create: `internal/store/queries/groups.sql`
- Run: `sqlc generate`
- Create: `internal/store/group.go`

**Step 1:** Write group queries:

```sql
-- ABOUTME: sqlc queries for group management.
-- ABOUTME: All group operations are org-scoped via org_id parameter.

-- name: CreateGroup :one
INSERT INTO groups (org_id, name, description) VALUES ($1, $2, $3) RETURNING *;

-- name: GetGroup :one
SELECT * FROM groups WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL LIMIT 1;

-- name: ListOrgGroups :many
SELECT * FROM groups WHERE org_id = $1 AND deleted_at IS NULL ORDER BY name;

-- name: UpdateGroup :exec
UPDATE groups SET name = $3, description = $4 WHERE id = $1 AND org_id = $2;

-- name: SoftDeleteGroup :exec
UPDATE groups SET deleted_at = now() WHERE id = $1 AND org_id = $2;

-- name: AddGroupMember :exec
INSERT INTO group_members (org_id, group_id, user_id) VALUES ($1, $2, $3)
ON CONFLICT (group_id, user_id) DO NOTHING;

-- name: RemoveGroupMember :exec
DELETE FROM group_members WHERE group_id = $1 AND user_id = $2 AND org_id = $3;

-- name: ListGroupMembers :many
SELECT gm.*, u.email, u.display_name
FROM group_members gm JOIN users u ON u.id = gm.user_id
WHERE gm.group_id = $1 AND gm.org_id = $2
ORDER BY u.display_name;
```

**Step 2:** `sqlc generate`.

**Step 3:** Write failing tests in `internal/store/group_test.go` BEFORE implementing:

```go
func TestCreateAndGetGroup(t *testing.T) { ... }

func TestSoftDeleteGroup_NameReuseAllowed(t *testing.T) {
    // Create group with name "X", soft-delete it.
    // Create another group with name "X" in the same org.
    // Expect: second create succeeds (partial unique index allows reuse after delete).
}

func TestGetGroup_DeletedReturnsNil(t *testing.T) {
    // Create a group, soft-delete it. GetGroup should return nil (deleted_at IS NULL filter).
}

func TestAddGroupMember_Idempotent(t *testing.T) {
    // Add same user to group twice. Second add is a no-op (ON CONFLICT DO NOTHING).
    // ListGroupMembers should show user once.
}

func TestListGroupMembers_OrgScoped(t *testing.T) {
    // Create two groups in two orgs, add members.
    // ListGroupMembers for group1 should not return group2's members.
}
```

**Step 4:** Implement `internal/store/group.go`. Run tests. Commit.

```bash
git commit -m "feat(store): group + group_member CRUD + tests"
```

---

## Task 20: `store.OrgTx` + `store.WorkerTx` helpers

**Files:**
- Modify: `internal/store/store.go`
- Add test to: `internal/store/` (integration test verifying `SET LOCAL app.org_id`)

**Step 1:** Write failing tests in `internal/store/org_tx_test.go`:

```go
// TestOrgTx_SetsOrgID verifies that OrgTx sets app.org_id for the duration of
// the transaction, and that RLS applies (org_members for other org are invisible).
func TestOrgTx_SetsOrgID(t *testing.T) {
	// Create two orgs and one member each.
	// Open OrgTx for org1.
	// Query org_members inside tx — should see only org1's member.
	// Confirm org2's member is not visible.
}

// TestOrgTx_FailClosed verifies that a raw query with NO app.org_id set
// returns 0 rows — not an error. This is the RLS fail-closed guarantee.
// If this test fails, the dual-layer isolation is broken.
func TestOrgTx_FailClosed(t *testing.T) {
	// Create an org + member using WorkerTx (bypass RLS to insert).
	// Then open a plain pool connection (no SET LOCAL app.org_id).
	// Query org_members directly — must return 0 rows (fail-closed), not an error.
}

// TestWorkerTx_BypassRLS verifies that WorkerTx with bypass_rls = 'on'
// can read rows from all orgs.
func TestWorkerTx_BypassRLS(t *testing.T) {
	// Create two orgs + members.
	// Open WorkerTx, query org_members — should return rows for both orgs.
}
```

**Step 2:** Implement `OrgTx` and `WorkerTx` in `internal/store/store.go` by appending after the existing `withTx`:

```go
// OrgTx opens a pgx native transaction and sets app.org_id = orgID for the
// duration of the transaction (PLAN.md §6.2). This makes RLS policies apply
// to all queries inside fn. Safe for connection pooling: SET LOCAL resets on
// commit or rollback.
//
// Use this for all org-scoped write operations from HTTP handlers.
func (s *Store) OrgTx(ctx context.Context, orgID uuid.UUID, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on panic or fn error
	if _, err := tx.Exec(ctx, "SET LOCAL app.org_id = $1", orgID); err != nil {
		return fmt.Errorf("set org_id: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// WorkerTx opens a pgx native transaction with RLS bypass enabled.
// ONLY for background worker goroutines (batch evaluator, EPSS, retention).
// NEVER call from HTTP handler code paths — see PLAN.md §6.2.
func (s *Store) WorkerTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin worker tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, "SET LOCAL app.bypass_rls = 'on'"); err != nil {
		return fmt.Errorf("set bypass_rls: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
```

**Step 3:** Run tests. Commit.

```bash
git commit -m "feat(store): OrgTx + WorkerTx helpers (SET LOCAL app.org_id/bypass_rls) + tests"
```

---

## Task 21: `api.Server` struct refactor

This is a refactor: no new behavior. All existing tests must continue to pass.

**Files:**
- Modify: `internal/api/server.go`
- Modify: `internal/api/smoke_test.go` (update call sites)
- Modify: `cmd/cvert-ops/main.go` (update `api.NewRouter(st)` call)

**Step 1:** Run existing tests first to confirm they pass:

```bash
go test ./... -count=1 -timeout 120s
```
All pass.

**Step 2:** Refactor `internal/api/server.go`. Add the `Server` struct and `NewServer` constructor. Keep `NewRouter` as a deprecated wrapper for now — remove it once call sites are updated.

```go
// Server holds the dependencies for the HTTP layer.
type Server struct {
    store      *store.Store
    cfg        *config.Config
    argon2Sem  chan struct{}
}

// NewServer creates a Server. Returns an error if Google OIDC initialization fails.
// If cfg.GoogleClientID is empty, Google OIDC is skipped.
func NewServer(s *store.Store, cfg *config.Config) (*Server, error) {
    sem := make(chan struct{}, cfg.Argon2MaxConcurrent)
    // GitHub oauth2.Config and Google oidc.Provider initialization here.
    // For now (before OAuth tasks), just create the sem.
    return &Server{store: s, cfg: cfg, argon2Sem: sem}, nil
}

// Handler builds and returns the http.Handler. Replaces NewRouter.
func (srv *Server) Handler() http.Handler {
    // Move all existing NewRouter logic here.
    // Replace all uses of `s *store.Store` with `srv.store`.
}

// acquireArgon2 tries to acquire the argon2 semaphore. Returns false if all
// slots are in use — the caller should return 503 immediately (do NOT block).
func (srv *Server) acquireArgon2() bool {
    select {
    case srv.argon2Sem <- struct{}{}:
        return true
    default:
        return false
    }
}

func (srv *Server) releaseArgon2() { <-srv.argon2Sem }
```

**Step 3:** Update `NewRouter` to delegate to `NewServer` + `Handler()`:

```go
// NewRouter is kept for backward compatibility with existing tests.
// New code should use NewServer + Handler().
func NewRouter(s *store.Store) http.Handler {
    // Minimal config for when NewRouter is called without config (tests, nil store).
    cfg := &config.Config{Argon2MaxConcurrent: 5}
    srv, _ := NewServer(s, cfg)
    return srv.Handler()
}
```

**Step 4:** Update `cmd/cvert-ops/main.go` `runServe` to use `NewServer`:

Replace:
```go
handler := api.NewRouter(st)
```
with:
```go
apiSrv, err := api.NewServer(st, cfg)
if err != nil {
    return fmt.Errorf("api server init: %w", err)
}
handler := apiSrv.Handler()
```

**Step 5:** Run all existing tests — they should still pass:

```bash
go test ./... -count=1 -timeout 120s
golangci-lint run ./...
```

**Step 6: Commit**

```bash
git add internal/api/server.go internal/api/smoke_test.go cmd/cvert-ops/main.go
git commit -m "refactor(api): introduce Server struct — argon2Sem; all existing tests pass"
```

---

## Task 22: Rate limiter + in-memory per-IP limiting

**Files:**
- Create: `internal/api/ratelimit.go`
- Create: `internal/api/ratelimit_test.go`

**Step 1:** Write failing tests:

```go
// Test that /auth/login returns 429 after exceeding rate limit.
func TestRateLimitLogin(t *testing.T) { ... }
```

**Step 2:** Implement `internal/api/ratelimit.go` using `golang.org/x/time/rate` (already in go.mod):

```go
// ABOUTME: Per-IP in-memory rate limiter for auth endpoints.
// ABOUTME: Uses golang.org/x/time/rate with LRU eviction via a cleanup goroutine.
package api

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ipRateLimiter struct {
    mu       sync.Mutex
    limiters map[string]*rate.Limiter
    rate     rate.Limit
    burst    int
    evictTTL time.Duration
    lastSeen map[string]time.Time
}

func newIPRateLimiter(r rate.Limit, burst int, evictTTL time.Duration) *ipRateLimiter {
    rl := &ipRateLimiter{
        limiters: make(map[string]*rate.Limiter),
        lastSeen: make(map[string]time.Time),
        rate:     r, burst: burst, evictTTL: evictTTL,
    }
    go rl.cleanupLoop()
    return rl
}

func (rl *ipRateLimiter) Allow(ip string) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    l, ok := rl.limiters[ip]
    if !ok {
        l = rate.NewLimiter(rl.rate, rl.burst)
        rl.limiters[ip] = l
    }
    rl.lastSeen[ip] = time.Now()
    return l.Allow()
}

func (rl *ipRateLimiter) cleanupLoop() {
    ticker := time.NewTicker(rl.evictTTL / 2)
    defer ticker.Stop()
    for range ticker.C {
        rl.mu.Lock()
        cutoff := time.Now().Add(-rl.evictTTL)
        for ip, last := range rl.lastSeen {
            if last.Before(cutoff) {
                delete(rl.limiters, ip)
                delete(rl.lastSeen, ip)
            }
        }
        rl.mu.Unlock()
    }
}

// authRateLimit returns a chi middleware that applies per-IP rate limiting.
// IP is extracted from the request using chi's RealIP middleware (must be before this).
func (srv *Server) authRateLimit() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ip := r.RemoteAddr // RealIP middleware already set this
            if !srv.rateLimiter.Allow(ip) {
                w.Header().Set("Retry-After", "60")
                http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}
```

Add `rateLimiter *ipRateLimiter` to `Server` struct. Initialize in `NewServer`:

```go
evictTTL := time.Duration(cfg.RateLimitEvictTTL)
if evictTTL == 0 { evictTTL = 15 * time.Minute }
srv.rateLimiter = newIPRateLimiter(rate.Limit(10.0/60), 10, evictTTL) // 10/min
```

**Step 3:** Run tests. Commit.

```bash
git commit -m "feat(api): in-memory per-IP rate limiter for auth endpoints"
```

---

## Task 23: `RequireAuthenticated` middleware

**Files:**
- Create: `internal/api/middleware_auth.go`
- Create: `internal/api/middleware_auth_test.go`

**Step 1:** Define context keys:

```go
// internal/api/context.go
package api

type contextKey int
const (
    ctxUserID       contextKey = iota
    ctxOrgID
    ctxRole
    ctxAPIKeyRole   // role from API key (may differ from org role)
)
```

**Step 2:** Write failing tests:

```go
// Test: valid JWT cookie → 200 with user injected into context
// Test: no cookie, no Bearer → 401
// Test: expired JWT → 401
// Test: valid API key header → 200 with user injected
// Test: revoked API key → 401
```

**Step 3:** Implement `RequireAuthenticated`:

```go
// ABOUTME: HTTP middleware for authentication via JWT cookie or API key Bearer header.
// ABOUTME: Injects userID and (for API keys) keyRole into request context.
package api

import (
    "context"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/hex"
    "net/http"
    "strings"
    "time"
)

func (srv *Server) RequireAuthenticated() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Try API key first (Authorization: Bearer header)
            if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
                rawKey := strings.TrimPrefix(authHeader, "Bearer ")
                if srv.tryAPIKeyAuth(r.Context(), rawKey, w, r, next) {
                    return
                }
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }
            // Try JWT cookie
            cookie, err := r.Cookie("access_token")
            if err != nil {
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }
            claims, err := auth.ParseAccessToken(cookie.Value, []byte(srv.cfg.JWTSecret))
            if err != nil {
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }
            ctx := context.WithValue(r.Context(), ctxUserID, claims.UserID)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func (srv *Server) tryAPIKeyAuth(ctx context.Context, rawKey string, w http.ResponseWriter, r *http.Request, next http.Handler) bool {
    hash := HashAPIKey(rawKey) // from internal/auth
    key, err := srv.store.LookupAPIKey(ctx, hash)
    if err != nil || key == nil { return false }
    // Constant-time compare
    stored, _ := hex.DecodeString(key.KeyHash)
    incoming, _ := hex.DecodeString(hash)
    if subtle.ConstantTimeCompare(stored, incoming) != 1 { return false }
    // Async last_used update
    go func() {
        bgCtx := context.WithoutCancel(ctx)
        _ = srv.store.UpdateAPIKeyLastUsed(bgCtx, key.ID)
    }()
    ctx = context.WithValue(ctx, ctxUserID, key.CreatedByUserID) // or a dedicated field
    ctx = context.WithValue(ctx, ctxAPIKeyRole, key.Role)
    next.ServeHTTP(w, r.WithContext(ctx))
    return true
}
```

**Important note:** The API key's `CreatedByUserID` is NOT the authenticated user in the usual sense — API keys authenticate as an org+role, not as a specific user. Reconsider the design: API keys should have their own user association for audit. Use `key.CreatedByUserID` as the "acting user" for audit purposes.

**Step 4:** Run tests. Commit.

```bash
git commit -m "feat(api): RequireAuthenticated middleware (JWT cookie + API key) + tests"
```

---

## Task 24: `RequireOrgRole` middleware

**Files:**
- Create: `internal/api/middleware_rbac.go`
- Create: `internal/api/middleware_rbac_test.go`

**Step 1:** Define the `Role` type and ordering:

```go
// internal/api/role.go
package api

type Role int
const (
    RoleViewer Role = 1
    RoleMember Role = 2
    RoleAdmin  Role = 3
    RoleOwner  Role = 4
)

func parseRole(s string) Role {
    switch s {
    case "owner":  return RoleOwner
    case "admin":  return RoleAdmin
    case "member": return RoleMember
    default:       return RoleViewer
    }
}
```

**Step 2:** Write failing tests for `RequireOrgRole`:

```go
// Test: user with admin role accesses admin-gated endpoint → 200
// Test: user with viewer role accesses admin-gated endpoint → 403
// Test: user not in org → 403
// Test: API key role capped by org role (key.role=admin but org_role=viewer → viewer)
```

**Step 3:** Implement `RequireOrgRole`:

```go
// ABOUTME: RBAC middleware: checks org membership and enforces minimum role.
// ABOUTME: Effective role = min(orgRole, apiKeyRole) to prevent key escalation.
func (srv *Server) RequireOrgRole(minRole Role) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            userID, ok := r.Context().Value(ctxUserID).(uuid.UUID)
            if !ok {
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }
            orgID, err := uuid.Parse(chi.URLParam(r, "org_id"))
            if err != nil {
                http.Error(w, "invalid org_id", http.StatusBadRequest)
                return
            }
            roleStr, err := srv.store.GetOrgMemberRole(r.Context(), orgID, userID)
            if err != nil || roleStr == "" {
                http.Error(w, "forbidden", http.StatusForbidden)
                return
            }
            orgRole := parseRole(roleStr)
            effectiveRole := orgRole
            // If authenticated via API key, cap effective role
            if apiKeyRole, ok := r.Context().Value(ctxAPIKeyRole).(string); ok && apiKeyRole != "" {
                keyRole := parseRole(apiKeyRole)
                if keyRole < effectiveRole {
                    effectiveRole = keyRole
                }
            }
            if effectiveRole < minRole {
                http.Error(w, "forbidden", http.StatusForbidden)
                return
            }
            ctx := context.WithValue(r.Context(), ctxOrgID, orgID)
            ctx = context.WithValue(ctx, ctxRole, effectiveRole)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

**Step 4:** Run tests. Commit.

```bash
git commit -m "feat(api): RequireOrgRole middleware + effective role cap + tests"
```

---

## Task 25: Register handler + first-user org bootstrap

**Files:**
- Create: `internal/api/auth.go`
- Create: `internal/api/auth_test.go`

**Step 1:** Write failing test:

```go
func TestRegisterFirstUser(t *testing.T) {
    // POST /api/v1/auth/register with email + password
    // Expect: 201, user created, default org created, user is owner
    // Verify in DB: users row exists, organizations row exists, org_members row with role=owner
}

func TestRegisterDuplicateEmail(t *testing.T) {
    // Register same email twice → 409
}
```

**Step 2:** Implement `registerHandler` in `internal/api/auth.go`:

Key logic:
1. Validate email + password (min 8 chars)
2. Check if email already exists → 409 if so
3. Acquire argon2 semaphore → `srv.acquireArgon2()` → 503 if busy
4. `defer srv.releaseArgon2()`
5. `auth.HashPassword(password)`
6. `s.CreateUser(...)` — in a transaction if `REGISTRATION_MODE` requires first-user logic
7. If `REGISTRATION_MODE == "open"` and this is the first user: `s.CreateOrg(...)`, `s.CreateOrgMember(orgID, userID, "owner")`
8. Issue tokens, set cookies, return 201

**Huma handler pattern:**

```go
type registerInput struct {
    Body struct {
        Email       string `json:"email" required:"true" format:"email"`
        Password    string `json:"password" required:"true" minLength:"8"`
        DisplayName string `json:"display_name"`
    }
}

type registerOutput struct {
    Body struct {
        UserID string `json:"user_id"`
        OrgID  string `json:"org_id,omitempty"`
    }
}
```

Register with huma in `Handler()`:
```go
huma.Register(api, huma.Operation{
    Method: http.MethodPost,
    Path:   "/auth/register",
}, srv.registerHandler)
```

**Step 3:** Run tests. Lint. Commit.

```bash
git commit -m "feat(api): register handler + first-user org bootstrap + tests"
```

---

## Task 26: Login handler

**Files:**
- Modify: `internal/api/auth.go`
- Add to: `internal/api/auth_test.go`

**Step 1:** Failing tests:

```go
func TestLoginSuccess(t *testing.T) {
    // Register user, then POST /api/v1/auth/login
    // Expect: 200, access_token cookie set, refresh_token cookie set
}
func TestLoginWrongPassword(t *testing.T) { /* 401 */ }
func TestLoginNonexistentUser(t *testing.T) { /* 401 — same timing to avoid enumeration */ }
```

**CRITICAL:** Login failure for wrong password and nonexistent user MUST take the same amount of time. Without this, an attacker can detect whether an email is registered by timing the response. For nonexistent user, still call `argon2.IDKey` with a dummy hash to normalize timing.

**Step 2:** Implement `loginHandler`. Key steps:
1. Apply rate limiting (handled by middleware on this route)
2. `GetUserByEmail(email)`
3. If user not found: **still run argon2 verify on a dummy hash** to normalize timing → 401
4. If found: acquire argon2 sem → `auth.VerifyPassword(password, user.PasswordHash)` → release sem
5. If wrong: 401
6. If correct: `s.CreateRefreshToken(...)`, issue access + refresh JWTs, set cookies, return 200

**Cookie settings:** Always set `HttpOnly: true`. `Secure: cfg.CookieSecure`. `SameSite: http.SameSiteLaxMode`. Name: `access_token` and `refresh_token`.

**Step 3:** Run tests. Commit.

```bash
git commit -m "feat(api): login handler + JWT/cookie issuance + timing-safe tests"
```

---

## Task 27: Refresh + logout handlers

**Files:**
- Modify: `internal/api/auth.go`
- Add to: `internal/api/auth_test.go`

**Step 1:** Failing tests:

```go
func TestRefreshRotates(t *testing.T) {
    // Login, then POST /api/v1/auth/refresh with refresh_token cookie
    // Expect: new access + refresh cookies, old refresh JTI marked used
}
func TestRefreshTheftDetection(t *testing.T) {
    // Login, use refresh token, then attempt to use the SAME token again after 60s
    // Expect: 401, token_version incremented
}
func TestRefreshGraceWindow(t *testing.T) {
    // Login, use refresh token (marking it used), immediately use same token again
    // Expect: 200 (within 60s grace window — concurrent tab scenario)
}
func TestLogoutClearsCookies(t *testing.T) { ... }
```

**Step 2:** Implement `refreshHandler` per the PLAN.md §7.1 JTI flow:
1. Parse `refresh_token` cookie → `auth.ParseRefreshToken(...)` → extract JTI + version
2. `s.GetRefreshToken(jti)` — look up in DB
3. Three-case logic:
   - Not found / version mismatch → 401
   - `used_at IS NOT NULL` AND `now() - used_at ≤ 60s` AND `replaced_by_jti != nil` → grace window: issue new access token using `replaced_by_jti` as the new refresh, return 200
   - `used_at IS NOT NULL` (> 60s or no replacement) → theft detected: `IncrementTokenVersion(userID)` → 401
   - `used_at IS NULL` → consume: `MarkRefreshTokenUsed(jti, newJTI)`, insert new refresh token, issue new access + refresh pair

**Step 3:** Implement `logoutHandler`:
1. Parse refresh cookie (ignore errors — just clear cookies)
2. `MarkRefreshTokenUsed(jti, jti)` to invalidate (mark it used with itself as replacement, no new token)
3. Clear both cookies (set `MaxAge: -1`)
4. Return 200

**Step 4:** Run tests. Commit.

```bash
git commit -m "feat(api): refresh + logout handlers + token rotation + theft detection tests"
```

---

## Task 28: `/auth/me` + `/user/orgs`

**Files:**
- Modify: `internal/api/auth.go`
- Add to: `internal/api/auth_test.go`

**Step 1:** Failing tests:

```go
func TestGetMe(t *testing.T) {
    // Login, GET /api/v1/auth/me with access_token cookie
    // Expect: 200 with user_id, email, display_name, orgs[]
}
```

**Step 2:** Implement behind `RequireAuthenticated()`:

```go
// GET /api/v1/auth/me
// Returns the current user's profile and org memberships.
type meOutput struct {
    Body struct {
        UserID      string `json:"user_id"`
        Email       string `json:"email"`
        DisplayName string `json:"display_name"`
        Orgs        []struct {
            OrgID string `json:"org_id"`
            Name  string `json:"name"`
            Role  string `json:"role"`
        } `json:"orgs"`
    }
}
```

**Step 3:** Run tests. Commit.

```bash
git commit -m "feat(api): /auth/me + /user/orgs + tests"
```

---

## Task 29: Change-password handler

**Files:**
- Modify: `internal/api/auth.go`
- Add to: `internal/api/auth_test.go`

**Step 1:** Write failing tests:

```go
func TestChangePassword_Success(t *testing.T) {
    // Register + login. POST /auth/change-password with correct old + new password.
    // Expect: 200. Verify new password works on subsequent login.
}

func TestChangePassword_WrongCurrentPassword(t *testing.T) {
    // Attempt change-password with wrong current password.
    // Expect: 401 (must verify old password first).
}

func TestChangePassword_InvalidatesRefreshTokens(t *testing.T) {
    // Register + login (obtaining refresh_token cookie).
    // Change password.
    // Attempt POST /auth/refresh with the old refresh token.
    // Expect: 401 (token_version was incremented, old refresh token invalid).
}
```

**Step 2:** Implement. Key points:
- Verify current password first (argon2 semaphore)
- Hash new password (argon2 semaphore)
- `UpdatePasswordHash(userID, newHash, 2)` — also increments `token_version` (in the sqlc query)
- The old access token becomes valid until expiry (≤15 min), but refresh tokens are now invalid
- Return 200

**Step 3:** Run tests. Commit.

```bash
git commit -m "feat(api): change-password + token_version revocation + tests"
```

---

## Task 30: Org management API — org CRUD

**Files:**
- Create: `internal/api/orgs.go`
- Create: `internal/api/orgs_test.go`

**Step 1:** Implement `POST /api/v1/orgs` (create org, creator becomes owner), `GET /api/v1/orgs/{org_id}`, `PATCH /api/v1/orgs/{org_id}`.

Route wiring in `Handler()`:

```go
apiRouter.Route("/orgs", func(r chi.Router) {
    r.Use(srv.RequireAuthenticated())
    r.Post("/", srv.createOrgHandler)

    r.Route("/{org_id}", func(r chi.Router) {
        r.Use(srv.RequireOrgRole(RoleViewer))
        r.Get("/", srv.getOrgHandler)
        r.With(srv.RequireOrgRole(RoleAdmin)).Patch("/", srv.updateOrgHandler)
        // members, invitations, api-keys, groups routes added below
    })
})
```

**Step 2:** Tests: create org + verify creator is owner, get org, update org name (admin), update org (viewer → 403).

```bash
git commit -m "feat(api): org create/read/update + tests"
```

---

## Task 31: Member management API

**Files:**
- Modify: `internal/api/orgs.go`

Key endpoints:
- `GET /api/v1/orgs/{org_id}/members` — any member (viewer+)
- `PATCH /api/v1/orgs/{org_id}/members/{user_id}` — admin+; cannot assign role > own role; cannot change owner role (use transfer endpoint for that)
- `DELETE /api/v1/orgs/{org_id}/members/{user_id}` — admin+; cannot remove sole owner (check `GetOrgMemberCount` for owner count)

```bash
git commit -m "feat(api): member list, update-role, remove + tests"
```

---

## Task 32: Invitation API

**Files:**
- Modify: `internal/api/orgs.go`

Key points:
- `POST /api/v1/orgs/{org_id}/invitations` — admin+; **always returns 202** regardless of whether email is registered; creates `org_invitations` row; response NEVER reveals if email is in the system
- Generate token: `crypto/rand` 32 bytes, hex-encoded
- `expires_at = now() + 7 days`
- Email delivery is deferred to Phase 3 (just create the record for now)
- `GET /api/v1/auth/invitations/{token}` — public; returns org name + role + expiry (NOT org_id or other sensitive info until accepted)
- `POST /api/v1/auth/invitations/{token}/accept` — requires `RequireAuthenticated()`; creates `org_members` row; marks invitation accepted; idempotent

```bash
git commit -m "feat(api): invitation list, cancel, public get, accept + tests"
```

---

## Task 33: API key management API

**Files:**
- Create: `internal/api/apikeys.go`
- Create: `internal/api/apikeys_test.go`

Key points:
- `POST /api/v1/orgs/{org_id}/api-keys` — member+; `role` in request body must be ≤ caller's effective role; raw key returned in `raw_key` response field **exactly once**
- `GET /api/v1/orgs/{org_id}/api-keys` — viewer+; never returns `key_hash`; returns id, name, role, expires_at, last_used_at, revoked_at
- `DELETE /api/v1/orgs/{org_id}/api-keys/{id}` — own keys or admin+

Huma note: The `raw_key` field in the create response is sensitive — add a comment in the OpenAPI description noting that the key is shown exactly once.

```bash
git commit -m "feat(api): API key list, create, revoke + raw key shown once + tests"
```

---

## Task 34: Groups API

**Files:**
- Create: `internal/api/groups.go`
- Create: `internal/api/groups_test.go`

Endpoints:
- `GET/POST /api/v1/orgs/{org_id}/groups` — GET = viewer+; POST = admin+
- `GET/PATCH/DELETE /api/v1/orgs/{org_id}/groups/{group_id}` — GET = viewer+; write = admin+; DELETE is soft-delete
- `GET/POST/DELETE /api/v1/orgs/{org_id}/groups/{group_id}/members` — GET = viewer+; write = admin+

```bash
git commit -m "feat(api): group CRUD + soft-delete + tests"
git commit -m "feat(api): group member add/remove/list + tests"
```

---

## Task 35: OAuth cookie helpers + state/nonce generation

**Files:**
- Create: `internal/api/oauth_helpers.go`

These helpers are used by both GitHub and Google OAuth handlers:

```go
// ABOUTME: OAuth helper functions: state/nonce generation, cookie management.
// ABOUTME: Used by GitHub OAuth2 and Google OIDC flow handlers.
package api

import (
    "crypto/rand"
    "encoding/hex"
    "net/http"
    "time"
)

// generateOAuthState generates 32 random bytes as a hex string for the OAuth state param.
func generateOAuthState() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil { return "", err }
    return hex.EncodeToString(b), nil
}

// setStateCookie sets the oauth_state HttpOnly cookie with a 5-minute expiry.
// SameSite=Lax is REQUIRED (not Strict) — the callback is a cross-site redirect.
func (srv *Server) setStateCookie(w http.ResponseWriter, state string) {
    http.SetCookie(w, &http.Cookie{
        Name:     "oauth_state",
        Value:    state,
        HttpOnly: true,
        Secure:   srv.cfg.CookieSecure,
        SameSite: http.SameSiteLaxMode,  // NOT Strict — cross-site callback
        MaxAge:   300, // 5 minutes
        Path:     "/",
    })
}

// validateStateCookie reads and deletes the oauth_state cookie, returning the state value.
// Returns an error if the cookie is missing or doesn't match the query param.
func (srv *Server) validateStateCookie(r *http.Request, w http.ResponseWriter, stateParam string) error { ... }

// setNonceCookie sets the oidc_nonce cookie for Google OIDC nonce verification.
func (srv *Server) setNonceCookie(w http.ResponseWriter, nonce string) { ... }

// validateNonceCookie reads and deletes the oidc_nonce cookie.
func (srv *Server) validateNonceCookie(r *http.Request, w http.ResponseWriter) (string, error) { ... }
```

```bash
git commit -m "feat(api): OAuth cookie helpers + state/nonce generation"
```

---

## Task 36: GitHub OAuth2 handler

**Files:**
- Modify: `internal/api/server.go` (add `ghOAuth *oauth2.Config` to Server)
- Create: `internal/api/oauth_github.go`
- Create: `internal/api/oauth_github_test.go`

**Step 1:** Add GitHub OAuth config init to `NewServer`:

```go
// In NewServer, if cfg.GitHubClientID != "":
srv.ghOAuth = &oauth2.Config{
    ClientID:     cfg.GitHubClientID,
    ClientSecret: cfg.GitHubClientSecret,
    RedirectURL:  cfg.ExternalURL + "/api/v1/auth/oauth/github/callback",
    Endpoint:     github.Endpoint,
    Scopes:       []string{"user:email"}, // REQUIRED — do not omit (PLAN.md §7.2)
}
```

**Step 2:** Write failing test using `httptest.Server` to mock GitHub endpoints:

```go
func TestGitHubOAuthFlow(t *testing.T) {
    // Mock GitHub /authorize redirect, token exchange, /user, /user/emails
    // Test the full callback → user upsert → JWT issuance flow
}
```

**Step 3:** Implement `oauth_github.go`:

`GET /api/v1/auth/oauth/github` (init):
1. Check `srv.ghOAuth != nil` → 501 if GitHub not configured
2. Generate state → `setStateCookie`
3. Redirect to `srv.ghOAuth.AuthCodeURL(state)`

`GET /api/v1/auth/oauth/github/callback`:
1. `validateStateCookie(r, w, r.URL.Query().Get("state"))` → 400 if invalid
2. Exchange code: `srv.ghOAuth.Exchange(ctx, code)`
3. `GET https://api.github.com/user` with token → get `id` (numeric) and `login`
4. `GET https://api.github.com/user/emails` → find `primary: true, verified: true` entry
5. `GetUserByProviderID(ctx, "github", strconv.Itoa(githubID))`
6. If not found: create new user (no password hash), `UpsertUserIdentity`
7. If found: `UpsertUserIdentity` to update email (it may have changed)
8. Issue tokens, set cookies, redirect to frontend (or return 200 for API clients)

**CRITICAL:** Match on `provider_user_id = strconv.Itoa(githubID)` — NEVER match by email (PLAN.md §7.2).

**Step 4:** Run tests. Commit.

```bash
git commit -m "feat(api): GitHub OAuth2 init + callback + identity upsert + tests"
```

---

## Task 37: Google OIDC handler

**Files:**
- Modify: `internal/api/server.go` (add `googleOIDC *oidc.Provider`)
- Create: `internal/api/oauth_google.go`
- Create: `internal/api/oauth_google_test.go`

**Step 1:** Add Google OIDC provider init to `NewServer` with retry loop:

```go
// In NewServer, if cfg.GoogleClientID != "":
var googleProvider *oidc.Provider
for attempt := 1; attempt <= 5; attempt++ {
    googleProvider, err = oidc.NewProvider(ctx, "https://accounts.google.com")
    if err == nil { break }
    slog.Warn("google oidc provider init failed, retrying", "attempt", attempt, "err", err)
    time.Sleep(time.Duration(attempt) * time.Second)
}
if err != nil { return nil, fmt.Errorf("google oidc provider: %w", err) }
srv.googleOIDC = googleProvider
srv.googleOAuth = &oauth2.Config{
    ClientID:     cfg.GoogleClientID,
    ClientSecret: cfg.GoogleClientSecret,
    RedirectURL:  cfg.ExternalURL + "/api/v1/auth/oauth/google/callback",
    Endpoint:     googleProvider.Endpoint(),
    Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
}
```

**Step 2:** Implement `oauth_google.go`:

`GET /api/v1/auth/oauth/google` (init):
1. Generate state + nonce
2. `setStateCookie`, `setNonceCookie`
3. Redirect with nonce: `srv.googleOAuth.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce))`

`GET /api/v1/auth/oauth/google/callback`:
1. `validateStateCookie(r, w, state)`
2. Exchange code → get token
3. Extract ID token: `rawIDToken, ok := token.Extra("id_token").(string)`
4. `srv.googleOIDC.Verifier(&oidc.Config{ClientID: srv.cfg.GoogleClientID}).Verify(ctx, rawIDToken)`
5. Extract claims: `idToken.Claims(&struct{ Sub, Email string }{})`
6. **NONCE VERIFICATION (required):** `validateNonceCookie(r, w)` → compare to nonce claim in ID token → 400 if mismatch
7. `GetUserByProviderID(ctx, "google", googleSub)` (sub = immutable Google Account ID)
8. Upsert user identity, issue tokens, set cookies

**CRITICAL from PLAN.md §7.2:**
- Nonce must be verified BEFORE calling `oidcVerifier.Verify()` — actually the nonce should be part of the `Verify` call parameters or checked manually from the extracted claims after verification
- Match on `sub` claim, NEVER on email

```bash
git commit -m "feat(api): Google OIDC init + callback + nonce verification + tests"
```

---

## Final verification steps

After all tasks are complete:

**Step 1:** Run full test suite:

```bash
go test ./... -count=1 -timeout 300s
```
All tests must pass.

**Step 2:** Run linter:

```bash
golangci-lint run ./...
```
Zero errors.

**Step 3:** Build the binary:

```bash
go build ./cmd/cvert-ops
```

**Step 4:** Run migrations against a fresh dev DB:

```bash
docker compose -f docker/compose.yml --env-file .env up -d
migrate -path migrations -database "$DATABASE_URL_MIGRATE" up
migrate -path migrations -database "$DATABASE_URL_MIGRATE" version
```
Expected: version 11.

**Step 5:** Run `pitfall-check` skill to check business logic against known pitfalls.

**Step 6:** Run `plan-check` skill specifying PLAN.md §6 + §7.

**Step 7:** Run `security-review` skill on the auth code.

---

## Commit summary

~37 commits produced. Branch: `dev`. When all tasks are complete, invoke `superpowers:finishing-a-development-branch`.

---

## Key reference: PLAN.md requirements checklist

Before marking Phase 2a complete, verify each required item from PLAN.md §7:

- [ ] JWT `WithValidMethods(["HS256"])` + `WithExpirationRequired()` on EVERY `ParseWithClaims` call
- [ ] `JWT_SECRET` missing → `log.Fatalf` at startup (never auto-generate)
- [ ] Argon2 semaphore is non-blocking (immediate 503, never queues)
- [ ] API key comparison uses `subtle.ConstantTimeCompare`
- [ ] `refresh_tokens` JTI table with grace window + theft detection
- [ ] OAuth2 `state` parameter on GitHub + Google; validated before code exchange
- [ ] OIDC nonce verified (Google only) before accepting ID token
- [ ] OAuth redirect URI from `EXTERNAL_URL` config, never from `r.Host`
- [ ] GitHub OAuth includes `user:email` scope
- [ ] Identity matching on `provider_user_id` (GitHub numeric ID, Google `sub`) — NEVER email
- [ ] `SameSite=Lax` (not Strict) on OAuth state/nonce cookies
- [ ] `SET LOCAL app.org_id` inside `OrgTx` for every org-scoped transaction
- [ ] `FORCE ROW LEVEL SECURITY` on all org-scoped tables
- [ ] `app.org_id` unset → fail-closed (0 rows, not error)
- [ ] `WorkerTx` (bypass_rls) ONLY called from worker code paths
- [ ] `org_id` denormalized on `group_members` (and all future child tables)
- [ ] Invitation flow never reveals whether email is registered
- [ ] API key effective role = min(key.role, currentOrgRole)
- [ ] Rate limiting on login, register, refresh endpoints
