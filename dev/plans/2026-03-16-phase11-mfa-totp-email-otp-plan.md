# MFA (TOTP + Email OTP + Recovery Codes) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add multi-factor authentication to CVErt Ops native accounts — TOTP, email OTP, one-time recovery codes, forced password reset via restricted sessions, and 3-layer enforcement.

**Architecture:** MFA gates the login flow via a short-lived "pending token" JWT carrying a `pending` array of requirements to clear sequentially. Four new global tables (`mfa_credentials`, `mfa_recovery_codes`, `mfa_challenges`, `mfa_requirements`), three new columns on `users`/`organizations`, and ~15 new API endpoints. The existing `auth.Writer` pattern handles audit logging; `secure/events.go` gets new event type constants.

**Tech Stack:** Go 1.26, PostgreSQL 15+, `golang-jwt/jwt/v5`, `pquerna/otp` (TOTP), `crypto/aes` (AES-256-GCM via `internal/crypto`), `wneessen/go-mail` (email delivery), huma/chi (HTTP), sqlc (queries).

**Design doc:** `dev/plans/2026-03-16-mfa-totp-email-otp-design.md`

---

## Mandatory Agent Instructions

**EVERY agent executing tasks from this plan MUST follow these instructions exactly.**

### Before Starting Any Work

1. Read the `superpowers:test-driven-development` skill (`Skill` tool) and follow it for ALL implementation.
2. Read `dev/testing-pitfalls.md` in full. Keep its checklist in mind for every test you write.
3. Read `dev/implementation-pitfalls.md` §1.11 (omitempty on PATCH), §2.4 (RLS bypass), §2.17 (transaction helper selection). These are directly relevant.
4. Read the design doc: `dev/plans/2026-03-16-mfa-totp-email-otp-design.md` — the authoritative specification for all MFA behavior.

### After Every Logical Group of Tasks

You MUST carefully review the batch of work from multiple perspectives and revise/refine as appropriate. Repeat this review loop (you must do a minimum of three review rounds; if you still find substantative issues in the third review, keep going with additional rounds until there are no findings) until you're confident there aren't any more issues. Then update your private journal and continue onto the next tasks.

**Mandatory QA check:** Before completing each batch, review your tests and test coverage against `dev/testing-pitfalls.md`. For each relevant section in that document, confirm your tests address it or document why it doesn't apply. Specifically check:
- §1 (Concurrency & TOCTOU) — recovery code consumption, email OTP consumption, rate limits
- §2 (Negative Property) — case sensitivity on emails, cleanup of expired challenges
- §3 (Error Path Differentiation) — anti-enumeration on MFA verify, error swallowing
- §4 (Validation Symmetry) — enrollment vs management validation consistency
- §6 (Data Lifecycle) — expired challenge filtering, soft-delete awareness
- §7 (Transaction & Store) — correct transaction helper usage in every store method
- §10 (RLS & Tenant Isolation) — mfa_requirements through AppStore (NOBYPASSRLS)
- §11 (Security Enforcement) — RBAC on admin endpoints, constant-time comparisons
- §13 (Feature Flag Enforcement) — force_password_reset checked at ALL entry points

### After Normal Final Verification Steps

You MUST carefully review the work across ALL batches from multiple perspectives and revise/refine as appropriate. Repeat this review loop (you must do a minimum of three review rounds; if you still find substantative issues in the third review, keep going with additional rounds until there are no findings) until you're confident there aren't any more issues, then proceed with /finishing-a-development-branch

---

## Dependency: `pquerna/otp` Library

TOTP implementation uses `github.com/pquerna/otp` — a well-maintained Go TOTP/HOTP library (RFC 6238/4226). Before starting Task 3, the executing agent MUST verify this dependency is current via web search per CLAUDE.md §Third-Party Dependencies. If it's archived or unmaintained, stop and ask Sam.

**Do NOT hand-roll TOTP.** The RFC 6238 implementation has subtle edge cases (time step calculation, base32 padding, URI encoding) that `pquerna/otp` handles correctly.

---

## File Conventions Reference

All agents must follow these patterns exactly. When in doubt, read the referenced file for the authoritative pattern.

### Store Methods

- **Global auth tables (no RLS):** Use `withBypassTx` — see `internal/store/auth.go` for pattern.
- **Org-scoped tables (RLS):** Use `withOrgTx` for API handler paths, `withBypassTx` for login-time cross-org checks.
- **Never access `s.db` or `s.q` directly** — always go through a transaction helper.
- sqlc queries go in `internal/store/queries/<topic>.sql`. Run `sqlc generate` after any `.sql` change.

### API Handlers

- Huma input/output structs with json/format/doc tags — see `internal/api/auth.go` lines 92-99.
- Route registration via `huma.Register()` in a `registerXxxRoutes(api, srv)` function — see `internal/api/auth.go` line 773+.
- Cookie responses via `SetCookie []string \`header:"Set-Cookie"\`` on output struct.
- Rate limiting via `srv.checkAuthRateLimit(ctx)` on all public auth endpoints.

### Tests

- Integration tests use `testutil.NewTestDB(t)` for a real Postgres container.
- Full HTTP stack via `httptest.NewServer(srv.Handler())`.
- Auth test helpers: `doRegister()`, `doLogin()`, `cookieValue()` — see `internal/api/auth_test.go`.
- **RLS tests:** Use `db.AppStore` (NOBYPASSRLS connection), not `db.Store` (superuser).
- **Test output must be pristine.** Expected errors must be captured and validated.

### Migrations

- File naming: `000NNN_description.{up,down}.sql` — next number is `000039`.
- `-- migrate:no-transaction` as first line (required for CONCURRENTLY indexes).
- `CREATE TABLE IF NOT EXISTS`, `CREATE INDEX CONCURRENTLY IF NOT EXISTS`.
- `GRANT ... TO cvert_ops_app` for every new table.
- Down migration drops in reverse dependency order.

### Security Events

- Add constants to `internal/secure/events.go` following existing pattern.
- Log via `srv.auditWriter.Log(ctx, audit.Entry{...})` — the audit writer is non-blocking and detaches from request context.
- Until a dedicated security_events table exists, MFA events use the audit_log table with `EntityType: "security_event"` and the event type as `Action`.

### Config

- Add new fields to `internal/config/config.go` Config struct with `env:"..."` and `envDefault:"..."` tags.
- Follow the existing grouping pattern (see `// ── Auth — ...` comment sections).

---

## Task Dependency Graph

```
Task 1 (Config) ─────────┐
Task 2 (Migration) ──────┤
                          ├─→ Task 4 (Store: MFA credentials)
Task 3 (TOTP package) ───┤   Task 5 (Store: Recovery codes)
                          │   Task 6 (Store: Challenges)
                          │   Task 7 (Store: Requirements)
                          │   Task 8 (Store: Mandate check)
                          │   Task 9 (Pending token JWT)
                          │
                          ├─→ Task 10 (Login handler modification)
                          │   Task 11 (MFA challenge + verify handlers)
                          │   Task 12 (TOTP enrollment handlers)
                          │   Task 13 (Email OTP enrollment handlers)
                          │   Task 14 (MFA management handlers)
                          │   Task 15 (Recovery code handlers)
                          │
                          ├─→ Task 16 (Middleware: pending token routing)
                          │   Task 17 (Password change handler modification)
                          │   Task 18 (Admin: MFA reset + force password reset)
                          │   Task 19 (Admin: MFA requirements + org settings)
                          │   Task 20 (Remember-device)
                          │   Task 21 (Security events + audit logging)
                          │   Task 22 (Expired challenge cleanup worker)
                          │
                          └─→ Task 23 (Integration: full flow tests)
                              Task 24 (Final review + lint + commit)
```

**Parallelizable groups:**
- Tasks 4–9 are independent store-layer tasks (parallelizable)
- Tasks 10–15 depend on store tasks but are mostly independent of each other
- Tasks 16–22 depend on earlier handler tasks
- Tasks 23–24 are sequential and final

---

## Task 1: Add MFA Config Fields

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

**Context:** The Config struct uses `caarlos0/env/v11` with struct tags. Read `internal/config/config.go` to see the existing pattern. MFA config fields are defined in the design doc §Site-Level Configuration.

### Step 1: Write the failing test

Add a test in `internal/config/config_test.go` that sets MFA-related env vars and verifies they're parsed correctly.

```go
func TestMFAConfigDefaults(t *testing.T) {
	// Set only required vars, let MFA fields use defaults
	t.Setenv("JWT_SECRET", "test-secret-min-32-chars-long-xx")
	t.Setenv("DATABASE_URL", "postgres://localhost/test")

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.False(t, cfg.MFARequiredSiteAdmins)
	assert.False(t, cfg.MFARequiredOrgOwners)
	assert.Equal(t, 10*time.Minute, cfg.MFAEmailOTPTTL)
	assert.Equal(t, 5, cfg.MFAEmailOTPMaxPerHour)
	assert.Equal(t, 3, cfg.MFAChallengeMaxAttempts)
	assert.Equal(t, 5*time.Minute, cfg.MFAPendingTokenTTL)
}
```

### Step 2: Run test to verify it fails

```bash
go test ./internal/config/... -run TestMFAConfigDefaults -v -count=1
```
Expected: FAIL — `cfg.MFAEmailOTPTTL` is zero value (field doesn't exist yet).

### Step 3: Add MFA config fields

In `internal/config/config.go`, add a new section after the existing auth config block:

```go
// ── Auth — MFA ───────────────────────────────────────────────────────────
MFARequiredSiteAdmins   bool          `env:"MFA_REQUIRED_SITE_ADMINS" envDefault:"false"`
MFARequiredOrgOwners    bool          `env:"MFA_REQUIRED_ORG_OWNERS" envDefault:"false"`
MFAEmailOTPTTL          time.Duration `env:"MFA_EMAIL_OTP_TTL" envDefault:"10m"`
MFAEmailOTPMaxPerHour   int           `env:"MFA_EMAIL_OTP_MAX_PER_HOUR" envDefault:"5"`
MFAChallengeMaxAttempts int           `env:"MFA_CHALLENGE_MAX_ATTEMPTS" envDefault:"3"`
MFAPendingTokenTTL      time.Duration `env:"MFA_PENDING_TOKEN_TTL" envDefault:"5m"`
```

### Step 4: Run test to verify it passes

```bash
go test ./internal/config/... -run TestMFAConfigDefaults -v -count=1
```
Expected: PASS

### Step 5: Commit

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add MFA configuration fields

Add env-var-backed config for MFA enforcement, email OTP timing,
challenge attempt limits, and pending token TTL."
```

---

## Task 2: Database Migration — MFA Tables

**Files:**
- Create: `migrations/000039_create_mfa_tables.up.sql`
- Create: `migrations/000039_create_mfa_tables.down.sql`

**Context:** Read `migrations/000038_relax_cve_sources_source_name_check.up.sql` to confirm the previous migration number. Read the design doc §Data Model for the exact table definitions. Read `migrations/000005_create_users.up.sql` for the table creation pattern.

**CRITICAL:** Every `CREATE INDEX` MUST use `CONCURRENTLY`. The file MUST start with `-- migrate:no-transaction`. These are project conventions — violating them will break CI.

### Step 1: Write the up migration

Create `migrations/000039_create_mfa_tables.up.sql`:

```sql
-- migrate:no-transaction
-- ABOUTME: MFA tables for TOTP, email OTP, recovery codes, challenges, and per-member requirements.
-- ABOUTME: See dev/plans/2026-03-16-mfa-totp-email-otp-design.md for design rationale.

-- mfa_credentials: one row per enrolled MFA method per user (global, no RLS)
CREATE TABLE IF NOT EXISTS mfa_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method          TEXT NOT NULL,
    secret_enc      BYTEA,
    last_used_step  BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    UNIQUE(user_id, method),
    CONSTRAINT mfa_cred_method      CHECK (method IN ('totp', 'email_otp')),
    CONSTRAINT mfa_cred_totp_secret CHECK (method != 'totp' OR secret_enc IS NOT NULL),
    CONSTRAINT mfa_cred_email_null  CHECK (method != 'email_otp' OR (secret_enc IS NULL AND last_used_step IS NULL))
);

GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_credentials TO cvert_ops_app;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_credentials_user_id ON mfa_credentials(user_id);

-- mfa_recovery_codes: per-user one-time recovery codes (global, no RLS)
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash       TEXT NOT NULL,
    used_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, code_hash)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_recovery_codes TO cvert_ops_app;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_recovery_codes_user_id ON mfa_recovery_codes(user_id);

-- mfa_challenges: active email OTP codes and remember-device tokens (global, no RLS)
CREATE TABLE IF NOT EXISTS mfa_challenges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_type  TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    attempts        INT NOT NULL DEFAULT 0,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT mfa_challenge_type CHECK (challenge_type IN ('email_otp', 'remember_device'))
);

GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_challenges TO cvert_ops_app;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_challenges_user_id ON mfa_challenges(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at);

-- mfa_requirements: per-member MFA mandates set by org owners/admins (org-scoped, RLS)
CREATE TABLE IF NOT EXISTS mfa_requirements (
    org_id          UUID NOT NULL,
    user_id         UUID NOT NULL,
    required_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id, user_id) REFERENCES org_members(org_id, user_id) ON DELETE CASCADE
);

ALTER TABLE mfa_requirements ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_requirements FORCE ROW LEVEL SECURITY;
CREATE POLICY mfa_requirements_policy ON mfa_requirements
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

GRANT SELECT, INSERT, DELETE ON mfa_requirements TO cvert_ops_app;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_requirements_user_id ON mfa_requirements(user_id);

-- Add force_password_reset column to users (if not already present from earlier migration)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'force_password_reset'
    ) THEN
        ALTER TABLE users ADD COLUMN force_password_reset BOOLEAN NOT NULL DEFAULT FALSE;
    END IF;
END$$;

-- Add org-level MFA settings
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS mfa_required_all BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS mfa_remember_device_allowed BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS mfa_remember_device_days INT NOT NULL DEFAULT 30;

-- Add CHECK constraint for remember device days range (idempotent via DO block)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.constraint_column_usage
        WHERE table_name = 'organizations' AND constraint_name = 'mfa_remember_days_range'
    ) THEN
        ALTER TABLE organizations ADD CONSTRAINT mfa_remember_days_range
            CHECK (mfa_remember_device_days BETWEEN 7 AND 90);
    END IF;
END$$;
```

### Step 2: Write the down migration

Create `migrations/000039_create_mfa_tables.down.sql`:

```sql
-- migrate:no-transaction
-- ABOUTME: Rollback MFA tables and org-level MFA columns.
-- ABOUTME: Drops in reverse dependency order.

-- Drop org-level MFA columns
ALTER TABLE organizations DROP CONSTRAINT IF EXISTS mfa_remember_days_range;
ALTER TABLE organizations DROP COLUMN IF EXISTS mfa_remember_device_days;
ALTER TABLE organizations DROP COLUMN IF EXISTS mfa_remember_device_allowed;
ALTER TABLE organizations DROP COLUMN IF EXISTS mfa_required_all;

-- Note: force_password_reset on users is NOT dropped here because it was
-- added in migration 000036 and may be used by other features.

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS mfa_requirements;
DROP TABLE IF EXISTS mfa_challenges;
DROP TABLE IF EXISTS mfa_recovery_codes;
DROP TABLE IF EXISTS mfa_credentials;
```

### Step 3: Run migration against dev database

```bash
go run ./cmd/cvert-ops migrate
```
Expected: Migration 000039 applied successfully.

### Step 4: Verify tables exist

```bash
# Use psql or the app's DB connection to check
go test ./internal/store/... -run TestNewTestDB -v -count=1 2>&1 | head -20
```

The test database setup runs all migrations. If any test that uses `testutil.NewTestDB` passes, the migration is syntactically valid.

### Step 5: Commit

```bash
git add migrations/000039_create_mfa_tables.up.sql migrations/000039_create_mfa_tables.down.sql
git commit -m "feat(migration): add MFA tables and org-level MFA columns

Creates mfa_credentials, mfa_recovery_codes, mfa_challenges,
mfa_requirements tables. Adds mfa_required_all, remember-device
settings to organizations."
```

---

## Task 3: Add `pquerna/otp` Dependency

**Files:**
- Modify: `go.mod`, `go.sum`

### Step 1: Verify dependency status

Before adding, web-search to verify `github.com/pquerna/otp` is actively maintained:
- Check last commit date, open issues, release history
- Confirm no known CVEs or security advisories
- If the library is archived or unmaintained, STOP and ask Sam

### Step 2: Add the dependency

```bash
go get github.com/pquerna/otp
```

### Step 3: Verify it imported cleanly

```bash
go build ./...
```

### Step 4: Commit

```bash
git add go.mod go.sum
git commit -m "deps: add pquerna/otp for RFC 6238 TOTP support"
```

---

## Task 4: Store Layer — MFA Credentials

**Files:**
- Create: `internal/store/queries/mfa.sql`
- Create: `internal/store/mfa.go`
- Create: `internal/store/mfa_test.go`

**Context:** Read `internal/store/queries/auth.sql` and `internal/store/auth.go` for the query and store method patterns. All MFA credential operations use `withBypassTx` because `mfa_credentials` is a global table (no RLS). Read the design doc §Data Model for the `mfa_credentials` table definition.

### Step 1: Write sqlc queries

Create `internal/store/queries/mfa.sql`:

```sql
-- ABOUTME: sqlc queries for MFA credential management.
-- ABOUTME: Used by store/mfa.go — global tables, no RLS.

-- name: GetMFACredentialsByUserID :many
SELECT * FROM mfa_credentials WHERE user_id = $1 ORDER BY created_at;

-- name: GetMFACredentialByUserAndMethod :one
SELECT * FROM mfa_credentials WHERE user_id = $1 AND method = $2;

-- name: CreateMFACredential :one
INSERT INTO mfa_credentials (user_id, method, secret_enc)
VALUES ($1, $2, $3)
RETURNING *;

-- name: UpdateMFACredentialLastUsed :exec
UPDATE mfa_credentials
SET last_used_step = $2, last_used_at = now()
WHERE id = $1;

-- name: DeleteMFACredential :execrows
DELETE FROM mfa_credentials WHERE user_id = $1 AND method = $2;

-- name: DeleteAllMFACredentials :execrows
DELETE FROM mfa_credentials WHERE user_id = $1;

-- name: UserHasMFACredentials :one
SELECT EXISTS(SELECT 1 FROM mfa_credentials WHERE user_id = $1) AS has_mfa;

-- name: CountMFACredentialsByUser :one
SELECT COUNT(*) FROM mfa_credentials WHERE user_id = $1;
```

### Step 2: Run sqlc generate

```bash
sqlc generate
```
Expected: Clean generation. If errors, fix the SQL syntax and retry.

### Step 3: Write store wrapper methods and tests (TDD)

Create `internal/store/mfa.go` with methods that wrap the generated queries inside `withBypassTx`. Each method should:
- Accept `ctx context.Context` and relevant parameters
- Use `withBypassTx` for all operations (global table, no org scope)
- Return appropriate types

Create `internal/store/mfa_test.go` with integration tests using `testutil.NewTestDB(t)`. Test:

1. **Create and retrieve credential** — insert TOTP credential with encrypted secret, verify retrieval
2. **Unique constraint** — inserting duplicate `(user_id, method)` returns an error
3. **CHECK constraint enforcement** — inserting `email_otp` with non-nil `secret_enc` fails; inserting `totp` with nil `secret_enc` fails
4. **Update last_used_step** — verify timestamp and step update
5. **Delete single method** — delete TOTP, verify email_otp remains
6. **Delete all credentials** — verify both methods removed
7. **UserHasMFACredentials** — true when credentials exist, false when empty
8. **CASCADE on user delete** — delete user, verify credentials gone

**IMPORTANT:** Use the real test database, not mocks. Follow the `testutil.NewTestDB(t)` pattern from existing store tests.

### Step 4: Run tests

```bash
go test ./internal/store/... -run TestMFA -v -count=1
```

### Step 5: Commit

```bash
git add internal/store/queries/mfa.sql internal/store/mfa.go internal/store/mfa_test.go internal/store/generated/
git commit -m "feat(store): add MFA credential CRUD operations

Queries and store methods for mfa_credentials table.
All operations use withBypassTx (global table, no RLS)."
```

---

## Task 5: Store Layer — Recovery Codes

**Files:**
- Modify: `internal/store/queries/mfa.sql` (append queries)
- Modify: `internal/store/mfa.go` (add methods)
- Modify: `internal/store/mfa_test.go` (add tests)

**Context:** Recovery codes are SHA-256 hashed, 10 per user. Format: `xxxxx-xxxxx` alphanumeric. Read the design doc §Recovery Code Details.

### Step 1: Add sqlc queries to `internal/store/queries/mfa.sql`

```sql
-- name: CreateMFARecoveryCode :exec
INSERT INTO mfa_recovery_codes (user_id, code_hash)
VALUES ($1, $2);

-- name: GetUnusedRecoveryCodeByHash :one
SELECT * FROM mfa_recovery_codes
WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL;

-- name: MarkRecoveryCodeUsed :exec
UPDATE mfa_recovery_codes SET used_at = now() WHERE id = $1;

-- name: CountUnusedRecoveryCodes :one
SELECT COUNT(*) FROM mfa_recovery_codes
WHERE user_id = $1 AND used_at IS NULL;

-- name: DeleteAllRecoveryCodes :execrows
DELETE FROM mfa_recovery_codes WHERE user_id = $1;
```

### Step 2: Run sqlc generate

```bash
sqlc generate
```

### Step 3: Add store methods and code generation helper

In `internal/store/mfa.go`, add:
- `GenerateRecoveryCodes(ctx, userID) ([]string, error)` — generates 10 codes, hashes with SHA-256, inserts all rows in a single transaction, returns plaintext codes
- `VerifyRecoveryCode(ctx, userID, code) (bool, int, error)` — hashes the input, looks up unused code, marks used if found, returns (success, remaining_count, error)
- `RegenerateRecoveryCodes(ctx, userID) ([]string, error)` — deletes old codes, generates new set (single transaction)
- `DeleteAllRecoveryCodes(ctx, userID) error`

**Recovery code generation logic:**
```go
// Generate a single recovery code: xxxxx-xxxxx (a-z0-9)
func generateRecoveryCode() (string, error) {
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    b := make([]byte, 10)
    for i := range b {
        idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
        if err != nil {
            return "", err
        }
        b[i] = chars[idx.Int64()]
    }
    return string(b[:5]) + "-" + string(b[5:]), nil
}

// Hash a recovery code with SHA-256
func hashRecoveryCode(code string) string {
    // Normalize: lowercase, strip dashes (defensive against user input variations)
    normalized := strings.ToLower(strings.ReplaceAll(code, "-", ""))
    h := sha256.Sum256([]byte(normalized))
    return hex.EncodeToString(h[:])
}
```

**IMPORTANT:** The hash function MUST normalize input (lowercase, strip dashes) before hashing. Users may type codes without dashes or with different casing.

### Step 4: Write tests

Test:
1. **Generate 10 codes** — verify count, format (`xxxxx-xxxxx`), all unique
2. **Verify valid code** — succeeds, remaining count decrements
3. **Verify used code** — fails (already consumed)
4. **Verify wrong code** — fails
5. **Verify with case/dash variation** — `AB3KX-9PM2F` and `ab3kx9pm2f` match the same hash
6. **Concurrent consumption** — two goroutines try to use the same code simultaneously; exactly one succeeds (testing-pitfalls §1: Token consumption)
7. **Regenerate** — old codes invalid, new codes work, count is 10
8. **CASCADE on user delete** — codes cleaned up

### Step 5: Run tests

```bash
go test ./internal/store/... -run TestRecoveryCode -v -count=1
```

### Step 6: Commit

```bash
git add internal/store/queries/mfa.sql internal/store/mfa.go internal/store/mfa_test.go internal/store/generated/
git commit -m "feat(store): add MFA recovery code generation and verification

10 one-time recovery codes per user, SHA-256 hashed, normalized
input (case-insensitive, dash-insensitive). Concurrent consumption
tested with barrier pattern."
```

---

## Task 6: Store Layer — MFA Challenges (Email OTP + Remember Device)

**Files:**
- Modify: `internal/store/queries/mfa.sql` (append queries)
- Modify: `internal/store/mfa.go` (add methods)
- Modify: `internal/store/mfa_test.go` (add tests)

**Context:** `mfa_challenges` stores both email OTP codes (short-lived, attempt-limited) and remember-device tokens (long-lived). Read the design doc §Email OTP Details and §mfa_challenges table definition.

### Step 1: Add sqlc queries

```sql
-- name: CreateMFAChallenge :one
INSERT INTO mfa_challenges (user_id, challenge_type, token_hash, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetActiveEmailOTPChallenge :one
SELECT * FROM mfa_challenges
WHERE user_id = $1 AND challenge_type = 'email_otp' AND expires_at > now()
LIMIT 1;

-- name: IncrementChallengeAttempts :one
UPDATE mfa_challenges SET attempts = attempts + 1
WHERE id = $1
RETURNING attempts;

-- name: DeleteEmailOTPChallenges :execrows
DELETE FROM mfa_challenges
WHERE user_id = $1 AND challenge_type = 'email_otp';

-- name: DeleteAllUserChallenges :execrows
DELETE FROM mfa_challenges WHERE user_id = $1;

-- name: DeleteRememberDeviceTokens :execrows
DELETE FROM mfa_challenges
WHERE user_id = $1 AND challenge_type = 'remember_device';

-- name: GetRememberDeviceToken :one
SELECT * FROM mfa_challenges
WHERE user_id = $1 AND challenge_type = 'remember_device'
  AND token_hash = $2 AND expires_at > now()
LIMIT 1;

-- name: CountRecentEmailOTPChallenges :one
SELECT COUNT(*) FROM mfa_challenges
WHERE user_id = $1 AND challenge_type = 'email_otp'
  AND created_at > $2;

-- name: DeleteExpiredChallenges :execrows
DELETE FROM mfa_challenges WHERE expires_at < now();

-- name: DeleteChallenge :exec
DELETE FROM mfa_challenges WHERE id = $1;
```

### Step 2: Run sqlc generate and add store methods

Store methods needed:
- `CreateEmailOTPChallenge(ctx, userID, codeHash, expiresAt) error` — deletes existing email OTP for user first (single active code), then inserts
- `VerifyEmailOTPChallenge(ctx, userID, codeHash, maxAttempts) (bool, error)` — looks up active challenge, increments attempts, verifies hash, deletes on success or max attempts
- `CreateRememberDeviceToken(ctx, userID, tokenHash, expiresAt) error`
- `ValidateRememberDeviceToken(ctx, userID, tokenHash) (bool, error)` — checks existence and expiry
- `DeleteRememberDeviceTokens(ctx, userID) error`
- `DeleteAllUserChallenges(ctx, userID) error`
- `CountRecentEmailOTPChallenges(ctx, userID, since) (int64, error)` — for rate limiting
- `DeleteExpiredChallenges(ctx) (int64, error)` — for cleanup worker

**CRITICAL:** `VerifyEmailOTPChallenge` MUST use a single transaction to atomically: read challenge → increment attempts → check hash → delete if matched or exhausted. This prevents TOCTOU on attempt counting (testing-pitfalls §1).

**CRITICAL:** The `token_hash` comparison for email OTP MUST use `subtle.ConstantTimeCompare` at the application layer (not SQL `=`). Hash the user's input with SHA-256, then compare the hash bytes. SQL `=` is not constant-time.

Actually, correction: Since we're comparing SHA-256 hashes (not secrets), and the input is a 6-digit code with max 3 attempts, timing attacks are not practical. SQL `=` comparison on hashes is acceptable here. The hash prevents the code from being readable in the DB — constant-time comparison is only needed for high-entropy secrets like API keys.

### Step 3: Write tests

Test:
1. **Create and verify email OTP** — happy path
2. **Single active code** — creating new challenge deletes existing one
3. **Expired challenge** — verify fails on expired code
4. **Attempt exhaustion** — 3 wrong codes, then correct code also fails (challenge deleted)
5. **Rate limiting** — `CountRecentEmailOTPChallenges` returns correct count within time window
6. **Remember-device token** — create, validate, invalidate after deletion
7. **Expired remember-device** — validate fails on expired token
8. **Delete expired** — cleanup removes only expired rows
9. **Concurrent email OTP verification** — two goroutines submit correct code simultaneously; exactly one succeeds (testing-pitfalls §1)

### Step 4: Run tests and commit

```bash
go test ./internal/store/... -run TestMFAChallenge -v -count=1
git add internal/store/queries/mfa.sql internal/store/mfa.go internal/store/mfa_test.go internal/store/generated/
git commit -m "feat(store): add MFA challenge operations for email OTP and device tokens

Email OTP: single-active-code enforcement, attempt counting, rate limiting.
Remember-device: token creation and validation with expiry.
Expired challenge cleanup for worker."
```

---

## Task 7: Store Layer — MFA Requirements (Org-Scoped)

**Files:**
- Modify: `internal/store/queries/mfa.sql` (append queries)
- Modify: `internal/store/mfa.go` (add methods)
- Modify: `internal/store/mfa_test.go` (add tests)

**Context:** `mfa_requirements` is the ONLY org-scoped MFA table. It has RLS. API handler calls use `withOrgTx`; login-time cross-org checks use `withBypassTx`. Read the design doc §mfa_requirements and §Enforcement Model.

### Step 1: Add sqlc queries

```sql
-- name: CreateMFARequirement :exec
INSERT INTO mfa_requirements (org_id, user_id, required_by)
VALUES ($1, $2, $3)
ON CONFLICT (org_id, user_id) DO NOTHING;

-- name: DeleteMFARequirement :execrows
DELETE FROM mfa_requirements WHERE org_id = $1 AND user_id = $2;

-- name: GetMFARequirementsByOrg :many
SELECT * FROM mfa_requirements WHERE org_id = $1 ORDER BY created_at;

-- name: UserHasMFARequirement :one
-- Cross-org check: does this user have an MFA requirement in ANY org?
-- Used at login time under withBypassTx.
SELECT EXISTS(
    SELECT 1 FROM mfa_requirements WHERE user_id = $1
) AS required;

-- name: UserInMFARequiredOrg :one
-- Does this user belong to any org with mfa_required_all=true?
-- Used at login time under withBypassTx.
SELECT EXISTS(
    SELECT 1 FROM org_members om
    JOIN organizations o ON o.id = om.org_id
    WHERE om.user_id = $1 AND o.mfa_required_all = true
) AS required;
```

### Step 2: Run sqlc generate and add store methods

Store methods:
- `CreateMFARequirement(ctx, orgID, userID, requiredByID) error` — uses `withOrgTx` (admin action within org context)
- `DeleteMFARequirement(ctx, orgID, userID) error` — uses `withOrgTx`
- `GetMFARequirementsByOrg(ctx, orgID) ([]MFARequirement, error)` — uses `withOrgTx`
- `UserHasMFARequirement(ctx, userID) (bool, error)` — uses `withBypassTx` (login-time cross-org check)
- `UserInMFARequiredOrg(ctx, userID) (bool, error)` — uses `withBypassTx` (login-time cross-org check)

**CRITICAL transaction helper selection:**
- `CreateMFARequirement`, `DeleteMFARequirement`, `GetMFARequirementsByOrg` → `withOrgTx` (API handler, org context available)
- `UserHasMFARequirement`, `UserInMFARequiredOrg` → `withBypassTx` (login-time, pre-org-context, must read across orgs)

### Step 3: Write tests

Test:
1. **Create requirement** — verify row exists
2. **Idempotent create** — ON CONFLICT DO NOTHING, no error on duplicate
3. **Delete requirement** — verify row gone
4. **CASCADE on membership removal** — remove user from org, requirement auto-deleted
5. **RLS: cross-tenant isolation** — create requirements in Org A and Org B via superuser, query via `db.AppStore` scoped to Org A; Org B's requirements must not appear (testing-pitfalls §10)
6. **UserHasMFARequirement (bypass)** — user with requirement in Org A, queried without org context
7. **UserInMFARequiredOrg (bypass)** — user in org with `mfa_required_all=true`
8. **No requirement after org leave** — composite FK CASCADE cleans up

### Step 4: Run tests and commit

```bash
go test ./internal/store/... -run TestMFARequirement -v -count=1
git add internal/store/queries/mfa.sql internal/store/mfa.go internal/store/mfa_test.go internal/store/generated/
git commit -m "feat(store): add MFA requirements CRUD with RLS

Per-member MFA mandates. Org-scoped with RLS (withOrgTx for admin
actions, withBypassTx for login-time cross-org checks).
Composite FK to org_members ensures cleanup on membership removal."
```

---

## Task 8: Store Layer — MFA Mandate Check Function

**Files:**
- Modify: `internal/store/mfa.go` (add composite check)
- Modify: `internal/store/mfa_test.go` (add tests)

**Context:** The 3-layer mandate check runs at login to determine if the user needs MFA. Read the design doc §Enforcement Model and §Dynamic Mandate Check.

### Step 1: Write the mandate check function

This is an application-layer function (not a sqlc query) that composes the three layers:

```go
// UserMFARequired checks all three enforcement layers to determine if this user
// must have MFA. Runs at login time under withBypassTx (cross-org queries).
// Returns (required bool, err error).
func (s *Store) UserMFARequired(ctx context.Context, userID uuid.UUID, isSiteAdmin bool, cfg MFAConfig) (bool, error) {
    // Layer 1: site config
    if cfg.RequiredSiteAdmins && isSiteAdmin {
        return true, nil
    }

    // Layer 2 + 3 are DB queries — need bypass context
    // ... (see design doc for full logic)
}
```

**MFAConfig** is a simple struct that holds just the config fields needed:
```go
type MFAConfig struct {
    RequiredSiteAdmins bool
    RequiredOrgOwners  bool
}
```

**IMPORTANT:** The `cfg.RequiredOrgOwners` check requires knowing if the user is an owner in ANY org. Add a query:

```sql
-- name: IsOrgOwner :one
-- Does this user have the 'owner' role in any org?
SELECT EXISTS(
    SELECT 1 FROM org_members WHERE user_id = $1 AND role = 'owner'
) AS is_owner;
```

### Step 2: Write tests

Test all combinations from the design doc §Valid combinations table:
1. Site admin + `MFA_REQUIRED_SITE_ADMINS=true` → required
2. Org owner + `MFA_REQUIRED_ORG_OWNERS=true` → required
3. Member of org with `mfa_required_all=true` → required
4. User with per-member requirement → required
5. None of the above → not required
6. Site admin + `MFA_REQUIRED_SITE_ADMINS=false` → checks other layers
7. User in multiple orgs, one requires MFA → required (any org triggers)

### Step 3: Run tests and commit

```bash
go test ./internal/store/... -run TestUserMFARequired -v -count=1
git add internal/store/queries/mfa.sql internal/store/mfa.go internal/store/mfa_test.go internal/store/generated/
git commit -m "feat(store): add 3-layer MFA mandate check

Composite check: site config → org-wide setting → per-member requirement.
All DB queries use withBypassTx for cross-org login-time evaluation."
```

---

## Task 9: Pending Token JWT (Restricted Session)

**⚠️ Merge note:** This task adds NEW types and functions to `internal/auth/jwt.go` — it does not modify existing signatures. Phase 8E (Secure pillar) separately changes `ParseAccessToken`/`ParseRefreshToken` signatures for dual-key support. These changes are additive and should merge cleanly, but if Phase 8E has landed by the time you reach this task, read `jwt.go` fresh to confirm the current state before writing code.

**Files:**
- Modify: `internal/auth/jwt.go` (add PendingClaims and issue/parse functions)
- Modify: `internal/auth/jwt_test.go` (add tests)

**Context:** Read `internal/auth/jwt.go` for the existing AccessClaims/RefreshClaims pattern. The pending token is a new JWT type with a `pending` array and optional `methods` array. Read the design doc §Restricted Session Token.

### Step 1: Write failing tests

```go
func TestIssueParsePendingToken(t *testing.T) {
    secret := []byte("test-secret-at-least-32-bytes-xx")
    userID := uuid.New()
    tokenVersion := 5
    pending := []string{"mfa_challenge", "password_reset"}
    methods := []string{"totp", "email_otp"}
    ttl := 5 * time.Minute

    tokenStr, err := auth.IssuePendingToken(secret, userID, tokenVersion, pending, methods, ttl)
    require.NoError(t, err)

    claims, err := auth.ParsePendingToken(tokenStr, secret)
    require.NoError(t, err)
    assert.Equal(t, userID, claims.UserID)
    assert.Equal(t, tokenVersion, claims.TokenVersion)
    assert.Equal(t, pending, claims.Pending)
    assert.Equal(t, methods, claims.Methods)
}

func TestPendingTokenExpired(t *testing.T) {
    secret := []byte("test-secret-at-least-32-bytes-xx")
    tokenStr, err := auth.IssuePendingToken(secret, uuid.New(), 1, []string{"mfa_challenge"}, nil, -1*time.Second)
    require.NoError(t, err)

    _, err = auth.ParsePendingToken(tokenStr, secret)
    assert.Error(t, err) // expired
}

func TestPendingTokenWrongAlgorithm(t *testing.T) {
    // Sign with HS384, parse with HS256-only validation
    // ... (must be rejected)
}
```

### Step 2: Run tests — verify they fail

```bash
go test ./internal/auth/... -run TestPendingToken -v -count=1
```

### Step 3: Implement PendingClaims

In `internal/auth/jwt.go`:

```go
// PendingClaims holds the claims for a restricted MFA/password-reset session token.
type PendingClaims struct {
    jwt.RegisteredClaims
    UserID       uuid.UUID `json:"sub"`
    TokenVersion int       `json:"tv"`
    Pending      []string  `json:"pending"`
    Methods      []string  `json:"methods,omitempty"` // only when pending contains "mfa_challenge"
}

func IssuePendingToken(secret []byte, userID uuid.UUID, tokenVersion int, pending, methods []string, ttl time.Duration) (string, error) {
    now := time.Now()
    claims := PendingClaims{
        RegisteredClaims: jwt.RegisteredClaims{
            IssuedAt:  jwt.NewNumericDate(now),
            ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
        },
        UserID:       userID,
        TokenVersion: tokenVersion,
        Pending:      pending,
        Methods:      methods,
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(secret)
}

func ParsePendingToken(tokenStr string, secret []byte) (*PendingClaims, error) {
    claims := &PendingClaims{}
    _, err := jwt.ParseWithClaims(tokenStr, claims, func(_ *jwt.Token) (any, error) {
        return secret, nil
    },
        jwt.WithValidMethods([]string{"HS256"}),
        jwt.WithExpirationRequired(),
    )
    if err != nil {
        return nil, fmt.Errorf("parse pending token: %w", err)
    }
    return claims, nil
}
```

### Step 4: Run tests — verify they pass

```bash
go test ./internal/auth/... -run TestPendingToken -v -count=1
```

### Step 5: Commit

```bash
git add internal/auth/jwt.go internal/auth/jwt_test.go
git commit -m "feat(auth): add PendingClaims JWT for MFA restricted sessions

Short-lived JWT carrying pending[] array of requirements and
methods[] for MFA challenge selection. HS256 only, expiration required."
```

---

## ── REVIEW CHECKPOINT: Tasks 1–9 ──

**STOP.** Review all store methods, migration, and JWT code before proceeding to handlers.

Checklist:
- [ ] All sqlc queries compile (`sqlc generate` clean)
- [ ] All store tests pass (`go test ./internal/store/... -count=1`)
- [ ] All auth tests pass (`go test ./internal/auth/... -count=1`)
- [ ] Migration applies and rolls back cleanly
- [ ] `golangci-lint run` passes on all changed files
- [ ] Transaction helper usage is correct per implementation-pitfalls §2.17
- [ ] RLS tests use `db.AppStore` for mfa_requirements
- [ ] Recovery code concurrent consumption test uses barrier pattern
- [ ] Email OTP concurrent verification test uses barrier pattern

Perform the mandatory 3-round review per the instructions at the top of this plan.

**⚠️ COMPACT NOW:** After the review is complete and all issues are resolved, run `/compact` before starting Task 10. Reviews consume significant context from file reads and verification — compacting here prevents an automatic compaction mid-task in the next batch, which would discard freshly-loaded task context.

---

## ⛔ HARD STOP: Phase 8E Dependency Gate

**DO NOT proceed past this point without explicit user approval.**

Tasks 10+ modify files that Phase 8E (Secure pillar, `dev/plans/2026-03-16-phase8-ops-secure-v2-plan.md`) is also modifying. Specifically:

- **`internal/auth/jwt.go`** — 8E changes `ParseAccessToken`/`ParseRefreshToken` signatures to accept dual keys. Task 9 (pending token) adds new functions to this file and must target the post-8E signatures.
- **`internal/api/auth.go`** — 8E wires security events into `loginHandler`. Task 10 modifies this same handler for MFA pending tokens.
- **`internal/api/middleware_auth.go`** — 8E changes middleware to use `writeProblem` and dual-key parsing. Task 16 adds pending-token route gating here.
- **`internal/api/server.go`** — 8E adds `ConfigHolder` and `EventWriter` to `ServerDeps`. MFA handlers need to be wired into the post-8E server.
- **`internal/secure/events.go`** — 8E creates `EventWriter` and `security_events` table. Task 21 should use 8E's infrastructure instead of the audit_log workaround.

**Action required:** Ask Sam to check the status of the Phase 8E implementation. Do NOT proceed until Sam confirms either:
1. Phase 8E has landed on `dev` and you should `git pull` before continuing, OR
2. Sam gives explicit approval to proceed despite 8E being incomplete (expect merge conflicts)

---

## Task 10: Modify Login Handler for MFA

**Files:**
- Modify: `internal/api/auth.go` (loginHandler)
- Modify: `internal/api/auth_test.go` (add MFA login tests)

**Context:** Read the current `loginHandler` in `internal/api/auth.go` (starts around line 221). Read the design doc §Login Flow (Modified). The login handler currently issues access+refresh tokens on successful password verification. We need to add MFA checks between password verification and token issuance.

### Step 1: Understand the current flow

The current login flow is:
1. Rate limit check
2. Get user by email (anti-enumeration timing normalization)
3. Reject disabled users
4. Account lockout check
5. Password verification (argon2)
6. Record success, issue tokens

The MFA-modified flow adds after step 5 (password verified):
1. Check: does user have MFA credentials? (`UserHasMFACredentials`)
2. If MFA enrolled: check remember-device cookie → if valid, skip MFA challenge
3. If MFA enrolled and no device token: add `"mfa_challenge"` to pending
4. Check: `force_password_reset` flag → add `"password_reset"` to pending
5. If no MFA enrolled: check mandate (`UserMFARequired`) → add `"mfa_enrollment_required"` to pending
6. If pending is empty: issue full tokens (existing flow)
7. If pending has items: issue pending token cookie, return `{ pending, methods }`

### Step 2: Write failing tests

Add tests to `internal/api/auth_test.go`:

```go
func TestLoginWithMFAEnrolled(t *testing.T) {
    // Register user, enroll TOTP (seed DB directly), then login
    // Expect: 200 with pending=["mfa_challenge"], methods=["totp"]
    // Expect: mfa_pending_token cookie set
    // Expect: NO access_token or refresh_token cookies
}

func TestLoginNoMFA_MFANotRequired(t *testing.T) {
    // Register user, no MFA enrolled, no mandate
    // Expect: normal login — access_token + refresh_token cookies
}

func TestLoginNoMFA_MFARequired(t *testing.T) {
    // Register user, no MFA enrolled, set mfa_required_all=true on org
    // Expect: 200 with pending=["mfa_enrollment_required"]
}

func TestLoginMFA_ForcePasswordReset(t *testing.T) {
    // Register user, enroll TOTP, set force_password_reset=true
    // Expect: pending=["mfa_challenge", "password_reset"]
}

func TestLoginNoMFA_ForcePasswordResetAndMFARequired(t *testing.T) {
    // Register user, no MFA, set force_password_reset=true + mfa mandate
    // Expect: pending=["password_reset", "mfa_enrollment_required"]
}
```

### Step 3: Modify loginOutput

The login output needs to change to include the pending state:

```go
type loginOutput struct {
    SetCookie []string `header:"Set-Cookie"`
    Body      struct {
        UserID  uuid.UUID `json:"user_id"              doc:"Authenticated user ID"`
        Pending []string  `json:"pending"              doc:"Remaining auth steps (empty = fully authenticated)"`
        Methods []string  `json:"methods,omitempty"    doc:"Available MFA methods (only when pending contains mfa_challenge)"`
    }
}
```

### Step 4: Modify loginHandler

After the successful password verification block (around line 296), replace the token issuance with:

```go
// ── MFA / restricted session checks ──────────────────────────────
var pending []string
var methods []string

hasMFA, err := srv.store.UserHasMFACredentials(ctx, user.ID)
if err != nil {
    slog.ErrorContext(ctx, "login: check MFA credentials", "error", err)
    return nil, huma.Error500InternalServerError("internal error")
}

if hasMFA {
    // Check remember-device cookie before requiring MFA challenge
    skipMFA := false
    if deviceCookie, cookieErr := extractCookie(ctx, "mfa_device_token"); cookieErr == nil && deviceCookie != "" {
        tokenHash := sha256Hex(deviceCookie)
        valid, err := srv.store.ValidateRememberDeviceToken(ctx, user.ID, tokenHash)
        if err != nil {
            slog.WarnContext(ctx, "login: check device token", "error", err)
        }
        if valid {
            skipMFA = true
            // Audit: device token used (see Task 21)
        }
    }
    if !skipMFA {
        pending = append(pending, "mfa_challenge")
        creds, err := srv.store.GetMFACredentialsByUserID(ctx, user.ID)
        if err != nil {
            slog.ErrorContext(ctx, "login: get MFA methods", "error", err)
            return nil, huma.Error500InternalServerError("internal error")
        }
        for _, c := range creds {
            methods = append(methods, c.Method)
        }
    }
}

if user.ForcePasswordReset {
    pending = append(pending, "password_reset")
}

if !hasMFA {
    isSiteAdmin, _ := srv.store.IsSiteAdmin(ctx, user.ID)
    mfaCfg := store.MFAConfig{
        RequiredSiteAdmins: srv.cfg.MFARequiredSiteAdmins,
        RequiredOrgOwners:  srv.cfg.MFARequiredOrgOwners,
    }
    required, err := srv.store.UserMFARequired(ctx, user.ID, isSiteAdmin, mfaCfg)
    if err != nil {
        slog.ErrorContext(ctx, "login: check MFA mandate", "error", err)
        return nil, huma.Error500InternalServerError("internal error")
    }
    if required {
        pending = append(pending, "mfa_enrollment_required")
    }
}

// Record successful login
srv.lockout.RecordSuccess(ctx, input.Body.Email)

if len(pending) > 0 {
    // Issue restricted pending token
    secret := []byte(srv.cfg.JWTSecret)
    pendingToken, err := auth.IssuePendingToken(
        secret, user.ID, int(user.TokenVersion),
        pending, methods, srv.cfg.MFAPendingTokenTTL,
    )
    if err != nil {
        slog.ErrorContext(ctx, "login: issue pending token", "error", err)
        return nil, huma.Error500InternalServerError("internal error")
    }
    out := &loginOutput{}
    out.Body.UserID = user.ID
    out.Body.Pending = pending
    out.Body.Methods = methods
    out.SetCookie = pendingTokenCookies(pendingToken, srv.cfg.CookieSecure, srv.cfg.MFAPendingTokenTTL)
    return out, nil
}

// No pending items — issue full tokens (existing flow)
// ... (move existing token issuance code here)
```

**IMPORTANT:** The `extractCookie` helper needs to read from the HTTP request. In huma handlers, the request is accessible via the context. Check how existing cookie reading works (see `refreshInput` which uses `cookie:"refresh_token"` tag). For the device token, add it to `loginInput`:

```go
type loginInput struct {
    MFADeviceToken string `cookie:"mfa_device_token" doc:"Remember-device token (optional)"`
    Body struct {
        Email    string `json:"email"    format:"email" maxLength:"254" doc:"User email address"`
        Password string `json:"password" minLength:"16" maxLength:"1024" doc:"Password"`
    }
}
```

**Helper for pending token cookie:**
```go
func pendingTokenCookies(token string, secure bool, ttl time.Duration) []string {
    c := &http.Cookie{
        Name:     "mfa_pending_token",
        Value:    token,
        Path:     "/api/v1/auth",
        HttpOnly: true,
        Secure:   secure,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   int(ttl.Seconds()),
    }
    return []string{c.String()}
}
```

### Step 5: Run tests

```bash
go test ./internal/api/... -run TestLogin -v -count=1
```

### Step 6: Commit

```bash
git add internal/api/auth.go internal/api/auth_test.go
git commit -m "feat(api): modify login handler for MFA pending token flow

Login now checks MFA enrollment, remember-device cookie, force
password reset, and MFA mandate. Issues restricted pending token
when additional auth steps are required."
```

---

## Task 11: MFA Challenge + Verify Handlers

**Files:**
- Create: `internal/api/auth_mfa.go`
- Create: `internal/api/auth_mfa_test.go`

**Context:** These handlers run during the MFA challenge step of login. They consume the `mfa_pending_token` cookie. Read the design doc §MFA Challenge Flow.

### Step 1: Write failing tests

```go
// POST /api/v1/auth/mfa/challenge — request email OTP code
func TestMFAChallengeEmailOTP(t *testing.T) {
    // Setup: register user, enroll email_otp, login (get pending token)
    // Call: POST /auth/mfa/challenge with mfa_pending_token cookie, body: {method: "email_otp"}
    // Expect: 200, email sent (check Mailpit or mock)
}

func TestMFAChallengeTOTP(t *testing.T) {
    // Setup: register user, enroll TOTP, login (get pending token)
    // Call: POST /auth/mfa/challenge with mfa_pending_token cookie, body: {method: "totp"}
    // Expect: 200 (no server action needed for TOTP)
}

func TestMFAChallengeInvalidPendingToken(t *testing.T) {
    // Call with expired or missing pending token
    // Expect: 401
}

func TestMFAChallengeRateLimit(t *testing.T) {
    // Send MFAEmailOTPMaxPerHour+1 challenge requests
    // Expect: last request returns 429
}

// POST /api/v1/auth/mfa/verify — submit MFA code
func TestMFAVerifyTOTP(t *testing.T) {
    // Setup: register user, enroll TOTP, login (get pending token)
    // Generate valid TOTP code from secret
    // Call: POST /auth/mfa/verify with body: {method: "totp", code: "123456"}
    // Expect: 200, pending=[], access_token + refresh_token cookies set
}

func TestMFAVerifyEmailOTP(t *testing.T) {
    // Setup: register user, enroll email_otp, login, request challenge
    // Extract code from DB (mfa_challenges.token_hash — for testing only, hash the code)
    // Call: POST /auth/mfa/verify with body: {method: "email_otp", code: "123456"}
    // Expect: 200, full tokens
}

func TestMFAVerifyRecoveryCode(t *testing.T) {
    // Setup: register user, enroll TOTP + recovery codes, login
    // Call: POST /auth/mfa/verify with body: {method: "recovery", code: "ab3kx-9pm2f"}
    // Expect: 200, full tokens, recovery codes remaining decremented
}

func TestMFAVerifyWrongCode(t *testing.T) {
    // Submit wrong TOTP code
    // Expect: 401, lockout counter incremented
}

func TestMFAVerifyTOTPReplay(t *testing.T) {
    // Submit same TOTP code twice (same time step)
    // First: 200; Second: 401 (replay detected)
}

func TestMFAVerifyWithRemainingPending(t *testing.T) {
    // pending=["mfa_challenge", "password_reset"]
    // After MFA verify: expect new pending token with pending=["password_reset"]
}

func TestMFAVerifyTokenVersionMismatch(t *testing.T) {
    // Get pending token, then increment user's token_version (simulating admin action)
    // Submit verify — expect 401 (tv mismatch forces re-login)
}
```

### Step 2: Implement handlers

Create `internal/api/auth_mfa.go`:

**Input/Output structs:**
```go
type mfaChallengeInput struct {
    MFAPendingToken string `cookie:"mfa_pending_token"`
    Body struct {
        Method string `json:"method" enum:"totp,email_otp" doc:"MFA method to challenge"`
    }
}

type mfaChallengeOutput struct {
    SetCookie []string `header:"Set-Cookie"`
}

type mfaVerifyInput struct {
    MFAPendingToken string `cookie:"mfa_pending_token"`
    Body struct {
        Method         string `json:"method" enum:"totp,email_otp,recovery" doc:"MFA method"`
        Code           string `json:"code" minLength:"1" maxLength:"20" doc:"Verification code"`
        RememberDevice bool   `json:"remember_device" doc:"Issue remember-device token"`
    }
}

type mfaVerifyOutput struct {
    SetCookie []string `header:"Set-Cookie"`
    Body struct {
        UserID  uuid.UUID `json:"user_id"`
        Pending []string  `json:"pending"`
        Methods []string  `json:"methods,omitempty"`
    }
}
```

**Handler logic for challengeHandler:**
1. Parse and validate pending token (expired? tv matches DB? `"mfa_challenge"` is first pending item?)
2. If method = `"email_otp"`: rate limit check → delete existing OTP → generate 6-digit code → hash → insert challenge → send email
3. If method = `"totp"`: return 200 (client-side, no server action)
4. Reissue pending token cookie with fresh TTL

**Handler logic for verifyHandler:**
1. Parse and validate pending token
2. Verify `tv` against database: `SELECT token_version FROM users WHERE id = $1`
3. Branch on method:
   - **TOTP:** Decrypt `secret_enc` from `mfa_credentials` → generate expected code using `pquerna/otp/totp` with `ValidateCustom` (SHA1, 6 digits, 30s, ±1 skew) → check `last_used_step` for replay → update `last_used_step` and `last_used_at`
   - **Email OTP:** Call `VerifyEmailOTPChallenge` store method
   - **Recovery:** Call `VerifyRecoveryCode` store method
4. On failure: increment lockout counter, return 401
5. On success: remove `"mfa_challenge"` from pending array
6. If `remember_device` requested: check org settings → create device token → set cookie
7. If pending still has items: reissue pending token with remaining items
8. If pending empty: issue full access + refresh tokens

**TOTP verification details** (using `pquerna/otp`):
```go
import "github.com/pquerna/otp/totp"

valid, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
    Period:    30,
    Skew:     1,        // ±1 time step (allows ~90s clock skew)
    Digits:   otp.DigitsSix,
    Algorithm: otp.AlgorithmSHA1,
})
```

**Email OTP code generation:**
```go
func generateEmailOTPCode() (string, error) {
    n, err := rand.Int(rand.Reader, big.NewInt(1000000))
    if err != nil {
        return "", err
    }
    return fmt.Sprintf("%06d", n.Int64()), nil
}
```

**CRITICAL:** The TOTP secret must be decrypted from `mfa_credentials.secret_enc` using the same AES-256-GCM key as SSO encryption (`SSOEncryptionKey` / a dedicated MFA key). The encryption key is accessed via `srv.ssoEncryptionKey()` or a new similar helper. Read `internal/api/sso.go` line 70-82 for the pattern.

### Step 3: Register routes

In `internal/api/auth_mfa.go`, add a `registerMFARoutes(api huma.API, srv *Server)` function:

```go
func registerMFARoutes(api huma.API, srv *Server) {
    huma.Register(api, huma.Operation{
        OperationID: "mfa-challenge",
        Method:      http.MethodPost,
        Path:        "/api/v1/auth/mfa/challenge",
        Tags:        []string{"auth", "mfa"},
        Summary:     "Request MFA challenge (email OTP code or signal TOTP readiness)",
    }, srv.mfaChallengeHandler)

    huma.Register(api, huma.Operation{
        OperationID: "mfa-verify",
        Method:      http.MethodPost,
        Path:        "/api/v1/auth/mfa/verify",
        Tags:        []string{"auth", "mfa"},
        Summary:     "Submit MFA verification code",
    }, srv.mfaVerifyHandler)
}
```

Call `registerMFARoutes(api, srv)` from the server's route setup (wherever `registerAuthRoutes` is called).

### Step 4: Run tests

```bash
go test ./internal/api/... -run TestMFA -v -count=1
```

### Step 5: Commit

```bash
git add internal/api/auth_mfa.go internal/api/auth_mfa_test.go
git commit -m "feat(api): add MFA challenge and verify handlers

POST /auth/mfa/challenge: request email OTP or signal TOTP readiness.
POST /auth/mfa/verify: submit code, handle TOTP/email OTP/recovery.
Pending token progression, remember-device token, token_version validation."
```

---

## ── REVIEW CHECKPOINT: Tasks 10–11 ──

The login + MFA challenge/verify flow is the security-critical core. Review thoroughly:

- [ ] Anti-enumeration: MFA verify returns same error format regardless of user state
- [ ] TOTP replay prevention: `last_used_step` checked and updated atomically
- [ ] Email OTP attempt exhaustion: challenge deleted after 3 failures
- [ ] Token version validation: pending token rejected if `tv` doesn't match DB
- [ ] Pending array progression: items removed in correct order
- [ ] No open DB transaction during email delivery (testing-pitfalls §8)
- [ ] Rate limiting on challenge endpoint (testing-pitfalls §5)

Perform the mandatory 3-round review.

**⚠️ COMPACT NOW:** After the review is complete and all issues are resolved, run `/compact` before starting Task 12. Reviews consume significant context from file reads and verification — compacting here prevents an automatic compaction mid-task in the next batch, which would discard freshly-loaded task context.

---

## Task 12: TOTP Enrollment Handlers

**Files:**
- Modify: `internal/api/auth_mfa.go` (add setup/confirm handlers)
- Modify: `internal/api/auth_mfa_test.go` (add tests)

**Context:** Read the design doc §TOTP Enrollment Flow. The enrollment flow has two steps: (1) generate secret + QR URI, set enrollment cookie; (2) verify code from authenticator app, persist credential.

### Step 1: Write failing tests

```go
func TestTOTPSetup(t *testing.T) {
    // Authenticated user calls POST /auth/mfa/totp/setup
    // Expect: 200 with qr_code_uri and secret in body
    // Expect: mfa_enrollment_token cookie set
    // Expect: qr_code_uri starts with "otpauth://totp/"
    // Expect: secret is valid base32
}

func TestTOTPConfirm(t *testing.T) {
    // Call setup, extract secret, generate valid TOTP code
    // Call POST /auth/mfa/totp/confirm with code + enrollment cookie
    // Expect: 200 with recovery_codes (first enrollment)
    // Expect: recovery_codes has 10 items, format xxxxx-xxxxx
    // Expect: mfa_credentials row created with method='totp'
}

func TestTOTPConfirmWrongCode(t *testing.T) {
    // Call setup, submit wrong code to confirm
    // Expect: 400/401 error
}

func TestTOTPConfirmWithoutSetup(t *testing.T) {
    // Call confirm without enrollment cookie
    // Expect: 401
}

func TestTOTPSetupDuringRestrictedEnrollment(t *testing.T) {
    // User with pending=["mfa_enrollment_required"]
    // Call setup + confirm
    // Expect: enrollment_required cleared from pending
}

func TestTOTPDoubleEnrollment(t *testing.T) {
    // User already has TOTP enrolled
    // Call setup again — expect 409 Conflict
}
```

### Step 2: Implement handlers

**Setup handler:**
```go
func (srv *Server) mfaTOTPSetupHandler(ctx context.Context, input *mfaTOTPSetupInput) (*mfaTOTPSetupOutput, error) {
    userID := getUserID(ctx) // from access token or pending enrollment token

    // Check not already enrolled
    existing, _ := srv.store.GetMFACredentialByUserAndMethod(ctx, userID, "totp")
    if existing != nil {
        return nil, huma.Error409Conflict("TOTP already enrolled")
    }

    // Generate TOTP key
    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      "CVErt Ops",
        AccountName: userEmail, // from user lookup
        Period:      30,
        SecretSize:  20,
        Digits:      otp.DigitsSix,
        Algorithm:   otp.AlgorithmSHA1,
    })
    if err != nil {
        return nil, huma.Error500InternalServerError("internal error")
    }

    // Validate URI round-trip (design doc requirement)
    parsed, err := otp.NewKeyFromURL(key.URL())
    if err != nil || parsed.Secret() != key.Secret() {
        slog.ErrorContext(ctx, "totp: URI round-trip failed")
        return nil, huma.Error500InternalServerError("internal error")
    }

    // Encrypt secret for enrollment cookie
    encKey, err := srv.ssoEncryptionKey()
    if err != nil {
        return nil, huma.Error500InternalServerError("encryption key not configured")
    }
    secretEnc, err := crypto.Encrypt(encKey, []byte(key.Secret()))
    if err != nil {
        return nil, huma.Error500InternalServerError("internal error")
    }

    // Create enrollment token (short-lived JWT containing encrypted secret)
    enrollToken, err := auth.IssueEnrollmentToken(...)

    out := &mfaTOTPSetupOutput{}
    out.Body.QRCodeURI = key.URL()
    out.Body.Secret = key.Secret()
    out.SetCookie = enrollmentTokenCookies(enrollToken, srv.cfg.CookieSecure)
    return out, nil
}
```

**Confirm handler:**
```go
func (srv *Server) mfaTOTPConfirmHandler(ctx context.Context, input *mfaTOTPConfirmInput) (*mfaTOTPConfirmOutput, error) {
    // 1. Read enrollment cookie, decrypt secret
    // 2. Validate TOTP code against secret
    // 3. Encrypt secret for DB storage
    // 4. INSERT INTO mfa_credentials
    // 5. If first MFA method: generate recovery codes
    // 6. Clear enrollment cookie
    // 7. If restricted enrollment session: remove "mfa_enrollment_required" from pending
    // 8. Return recovery codes (if generated)
}
```

**Enrollment token approach:** The enrollment token is a cookie containing the encrypted TOTP secret. It does NOT go in the database (the secret is provisional until confirmed). Use the same `IssuePendingToken`-style JWT with a different claim type, or use a simple encrypted cookie:

Option: Use a new JWT claim type `EnrollmentClaims` with `SecretEnc []byte` and short TTL (5 min). This keeps the pattern consistent with pending tokens.

```go
type EnrollmentClaims struct {
    jwt.RegisteredClaims
    UserID    uuid.UUID `json:"sub"`
    SecretEnc []byte    `json:"sec"` // AES-256-GCM encrypted TOTP secret
}
```

### Step 3: Register routes

```go
huma.Register(api, huma.Operation{
    OperationID: "mfa-totp-setup",
    Method:      http.MethodPost,
    Path:        "/api/v1/auth/mfa/totp/setup",
    Tags:        []string{"auth", "mfa"},
    Summary:     "Generate TOTP secret and QR code URI",
}, srv.mfaTOTPSetupHandler)

huma.Register(api, huma.Operation{
    OperationID: "mfa-totp-confirm",
    Method:      http.MethodPost,
    Path:        "/api/v1/auth/mfa/totp/confirm",
    Tags:        []string{"auth", "mfa"},
    Summary:     "Verify TOTP code and finalize enrollment",
}, srv.mfaTOTPConfirmHandler)
```

### Step 4: Run tests and commit

```bash
go test ./internal/api/... -run TestTOTP -v -count=1
git add internal/api/auth_mfa.go internal/api/auth_mfa_test.go internal/auth/jwt.go
git commit -m "feat(api): add TOTP enrollment (setup + confirm) handlers

Two-step enrollment: generate secret + QR URI, verify code from authenticator.
Secret stored encrypted (AES-256-GCM). Recovery codes generated on first enrollment."
```

---

## Task 13: Email OTP Enrollment Handlers

**Files:**
- Modify: `internal/api/auth_mfa.go`
- Modify: `internal/api/auth_mfa_test.go`

**Context:** Email OTP enrollment is simpler than TOTP — no secret to store, just verify the user can receive codes at their email. Read the design doc §Email OTP Enrollment.

### Step 1: Write failing tests

```go
func TestEmailOTPSetup(t *testing.T) {
    // Authenticated user calls POST /auth/mfa/email-otp/setup
    // Expect: 200, email sent
}

func TestEmailOTPConfirm(t *testing.T) {
    // Call setup, extract code from DB, submit to confirm
    // Expect: 200, mfa_credentials row created with method='email_otp'
    // Expect: if first method, recovery codes returned
}

func TestEmailOTPConfirmWrongCode(t *testing.T) {
    // Wrong code → 401
}

func TestEmailOTPAlreadyEnrolled(t *testing.T) {
    // Already have email_otp enrolled → 409
}
```

### Step 2: Implement handlers

**Setup:** Same as challenge flow — generate 6-digit code, hash, insert challenge, send email.

**Confirm:** Verify code against active challenge → insert `mfa_credentials` row with `method='email_otp'`, `secret_enc=NULL` → generate recovery codes if first method.

### Step 3: Register routes and run tests

```bash
go test ./internal/api/... -run TestEmailOTP -v -count=1
git add internal/api/auth_mfa.go internal/api/auth_mfa_test.go
git commit -m "feat(api): add email OTP enrollment (setup + confirm) handlers

Sends verification code to user's email, confirms receipt.
No secret stored for email OTP — code generated on each challenge."
```

---

## Task 14: MFA Management Handlers

**Files:**
- Modify: `internal/api/auth_mfa.go`
- Modify: `internal/api/auth_mfa_test.go`

**Context:** Read the design doc §MFA Management. These are authenticated-user operations for viewing and removing MFA methods.

### Step 1: Write failing tests

```go
func TestMFAMethodsList(t *testing.T) {
    // User with TOTP + email_otp enrolled
    // GET /auth/mfa/methods
    // Expect: both methods listed, recovery_codes_remaining, required status
}

func TestMFAMethodsListEmpty(t *testing.T) {
    // User with no MFA
    // Expect: empty methods array, required=false
}

func TestMFARemoveMethod(t *testing.T) {
    // User with TOTP + email_otp, remove TOTP
    // DELETE /auth/mfa/methods/totp with current_password
    // Expect: 204, TOTP gone, email_otp remains, recovery codes still exist
}

func TestMFARemoveLastMethod(t *testing.T) {
    // User with only TOTP, no mandate
    // Remove TOTP
    // Expect: 204, recovery codes also deleted
}

func TestMFARemoveLastMethodBlocked(t *testing.T) {
    // User with TOTP, mandate active (org requires MFA)
    // Remove TOTP
    // Expect: 403 "MFA is required by your organization"
}

func TestMFARemoveRequiresPassword(t *testing.T) {
    // DELETE without current_password
    // Expect: 400 or 422
}

func TestMFARemoveWrongPassword(t *testing.T) {
    // Wrong current_password
    // Expect: 401
}
```

### Step 2: Implement handlers

**GET /auth/mfa/methods:**
```go
func (srv *Server) mfaMethodsHandler(ctx context.Context, input *mfaMethodsInput) (*mfaMethodsOutput, error) {
    userID := getUserID(ctx)

    creds, _ := srv.store.GetMFACredentialsByUserID(ctx, userID)
    remaining, _ := srv.store.CountUnusedRecoveryCodes(ctx, userID)

    // Build required_reasons from all three layers
    reasons := srv.buildMFARequiredReasons(ctx, userID)

    out := &mfaMethodsOutput{}
    out.Body.Methods = mapCredentials(creds)
    out.Body.RecoveryCodesRemaining = int(remaining)
    out.Body.Required = len(reasons) > 0
    out.Body.RequiredReasons = reasons
    return out, nil
}
```

**DELETE /auth/mfa/methods/{method}:**
```go
func (srv *Server) mfaRemoveMethodHandler(ctx context.Context, input *mfaRemoveMethodInput) (*struct{}, error) {
    userID := getUserID(ctx)

    // Re-authenticate with current password
    // ...

    // Check: is this the last method AND is MFA mandated?
    count, _ := srv.store.CountMFACredentialsByUser(ctx, userID)
    if count <= 1 {
        required, _ := srv.store.UserMFARequired(ctx, userID, ...)
        if required {
            return nil, huma.Error403Forbidden("MFA is required and cannot be disabled")
        }
    }

    // Delete the method
    deleted, _ := srv.store.DeleteMFACredential(ctx, userID, input.Method)
    if deleted == 0 {
        return nil, huma.Error404NotFound("method not enrolled")
    }

    // If no remaining credentials, delete recovery codes too
    remaining, _ := srv.store.CountMFACredentialsByUser(ctx, userID)
    if remaining == 0 {
        srv.store.DeleteAllRecoveryCodes(ctx, userID)
    }

    return nil, nil // 204
}
```

### Step 3: Register routes and run tests

```bash
go test ./internal/api/... -run TestMFAMethod -v -count=1
git add internal/api/auth_mfa.go internal/api/auth_mfa_test.go
git commit -m "feat(api): add MFA methods list and remove handlers

GET /auth/mfa/methods: list enrolled methods, recovery codes remaining,
enforcement reasons. DELETE /auth/mfa/methods/{method}: remove method
with password re-auth and mandate blocking."
```

---

## Task 15: Recovery Code Regeneration Handler

**Files:**
- Modify: `internal/api/auth_mfa.go`
- Modify: `internal/api/auth_mfa_test.go`

**Context:** Read the design doc §MFA Management (recovery-codes/regenerate).

### Step 1: Write failing tests

```go
func TestRecoveryCodeRegenerate(t *testing.T) {
    // User with TOTP enrolled + recovery codes
    // POST /auth/mfa/recovery-codes/regenerate with current_password
    // Expect: 200, new codes returned (10), old codes invalid
}

func TestRecoveryCodeRegenerateNoMFA(t *testing.T) {
    // User with no MFA enrolled
    // Expect: 409 Conflict
}

func TestRecoveryCodeRegenerateWrongPassword(t *testing.T) {
    // Wrong password → 401
}
```

### Step 2: Implement and test

### Step 3: Commit

```bash
git add internal/api/auth_mfa.go internal/api/auth_mfa_test.go
git commit -m "feat(api): add recovery code regeneration handler

Requires password re-auth and active MFA enrollment.
Deletes old codes, generates 10 new ones, returns plaintext once."
```

---

## ── REVIEW CHECKPOINT: Tasks 12–15 ──

Enrollment + management handlers. Check:

- [ ] TOTP setup validates URI round-trip
- [ ] TOTP secret encrypted before DB storage
- [ ] Recovery codes generated on first enrollment only (not on second method)
- [ ] Method removal checks mandate before allowing deletion of last method
- [ ] Recovery codes deleted when last method removed
- [ ] Password re-auth uses argon2 semaphore (not a new unthrottled path)
- [ ] All handlers return consistent error formats

Perform the mandatory 3-round review.

**⚠️ COMPACT NOW:** After the review is complete and all issues are resolved, run `/compact` before starting Task 16. Reviews consume significant context from file reads and verification — compacting here prevents an automatic compaction mid-task in the next batch, which would discard freshly-loaded task context.

---

## Task 16: Middleware — Pending Token Route Gating

**Files:**
- Modify: `internal/api/middleware_auth.go`
- Modify: `internal/api/middleware_auth_test.go` (or auth_test.go)

**Context:** Read the design doc §Middleware. The pending token restricts which routes are accessible based on `pending[0]`.

### Step 1: Write failing tests

```go
func TestPendingTokenBlocksProtectedRoutes(t *testing.T) {
    // User with pending=["mfa_challenge"]
    // Call GET /api/v1/cves — expect 403
}

func TestPendingTokenAllowsMFARoutes(t *testing.T) {
    // User with pending=["mfa_challenge"]
    // Call POST /auth/mfa/verify — expect not 403 (may be 401 for other reasons)
}

func TestPendingTokenPasswordResetAllowsChangePassword(t *testing.T) {
    // User with pending=["password_reset"]
    // Call POST /auth/password/change — expect not 403
}

func TestPendingTokenEnrollmentAllowsSetup(t *testing.T) {
    // User with pending=["mfa_enrollment_required"]
    // Call POST /auth/mfa/totp/setup — expect not 403
}
```

### Step 2: Modify middleware

The existing `RequireAuthenticated` middleware checks access_token cookies. We need to also handle pending tokens for MFA routes. There are two approaches:

**Approach A (recommended):** The MFA challenge/verify/enrollment handlers read the `mfa_pending_token` cookie themselves (they already do). Protected routes continue to require the `access_token` cookie. No middleware change needed — the existing middleware already rejects requests without a valid access_token.

**Approach B:** Add pending token awareness to middleware.

Since the MFA handlers already read and validate the pending token cookie directly (Task 11, 12, 13), and the existing middleware rejects non-authenticated requests, Approach A may be sufficient. The key question is: can a user with only a pending token (no access token) reach non-MFA routes?

Answer: No — the pending token is set as `mfa_pending_token` cookie, not `access_token`. The existing middleware looks for `access_token` cookie. A user with only a pending token will get 401 on all authenticated routes, which is correct.

**However**, we need to ensure the `force_password_reset` check in the existing middleware also handles the new pending token flow. Currently, the middleware checks `authStatus.ForcePasswordReset` and restricts to password-change routes. With MFA, a forced-reset user might also need MFA first. The pending token flow handles this ordering correctly — the user completes MFA first, THEN changes password.

**Modification needed:** The existing force_password_reset check in the middleware should be aware that if a pending token exists (user is mid-MFA), the force_password_reset enforcement is deferred to the pending token flow.

Actually, on reflection: if a user has completed MFA and password reset via the pending token flow, they receive full access+refresh tokens. At that point, `force_password_reset` should be `false` (cleared during password change in Task 17). So the middleware check only fires for users who somehow have access tokens AND force_password_reset=true, which shouldn't happen in the MFA flow.

**Minimal change:** Add MFA-related paths to the `allowed` list when `force_password_reset` is true:

```go
if authStatus.ForcePasswordReset {
    path := r.URL.Path
    allowed := strings.HasSuffix(path, "/auth/change-password") ||
        strings.HasSuffix(path, "/auth/me") ||
        strings.HasSuffix(path, "/auth/logout") ||
        strings.Contains(path, "/auth/mfa/")  // allow MFA routes during forced reset
    // ...
}
```

### Step 3: Run tests and commit

```bash
go test ./internal/api/... -run TestPendingToken -v -count=1
git add internal/api/middleware_auth.go internal/api/middleware_auth_test.go
git commit -m "feat(middleware): allow MFA routes during forced password reset

Pending token flow handles the MFA+reset ordering. Middleware
allows /auth/mfa/* paths when force_password_reset is active."
```

---

## Task 17: Password Change Handler Modification

**Files:**
- Modify: `internal/api/auth.go` (changePasswordHandler)
- Modify: `internal/api/auth_test.go` (add tests)

**Context:** Read the design doc §Forced Password Reset Flow. The password change handler must work in both full-session and restricted-session modes. In restricted mode (pending token with `"password_reset"`), `current_password` is not required.

### Step 1: Write failing tests

```go
func TestPasswordChangeInRestrictedSession(t *testing.T) {
    // User with pending=["password_reset"] after MFA completion
    // POST /auth/password/change with only new_password (no current_password)
    // Expect: 200, force_password_reset cleared, full tokens issued
}

func TestPasswordChangeFullSession(t *testing.T) {
    // Normal authenticated user
    // POST /auth/password/change with current_password + new_password
    // Expect: 200, token_version incremented
}

func TestPasswordChangeRestrictedSessionClearsRememberDevice(t *testing.T) {
    // After forced reset, device tokens should be cleared
    // (design doc: force-password-reset deletes remember-device tokens)
}
```

### Step 2: Modify handler

The password change handler needs to:
1. Check if this is a restricted session (pending token with `"password_reset"`)
2. If restricted: skip `current_password` validation (password may be compromised)
3. Hash new password with argon2
4. Update password hash, clear `force_password_reset`, increment `token_version`
5. Delete remember-device tokens for this user
6. If restricted session with remaining pending items: reissue pending token
7. If no remaining items: issue full tokens

**IMPORTANT:** The handler must accept EITHER an access_token cookie OR an mfa_pending_token cookie. Use a helper to try both:

```go
func (srv *Server) resolveAuthContext(ctx context.Context, accessCookie, pendingCookie string) (userID uuid.UUID, isPending bool, pendingClaims *auth.PendingClaims, err error) {
    // Try access token first
    if accessCookie != "" {
        claims, err := auth.ParseAccessToken(accessCookie, []byte(srv.cfg.JWTSecret))
        if err == nil {
            return claims.UserID, false, nil, nil
        }
    }
    // Try pending token
    if pendingCookie != "" {
        claims, err := auth.ParsePendingToken(pendingCookie, []byte(srv.cfg.JWTSecret))
        if err == nil {
            return claims.UserID, true, claims, nil
        }
    }
    return uuid.Nil, false, nil, fmt.Errorf("no valid auth token")
}
```

### Step 3: Run tests and commit

```bash
go test ./internal/api/... -run TestPasswordChange -v -count=1
git add internal/api/auth.go internal/api/auth_test.go
git commit -m "feat(api): modify password change for restricted session support

Accepts pending token (forced reset) or access token (normal change).
Clears force_password_reset flag, deletes device tokens, progresses
pending array."
```

---

## Task 18: Admin Actions — MFA Reset + Force Password Reset

**Files:**
- Create: `internal/api/admin_mfa.go`
- Create: `internal/api/admin_mfa_test.go`

**Context:** Read the design doc §Admin Actions. These are org-scoped endpoints under `/api/v1/orgs/{org_id}/members/{user_id}/...`. Read existing admin handlers (e.g., `internal/api/admin_users.go`) for the pattern.

### Step 1: Write failing tests

```go
func TestAdminMFAReset(t *testing.T) {
    // Owner resets member's MFA
    // Expect: all MFA state cleared, sessions invalidated
}

func TestAdminMFAResetByAdmin(t *testing.T) {
    // Admin resets member's MFA — expect success
}

func TestAdminMFAResetOwnerByAdmin(t *testing.T) {
    // Admin tries to reset owner's MFA — expect 403
    // (only site admin can reset owner's MFA)
}

func TestAdminMFAResetByMember(t *testing.T) {
    // Member tries to reset anyone's MFA — expect 403
}

func TestAdminForcePasswordReset(t *testing.T) {
    // Owner forces member password reset
    // Expect: force_password_reset=true, sessions invalidated, device tokens deleted
}

func TestAdminForcePasswordResetOAuthUser(t *testing.T) {
    // Force reset on OAuth-only user (no password)
    // Expect: 400 "user has no native identity"
}

func TestAdminSendPasswordReset(t *testing.T) {
    // Admin sends reset email for member
    // Expect: 200, email sent
}

func TestAdminSendPasswordResetRateLimit(t *testing.T) {
    // 4 sends in an hour → last one rate-limited
}
```

### Step 2: Implement handlers

**POST /orgs/{org_id}/members/{user_id}/reset-mfa:**
```go
func (srv *Server) adminResetMFAHandler(ctx context.Context, input *adminResetMFAInput) (*struct{}, error) {
    actorID := getUserID(ctx)
    orgID := input.OrgID
    targetID := input.UserID

    // Permission check: owner can reset members/admins; site admin can reset owners
    // ... (check roles, reject if insufficient)

    // Delete all MFA state
    srv.store.DeleteAllMFACredentials(ctx, targetID)
    srv.store.DeleteAllRecoveryCodes(ctx, targetID)
    srv.store.DeleteAllUserChallenges(ctx, targetID)

    // Invalidate all sessions
    srv.store.IncrementTokenVersion(ctx, targetID)

    // Audit event
    srv.auditWriter.Log(ctx, audit.Entry{
        OrgID:      orgID,
        ActorID:    &actorID,
        Action:     secure.EventMFAAdminReset,
        EntityType: "security_event",
        EntityID:   targetID.String(),
        Success:    true,
        Metadata:   map[string]any{"target_user_id": targetID, "severity": secure.SeverityCritical},
    })

    return nil, nil // 204
}
```

**POST /orgs/{org_id}/members/{user_id}/force-password-reset:**
- Check target has native identity (`password_hash IS NOT NULL`)
- Set `force_password_reset = true`
- Increment `token_version`
- Delete remember-device tokens

**POST /orgs/{org_id}/members/{user_id}/send-password-reset:**
- Rate limit (same as user-initiated)
- Generate reset token, send email

### Step 3: Register routes, run tests, commit

```bash
go test ./internal/api/... -run TestAdmin -v -count=1
git add internal/api/admin_mfa.go internal/api/admin_mfa_test.go
git commit -m "feat(api): add admin MFA reset, force password reset, send reset email

Org owner resets members/admins; site admin resets owners.
Force password reset invalidates sessions and device tokens.
Full RBAC hierarchy enforcement."
```

---

## Task 19: Admin Actions — MFA Requirements + Org Settings

**Files:**
- Modify: `internal/api/admin_mfa.go`
- Modify: `internal/api/admin_mfa_test.go`

**Context:** Read the design doc §Permission Matrix and §API Surface (Admin Actions).

### Step 1: Write failing tests

```go
func TestAdminRequireMFA(t *testing.T) {
    // Owner adds per-member MFA requirement
    // POST /orgs/{org_id}/members/{user_id}/require-mfa
    // Expect: 201
}

func TestAdminUnrequireMFA(t *testing.T) {
    // Owner removes per-member MFA requirement
    // DELETE /orgs/{org_id}/members/{user_id}/require-mfa
    // Expect: 204
}

func TestAdminRequireMFAByMember(t *testing.T) {
    // Member tries to require MFA → 403
}

func TestAdminUpdateOrgMFASettings(t *testing.T) {
    // PATCH /orgs/{org_id}/settings with mfa_required_all, remember-device settings
    // Expect: 200
}

func TestAdminUpdateOrgMFASettingsRememberDeviceDaysRange(t *testing.T) {
    // Set mfa_remember_device_days=3 → 400 (below minimum 7)
    // Set mfa_remember_device_days=100 → 400 (above maximum 90)
}

func TestMembersListMFAEnrolled(t *testing.T) {
    // GET /orgs/{org_id}/members — verify mfa_enrolled field present
}
```

### Step 2: Implement handlers

**POST /orgs/{org_id}/members/{user_id}/require-mfa** and **DELETE** variant — simple CRUD on `mfa_requirements` table with RBAC check (owner/admin only).

**PATCH /orgs/{org_id}/settings** — modify existing org settings handler to include MFA fields. Use pointer types for PATCH fields per implementation-pitfalls §1.11.

**GET /orgs/{org_id}/members** — modify existing members list to include `mfa_enrolled` derived field.

### Step 3: Run tests and commit

```bash
git add internal/api/admin_mfa.go internal/api/admin_mfa_test.go
git commit -m "feat(api): add per-member MFA requirements and org MFA settings

Per-member require/unrequire endpoints. Org-level mfa_required_all
and remember-device settings. Members list includes mfa_enrolled."
```

---

## Task 20: Remember-Device Implementation

**Files:**
- Modify: `internal/api/auth_mfa.go` (update verify handler)
- Modify: `internal/api/auth_mfa_test.go`
- Modify: `internal/api/auth.go` (login handler — device cookie reading)

**Context:** Read the design doc §Cookie Specifications for device token cookie details. Remember-device was partially implemented in Tasks 10-11. This task ensures the full flow works end-to-end.

### Step 1: Write failing tests

```go
func TestRememberDeviceFlow(t *testing.T) {
    // 1. Login → MFA challenge → verify with remember_device=true
    // 2. Expect: mfa_device_token cookie set
    // 3. Logout
    // 4. Login again → expect NO MFA challenge (device remembered)
}

func TestRememberDeviceOrgDisallowed(t *testing.T) {
    // Org has mfa_remember_device_allowed=false
    // Verify with remember_device=true → no device cookie set
}

func TestRememberDeviceExpiry(t *testing.T) {
    // Create device token with short TTL
    // Wait for expiry → next login requires MFA
}

func TestRememberDeviceInvalidatedOnPasswordChange(t *testing.T) {
    // Have device token → change password → device token invalid
}

func TestRememberDeviceInvalidatedOnMFAReset(t *testing.T) {
    // Have device token → admin resets MFA → device token invalid
}
```

### Step 2: Implement device token creation/validation

In the verify handler (Task 11), the remember-device logic:
```go
if input.Body.RememberDevice {
    // Look up org settings for user
    org, _ := srv.getOrgForRememberDevice(ctx, userID)
    if org != nil && org.MFARememberDeviceAllowed {
        token := generateSecureToken(32) // crypto/rand
        tokenHash := sha256Hex(token)
        expiresAt := time.Now().AddDate(0, 0, org.MFARememberDeviceDays)
        srv.store.CreateRememberDeviceToken(ctx, userID, tokenHash, expiresAt)

        cookie := &http.Cookie{
            Name:     "mfa_device_token",
            Value:    token,
            Path:     "/api/v1/auth/login",
            HttpOnly: true,
            Secure:   srv.cfg.CookieSecure,
            SameSite: http.SameSiteLaxMode,
            MaxAge:   org.MFARememberDeviceDays * 86400,
        }
        out.SetCookie = append(out.SetCookie, cookie.String())
    }
}
```

**Note on "which org" for remember-device:** A user may be in multiple orgs. The design doc says remember-device is org-configurable. At login time, there's no org context (user hasn't selected an org yet). **Approach:** Use the most restrictive setting — if ANY org the user belongs to disallows remember-device, don't issue the token. Or, use the org-level settings from the user's most recently active org. This needs a design decision.

**RECOMMENDED:** Check if ALL orgs the user belongs to allow remember-device. If any disallow, don't issue. This is the most secure option and avoids the "which org" ambiguity. Implement as a store query:

```sql
-- name: AllUserOrgsAllowRememberDevice :one
SELECT NOT EXISTS(
    SELECT 1 FROM org_members om
    JOIN organizations o ON o.id = om.org_id
    WHERE om.user_id = $1 AND o.mfa_remember_device_allowed = false
) AS allowed;

-- name: MinRememberDeviceDays :one
SELECT COALESCE(MIN(o.mfa_remember_device_days), 30) AS days
FROM org_members om
JOIN organizations o ON o.id = om.org_id
WHERE om.user_id = $1;
```

### Step 3: Run tests and commit

```bash
go test ./internal/api/... -run TestRememberDevice -v -count=1
git add internal/api/auth_mfa.go internal/api/auth_mfa_test.go internal/api/auth.go internal/store/queries/mfa.sql internal/store/mfa.go
git commit -m "feat(api): complete remember-device token flow

Device tokens issued on MFA verify when org allows. Most restrictive
org setting wins. Tokens invalidated on password change, MFA reset,
and forced password reset."
```

---

## Task 21: Security Events + Audit Logging

**Files:**
- Modify: `internal/secure/events.go` (add MFA event constants)
- Modify: `internal/secure/events_test.go` (add tests)
- Modify: `internal/api/auth_mfa.go` (add audit calls to all handlers)

**Context:** Read `internal/secure/events.go` for the existing event type constants and severity mapping. Read `internal/audit/writer.go` for the audit writer pattern. Read the design doc §Security Events.

### Step 1: Add event constants

```go
// MFA authentication events
EventMFAChallengeRequested    = "mfa.challenge_requested"
EventMFAVerifySuccess         = "mfa.verify_success"
EventMFAVerifyFailed          = "mfa.verify_failed"
EventMFAChallengeExhausted    = "mfa.challenge_exhausted"
EventMFAEmailOTPRateLimited   = "mfa.email_otp_rate_limited"
EventMFARememberDeviceIssued  = "mfa.remember_device_issued"
EventMFARememberDeviceUsed    = "mfa.remember_device_used"

// Recovery code events
EventMFARecoveryCodesGenerated = "mfa.recovery_codes_generated"
EventMFARecoveryCodeUsed       = "mfa.recovery_code_used"
EventMFARecoveryCodeFailed     = "mfa.recovery_code_failed"

// Enrollment/management events
EventMFAMethodEnrolled         = "mfa.method_enrolled"
EventMFAMethodRemoved          = "mfa.method_removed"
EventMFAAllMethodsRemoved      = "mfa.all_methods_removed"
EventMFAEnrollmentFailed       = "mfa.enrollment_failed"
EventMFADisableBlocked         = "mfa.disable_blocked"

// Admin action events
EventMFAAdminReset             = "mfa.admin_reset"
EventMFAAdminRequireMember     = "mfa.admin_require_member"
EventMFAAdminUnrequireMember   = "mfa.admin_unrequire_member"
EventMFAOrgRequireAllEnabled   = "mfa.org_require_all_enabled"
EventMFAOrgRequireAllDisabled  = "mfa.org_require_all_disabled"
EventAuthPasswordResetForced   = "auth.password_reset_forced"
EventAuthPasswordResetForcedCompleted = "auth.password_reset_forced_completed"
EventAuthPasswordResetSentByAdmin     = "auth.password_reset_sent_by_admin"
```

### Step 2: Add severity mapping

```go
// Add to eventSeverity map
EventMFAChallengeRequested:    SeverityInfo,
EventMFAVerifySuccess:         SeverityInfo,
EventMFAVerifyFailed:          SeverityWarning,
EventMFAChallengeExhausted:    SeverityWarning,
EventMFAEmailOTPRateLimited:   SeverityWarning,
EventMFARememberDeviceIssued:  SeverityInfo,
EventMFARememberDeviceUsed:    SeverityInfo,
EventMFARecoveryCodesGenerated: SeverityInfo,
EventMFARecoveryCodeUsed:       SeverityWarning,
EventMFARecoveryCodeFailed:     SeverityWarning,
EventMFAMethodEnrolled:         SeverityInfo,
EventMFAMethodRemoved:          SeverityInfo,
EventMFAAllMethodsRemoved:      SeverityWarning,
EventMFAEnrollmentFailed:       SeverityWarning,
EventMFADisableBlocked:         SeverityWarning,
EventMFAAdminReset:             SeverityCritical,
EventMFAAdminRequireMember:     SeverityInfo,
EventMFAAdminUnrequireMember:   SeverityInfo,
EventMFAOrgRequireAllEnabled:   SeverityInfo,
EventMFAOrgRequireAllDisabled:  SeverityWarning,
EventAuthPasswordResetForced:   SeverityCritical,
EventAuthPasswordResetForcedCompleted: SeverityInfo,
EventAuthPasswordResetSentByAdmin:     SeverityInfo,
```

### Step 3: Add audit calls to all MFA handlers

Go through every handler in `auth_mfa.go` and `admin_mfa.go` and add appropriate `srv.auditWriter.Log()` calls. Use the pattern from existing handlers. Every MFA action in the design doc §Security Events table must have a corresponding audit call.

**IMPORTANT for recovery codes:** Audit both success AND failure:
```go
// On recovery code success
srv.auditWriter.Log(ctx, audit.Entry{
    Action:     secure.EventMFARecoveryCodeUsed,
    EntityType: "security_event",
    EntityID:   userID.String(),
    Success:    true,
    Metadata:   map[string]any{"codes_remaining": remaining, "severity": secure.SeverityWarning},
})

// On recovery code failure
srv.auditWriter.Log(ctx, audit.Entry{
    Action:     secure.EventMFARecoveryCodeFailed,
    EntityType: "security_event",
    EntityID:   userID.String(),
    Success:    false,
    Metadata:   map[string]any{"severity": secure.SeverityWarning},
})
```

### Step 4: Add slog calls for system logging

Per the design doc §System Logging, add structured slog entries:
- ERROR: TOTP encryption/decryption failure, email OTP delivery failure, DB transaction failure
- WARN: recovery codes remaining ≤ 2
- INFO: MFA verification latency, email OTP sent

**CRITICAL:** Never log secrets, codes, or hashes at any level.

### Step 5: Test and commit

```bash
go test ./internal/secure/... -v -count=1
go test ./internal/api/... -run TestMFA -v -count=1
git add internal/secure/events.go internal/secure/events_test.go internal/api/auth_mfa.go internal/api/admin_mfa.go
git commit -m "feat(audit): add MFA security events and audit logging

22 event types covering authentication, recovery codes, enrollment,
management, and admin actions. Severity mapping per design doc.
slog entries for operational monitoring."
```

---

## Task 22: Expired Challenge Cleanup Worker

**Files:**
- Modify: `internal/worker/` (add periodic task or modify existing scheduler)
- Test file for the cleanup

**Context:** Read the design doc §Retention. `mfa_challenges` needs periodic cleanup of expired rows. Read existing worker patterns in `internal/worker/`.

### Step 1: Write test

```go
func TestDeleteExpiredChallenges(t *testing.T) {
    db := testutil.NewTestDB(t)
    // Insert expired and non-expired challenges
    // Call store.DeleteExpiredChallenges
    // Verify only expired rows deleted
}
```

### Step 2: Add to existing periodic cleanup

If there's already a periodic cleanup job (e.g., for expired refresh tokens), add `DeleteExpiredChallenges` to it. If not, create a simple periodic task:

```go
// In the worker's periodic task list
{
    Name:     "mfa-challenge-cleanup",
    Interval: 1 * time.Hour,
    Fn: func(ctx context.Context) error {
        deleted, err := store.DeleteExpiredChallenges(ctx)
        if err != nil {
            return err
        }
        if deleted > 0 {
            slog.InfoContext(ctx, "mfa: cleaned expired challenges", "count", deleted)
        }
        return nil
    },
},
```

### Step 3: Test and commit

```bash
go test ./internal/store/... -run TestDeleteExpired -v -count=1
git add internal/worker/ internal/store/mfa.go internal/store/mfa_test.go
git commit -m "feat(worker): add periodic cleanup for expired MFA challenges

Hourly job removes expired email OTP and remember-device tokens."
```

---

## ── REVIEW CHECKPOINT: Tasks 16–22 ──

Final handler + infrastructure review:

- [ ] Middleware allows MFA routes during forced password reset
- [ ] Password change works in both full and restricted session modes
- [ ] Admin RBAC hierarchy enforced (owner→member/admin, site-admin→owner)
- [ ] Remember-device uses most-restrictive org setting
- [ ] All security events from design doc are logged
- [ ] Recovery code generation AND usage are audited (success and failure)
- [ ] Expired challenge cleanup runs hourly
- [ ] No secrets/codes/hashes in slog output
- [ ] `golangci-lint run` passes on all changed files

Perform the mandatory 3-round review.

**⚠️ COMPACT NOW:** After the review is complete and all issues are resolved, run `/compact` before starting Task 23. Reviews consume significant context from file reads and verification — compacting here prevents an automatic compaction mid-task in the next batch, which would discard freshly-loaded task context.

---

## Task 23: Integration Tests — Full End-to-End Flows

**Files:**
- Create: `internal/api/auth_mfa_integration_test.go`

**Context:** These tests exercise complete multi-step flows as a real user would experience them. They use the full HTTP stack via `httptest.Server`.

### Step 1: Write integration tests

```go
func TestFullTOTPLoginFlow(t *testing.T) {
    // 1. Register user
    // 2. Login (no MFA) → get tokens
    // 3. Enroll TOTP (setup + confirm) → get recovery codes
    // 4. Logout
    // 5. Login → get pending token with mfa_challenge
    // 6. Verify TOTP → get full tokens
    // 7. Access protected route → 200
}

func TestFullEmailOTPLoginFlow(t *testing.T) {
    // Same as TOTP but with email OTP
    // 1. Register, login, enroll email_otp
    // 2. Logout, login → pending
    // 3. Request challenge (email sent)
    // 4. Extract code, verify → full tokens
}

func TestFullRecoveryCodeFlow(t *testing.T) {
    // 1. Register, enroll TOTP, get recovery codes
    // 2. Logout, login → pending
    // 3. Verify with recovery code → full tokens
    // 4. Check remaining codes decremented
}

func TestFullForcedPasswordResetWithMFA(t *testing.T) {
    // 1. Register, enroll TOTP
    // 2. Admin sets force_password_reset
    // 3. Login → pending=["mfa_challenge", "password_reset"]
    // 4. Verify TOTP → pending=["password_reset"]
    // 5. Change password → full tokens
    // 6. Verify force_password_reset=false
}

func TestFullMFAEnrollmentRequired(t *testing.T) {
    // 1. Register user
    // 2. Admin enables mfa_required_all on org
    // 3. Login → pending=["mfa_enrollment_required"]
    // 4. Enroll TOTP (setup + confirm) → full tokens
}

func TestFullRememberDeviceFlow(t *testing.T) {
    // 1. Register, enroll TOTP
    // 2. Login → MFA → verify with remember_device=true → device cookie
    // 3. Logout
    // 4. Login again (with device cookie) → NO MFA challenge, full tokens directly
}

func TestMFADoesNotApplyToOAuthUsers(t *testing.T) {
    // OAuth-only user with org MFA mandate
    // Login via OAuth → full tokens (no MFA required)
}

func TestMFADoesNotApplyToAPIKeys(t *testing.T) {
    // User with MFA + API key
    // API key request → 200 (no MFA challenge)
}

func TestPasswordResetDoesNotBypassMFA(t *testing.T) {
    // 1. Register, enroll TOTP
    // 2. Use forgot-password flow to reset password
    // 3. After reset, login → still requires MFA challenge
}

func TestConcurrentRecoveryCodeUse(t *testing.T) {
    // Two goroutines submit the same recovery code simultaneously
    // Exactly one succeeds (testing-pitfalls §1)
}
```

### Step 2: Run tests

```bash
go test ./internal/api/... -run TestFull -v -count=1 -timeout 120s
```

### Step 3: Commit

```bash
git add internal/api/auth_mfa_integration_test.go
git commit -m "test(api): add MFA end-to-end integration tests

Full login flows: TOTP, email OTP, recovery codes, forced password reset,
mandated enrollment, remember-device, OAuth bypass, API key bypass,
concurrent recovery code consumption."
```

---

## Task 24: Final Verification + Lint + Commit

### Step 1: Run full test suite

```bash
go test ./... -count=1 -timeout 300s
```

### Step 2: Run linter

```bash
golangci-lint run
```

### Step 3: Fix any issues found

### Step 4: Run sqlc verify

```bash
sqlc generate
```
Verify no uncommitted generated file changes.

### Step 5: Run the `/pitfall-check` skill on all new business logic files

### Step 6: Run the `/security-review` skill on the MFA auth code

### Step 7: Final commit if any fixes were needed

```bash
git add -A
git commit -m "fix: address lint and review findings from MFA implementation"
```

### Step 8: Proceed with /finishing-a-development-branch

---

## Appendix A: Helper Functions Needed

These helpers are used across multiple tasks. Implement them as needed (don't create them all upfront — YAGNI).

```go
// sha256Hex returns the hex-encoded SHA-256 hash of s.
func sha256Hex(s string) string {
    h := sha256.Sum256([]byte(s))
    return hex.EncodeToString(h[:])
}

// generateSecureToken returns n random bytes as a hex string.
func generateSecureToken(n int) (string, error) {
    b := make([]byte, n)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return hex.EncodeToString(b), nil
}

// pendingTokenCookies creates the mfa_pending_token Set-Cookie header.
func pendingTokenCookies(token string, secure bool, ttl time.Duration) []string { ... }

// clearPendingTokenCookie creates a Set-Cookie that expires the pending token.
func clearPendingTokenCookie(secure bool) string { ... }

// enrollmentTokenCookies creates the mfa_enrollment_token Set-Cookie header.
func enrollmentTokenCookies(token string, secure bool) []string { ... }

// clearEnrollmentTokenCookie creates a Set-Cookie that expires the enrollment token.
func clearEnrollmentTokenCookie(secure bool) string { ... }

// deviceTokenCookie creates the mfa_device_token Set-Cookie header.
func deviceTokenCookie(token string, secure bool, days int) string { ... }
```

## Appendix B: Files Modified/Created Summary

| File | Action | Task |
|------|--------|------|
| `internal/config/config.go` | Modify | 1 |
| `internal/config/config_test.go` | Modify | 1 |
| `migrations/000039_create_mfa_tables.up.sql` | Create | 2 |
| `migrations/000039_create_mfa_tables.down.sql` | Create | 2 |
| `go.mod`, `go.sum` | Modify | 3 |
| `internal/store/queries/mfa.sql` | Create | 4–8 |
| `internal/store/mfa.go` | Create | 4–8 |
| `internal/store/mfa_test.go` | Create | 4–8 |
| `internal/auth/jwt.go` | Modify | 9, 12 |
| `internal/auth/jwt_test.go` | Modify | 9 |
| `internal/api/auth.go` | Modify | 10, 17 |
| `internal/api/auth_test.go` | Modify | 10, 17 |
| `internal/api/auth_mfa.go` | Create | 11–15, 20 |
| `internal/api/auth_mfa_test.go` | Create | 11–15, 20 |
| `internal/api/middleware_auth.go` | Modify | 16 |
| `internal/api/admin_mfa.go` | Create | 18–19 |
| `internal/api/admin_mfa_test.go` | Create | 18–19 |
| `internal/secure/events.go` | Modify | 21 |
| `internal/secure/events_test.go` | Modify | 21 |
| `internal/worker/` (scheduler) | Modify | 22 |
| `internal/api/auth_mfa_integration_test.go` | Create | 23 |
| `internal/store/generated/` | Regenerated | 4–8 |

## Appendix C: Subagent Ambiguity Risk Mitigation

The following areas are most likely to cause subagent confusion. Each risk is addressed with explicit instructions:

1. **Transaction helper selection** — Every store method lists the specific helper to use. Agents MUST read `implementation-pitfalls.md` §2.17 before writing store code. The rule: `withOrgTx` for API handlers with org context, `withBypassTx` for auth paths and cross-org queries, `WorkerTx` for background jobs only.

2. **Encryption key access** — TOTP secret encryption uses the same key pattern as SSO secrets. Agents MUST read `internal/api/sso.go` lines 70-82 for the `ssoEncryptionKey()` helper. Do NOT invent a new key management pattern.

3. **Cookie handling in huma** — huma reads cookies via struct tags (`cookie:"name"`), not `r.Cookie()`. Agents MUST read existing cookie patterns in `auth.go` (loginInput doesn't use cookies for request but refreshInput does for refresh_token). Output cookies use `SetCookie []string \`header:"Set-Cookie"\``.

4. **Pending token vs access token disambiguation** — Handlers that accept EITHER token type need explicit logic to try both. The `resolveAuthContext` helper (Task 17) handles this. Agents must not assume only one token type.

5. **"First MFA method" detection for recovery codes** — Recovery codes are generated only on the FIRST method enrollment. Agents must check `CountMFACredentialsByUser` BEFORE inserting the new credential to determine if this is the first enrollment. Checking AFTER would always show count≥1.

6. **Remember-device "which org" ambiguity** — At login time, no org is selected. The plan specifies using the most-restrictive org setting. Agents MUST implement the `AllUserOrgsAllowRememberDevice` query, not pick a single org.

7. **Audit logging for security events** — Until the `security_events` table exists, events use the existing `audit_log` table with `EntityType: "security_event"`. Agents MUST NOT try to create a `security_events` table or writer.
