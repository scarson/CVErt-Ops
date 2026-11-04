# Phase 5C — Audit Logging, SSO Connections, OIDC Login Flow

> **Date:** 2026-03-01 to 2026-03-02
> **Commits:** `03ca3a3`..`0feb8f2` on `dev`
> **Plan:** `dev/plans/2026-03-01-phase5-implementation-plan.md`

## What was built

| Feature | Files | Description |
|---|---|---|
| Audit log migration | `migrations/000027_audit_log.{up,down}.sql` | `audit_log` table with RLS, autovacuum tuning. No FK to `organizations` or `users` — audit records survive entity deletion |
| Secret redaction | `internal/audit/redact.go` | Write-time redaction using keyword-based substring matching (secret, password, api_key, token, etc.) |
| Audit writer | `internal/audit/writer.go` | Non-blocking inserts via goroutines with `context.WithoutCancel`. `sync.WaitGroup` for deterministic test flushing |
| Audit integration in handlers | All mutation handlers | All create/update/delete handlers emit audit entries with old_state/new_state snapshots |
| Audit log list endpoint | `internal/api/audit_log.go` | `GET /api/v1/orgs/{org_id}/audit-log` with admin+ RBAC, enterprise tier gating, keyset pagination |
| AES-256-GCM crypto | `internal/crypto/aes.go` | Encrypt/Decrypt for OIDC client secrets at rest |
| SSO connections migration | `migrations/000028_sso_connections.{up,down}.sql` | `sso_connections` (one per org, `client_secret_enc BYTEA`) and `sso_email_domains`. Both with RLS |
| SSO CRUD handlers | `internal/api/sso.go` | Create/Get/Patch/Delete SSO connection + PUT domains + domain discovery. Enterprise tier gated, owner-only RBAC |
| OIDC login flow | `internal/api/oauth_oidc.go` | SSO login initiation + callback with ID token verification. Does NOT auto-create users — requires pre-existing linked identity |
| Mock OIDC IdP | `internal/testutil/mock_oidc.go` | Test utility serving OIDC discovery, JWKS, and token endpoints with real RSA-signed ID tokens |

## Key implementation decisions

- **Non-blocking audit writes** — `context.WithoutCancel` detaches from request lifecycle. Errors logged, never propagated to API callers
- **Write-time redaction (not read-time)** — Secrets stripped before INSERT, ensuring they never reach the database
- **Audit log intentionally FK-free** — `org_id` and `actor_id` are NOT foreign keys. Audit records must survive org/user deletion for compliance
- **SSO: one connection per org** — UNIQUE constraint on `sso_connections.org_id`. Simple for initial implementation
- **Client secrets encrypted at rest** — AES-256-GCM with nonce-prepended format. Masked as `"[encrypted]"` in API responses
- **OIDC login does NOT auto-create users** — Unlike Google/GitHub OAuth, SSO login requires a pre-existing linked identity. Prevents unauthorized access through misconfigured IdP
- **State parameter encodes connection_id** — `{random_hex}_{connection_uuid}` allows single callback endpoint to identify which SSO connection to use
- **OIDC provider caching** — `sync.Map` caches `*oidc.Provider` instances by issuer URL

## Tests added

| Test | File | What it verifies |
|---|---|---|
| Redaction unit tests | `internal/audit/redact_test.go` | Keyword matching, URL redaction, nested map recursion |
| Writer unit tests | `internal/audit/writer_test.go` | Non-blocking insert, Flush determinism, email resolution fallback |
| Audit store integration | `internal/store/audit_test.go` | Insert/List with pagination, filters, RLS enforcement |
| Audit handler tests | `internal/api/audit_log_test.go` | RBAC, enterprise tier gating, pagination, filters |
| Audit integration tests | `internal/api/audit_integration_test.go` | All mutation handlers emit correct audit entries |
| AES-256-GCM unit tests | `internal/crypto/aes_test.go` | Encrypt/decrypt round-trip, wrong key rejection, nonce uniqueness |
| SSO store integration | `internal/store/sso_test.go` | CRUD, email domain management, RLS, encryption round-trip |
| SSO handler tests | `internal/api/sso_test.go` | CRUD, domain management, tier gating, RBAC, discovery |
| OIDC login/callback tests | `internal/api/oauth_oidc_test.go` | Full OIDC flow with mock IdP — login, callback, token exchange, nonce validation, conflict detection |

## Quality checks

- All tests pass (`go test ./...`)
- Code review remediation: email resolution in audit writer, invitation audit logging, file renames
