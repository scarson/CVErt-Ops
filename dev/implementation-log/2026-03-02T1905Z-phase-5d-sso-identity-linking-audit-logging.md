# Phase 5D — SSO Identity Linking + Audit Logging

> **Date:** 2026-03-02
> **Commits:** `75bca91` (identity linking), `4909767` (audit logging) on `dev`
> **Plan:** `dev/plans/2026-03-01-phase5-implementation-plan.md`, Tasks 25–27

## What was built

| Feature | Files | Description |
|---|---|---|
| SSO identity linking | `oauth_oidc.go`, `server.go` | Two-endpoint OIDC flow: `GET /orgs/{org_id}/sso/link` (org-scoped, auth required) + `GET /auth/oidc/link-callback` (public, reads user from JWT cookie) |
| Conflict detection | `oauth_oidc.go` | Link callback checks `GetUserByProviderID` before upserting — returns 409 if identity already linked to different user; idempotent for same-user re-link |
| OIDC helper extraction | `oauth_oidc.go` | `oidcBuildOAuthConfig`, `oidcInitRedirect`, `oidcVerifyCallback` — shared by login and link flows, ~100 lines deduplication |
| SSO audit logging | `sso.go`, `oauth_oidc.go` | Audit entries for SSO connection create/update/delete and identity linking |

## Key implementation decisions

- **Link callback is a public route** — no RequireAuthenticated middleware. The user's JWT is read from the `access_token` cookie manually (same pattern as `ParseAccessToken`). This is because the OIDC callback URL must be pre-registered with the IdP and can't have auth middleware blocking the redirect.
- **Delete handler reads before deleting** — `deleteSSOHandler` now loads the connection before calling `DeleteSSOConnection` so it can include entity details (ID, display_name) in the audit trail.
- **Link callback loads connection for orgID** — `oidcLinkCallbackHandler` calls `GetSSOConnectionByID(connID)` to resolve the orgID for the audit entry, since the link callback route has no org context. Acceptable extra query on a non-hot path.
- **ActorID set explicitly in link callback** — since the route has no auth middleware, `ctxUserID` isn't in context. The audit entry sets `ActorID: &userID` directly.
- **Audit for create SSO includes client_secret** — the `NewState` map includes the plaintext `client_secret` value. The `redactSecrets` function in the audit writer automatically redacts fields matching "secret" keywords before DB write.

## Tests added

| Test | File | What it verifies |
|---|---|---|
| `TestIdentityLinking_Success` | `oauth_oidc_test.go` | Full OIDC link flow: init → redirect → callback → verify identity created in DB |
| `TestIdentityLinking_AlreadyLinked` | `oauth_oidc_test.go` | Pre-existing identity for different user → 409 Conflict |
| `TestAudit_SSOOperations` | `sso_test.go` | Create/Update/Delete sub-tests verify audit entries |
| `TestAudit_IdentityLinking` | `oauth_oidc_test.go` | Verify audit entry for identity linking with correct orgID and entity type |

## Quality checks

- **go test ./...:** All pass (transient testcontainer failures on `audit` and `retention` packages pass when run individually — Docker resource contention)
- **golangci-lint:** 0 issues
