# Bug Hunt Report — Phase 2a (Auth & RBAC) — Exploratory

**Date:** 2026-03-03
**Variant:** BH-O (Exploratory — depth-first from high-risk entry points)
**Analyst:** Claude

## Scope

**Files analyzed (deep):**
- `internal/api/middleware_auth.go` — auth middleware (JWT + API key gate)
- `internal/api/middleware_rbac.go` — RBAC role enforcement
- `internal/api/middleware_csrf.go` — CSRF custom-header protection
- `internal/api/auth.go` — register, login, refresh, logout, me, change-password, invitations
- `internal/api/oauth_github.go` — GitHub OAuth2 flow
- `internal/api/oauth_google.go` — Google OIDC flow
- `internal/api/oauth_oidc.go` — Generic OIDC SSO flow
- `internal/api/oauth_helpers.go` — state/nonce cookie management
- `internal/api/server.go` — route wiring and middleware composition
- `internal/api/ratelimit.go` — per-IP rate limiting
- `internal/api/apikeys.go` — API key CRUD handlers
- `internal/api/orgs.go` — org management, members, invitations
- `internal/api/groups.go` — group management
- `internal/auth/jwt.go` — JWT issuance and parsing
- `internal/auth/apikey.go` — API key generation and hashing
- `internal/auth/hash.go` — argon2id password hashing
- `internal/store/auth.go` — user/token store methods
- `internal/store/apikey.go` — API key store methods
- `internal/store/org.go` — org/member/invitation store methods
- `internal/store/group.go` — group store methods

**SQL queries verified:** `queries/auth.sql`, `queries/apikeys.sql`, `queries/groups.sql`

**Exploration strategy:** Started from the auth middleware and JWT handling (the security gate), then followed threads into the RBAC middleware, OAuth callback flows, refresh token chain, and API key authentication path. Each finding was traced through caller→callee chains to verify impact.

## Bugs

### 1. API key not scoped to its org during authentication

**Location:** `internal/api/middleware_auth.go:48-66`
**Severity:** significant
**Evidence:**

`tryAPIKeyAuth` retrieves the key via `LookupAPIKey(hash)` (which returns all columns including `org_id`) but only injects `key.CreatedByUserID` and `key.Role` into the context. It never checks that the key's `org_id` matches the org being accessed in the URL.

```go
// Line 63-64: injects user and role, but NOT the key's org_id
ctx := context.WithValue(r.Context(), ctxUserID, key.CreatedByUserID)
ctx = context.WithValue(ctx, ctxAPIKeyRole, key.Role)
```

The downstream `RequireOrgRole` middleware (line 34) checks the user's membership in the *URL's* org, not the *key's* org. So a key created for OrgA (role=admin) can authenticate requests to OrgB if the key's creator is also a member of OrgB.

The effective role is correctly capped to `min(orgMemberRole, apiKeyRole)`, so this isn't a privilege escalation. But it violates the principle that an API key is scoped to the org where it was created:
- OrgA admins can list/revoke the key but have no visibility into its use against OrgB
- The key's `org_id` column is stored but never enforced, creating a false sense of scoping

**Impact:** API keys work across all orgs the creator belongs to. Org admins cannot fully control the blast radius of keys created within their org.

### 2. GitHub and Google OAuth bypass RegistrationMode

**Location:** `internal/api/oauth_github.go:135-146`, `internal/api/oauth_google.go:123-134`
**Severity:** significant
**Evidence:**

The native register handler correctly gates on registration mode:
```go
// auth.go:116-118
if srv.cfg.RegistrationMode != "open" {
    return nil, huma.Error403Forbidden("registration is not open on this server")
}
```

But both OAuth callback handlers auto-create users without checking `RegistrationMode`:
```go
// oauth_github.go:135-146 (no RegistrationMode check)
if user == nil {
    displayName := ghUser.Name
    // ...
    user, err = srv.store.CreateUser(ctx, primaryEmail, displayName, "", 0)
    // ...
}
```

```go
// oauth_google.go:123-134 (no RegistrationMode check)
if user == nil {
    displayName := claims.Name
    // ...
    user, err = srv.store.CreateUser(ctx, claims.Email, displayName, "", 0)
    // ...
}
```

The generic OIDC SSO flow (`oauth_oidc.go:250-252`) correctly does NOT auto-create users, returning 403 instead. This inconsistency confirms the GitHub/Google flows are likely missing the check rather than intentionally exempt.

**Impact:** On an "invite-only" server, anyone with a GitHub or Google account can self-register by using the OAuth flow, completely bypassing the registration restriction.

### 3. OIDC nonce comparison not constant-time

**Location:** `internal/api/oauth_google.go:110`, `internal/api/oauth_oidc.go:191`
**Severity:** minor
**Evidence:**

The state cookie validation correctly uses constant-time comparison (`oauth_helpers.go:53`):
```go
if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(stateParam)) != 1 {
```

But nonce comparison in both Google OIDC and generic OIDC uses plain string comparison:
```go
// oauth_google.go:110
if storedNonce != claims.Nonce {

// oauth_oidc.go:191
if storedNonce != c.Nonce {
```

The practical risk is limited: nonces are single-use, random 64-char hex strings, and the comparison is against a value from a cryptographically verified ID token. An attacker would need to have compromised the OIDC flow to manipulate the nonce claim, at which point the timing oracle is irrelevant. However, the inconsistency with the state comparison suggests the constant-time pattern was intended but missed here.

**Impact:** Theoretical timing side-channel on nonce values. Low practical exploitability but violates the codebase's own security pattern.

## Design Concerns

### Group member handler doesn't verify org membership

`addGroupMemberHandler` (`groups.go:254-284`) accepts any valid UUID as `user_id` and inserts it into `group_members`. The `group_members` table has a FK to `users(id)` but NOT to `org_members(org_id, user_id)`. This means an admin can add a user to an org's group even if that user is not a member of the org. The impact is low (requires knowing a valid user UUID, group membership doesn't grant authorization), but it creates a dangling reference.

### Refresh token pair issuance is non-atomic

`issueRefreshPair` (`auth.go:345-366`) creates the new refresh token first, then marks the old one as used. If the mark step fails (DB error, network issue), the function returns an error but the new token already exists in the DB. The old token remains "unused" and can be used again on retry, creating a parallel token chain. Not a security issue (same user, correct token version check), but could leak orphaned tokens in the DB under failure conditions.
