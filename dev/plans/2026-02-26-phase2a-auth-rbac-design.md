# Phase 2a Design: Org Model + Users + Auth + RBAC + RLS

**Date:** 2026-02-26
**Scope:** PLAN.md §6 (multi-tenancy/RLS) + §7 (auth/RBAC)
**Phase tracker:** Phase 2 "Org model + RBAC" — first sub-phase

---

## Decisions Made (Resolved in Brainstorming)

| Topic | Decision |
|---|---|
| Auth scope | Full stack: native email/password + API keys + GitHub OAuth + Google OIDC |
| OAuth in Phase 2a? | Yes — all of §7.2 |
| JWT claims | Minimal: `sub`=user_uuid, `tv`=token_version, `exp`, `iat`. No org_id/role in token. |
| DB role separation | Split `DATABASE_URL_MIGRATE` (superuser, DDL) from `DATABASE_URL` (app role, NOBYPASSRLS) |
| Code organization | `internal/auth` package (pure functions) + `api.Server` struct |
| Service layer | No — YAGNI. Handlers call store directly. |
| User enumeration via invitation | Invitation-based flow: server never reveals whether email is registered |
| Groups in Phase 2a? | Yes — full group CRUD + group member management |
| org slug | Not implemented — orgs identified by UUID in API paths |

---

## Package Structure

### New: `internal/auth/`
Pure functions, no HTTP concerns, no global state (except argon2Sem is on the Server, not here).

```
internal/auth/
  jwt.go      — Claims struct, IssueAccessToken, ParseAccessToken, IssueRefreshToken
  hash.go     — HashPassword(password) (string, error), VerifyPassword(password, hash) (bool, error)
  apikey.go   — GenerateKey() (rawKey, hash []byte, err), HashKey(rawKey), ExtractPrefix(rawKey)
```

**JWT claims struct:**
```go
type Claims struct {
    jwt.RegisteredClaims          // sub=user_uuid, exp, iat
    TokenVersion  int    `json:"tv"`
}
```
- `ParseAccessToken` enforces `WithValidMethods(["HS256"])` + `WithExpirationRequired()` on every call.
- `token_version` is NOT validated against DB on access token use — access tokens are short-lived (≤15 min) and stateless. Only refresh tokens validate against DB.

**Argon2id:**
- `HashPassword` / `VerifyPassword` are pure — no semaphore inside.
- Callers acquire `srv.acquireArgon2()` (non-blocking, returns false → 503) before calling.
- Parameters: memory=19456 KiB, iterations=2, parallelism=1, salt=16 bytes, key=32 bytes (OWASP spec).

**API key:**
- Format: `cvo_` + base58(32 random bytes)
- Stored: only `sha256(rawKey)` as `key_hash` (hex). No prefix stored — UNIQUE index on `key_hash` gives O(1) lookup.
- Display: raw key shown exactly once in create response.
- Auth check: `sha256(presented)` → `WHERE key_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())` → `subtle.ConstantTimeCompare(stored, incoming)`.

### Modified: `internal/api`

`NewRouter(s *store.Store)` → `api.Server` struct:

```go
type Server struct {
    store      *store.Store
    cfg        *config.Config
    argon2Sem  chan struct{}       // buffered, size = cfg.Argon2MaxConcurrent
    ghOAuth    *oauth2.Config     // nil if GitHub not configured
    googleOIDC *oidc.Provider     // nil if Google not configured
    rateLimiter *rateLimiter      // in-memory per-IP, for auth endpoints
}

func NewServer(s *store.Store, cfg *config.Config) (*Server, error)
func (srv *Server) Handler() http.Handler
```

`NewServer`:
- Initializes argon2 semaphore (buffered channel).
- If `cfg.GitHubClientID != ""`: configures GitHub `oauth2.Config` (no network call).
- If `cfg.GoogleClientID != ""`: calls `oidc.NewProvider` with retry loop (same pattern as DB startup retry). Fails loudly if Google unreachable after retries — startup is the dependency health check.
- Impact on `cmd/cvert-ops/main.go`: one call-site change.

---

## Database Migrations

Migrations 000004–000009 (one logical concern per file). All use `-- migrate:no-transaction` because concurrent index creation is required.

### Migration 000004: `organizations`
```sql
CREATE TABLE organizations (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz NULL
);
CREATE INDEX CONCURRENTLY organizations_name_idx ON organizations (name);
```
No RLS — organizations are not org-scoped (they are the org themselves).

### Migration 000005: `users` + `user_identities`
```sql
CREATE TABLE users (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email                text NOT NULL,
    display_name         text NOT NULL DEFAULT '',
    password_hash        text NULL,            -- NULL if OAuth-only account
    password_hash_version int NOT NULL DEFAULT 2, -- 2=argon2id
    token_version        int NOT NULL DEFAULT 1,
    created_at           timestamptz NOT NULL DEFAULT now(),
    last_login_at        timestamptz NULL
);
CREATE UNIQUE INDEX CONCURRENTLY users_email_uq ON users (email);

CREATE TABLE user_identities (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider         text NOT NULL,           -- 'github', 'google', 'native'
    provider_user_id text NOT NULL,
    email            text NOT NULL,           -- display attribute, not auth key
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX CONCURRENTLY user_identities_provider_uq
    ON user_identities (provider, provider_user_id);
CREATE INDEX CONCURRENTLY user_identities_user_idx ON user_identities (user_id);
```
No RLS — global tables. `user_identities` matched by `(provider, provider_user_id)` — never by email. `UNIQUE(email)` is NOT enforced globally — a user may link both GitHub and Google with the same email.

### Migration 000006: `refresh_tokens`
Per §7.1 spec:
```sql
CREATE TABLE refresh_tokens (
    jti              uuid PRIMARY KEY,
    user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_version    int  NOT NULL,
    expires_at       timestamptz NOT NULL,
    used_at          timestamptz NULL,
    replaced_by_jti  uuid NULL REFERENCES refresh_tokens(jti),
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX CONCURRENTLY refresh_tokens_user_idx ON refresh_tokens (user_id, expires_at);
```
No RLS — global table (user-scoped, not org-scoped).

### Migration 000007: `org_members` + RLS
```sql
CREATE TABLE org_members (
    org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        text NOT NULL,    -- 'owner', 'admin', 'member', 'viewer'
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX CONCURRENTLY org_members_org_idx ON org_members (org_id);
CREATE INDEX CONCURRENTLY org_members_user_idx ON org_members (user_id);

ALTER TABLE org_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_members FORCE ROW LEVEL SECURITY;
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

### Migration 000008: `api_keys` + RLS
```sql
CREATE TABLE api_keys (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by_user_id  uuid NOT NULL REFERENCES users(id),
    key_hash            text NOT NULL,     -- sha256(raw_key), hex
    name                text NOT NULL,
    role                text NOT NULL,     -- role ≤ creator's role at creation time
    expires_at          timestamptz NULL,  -- NULL = never
    last_used_at        timestamptz NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    revoked_at          timestamptz NULL
);
CREATE UNIQUE INDEX CONCURRENTLY api_keys_hash_uq ON api_keys (key_hash);
CREATE INDEX CONCURRENTLY api_keys_org_idx ON api_keys (org_id);

-- RLS: same pattern as org_members
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

### Migration 000009: `org_invitations`
```sql
CREATE TABLE org_invitations (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email        text NOT NULL,
    role         text NOT NULL DEFAULT 'member',
    token        text NOT NULL,    -- 32 random bytes, hex; UNIQUE
    created_by   uuid NOT NULL REFERENCES users(id),
    expires_at   timestamptz NOT NULL,
    accepted_at  timestamptz NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX CONCURRENTLY org_invitations_token_uq ON org_invitations (token);
CREATE INDEX CONCURRENTLY org_invitations_org_idx ON org_invitations (org_id);
```
No RLS — the accept endpoint is public (no org context) and the list/cancel endpoints enforce RBAC at handler level.

### Migration 000010: `groups` + RLS
```sql
CREATE TABLE groups (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         text NOT NULL,
    description  text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    deleted_at   timestamptz NULL
);
-- Partial unique: allow name reuse after soft-delete
CREATE UNIQUE INDEX CONCURRENTLY groups_name_uq ON groups (org_id, name) WHERE deleted_at IS NULL;
CREATE INDEX CONCURRENTLY groups_org_idx ON groups (org_id);

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

### Migration 000011: `group_members` + RLS
```sql
CREATE TABLE group_members (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,  -- denormalized
    group_id    uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (group_id, user_id)
);
CREATE INDEX CONCURRENTLY group_members_org_idx ON group_members (org_id);
CREATE INDEX CONCURRENTLY group_members_group_idx ON group_members (group_id);

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
`org_id` is denormalized per §6.2 — RLS on `groups` does NOT protect `group_members`.

---

## Store Methods

**`store/auth.go`** (global tables — no org scoping):
```
CreateUser(ctx, email, displayName, passwordHash string) (*User, error)
GetUserByID(ctx, userID uuid.UUID) (*User, error)
GetUserByEmail(ctx, email string) (*User, error)
IncrementTokenVersion(ctx, userID uuid.UUID) (int, error)
UpsertUserIdentity(ctx, userID uuid.UUID, provider, providerUserID, email string) error
GetUserByProviderID(ctx, provider, providerUserID string) (*User, error)
CreateRefreshToken(ctx, jti, userID uuid.UUID, version int, expiresAt time.Time) error
LookupRefreshToken(ctx, jti uuid.UUID) (*RefreshToken, error)
MarkRefreshTokenUsed(ctx, jti, replacedByJTI uuid.UUID) error
DeleteExpiredRefreshTokens(ctx) (int64, error)
```
`GetUserByEmail` is called ONLY from login and OAuth callbacks — never from org-admin endpoints. This prevents user enumeration via invitation.

**`store/org.go`** (org-scoped methods take `orgID`):
```
CreateOrg(ctx, name string) (*Org, error)
GetOrgByID(ctx, orgID uuid.UUID) (*Org, error)
CreateOrgMember(ctx, orgID, userID uuid.UUID, role string) error
GetOrgMemberRole(ctx, orgID, userID uuid.UUID) (string, error)
ListOrgMembers(ctx, orgID uuid.UUID) ([]*OrgMember, error)
UpdateOrgMemberRole(ctx, orgID, userID uuid.UUID, newRole string) error
RemoveOrgMember(ctx, orgID, userID uuid.UUID) error
ListUserOrgs(ctx, userID uuid.UUID) ([]*OrgMembership, error)
CreateOrgInvitation(ctx, orgID uuid.UUID, email, role, token string, createdBy uuid.UUID, expiresAt time.Time) error
GetInvitationByToken(ctx, token string) (*Invitation, error)
AcceptInvitation(ctx, invitationID, userID uuid.UUID) error
ListOrgInvitations(ctx, orgID uuid.UUID) ([]*Invitation, error)
CancelInvitation(ctx, orgID, invitationID uuid.UUID) error
```

**`store/apikey.go`**:
```
CreateAPIKey(ctx, orgID, createdBy uuid.UUID, keyHash, name, role string, expiresAt *time.Time) (*APIKey, error)
LookupAPIKey(ctx, keyHash string) (*APIKey, error)    // includes revoked/expired filter
ListOrgAPIKeys(ctx, orgID uuid.UUID) ([]*APIKey, error)
RevokeAPIKey(ctx, orgID, keyID uuid.UUID) error
UpdateAPIKeyLastUsed(ctx, keyID uuid.UUID) error      // best-effort, called async
```

**`store/group.go`**:
```
CreateGroup, GetGroup, ListOrgGroups, UpdateGroup, DeleteGroup (soft)
AddGroupMember, RemoveGroupMember, ListGroupMembers
```

**`store.OrgTx(ctx, orgID, fn)`** — transaction helper on `Store`:
Opens a pgx transaction, runs `SET LOCAL app.org_id = $1`, calls `fn(pgx.Tx)`, commits (or rolls back on error). Used by any handler that writes org-scoped data. This is the only place `app.org_id` is set — never in the middleware (SET LOCAL is transaction-scoped, not request-scoped).

---

## RBAC Middleware

**Role ordering (typed):** `RoleViewer(1) < RoleMember(2) < RoleAdmin(3) < RoleOwner(4)`

### `RequireAuthenticated`
1. Check `Authorization: Bearer <key>` header → if present:
   - `sha256(presented)` → `LookupAPIKey(ctx, hash)` → if found and not expired/revoked → `subtle.ConstantTimeCompare`
   - Async `UpdateAPIKeyLastUsed` (fire-and-forget, `context.WithoutCancel(r.Context())`)
   - Inject `userID` + `apiKeyRole` into context
2. Else check JWT access token cookie:
   - `ParseAccessToken(cookie, secret)` → extract `sub` + `tv`
   - Inject `userID` into context
3. Neither valid → 401

Note: access token `token_version` is NOT validated against DB (stateless JWT; 15-min max window after revocation).

### `RequireOrgRole(minRole Role)`
1. Extract `{org_id}` from chi URL params
2. Extract `userID` from context
3. `GetOrgMemberRole(ctx, orgID, userID)` → `orgRole`
4. No membership → 403
5. If authenticated via API key: `effectiveRole = min(apiKeyRole, orgRole)` — key cannot exceed current org role
6. `effectiveRole < minRole` → 403
7. Inject `orgID` + `effectiveRole` into context

### Route wiring pattern
```go
apiRouter.Route("/orgs/{org_id}", func(r chi.Router) {
    r.Use(srv.RequireAuthenticated())
    r.Use(srv.RequireOrgRole(RoleViewer))  // floor for all org routes
    r.Get("/members", srv.listMembersHandler)
    r.With(srv.RequireOrgRole(RoleAdmin)).Post("/invitations", srv.createInvitationHandler)
    // ...
})
```

### Rate limiting
In-memory per-IP limiter on auth endpoints using `golang.org/x/time/rate`. Applied to:
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/refresh`

Rate limit config: reasonable defaults (e.g., 10 req/min per IP). IP extracted respecting `TrustedProxies` config. LRU eviction using `RateLimitEvictTTL`.

### CSRF
`SameSite=Lax` + HttpOnly on all auth cookies. API key auth via `Authorization` header — CSRF not applicable. No separate CSRF token double-submit needed for Phase 2a.

---

## HTTP Handlers (Summary)

**Auth (no org context):**
- `POST /api/v1/auth/register` — argon2id hash; first user creates default org; `REGISTRATION_MODE` enforcement
- `POST /api/v1/auth/login` — argon2 semaphore; issue access+refresh token pair; set HttpOnly cookies
- `POST /api/v1/auth/refresh` — JTI lookup + grace window (60s) + theft detection; issue new pair
- `POST /api/v1/auth/logout` — mark refresh token used; clear cookies
- `GET /api/v1/auth/me` — return user ID, email, display_name, org memberships
- `GET /api/v1/user/orgs` — list orgs + roles for current user (may merge into /auth/me)
- `PATCH /api/v1/auth/password` — verify old password; hash new; increment `token_version`
- `GET /api/v1/auth/oauth/{provider}` — generate state + nonce (Google only); set cookies; redirect
- `GET /api/v1/auth/oauth/{provider}/callback` — validate state/nonce; exchange code; upsert identity; issue tokens
- `GET /api/v1/auth/invitations/{token}` — return invitation details (org name, role)
- `POST /api/v1/auth/invitations/{token}/accept` — requires auth; create `org_members`; mark accepted

**Org management (RBAC-gated):**
- `POST /api/v1/orgs` — create org; make caller `owner`
- `GET/PATCH /api/v1/orgs/{org_id}` — GET = viewer+; PATCH = admin+
- `GET /api/v1/orgs/{org_id}/members` — viewer+
- `POST /api/v1/orgs/{org_id}/invitations` — admin+; always 202; never reveals if email registered
- `GET/DELETE /api/v1/orgs/{org_id}/invitations/{id}` — admin+
- `PATCH /api/v1/orgs/{org_id}/members/{user_id}` — admin+; role ≤ own role; cannot elevate to owner
- `DELETE /api/v1/orgs/{org_id}/members/{user_id}` — admin+; cannot remove sole owner

**API keys (org-scoped):**
- `GET /api/v1/orgs/{org_id}/api-keys` — viewer+ (own keys only unless admin+)
- `POST /api/v1/orgs/{org_id}/api-keys` — member+; role ≤ caller's effective role; raw key returned once
- `DELETE /api/v1/orgs/{org_id}/api-keys/{id}` — own keys or admin+

**Groups (org-scoped):**
- `GET/POST /api/v1/orgs/{org_id}/groups` — GET = viewer+; POST = admin+
- `GET/PATCH/DELETE /api/v1/orgs/{org_id}/groups/{group_id}` — GET = viewer+; PATCH/DELETE = admin+
- `GET/POST/DELETE /api/v1/orgs/{org_id}/groups/{group_id}/members` — GET = viewer+; write = admin+

---

## OAuth Implementation Notes

### GitHub (raw OAuth2 — NOT OIDC)
GitHub does not expose OIDC discovery. Use `golang.org/x/oauth2` + `golang.org/x/oauth2/github`.
1. Init: redirect to GitHub with `state` cookie + `user:email` scope (required)
2. Callback: validate state cookie; exchange code; `GET /user` (get numeric `id`); `GET /user/emails` (get primary+verified email)
3. Identity: match on `provider='github'` + `provider_user_id=strconv.Itoa(githubID)` — NEVER by email

### Google (OIDC)
1. Init: generate state + nonce; set both as `HttpOnly, Secure, SameSite=Lax` cookies; redirect with nonce in auth URL params
2. Callback: validate state; extract ID token; validate nonce claim against cookie BEFORE `oidcVerifier.Verify()`; extract `sub` + `email`
3. Identity: match on `provider='google'` + `provider_user_id=sub` — NEVER by email

### OAuth redirect URI
Always from `cfg.ExternalURL` — never from `r.Host`. Validated at startup to be non-empty HTTPS (HTTP allowed for localhost only).

### `SameSite` for OAuth state/nonce cookies
Must be `SameSite=Lax` (NOT Strict) — OAuth callback is a cross-site redirect. Strict blocks the cookie from being sent on the redirect, breaking all OAuth logins.

---

## Security Properties Verified

- No user enumeration via invitation (response always 202, no user lookup)
- API key effective role = `min(keyRole, currentOrgRole)` — keys don't retain permissions after demotion
- `subtle.ConstantTimeCompare` for API key hash comparison
- `WithValidMethods(["HS256"])` + `WithExpirationRequired()` on every JWT parse
- Argon2 semaphore: non-blocking (immediate 503) — never queues
- Rate limiting on login/register/refresh — first line of defense before argon2 semaphore
- DB role `NOBYPASSRLS` — RLS fail-closed when `app.org_id` unset
- `SET LOCAL` for `app.org_id` — transaction-scoped, cannot leak across connections
- `FORCE ROW LEVEL SECURITY` on all org-scoped tables — prevents table owner bypass
- OAuth CSRF: `state` parameter + cookie comparison (both GitHub and Google)
- OIDC nonce verification (Google only) — prevents replay of captured ID tokens
- OAuth redirect URI from `EXTERNAL_URL` config — never from `r.Host`
- `SameSite=Lax` (not Strict) for OAuth state/nonce cookies — required for cross-site redirect

---

## Commit Decomposition (~37 commits)

### Infrastructure (2)
1. `infra: add DATABASE_URL_MIGRATE to config + .env.example`
2. `infra: docker/init.sql — create app DB role with NOBYPASSRLS and grant permissions`

### Migrations (8)
3. `feat(migration): organizations table`
4. `feat(migration): users + user_identities tables`
5. `feat(migration): refresh_tokens table`
6. `feat(migration): org_members table + RLS`
7. `feat(migration): api_keys table + RLS`
8. `feat(migration): org_invitations table`
9. `feat(migration): groups table + RLS`
10. `feat(migration): group_members table + org_id denormalization + RLS`

### internal/auth package (3)
11. `feat(auth): JWT Claims, IssueAccessToken, ParseAccessToken + tests`
12. `feat(auth): argon2id HashPassword, VerifyPassword + tests`
13. `feat(auth): API key GenerateKey, HashKey + tests`

### Store methods (6)
14. `feat(store): user CRUD + GetUserByProviderID + tests`
15. `feat(store): refresh token CRUD + tests`
16. `feat(store): org + OrgMember CRUD + ListUserOrgs + tests`
17. `feat(store): API key CRUD + UpdateAPIKeyLastUsed + tests`
18. `feat(store): org invitation CRUD + tests`
19. `feat(store): group + group_member CRUD + tests`

### Server refactor (1)
20. `refactor(api): introduce Server struct — argon2Sem, OAuth config init; all existing tests pass`

### Native auth handlers (5)
21. `feat(api): register handler + first-user org bootstrap + tests`
22. `feat(api): login handler + JWT/cookie issuance + tests`
23. `feat(api): refresh + logout handlers + token rotation/theft tests`
24. `feat(api): /auth/me + /user/orgs + tests`
25. `feat(api): change-password + token_version revocation + tests`

### RBAC middleware (2)
26. `feat(api): RequireAuthenticated middleware (JWT + API key + rate limiter) + tests`
27. `feat(api): RequireOrgRole middleware + effective role cap + tests`

### Org management API (4)
28. `feat(api): org create/read/update + tests`
29. `feat(api): member list, invite, update-role, remove + tests`
30. `feat(api): invitation list, cancel, accept + tests`
31. `feat(api): API key list, create, revoke + tests`

### Groups API (2)
32. `feat(api): group CRUD + tests`
33. `feat(api): group member add/remove/list + tests`

### OrgTx helper (1)
34. `feat(store): OrgTx helper (SET LOCAL app.org_id) + integration tests`

### OAuth (3)
35. `feat(api): OAuth cookie helpers + state/nonce generation`
36. `feat(api): GitHub OAuth2 init + callback + identity upsert + tests`
37. `feat(api): Google OIDC init + callback + nonce verify + tests`

---

## What's NOT in Phase 2a

- Email delivery for invitations (Phase 3 — notifications)
- Ownership transfer (Phase 2b or later — edge case)
- Org deletion (Phase 2b)
- SAML / generic OIDC (Enterprise milestone)
- Watchlists, alert rules (Phase 2b)
