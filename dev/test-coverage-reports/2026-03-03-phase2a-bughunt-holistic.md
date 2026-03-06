# Bug Hunt Report — Phase 2a (Auth & RBAC) — Holistic

## Scope

**Files analyzed (22 source files):**

- `internal/auth/apikey.go`, `internal/auth/hash.go`, `internal/auth/jwt.go`
- `internal/store/auth.go`, `internal/store/apikey.go`, `internal/store/org.go`, `internal/store/group.go`
- `internal/api/server.go`, `internal/api/context.go`, `internal/api/role.go`
- `internal/api/middleware_auth.go`, `internal/api/middleware_rbac.go`, `internal/api/middleware_csrf.go`, `internal/api/middleware_tier.go`
- `internal/api/ratelimit.go`
- `internal/api/auth.go`, `internal/api/orgs.go`, `internal/api/groups.go`, `internal/api/apikeys.go`
- `internal/api/oauth_helpers.go`, `internal/api/oauth_github.go`, `internal/api/oauth_google.go`, `internal/api/oauth_oidc.go`

**Supporting files consulted:** migrations (RLS policies), `PLAN.md` (§7.2, §19.4), `internal/testutil/postgres.go`.

**Approach:** Read all source files, then followed cross-cutting flows (OAuth login, token rotation, invitation acceptance, RBAC middleware chain) looking for contradictions between components.

## Bugs

### 1. GitHub/Google OAuth auto-create users bypass registration mode

**Location:** `internal/api/oauth_github.go:135-153`, `internal/api/oauth_google.go:123-141`
**Severity:** significant
**Evidence:**

The native register handler (`auth.go:116`) enforces registration mode:
```go
if srv.cfg.RegistrationMode != "open" {
    return nil, huma.Error403Forbidden("registration is not open on this server")
}
```

The GitHub and Google OAuth callbacks create new users unconditionally when `user == nil` (no existing provider identity). Neither callback checks `srv.cfg.RegistrationMode`. The OIDC SSO callback (`oauth_oidc.go:250`) correctly prevents auto-creation ("no linked identity — ask your admin to link your account"), showing the expected pattern.

**Impact:** In invite-only mode (the default per PLAN.md §19.4), anyone with a GitHub or Google account can create an account on the system by clicking the OAuth login button, bypassing the intended access control. This is a policy violation for self-hosted security teams.


### 2. OAuth user creation fails with generic 500 on email collision

**Location:** `internal/api/oauth_github.go:141`, `internal/api/oauth_google.go:129`
**Severity:** significant
**Evidence:**

Migration `000005_create_users.up.sql` creates `UNIQUE INDEX users_email_uq ON users (email)`. When a user registers via email/password and later tries to log in via GitHub/Google OAuth with the same email, the flow is:

1. `GetUserByProviderID("github", "123")` → nil (no linked identity)
2. `CreateUser(ctx, primaryEmail, displayName, "", 0)` → unique constraint violation
3. Handler logs "create user" error and returns `http.Error(w, "internal error", 500)`

The native register handler (`auth.go:153`) handles this gracefully:
```go
if pgErrCode(err) == "23505" {
    return nil, huma.Error409Conflict("email already registered")
}
```

The OAuth callbacks have no such handling. The user gets an opaque 500 error with no recovery path. There is also no mechanism to link a GitHub/Google identity to an existing email/password account (unlike OIDC SSO, which has the `/sso/link` flow).

**Impact:** Users who registered via email and later try GitHub/Google login get a broken, confusing error. No self-service recovery path exists.


### 3. Standalone `AcceptInvitation` store method bypasses RLS

**Location:** `internal/store/org.go:302-307`
**Severity:** minor
**Evidence:**

```go
func (s *Store) AcceptInvitation(ctx context.Context, id uuid.UUID) error {
    if err := s.q.AcceptInvitation(ctx, id); err != nil {
        return fmt.Errorf("accept invitation: %w", err)
    }
    return nil
}
```

This method queries `s.q` directly — no transaction helper (`withOrgTx` or `withBypassTx`). Migration `000012_org_invitations_rls.up.sql` enables `ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` on `org_invitations`. Without setting `app.bypass_rls` or `app.org_id`, the RLS policy evaluates to false and the UPDATE silently affects 0 rows.

The method appears in `org_test.go:200` but tests use a superuser store (`store.Store` backed by the container owner role, not `cvert_ops_app`), so the test passes despite the method being broken under RLS.

The production handler (`acceptInvitationHandler`) correctly uses `AcceptOrgInvitation` (which wraps `withBypassTx`), so this is not currently exploitable. However, the method's existence is a trap for future callers.

**Impact:** Any future caller of the standalone `AcceptInvitation` method would silently fail — the invitation would appear accepted but the DB row would be unchanged.


## Design Concerns

### OAuth callback endpoints lack rate limiting

The GitHub, Google, and OIDC OAuth callbacks (`/auth/oauth/github/callback`, `/auth/oauth/google/callback`, `/auth/oidc/callback`, `/auth/oidc/link-callback`) are not behind the `srv.authRateLimit()` middleware. While they are protected by state cookies and require valid authorization codes, the code exchange step makes an outbound HTTP call per invocation. A flood of callback requests with invalid/reused codes could cause excessive outbound connections.

The auth endpoints registered via huma (`register`, `login`, `refresh`) call `srv.checkAuthRateLimit(ctx)` within the handler. The SSO discover endpoint has `apiRouter.With(srv.authRateLimit()).Post(...)`. The OAuth callbacks have neither.

### `addGroupMemberHandler` does not validate org membership of target user

`groups.go:279` calls `AddGroupMember(orgID, groupID, userID)` where `userID` comes from the request body without verifying the target is a member of the org. If the DB has appropriate FK constraints (`group_members.user_id` → `org_members` composite), the insert would fail with a constraint violation returning a generic 500. If the FK only references `users.id`, a user from a different org could be added to the group. The handler should either validate membership or handle the FK violation explicitly.

### Refresh token rotation: `CreateRefreshToken` and `MarkRefreshTokenUsed` are not in the same transaction

`auth.go:357-364`: the new refresh token is created first, then the old one is marked as used. If the second operation fails, an orphaned token exists in the DB. The client receives an error and retries with the old (still-unused) token, which succeeds — so there's no data loss. The orphan expires naturally. This is acceptable but worth knowing: under repeated failures the refresh_tokens table accumulates orphans faster than the cleanup job removes them.
