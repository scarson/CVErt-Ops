# Bug Hunt Report — Phase 2a (Multi-Pass)

## Scope
**Packages/files analyzed:**
- `internal/auth/`: apikey.go, hash.go, jwt.go
- `internal/store/`: auth.go, apikey.go, org.go, group.go
- `internal/api/`: server.go, middleware_auth.go, middleware_rbac.go, middleware_csrf.go, middleware_tier.go, ratelimit.go, auth.go, orgs.go, groups.go, apikeys.go, oauth_helpers.go, oauth_github.go, oauth_google.go, oauth_oidc.go
- Supporting files: context.go, role.go, sso.go, org_tier.go

**All five passes performed:** Contract Violations, Cross-Sibling Pattern Violations, Failure Mode Reasoning, Concurrency Reasoning, Error Propagation.

---

## Bugs

### 1. Admin can remove org owner — missing caller-vs-target role check
**Location:** internal/api/orgs.go:283-338 (removeMemberHandler)
**Severity:** significant
**Evidence:** `updateMemberRoleHandler` (line 255) explicitly blocks admins from modifying owners: `if *currentRole == "owner" { http.Error(w, "cannot change role of an org owner", http.StatusForbidden) }`. But `removeMemberHandler` has no equivalent check — it only prevents removing the *sole* owner (line 310-320). An admin-role user can remove any non-sole owner from the org. The only guard is `RequireOrgRole(RoleAdmin)` on the route, which is insufficient: admins should not be able to remove owners.
**Impact:** An admin can expel an org owner (when multiple owners exist), violating the RBAC hierarchy where owners outrank admins.
**Found in:** Pass 1 — Contract Violations / Pass 2 — Cross-Sibling Pattern Violations

### 2. OAuth flows bypass registration mode — users can self-register via OAuth when mode is invite-only
**Location:** internal/api/oauth_github.go:135-152, internal/api/oauth_google.go:123-141
**Severity:** significant
**Evidence:** `registerHandler` (auth.go:116) checks `srv.cfg.RegistrationMode != "open"` and rejects registration with 403 when invite-only. Neither `githubCallbackHandler` nor `googleCallbackHandler` perform this check — both unconditionally create new users at `CreateUser(ctx, ...)` when `GetUserByProviderID` returns nil. The OIDC SSO callback (oauth_oidc.go) is exempt since it deliberately requires pre-linked identities, but GitHub and Google OAuth auto-provision users regardless of registration mode.
**Impact:** Setting `REGISTRATION_MODE=invite-only` does not prevent user self-registration via GitHub or Google OAuth. Anyone with a GitHub/Google account can create an account on the instance.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

### 3. Standalone AcceptInvitation store method bypasses RLS
**Location:** internal/store/org.go:302-307
**Severity:** minor (latent — not currently called from handlers)
**Evidence:** `AcceptInvitation` uses `s.q.AcceptInvitation(ctx, id)` directly instead of a transaction helper (`withOrgTx` or `withBypassTx`). All other org-scoped store methods use transaction helpers. Without `SET LOCAL app.org_id` or `SET LOCAL app.bypass_rls`, PostgreSQL RLS evaluates `current_setting('app.org_id', true)` as NULL, so `NULL = org_id` is false for every row. The UPDATE would silently match 0 rows. The handler (`acceptInvitationHandler`) correctly uses `AcceptOrgInvitation` (which wraps both CreateOrgMember + AcceptInvitation SQL within `withBypassTx`), so this exported method is currently dead code.
**Impact:** If any future code calls `AcceptInvitation` directly, the invitation will silently NOT be marked as accepted.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

### 4. tryAPIKeyAuth swallows database errors as 401
**Location:** internal/api/middleware_auth.go:51
**Severity:** minor
**Evidence:** `srv.store.LookupAPIKey(r.Context(), hash)` can return a database error (connection failure, timeout, etc.), but the handler treats all errors identically to "key not found": `if err != nil || key == nil { return false }`. No logging occurs. The caller (`RequireAuthenticated`) responds with 401 "unauthorized". A transient DB outage would cause all API-key-authenticated requests to fail with 401 (not 500) and produce zero server logs.
**Impact:** During DB issues, API key users get misleading 401 errors. Operators see no log evidence of the underlying database problem for API-key-auth requests (JWT cookie auth would still hit the DB for other operations, so the outage might surface elsewhere — but the auth path itself is silent).
**Found in:** Pass 5 — Error Propagation

### 5. OAuth callbacks don't update last_login_at
**Location:** internal/api/oauth_github.go:182-188, internal/api/oauth_google.go:170-176, internal/api/oauth_oidc.go:270-280
**Severity:** minor
**Evidence:** The native `loginHandler` (auth.go:248) calls `srv.store.UpdateLastLogin(ctx, user.ID)` after successful authentication. All three OAuth/OIDC callback handlers skip this step. They proceed directly from issuing JWT tokens to setting cookies and responding.
**Impact:** `users.last_login_at` is never updated for OAuth-authenticated users. Any admin dashboard or audit feature relying on this field would show stale or null values for users who exclusively use OAuth login.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

---

## Design Concerns

### OAuth email collision produces cryptic 500
When a user registers natively with email X, then attempts GitHub/Google OAuth login (which uses the same email X but a different provider identity), `GetUserByProviderID` returns nil (no linked identity), and `CreateUser` fails with a unique_violation on the email column. The OAuth callbacks catch this as a generic error and return `"internal error"` (500). The user receives no indication that their email is already registered via a different method. There is no account-linking mechanism.

### Inconsistent error format across endpoints
Huma-registered endpoints (auth routes) return RFC 9457 JSON Problem Details errors. Chi-registered endpoints (org/member/group/invitation/API-key routes) return plain text via `http.Error()`. API consumers receive different error formats depending on which endpoint they hit.

### addGroupMemberHandler does not verify org membership
`addGroupMemberHandler` (groups.go:254) accepts any user_id in the request body and passes it to `AddGroupMember` without verifying the target user is an org member. An admin could add a user to a group who doesn't belong to the org. The DB may have FK constraints that prevent this, but the handler itself performs no validation.

### revokeAPIKeyHandler route permits viewer role
The `DELETE /{id}` route for API keys (server.go:225) inherits only `RoleViewer` from the parent route group. The handler internally checks ownership for non-admin callers, which prevents actual abuse (a viewer can't have created any keys). However, the route is more permissive than necessary — adding `RequireOrgRole(RoleMember)` would be defense-in-depth.

### Refresh token rotation TOCTOU window
In `refreshHandler`, the token is read from the DB, checked for usage, and then marked as used — without database-level locking. Two concurrent requests using the same refresh token can both pass the `stored.UsedAt.Valid` check and each issue new token pairs. The 60-second grace period handles the common case (browser tabs), but truly concurrent requests create two valid replacement tokens. This is a known trade-off in optimistic token rotation.
