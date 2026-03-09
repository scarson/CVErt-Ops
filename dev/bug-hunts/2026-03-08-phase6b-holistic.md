# Bug Hunt Report — Phase 6B Holistic

## Scope
Read all Phase 6B production source files: `internal/api/auth.go` (register/bootstrap), `internal/api/orgs.go` (invitations, resend), `internal/api/channels.go` (test endpoint, RBAC), `internal/api/server.go` (route registration), `internal/store/org.go`, `internal/store/queries/org.sql`, `internal/store/generated/org.sql.go`, `internal/notify/render.go`, and both invitation email templates.

Approached by reading every file in full, then reasoning about multi-step flows (bootstrap registration, invitation lifecycle, channel test delivery) and authorization boundaries.

## Bugs

### 1. TOCTOU race in invite-only bootstrap allows unauthorized registration
**Location:** internal/api/auth.go:116-122 vs internal/store/org.go:66-123
**Severity:** significant
**Evidence:** The registration gate checks `CountUsers(ctx)` at auth.go:119 *before* user creation at auth.go:155. The advisory lock that serializes bootstrap is only acquired inside `BootstrapFirstUserOrg` at org.go:87 — *after* the user already exists. Two concurrent requests to a fresh instance in invite-only mode can both observe `userCount == 0`, both pass the gate, and both create user rows (different emails, no unique constraint violation). Once two users exist, `BootstrapFirstUserOrg` sees `count != 1` for both and creates no org for either.

**Impact:** In invite-only mode, a second user can register without an invitation (authorization bypass). Additionally, neither user gets a bootstrap org, leaving the system in a state where no org exists and no one can create invitations. The first user does become site admin via `SetFirstSiteAdmin` and can create an org via `POST /orgs`, so the system isn't fully bricked — but the unauthorized second user persists.

The fix would be to move the `CountUsers` check inside the advisory-locked transaction, or to use the same advisory lock key earlier in the registration flow to serialize the entire bootstrap sequence.

### 2. Bootstrap gate swallows DB errors as authorization denial
**Location:** internal/api/auth.go:119
**Severity:** minor
**Evidence:** `if err != nil || userCount > 0` — when `CountUsers` returns an error, the handler returns 403 ("registration is disabled") with no logging. A transient DB failure during the first user's registration in invite-only mode is indistinguishable from "registration is disabled" to the caller. The error at auth.go:127-128 shows the pattern of logging DB errors, but line 119 does not.
**Impact:** First-user bootstrap fails silently on DB errors. Operator has no log entry to diagnose why registration was rejected on a fresh instance.

### 3. ListAllOrgs query includes soft-deleted organizations
**Location:** internal/store/queries/org.sql:86
**Severity:** minor
**Evidence:** `SELECT id, tier, tier_overrides FROM organizations;` has no `WHERE deleted_at IS NULL` filter. Compare with `GetOrgByID` (line 12) and `UpdateOrg` (line 8) which both filter `deleted_at IS NULL`. `ListAllOrgs` is used by `Store.ListAllOrgs` (org.go:390) for "retention and batch operations."
**Impact:** Batch retention/processing jobs iterate over soft-deleted orgs, wasting resources and potentially performing operations on data that should be inaccessible. Not a security issue since downstream operations would fail gracefully, but violates the soft-delete contract.

## Design Concerns

### CountUsers runs outside any transaction
`Store.CountUsers` (auth.go:59) queries `s.q.CountUsers` directly — no transaction, no RLS bypass wrapper. While the `users` table likely doesn't have RLS, this breaks the project convention where every store method uses a transaction helper. If RLS were ever added to `users`, this would silently return 0 (fail-open for the bootstrap gate in invite-only mode).

### Concurrent invitation accept could return 500
`acceptInvitationHandler` (auth.go:621) checks idempotency at line 652 and `AcceptedAt` at line 663, then calls `AcceptOrgInvitation`. If two concurrent accepts pass the idempotency check simultaneously, `CreateOrgMember` inside `AcceptOrgInvitation` would hit a unique constraint violation on `(org_id, user_id)`, propagating as a 500 to the second caller rather than a graceful idempotent response. Low probability but could confuse users.

### GetOrgByID runs without a transaction wrapper
`Store.GetOrgByID` (org.go:126) queries `s.q` directly without `withBypassTx`. It works because the `organizations` table doesn't have `org_id`-based RLS, but it deviates from the pattern used by every other store method. Called from multiple places including `sendInvitationEmail` (orgs.go:574), `getInvitationHandler` (auth.go:597), and middleware.
