# Bug Hunt Report — Phase 6B Multipass

## Scope
**Files analyzed:**
- `internal/api/auth.go` — auth handlers (register, login, refresh, logout, me, change-password, invitations, providers)
- `internal/api/orgs.go` — org CRUD, member management, invitation management
- `internal/api/channels.go` — notification channel CRUD, test, rotate-secret
- `internal/api/server.go` — server struct, constructor, handler wiring
- `internal/store/org.go` — store methods for orgs, members, invitations
- `internal/store/queries/org.sql` — sqlc queries
- `internal/notify/render.go` — template rendering
- `internal/notify/templates/email_invitation.html.tmpl` — HTML invitation template
- `internal/notify/templates/email_invitation.txt.tmpl` — text invitation template

**All five passes performed.**

---

## Pass 1: Contract Violations

### BUG-1: Bootstrap allows registration even when CountUsers errors
**Location:** internal/api/auth.go:118-121
**Severity:** significant
**Evidence:** The code is:
```go
if srv.cfg.RegistrationMode != "open" {
    userCount, err := srv.store.CountUsers(ctx)
    if err != nil || userCount > 0 {
        return nil, huma.Error403Forbidden("registration is disabled — use an invitation link")
    }
}
```
When `CountUsers` returns an error, `userCount` is 0 (the zero value) and `err != nil` is true, so the code correctly returns 403. This is **fail-closed** — no bug here on closer inspection.

**RETRACTED** — false alarm. The `||` short-circuits correctly: any error → 403.

### BUG-2: `testWebhookChannel` bypasses org-scoped RLS isolation
**Location:** internal/api/channels.go:522-523
**Severity:** minor
**Evidence:** `testWebhookChannel` takes only a `channelID` and calls `GetNotificationChannelForDelivery` which uses `withBypassTx` (RLS bypass). However, the handler at line 493 already verified the channel belongs to the org via `GetNotificationChannel(ctx, orgID, id)` before calling `testWebhookChannel`. So the bypass is safe in this call path. The concern is that `testWebhookChannel` as a standalone function accepts only a channel ID with no org check — but it's a private method only called from the handler. **Not a bug in practice**, but a design concern (see below).

**RETRACTED** — defense in depth is already provided by the handler.

*(Pass 1 complete — no contract violations found in this scope.)*

---

## Pass 2: Cross-Sibling Pattern Violations

### BUG-1: PATCH channel allows empty/whitespace name
**Location:** internal/api/channels.go:277-278
**Severity:** significant
**Evidence:** `createChannelHandler` validates `strings.TrimSpace(req.Name) == ""` (line 81), correctly rejecting empty or whitespace-only names. But `patchChannelHandler` does not validate the name when `req.Name != nil`:
```go
if req.Name != nil {
    params.Name = *req.Name
}
```
A PATCH with `{"name": ""}` or `{"name": "   "}` will set the channel name to empty string or whitespace. Every other create handler in scope validates name before persisting.
**Impact:** Channels can end up with empty names, breaking UI display and potentially causing issues in notification delivery logs where channel names are used for identification.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

### BUG-2: cancelInvitationHandler silently succeeds for non-existent invitations
**Location:** internal/api/orgs.go:488-509
**Severity:** minor
**Evidence:** `cancelInvitationHandler` executes `srv.store.CancelInvitation(ctx, orgID, invID)` which runs `DELETE FROM org_invitations WHERE id = $1 AND org_id = $2`. If the invitation doesn't exist, the DELETE affects 0 rows and returns nil error. The handler returns 204 regardless. Compare with the sibling `deleteChannelHandler` (channels.go:340-390) which fetches the channel first and returns 404 if not found. Also compare with `resendInvitationHandler` which calls `GetOrgInvitationByID` first and returns 404.
**Impact:** Callers receive 204 for non-existent invitation IDs. While idempotent DELETE is a valid REST design choice, the inconsistency with sibling handlers and the missing audit log entry (unlike deleteChannelHandler which logs) suggests this is an oversight rather than a deliberate choice.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

### BUG-3: Org create/update allow whitespace-only names
**Location:** internal/api/orgs.go:69-71, internal/api/orgs.go:128-130
**Severity:** minor
**Evidence:** Both `createOrgHandler` and `updateOrgHandler` check `req.Name == ""` but don't trim whitespace, unlike `createChannelHandler` which uses `strings.TrimSpace(req.Name) == ""`. A name of `"   "` passes validation in orgs but would be rejected in channels.
**Impact:** Orgs can be created with whitespace-only names, which would display as blank in the UI and confuse users.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

### BUG-4: createInvitationHandler doesn't check for duplicate pending invitations
**Location:** internal/api/orgs.go:365-455
**Severity:** minor
**Evidence:** `createInvitationHandler` doesn't check if a pending invitation already exists for the same email+org. You can create multiple pending invitations for the same email. Each counts toward `CountMemberSlotsUsedByOrg` (which sums members + unexpired/unaccepted invitations), so an admin could inadvertently exhaust their tier member limit by re-inviting the same email multiple times instead of using the resend endpoint.
**Impact:** Wasted member slots in tier accounting; confusing duplicate emails sent to the same recipient; cluttered invitation list.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

---

## Pass 3: Failure Mode Reasoning

### BUG-5: Registration returns 500 after user is already committed
**Location:** internal/api/auth.go:155-179
**Severity:** minor
**Evidence:** The registration flow is:
1. `CreateUser` (line 155) — commits user to DB
2. `SetFirstSiteAdmin` (line 165) — non-fatal on error, fine
3. `BootstrapFirstUserOrg` (line 176) — if this **errors** (DB failure), line 178 returns 500

At this point the user row is already committed to the database. The client receives 500 and may retry, hitting 409 "email already registered". The user exists but has no org and doesn't know they can log in.
**Impact:** Partial state: user exists without auto-created org, and the client has no indication the user was created. The user can recover by logging in, but the UX is confusing. This is a narrow DB-failure edge case.
**Found in:** Pass 3 — Failure Mode Reasoning

*(Pass 3 complete — one minor failure mode found. The invitation and channel flows handle failure gracefully: email sends are best-effort, and the accept-invitation flow has proper idempotency checks.)*

---

## Pass 4: Concurrency Reasoning

### BUG-6: Concurrent invitation accept returns 500 instead of idempotent 200
**Location:** internal/api/auth.go:652-667
**Severity:** significant
**Evidence:** The accept-invitation flow has a TOCTOU between the idempotency check and the actual insert:
1. Line 653: `GetOrgMemberRole` — checks if already a member (separate bypass tx)
2. Line 667: `AcceptOrgInvitation` → `CreateOrgMember` (separate bypass tx)

If the same user clicks "Accept" in two browser tabs simultaneously:
- Both requests pass the membership check at line 653 (not yet a member)
- Both call `AcceptOrgInvitation`
- First succeeds: inserts `org_members` row + marks invitation accepted
- Second fails: `CREATE TABLE org_members ... PRIMARY KEY (org_id, user_id)` (migration 000007) causes a unique constraint violation → error propagates as 500

The intended behavior is idempotent 200. The fix would be to catch the PK violation (pgcode `23505`) in `AcceptOrgInvitation` and return nil, or to use `INSERT ... ON CONFLICT DO NOTHING`.
**Impact:** Double-clicking the accept button or accepting in two tabs surfaces a spurious 500 error instead of the documented idempotent 200 behavior.
**Found in:** Pass 4 — Concurrency Reasoning

### BUG-7: First-user bootstrap TOCTOU in invite-only mode
**Location:** internal/api/auth.go:116-121 vs internal/api/auth.go:155 vs internal/store/org.go:66-123
**Severity:** minor
**Evidence:** In invite-only mode, `registerHandler` checks `CountUsers(ctx)` (line 118) to allow the very first user to register. But this check is not in the same transaction as `CreateUser` (line 155). If two users race:
1. Both call `CountUsers` → both see 0 → both pass the mode check
2. Both call `CreateUser` → both succeed (different emails)
3. Both call `BootstrapFirstUserOrg` → advisory lock serializes, but count is now 2 → **neither** gets an auto-created org

Result: two users exist, no org, system requires manual intervention. `SetFirstSiteAdmin` is atomic (NOT EXISTS subquery), so exactly one becomes admin, but neither has an org to manage.
**Impact:** Extremely narrow race window, only on first deployment. Both users can log in and create orgs manually. But the auto-bootstrap promise is broken for both.
**Found in:** Pass 4 — Concurrency Reasoning

---

## Pass 5: Error Propagation

### BUG-8: sendInvitationEmail silently swallows nil org/inviter without logging
**Location:** internal/api/orgs.go:584-586
**Severity:** minor
**Evidence:** After fetching org and inviter, the function checks:
```go
if org == nil || inviter == nil {
    return
}
```
If `GetOrgByID` returns `(nil, nil)` (org soft-deleted) or `GetUserByID` returns `(nil, nil)` (user deleted), the email silently doesn't send with no log message. The earlier error cases (lines 575-583) are logged at ERROR level, but the "found but nil" case at line 584 is completely silent.

Compare: every other nil-check in the invitation flow either logs or returns an error to the caller. This path swallows the condition entirely.
**Impact:** If the org or inviter is deleted between invitation creation and email send, the admin receives 202 (invitation created) but no email is sent and no log message indicates why. Debugging "invitation email never arrived" would be difficult. The window is extremely narrow but the silent swallow violates the logging pattern established by the surrounding code.
**Found in:** Pass 5 — Error Propagation

*(Pass 5 complete — error propagation is generally solid across this scope. Store errors are wrapped with context and surfaced as 500. Best-effort paths log failures. The main gap is the silent nil swallow above.)*

---

## Bugs (Summary)

| # | Title | Severity | Pass |
|---|-------|----------|------|
| 1 | PATCH channel allows empty/whitespace name | significant | 2 |
| 2 | cancelInvitationHandler silently succeeds for non-existent invitations | minor | 2 |
| 3 | Org create/update allow whitespace-only names | minor | 2 |
| 4 | createInvitationHandler doesn't check for duplicate pending invitations | minor | 2 |
| 5 | Registration returns 500 after user is already committed | minor | 3 |
| 6 | Concurrent invitation accept returns 500 instead of idempotent 200 | significant | 4 |
| 7 | First-user bootstrap TOCTOU in invite-only mode | minor | 4 |
| 8 | sendInvitationEmail silently swallows nil org/inviter | minor | 5 |

## Design Concerns

1. **Invitation slot exhaustion via duplicates** — `createInvitationHandler` doesn't check for existing pending invitations to the same email (BUG-4). Combined with `CountMemberSlotsUsedByOrg` counting all pending invitations, an admin can unintentionally exhaust their tier member limit. The tier check and the duplicate check are logically coupled but currently independent.

2. **Accept-invitation idempotency is split across transactions** — The membership check (line 653) and the insert (line 667) are in separate transactions. This creates the TOCTOU in BUG-6. The idempotency guarantee should be moved into `AcceptOrgInvitation` itself, e.g., `INSERT INTO org_members ... ON CONFLICT (org_id, user_id) DO NOTHING RETURNING *` to make it atomic.

3. **testWebhookChannel takes only channelID, not orgID** — While the handler pre-validates org ownership, the private method `testWebhookChannel` (channels.go:522) uses `GetNotificationChannelForDelivery` which bypasses RLS. If a future caller forgets the pre-check, it becomes a tenant isolation bypass. Passing orgID through to the delivery query would provide defense in depth.

4. **Inconsistent validation strictness between create and patch** — Channel create validates name trimming; channel patch does not. Org create/update don't trim at all. A consistent validation helper (e.g., `validateName(s string) error`) used across all CRUD paths would prevent this class of bug.

5. **Audit logging coverage gaps** — Channel CRUD and member mutations have audit entries. But invitation create, cancel, and resend have no audit entries. For a security product, invitation management is a high-value audit target (who was invited, by whom, when was it resent/cancelled).
