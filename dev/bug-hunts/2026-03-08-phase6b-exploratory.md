# Bug Hunt Report — Phase 6B Exploratory

## Scope

Analyzed Phase 6B missing-feature code with depth-first exploration of high-risk areas:

**Deep exploration:**
- `internal/api/auth.go` — first-user bootstrap in `registerHandler` (lines 112-191)
- `internal/api/orgs.go` — `sendInvitationEmail`, `resendInvitationHandler` (lines 511-610)
- `internal/api/channels.go` — `testChannelHandler`, `testWebhookChannel`, `testEmailChannel` (lines 477-584)
- `internal/api/server.go` — route registration and RBAC middleware on channel/invitation routes (lines 219-374)
- `internal/store/org.go` — `BootstrapFirstUserOrg`, `CountMemberSlotsUsedByOrg`, `GetOrgInvitationByID`
- `internal/store/auth.go` — `CountUsers`, `CreateUser`, `SetFirstSiteAdmin`
- `internal/notify/render.go` — `RenderInvitation`, template init
- `internal/notify/templates/email_invitation.{html,txt}.tmpl`

**Threads followed:**
- `CountUsers` → generated SQL → transaction isolation analysis
- `CreateUser` → transaction boundary → race window with `BootstrapFirstUserOrg`
- `SetFirstSiteAdmin` → generated SQL atomic check
- `testWebhookChannel` → `GetNotificationChannelForDelivery` → bypass RLS + TOCTOU analysis
- `sendInvitationEmail` → `GetOrgByID` + `GetUserByID` → null safety

## Bugs

### 1. First-user registration race allows unauthorized account creation in invite-only mode

**Location:** `internal/api/auth.go:116-122`
**Severity:** significant

**Evidence:** In invite-only mode, `registerHandler` gates on `CountUsers`:

```go
if srv.cfg.RegistrationMode != "open" {
    userCount, err := srv.store.CountUsers(ctx)
    if err != nil || userCount > 0 {
        return nil, huma.Error403Forbidden("registration is disabled — use an invitation link")
    }
}
```

`CountUsers` (store/auth.go:59) uses `s.q.CountUsers(ctx)` — a bare query on the pool, no transaction. `CreateUser` (store/auth.go:19) similarly uses `s.q.CreateUser(ctx)` with no transaction. Neither operation participates in the advisory lock that `BootstrapFirstUserOrg` uses.

**Race sequence (invite-only mode, empty DB):**
1. Request A: `CountUsers()` → 0, passes gate
2. Request B: `CountUsers()` → 0, passes gate (A hasn't committed its user yet)
3. Both proceed through email check, argon2, and `CreateUser` — both succeed (different emails)
4. `SetFirstSiteAdmin`: atomic SQL `WHERE NOT EXISTS(...)` — only one wins
5. `BootstrapFirstUserOrg`: advisory lock, first acquires lock sees `count=1`, creates org. Second sees `count=2`, returns nil

**Impact:** An unauthorized user can register in invite-only mode by timing their request with the legitimate first-user bootstrap. The rogue user exists in the system with no org membership and no site admin flag, but they have a valid account — bypassing the invite-only restriction. On a fresh instance with a narrow race window, this is exploitable if the attacker knows the instance is being set up.

**Fix approach:** Move the `CountUsers` check inside `BootstrapFirstUserOrg`'s advisory-locked transaction, or gate the entire registration path (not just the org bootstrap) with the same advisory lock. Alternatively, make the invite-only check and user creation atomic within a single serializable transaction.

## Design Concerns

### CountUsers and CreateUser bypass transaction helpers

`CountUsers` (store/auth.go:59) and `CreateUser` (store/auth.go:19) both use `s.q` directly rather than a transaction helper. The `users` table isn't org-scoped so there's no RLS issue, but this violates the project convention ("Never query `s.db` directly in store methods — always use a transaction helper") and contributes to the race condition above. Other auth store methods like `GetUserByID` and `GetUserByEmail` follow the same pattern, suggesting this is a systemic choice for user-scoped operations, but it removes transactional guarantees.

### Error masquerading on CountUsers failure

At auth.go:119, a database error from `CountUsers` is treated the same as "users exist" — both return 403. This is fail-closed (good for security) but silently swallows the database error. A transient DB failure during first-user setup would be indistinguishable from "registration disabled," with no 500 or log entry to indicate the real problem. The `err` is never logged.

### testEmailChannel doesn't check SMTP configuration

`testEmailChannel` (channels.go:564) immediately attempts to send via `notify.EmailSend` without checking whether SMTP is configured. Compare with `sendInvitationEmail` (orgs.go:571) which returns early if `srv.cfg.SMTPHost == ""`. The test endpoint will fail with a low-level connection error ("dial tcp :0: connect: connection refused" or similar) rather than a clear "SMTP not configured" message. Not incorrect — the test correctly reports failure — but the error message is unhelpful.
