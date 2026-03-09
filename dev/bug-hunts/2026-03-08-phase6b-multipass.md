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
