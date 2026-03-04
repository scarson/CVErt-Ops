# Bug Hunt Report — Phase 5 (Holistic)

**Date:** 2026-03-04
**Variant:** BH-S (Holistic)

## Scope

Files analyzed (15 source files, no test files):
- `internal/tier/resolver.go`, `internal/tier/limits.go` — tier resolution
- `internal/api/middleware_tier.go`, `internal/api/tier_cache.go`, `internal/api/org_ratelimit.go`, `internal/api/org_tier.go` — tier middleware, cache, rate limiting, tier handler
- `internal/retention/runner.go`, `internal/store/retention.go` — retention cleanup
- `internal/audit/redact.go`, `internal/audit/writer.go` — audit redaction and writer
- `internal/api/audit_log.go`, `internal/store/audit.go` — audit log handler and store
- `internal/crypto/aes.go` — AES-256-GCM encryption
- `internal/api/sso.go`, `internal/store/sso.go` — SSO CRUD handlers and store

Also examined for cross-reference: `internal/store/queries/sso.sql` (SQL queries), `internal/api/server.go` (auditLog helper), `internal/api/watchlists.go` (decodeTimeCursor shared function), `internal/api/alert_events.go`, `internal/api/alert_rules.go` (cursor pattern comparison), `internal/store/org.go` (OrgTierRow).

**Approach:** Read all source files first, then analyzed for contract violations, cross-file pattern inconsistencies, silent data loss paths, and missing security invariants.

## Bugs

### 1. PATCH SSO allows empty required fields
**Location:** `internal/api/sso.go:280-315`
**Severity:** significant
**Evidence:** The create handler (`createSSOHandler`, lines 117-132) validates that `display_name`, `issuer_url`, `client_id`, and `client_secret` are all non-empty after trimming. The PATCH handler (`patchSSOHandler`, lines 280-315) applies `strings.TrimSpace` to patched values but never checks for empty results:
```go
displayName := current.DisplayName
if req.DisplayName != nil {
    displayName = strings.TrimSpace(*req.DisplayName) // no empty check
}
```
A PATCH with `{"display_name": ""}` or `{"issuer_url": "  "}` or `{"client_id": ""}` stores an empty string. For `client_secret`, patching with `""` encrypts an empty string and stores it — the OIDC token exchange will fail silently at next login attempt.

**Impact:** Org owner can break their SSO connection by patching any required field to empty. The connection appears valid in the database but will fail at OIDC runtime. Recovery requires knowing to patch the field back to a valid value.

### 2. Missing audit trail for SSO domain changes
**Location:** `internal/api/sso.go:426-471`
**Severity:** significant
**Evidence:** All four SSO mutation handlers log audit entries:
- `createSSOHandler` (line 182): logs `action: "create"`
- `patchSSOHandler` (line 361): logs `action: "update"`
- `deleteSSOHandler` (line 412): logs `action: "delete"`
- `putSSODomainsHandler` (line 426-471): **no audit log call**

The `putSSODomainsHandler` replaces all email domains for an SSO connection but does not call `srv.auditLog()`. Compare with the three sibling handlers which all include audit entries.

**Impact:** Email domain changes control which users are routed to which identity provider. An attacker with owner access could add their controlled domain, authenticate via their own IdP, and there would be no audit trail of the domain change. This is the only SSO mutation without an audit record.

### 3. SSO domain conflict returns 500 instead of 409
**Location:** `internal/api/sso.go:464-467` and `internal/store/queries/sso.sql:19-21`
**Severity:** minor
**Evidence:** The SQL query named `UpsertSSOEmailDomain` is actually a plain INSERT with no `ON CONFLICT` clause:
```sql
-- name: UpsertSSOEmailDomain :exec
INSERT INTO sso_email_domains (domain, sso_connection_id, org_id)
VALUES ($1, $2, $3);
```
When org B tries to claim a domain already owned by org A, the globally-unique constraint on `domain` fires a unique constraint violation. The handler catches this as a generic error:
```go
if err := srv.store.SetSSOEmailDomains(r.Context(), conn.ID, orgID, req.Domains); err != nil {
    slog.ErrorContext(r.Context(), "sso put domains: store", "error", err)
    http.Error(w, "internal error", http.StatusInternalServerError)
    return
}
```
A unique violation is treated identically to a database outage — 500 "internal error" with no useful message to the caller.

**Impact:** API caller cannot distinguish "domain already claimed by another org" from "database error". The misleading function name `UpsertSSOEmailDomain` could lead future developers to believe it handles conflicts gracefully when it does not. The correct response for a conflicting domain would be 409 Conflict.

### 4. Malformed keyset cursor silently resets pagination to page 1
**Location:** `internal/api/audit_log.go:117-123`
**Severity:** minor
**Evidence:** When a cursor fails to decode, the error is silently ignored:
```go
if c := r.URL.Query().Get("cursor"); c != "" {
    t, id, err := decodeTimeCursor(c)
    if err == nil {
        p.CursorCreatedAt = &t
        p.CursorID = &id
    }
    // err != nil → silently proceeds without cursor
}
```
A client with a corrupted or truncated cursor token gets page 1 data instead of a 400 error.

**Note:** This is a cross-codebase pattern — `alert_events.go:68-74`, `alert_rules.go:316-322`, and `watchlists.go:293-299` all exhibit the same behavior. All four handlers silently drop cursor parse errors, indicating a deliberate design choice rather than a Phase 5-specific omission. Still, silent pagination reset causes duplicate data delivery and potential infinite loops in naive client implementations.

**Impact:** Clients paginating through audit logs (or other cursor-paginated endpoints) will silently restart from the beginning if the cursor is corrupted, leading to duplicate processing of entries.

## Design Concerns

### Redaction does not recurse into arrays
`internal/audit/redact.go:39-43` — The `redactSecrets` function recurses into nested `map[string]any` values but not `[]any` slices. If a future caller passes an entity state containing an array of objects with sensitive keys (e.g., `{"configs": [{"secret": "abc"}]}`), the nested secrets would pass through unredacted. Currently safe because all callers construct flat maps, but fragile if someone passes a full struct as state via the marshal-unmarshal path in `writer.go:122-135`.

### PATCH SSO allows clearing all OIDC scopes
`internal/api/sso.go:308-311` — Sending `"scopes": []` in a PATCH request sets scopes to an empty slice. OIDC requires at least the `openid` scope. The create path defaults nil scopes to `["openid", "profile", "email"]` (`internal/store/sso.go:25-27`), but the PATCH path has no minimum-scopes validation. An owner could break OIDC by clearing scopes.

### Rate limiter resets burst tokens on tier change
`internal/api/org_ratelimit.go:50-52` — When the resolved rate or burst changes (e.g., tier downgrade from enterprise→free), a fresh `rate.Limiter` is created with full burst capacity. An org that just hit its rate limit gets a fresh quota immediately after a tier change. Not exploitable without admin intervention, but worth noting.

### Retention cleanup table ordering may starve later tables
`internal/retention/runner.go:62-97` — Global tables are always cleaned first; tier-gated tables (alert_events, notification_deliveries, audit_log) run last. If any early table has a large backlog, the deadline may be reached before tier-gated cleanup begins. Each skipped table logs a warning ("retention max runtime reached") but no data is cleaned. If the backlog persists across runs, the same tables are always starved.
