# Bug Hunt Report — Exploratory (Phase 5)

**Date:** 2026-03-04
**Method:** Exploratory depth-first analysis
**Analyst:** Claude (code-bug-hunter-exploratory)

## Scope

**Files analyzed (15 files across 6 packages):**

| Package | Files |
|---------|-------|
| `internal/tier/` | `resolver.go`, `limits.go` |
| `internal/api/` | `middleware_tier.go`, `tier_cache.go`, `org_ratelimit.go`, `org_tier.go`, `audit_log.go`, `sso.go` |
| `internal/retention/` | `runner.go` |
| `internal/store/` | `retention.go`, `audit.go`, `sso.go` |
| `internal/audit/` | `redact.go`, `writer.go` |
| `internal/crypto/` | `aes.go` |

**Exploration strategy:** Started with highest-risk files (retention runner, crypto, tier resolver, audit writer, tier middleware) and followed threads into callees, SQL queries, and sibling implementations.

**Threads followed:**
- SSO PATCH handler → create handler validation comparison → store layer → SQL queries
- Retention runner → `ListAllOrgs` → SQL (soft-delete filtering)
- Audit writer → redaction → `marshalState` type handling
- Tier middleware → resolver → limits → rate limiter lifecycle
- Cursor decode error handling → all paginated handlers (cross-cut)
- SSO domain upsert → SQL (unique constraint behavior)

## Bugs

### 1. PATCH SSO handler allows clearing required fields to empty strings

**Location:** [sso.go:280-315](internal/api/sso.go#L280-L315)
**Severity:** significant
**Evidence:**

The create handler (`createSSOHandler`) validates that `display_name`, `issuer_url`, `client_id`, and `client_secret` are all non-empty after trimming (lines 117-132):

```go
if strings.TrimSpace(req.DisplayName) == "" {
    http.Error(w, "display_name is required", http.StatusUnprocessableEntity)
    return
}
// same for issuer_url, client_id, client_secret
```

The PATCH handler (`patchSSOHandler`) merges provided fields onto the current values without any non-empty validation:

```go
displayName := current.DisplayName
if req.DisplayName != nil {
    displayName = strings.TrimSpace(*req.DisplayName) // no empty check
}
issuerURL := current.IssuerUrl
if req.IssuerURL != nil {
    issuerURL = strings.TrimSpace(*req.IssuerURL)     // no empty check
}
clientID := current.ClientID
if req.ClientID != nil {
    clientID = strings.TrimSpace(*req.ClientID)        // no empty check
}
secretEnc := current.ClientSecretEnc
if req.ClientSecret != nil {
    // encrypts *req.ClientSecret without checking empty  // no empty check
    secretEnc, err = crypto.Encrypt(key, []byte(*req.ClientSecret))
}
```

**Impact:** Sending `{"issuer_url": ""}` or `{"client_secret": " "}` via PATCH will write empty/whitespace values to the database. This breaks the OIDC flow irreversibly — the SSO connection becomes non-functional. The only recovery is a subsequent PATCH with valid values. Because the SSO PATCH endpoint is enterprise-only and owner-only (RBAC-gated), the blast radius is limited to self-inflicted damage, but it's still a data integrity violation.

### 2. SSO domain claim collision returns opaque 500 instead of 409

**Location:** [sso.go:464-467](internal/api/sso.go#L464-L467)
**Severity:** minor
**Evidence:**

When `putSSODomainsHandler` attempts to set a domain already claimed by another org, the unique constraint violation on `sso_email_domains.domain` propagates as an unhandled error:

```go
if err := srv.store.SetSSOEmailDomains(r.Context(), conn.ID, orgID, req.Domains); err != nil {
    slog.ErrorContext(r.Context(), "sso put domains: store", "error", err)
    http.Error(w, "internal error", http.StatusInternalServerError) // generic 500
    return
}
```

The store layer wraps the error (`fmt.Errorf("insert domain %q: %w", domain, err)`) but the handler doesn't use `isUniqueViolation()` to check for the 23505 code and return a 409 Conflict. Compare with `createSSOHandler` at line 159 which correctly checks `isUniqueViolation(err)`.

Note: the SQL for `UpsertSSOEmailDomain` is a plain INSERT (no ON CONFLICT clause) despite the misleading name, so the unique constraint does prevent domain hijacking. The issue is only the error reporting.

**Impact:** Users get an unhelpful "internal error" when trying to claim a domain already owned by another org. They cannot distinguish between a server failure and a domain conflict.

## Design Concerns

### Silent cursor decode failure across all paginated endpoints

**Files:** `audit_log.go:117-123`, `alert_events.go:68-73`, `alert_rules.go:316-321`, `watchlists.go:293-298`

All paginated handlers silently ignore malformed cursor values, falling back to the first page:

```go
if c := r.URL.Query().Get("cursor"); c != "" {
    t, id, err := decodeTimeCursor(c)
    if err == nil {         // error silently dropped
        p.CursorCreatedAt = &t
        p.CursorID = &id
    }
}
```

This is a consistent pattern (not an isolated oversight), but it means a client with a corrupted cursor will silently receive page 1 again instead of a 400 error. For audit log pagination — which is security-relevant — this could cause incomplete log review if cursor corruption goes unnoticed.

### Audit redaction does not recurse into arrays

**File:** [redact.go:39-42](internal/audit/redact.go#L39-L42)

`redactSecrets` recurses into nested `map[string]any` values but does not handle `[]any` (arrays of objects). If a future audit entry contains an array of maps with sensitive keys, those nested secrets would not be redacted:

```go
if nested, ok := v.(map[string]any); ok {
    out[k] = redactSecrets(entityType, nested) // handles nested maps
    continue
}
// no handling for []any — arrays pass through unredacted
```

Currently, all audit entries use flat maps (handlers construct state explicitly), so this gap has no practical impact. However, if someone passes a struct with array fields as audit state, the `marshalState` function would marshal → unmarshal → redact, and array-nested secrets would leak into the audit log.

### UpsertSSOEmailDomain SQL is a plain INSERT despite name

**File:** `internal/store/queries/sso.sql:19-21`

```sql
-- name: UpsertSSOEmailDomain :exec
INSERT INTO sso_email_domains (domain, sso_connection_id, org_id)
VALUES ($1, $2, $3);
```

The name says "Upsert" but there is no `ON CONFLICT` clause. The current callers (which delete-then-insert within a transaction) work correctly, but the name is misleading and could cause future callers to assume upsert semantics.
