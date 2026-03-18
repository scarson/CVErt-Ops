# Pitfall Audit: API & HTTP Patterns

**Date:** 2026-03-18
**Auditor:** audit-api agent (Explore)
**Scope:** 11 pitfalls across API handlers, HTTP server, middleware, pagination
**Code paths:** `internal/api/*`, `cmd/cvert-ops/main.go`, `internal/store/cve.go`

---

## Summary Table

| ID | Title | Status | Evidence |
|---|---|---|---|
| 1.5 | r.Context() Background Assassination | VALIDATED | `auth_password_reset.go:139`, `middleware_auth.go:147` — WithoutCancel on all spawns |
| 1.11 | omitempty on PATCH Structs | VALIDATED | `alert_rules.go:38-45`, `channels.go:37-40` — pointer types on all PATCH fields |
| 3.7 | Unbounded Request Body | VALIDATED | `server.go:214` — RequestSize(1<<20) globally before routes |
| 3.8 | Slowloris DOS | VALIDATED | `main.go:296-302` — ReadHeaderTimeout:5s, ReadTimeout:15s, IdleTimeout:120s |
| 5.8 | IP Rate Limiter Global Ban | DIVERGED (better) | `server.go:209` — chi RealIP middleware handles XFF securely |
| 5.18 | Keyset Pagination Tie-Breaker | VALIDATED | `cves.go:118-124`, `cve.go:197-198` — composite (SortDate, CVEID) cursor |
| 5.19 | pgx Prepared Statements (PgBouncer) | VALIDATED | `main.go:641,699-700` — QueryExecModeSimpleProtocol + env var override |
| 9.1 | Partial Unique Index → 500 not 409 | PARTIALLY VALIDATED | Auth paths catch 23505; channels/alert_rules/reports do NOT |
| 9.2 | PATCH Re-Validates Same as POST | VALIDATED | `channels.go:282-307` — identical validation in both POST and PATCH |
| 13.3 | API Response Contract Consistency | VALIDATED | `contract.go:26-115` — writeProblem, writeList, encodePageCursor standardized |

**Totals:** 8 VALIDATED, 1 DIVERGED (better), 1 PARTIALLY VALIDATED (gap)

---

## Detailed Findings

### 1.5 r.Context() Background Assassination
**Status:** VALIDATED
**Evidence:** `auth_password_reset.go:139` (context.WithoutCancel for email delivery), `middleware_auth.go:147` (context.WithoutCancel for API key last-used update)
**All instances checked:** All 2 goroutine spawns from HTTP handlers use WithoutCancel. Comment at line 138: "email delivery must survive the HTTP response"
**Notes:** Pattern correctly implemented at all spawn points.

### 1.11 omitempty on PATCH Structs
**Status:** VALIDATED
**Evidence:** `alert_rules.go:38-45` (patchAlertRuleBody: *string, *bool, *[]string), `channels.go:37-40` (patchChannelBody: *string, *json.RawMessage)
**All instances checked:** All PATCH request structs use pointer types. Handler code (alert_rules.go:437-460) correctly checks `!= nil` before updating.
**Notes:** Correctly distinguishes "not provided" (nil) from explicit zero values.

### 3.7 Unbounded Request Body
**Status:** VALIDATED
**Evidence:** `server.go:214` — `r.Use(middleware.RequestSize(1 << 20))`
**Notes:** 1MB limit registered globally before all routes. Comment references PLAN.md §18.3.

### 3.8 Slowloris DOS
**Status:** VALIDATED
**Evidence:** `main.go:296-302` — ReadHeaderTimeout:5s, ReadTimeout:15s, IdleTimeout:120s
**All instances checked:** Main server (296-302), metrics server (311), worker metrics server (477)
**Notes:** WriteTimeout intentionally omitted (comment references PLAN.md §18.3). All servers configured.

### 5.8 IP Rate Limiter Global Ban
**Status:** DIVERGED (better implementation)
**Evidence:** `server.go:209` — `r.Use(middleware.RealIP)` runs before `clientIPMiddleware` at `ratelimit.go:101-109`
**Notes:** Uses chi's RealIP middleware which handles XFF parsing securely, rather than the pitfall's custom TRUSTED_PROXIES approach. Chi's implementation is a well-tested library solution. The pitfall's recommendation for explicit TRUSTED_PROXIES CIDR config is more precise but chi's approach is acceptable.

### 5.18 Keyset Pagination Tie-Breaker
**Status:** VALIDATED
**Evidence:** `cves.go:118-124` (Cursor struct: SortDate + CVEID), `cve.go:197-198` (WHERE clause: `(date_modified_canonical, cve_id) < (?, ?)`)
**All instances checked:** CVE list endpoint uses composite cursor. Alert events also paginated with composite cursor.
**Notes:** Implementation exactly matches prescription.

### 5.19 pgx Named Prepared Statements
**Status:** VALIDATED
**Evidence:** `main.go:641` (migration DB: SimpleProtocol), `main.go:699-700` (pool DB: conditional on DB_QUERY_EXEC_MODE env var)
**Notes:** Simple protocol is default. Both migration and pool connections configured correctly.

### 9.1 Partial Unique Index → 500 not 409 — GAP FOUND
**Status:** PARTIALLY VALIDATED
**Evidence:**
- **Implemented:** `auth.go:172` catches pgErrCode=="23505" → 409 for duplicate email. `oauth_github.go:150`, `oauth_google.go:138` handle 23505 on concurrent registration. `watchlists.go:133-134` handles unique constraint.
- **NOT implemented:** `channels.go` create handler, `alert_rules.go` create handler, `reports.go` create handler do NOT catch 23505.
**All instances checked:** Auth paths ✓, OAuth paths ✓, Watchlists ✓, Channels ✗, Alert rules ✗, Reports ✗
**Notes:** This is exactly the gap the pitfall describes. Users creating duplicate-named notification channels, alert rules, or scheduled reports get "Internal Server Error" (500) instead of "this name already exists" (409). The fix is straightforward: add `pgErrCode(err) == "23505"` → 409 in each create/rename handler.
**Assessment:** Medium severity — bad UX, not a security issue. Users can retry with a different name but the error message is confusing.

### 9.2 PATCH Re-Validates Same as POST
**Status:** VALIDATED
**Evidence:** `channels.go:282-307` — PATCH handler applies identical SSRF + email validation as POST handler (lines 111-133)
**Notes:** Validation correctly shared/re-applied across both create and update handlers.

### 13.3 API Response Contract Consistency
**Status:** VALIDATED
**Evidence:** `contract.go:26-71` (writeProblem — RFC 9457), `contract.go:89-105` (writeList — `{items: [], next_cursor: "..."}`), `contract.go:109-115` (encodePageCursor — base64url JSON)
**All instances checked:** All list endpoints use writeList. All error responses use writeProblem variants. Pagination cursor format standardized.
**Notes:** Contract is consistent across endpoints. This was flagged as a gap in the March 10 health review but has been addressed.

---

## New Discoveries

1. **9.1 unique constraint gap** — channels, alert_rules, and scheduled_reports create handlers return 500 on duplicate names. This is an active code gap, not a theoretical concern.

2. **API key security pattern** — `middleware_auth.go:131` uses `subtle.ConstantTimeCompare` + `auth.HashAPIKey()`. Opaque hashing, not JWT-based. Correctly implemented.

3. **Server lifecycle** — `apiSrv.Close()` properly called via defer in main.go. Stops rate limiters, tier cache, lockout manager.

---

## Assessment

API & HTTP patterns are **well-implemented with one real gap**. The 9.1 unique constraint handling is partially done — auth paths are correct but CRUD handlers for channels/rules/reports still surface 500s on duplicate names. This should be prioritized as a UX fix. All other patterns (background context, PATCH semantics, pagination, server timeouts, contract consistency) are production-ready.
