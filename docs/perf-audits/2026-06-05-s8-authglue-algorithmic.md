# S8 Auth Glue — Algorithmic Lane
<!-- ABOUTME: Performance audit report for S8 auth/MFA/SSO/OAuth glue, algorithmic complexity lane. -->
<!-- ABOUTME: Cold sweep — coverage-oriented; only reports real aggregate impact findings. -->

**Date:** 2026-06-05
**Slice:** S8 — AuthN/MFA/SSO/OAuth glue (cold sweep)
**Lane:** algorithmic complexity
**Scope:** `internal/api/{auth,auth_mfa,auth_password_reset,auth_email_verification,sso,oauth_oidc,oauth_github,oauth_google,oauth_helpers,apikeys,lockout,middleware_auth,middleware_apikey_query,middleware_csrf}.go`, `internal/auth/**`, `internal/store/{auth,mfa,apikey,sso,password_reset,email_verification}.go`

---

## Summary

The auth glue is predominantly request-scoped CRUD and token verification. JWT verification is a constant-time HMAC-SHA256 operation (plus optional dual-key fallback — one extra parse on the rare rotation path). argon2id cost is intentional and gated by a semaphore. No linear scans over unbounded collections, no O(n) per-key lookups, no recomputation of cached values. One structural issue was found on the hot JWT path.

---

### MINOR — 3-round-trip bypass transaction wrapping a non-RLS table on every authenticated request

**Location:** `internal/store/auth.go:236` (`GetUserAuthStatus`) → `internal/store/store.go:48` (`withBypassTx`)

**Problem:** Every JWT-authenticated request calls `GetUserAuthStatus`, which wraps a single-row SELECT against the `users` table in a `withBypassTx` transaction. That transaction executes three SQL statements: `BEGIN`, `SET LOCAL app.bypass_rls = 'on'`, the SELECT, and `COMMIT`. The `users` table has no `ENABLE ROW LEVEL SECURITY` in any migration (confirmed by grep across all migrations). The `SET LOCAL` is therefore a no-op guard on this particular table — the overhead is real but the protection it provides is zero. The same pattern applies to `IsUserEnabled` on the API-key hot path, which also calls `withBypassTx` against the same `users` table and runs as a second independent transaction within the same request.

**Impact:** Reachability is 100% — every JWT-authenticated request hits this path. The per-occurrence cost is two extra Postgres round-trips (BEGIN + SET LOCAL, COMMIT) beyond what the query itself requires. Under the project's `QueryExecModeSimpleProtocol` + PgBouncer transaction-mode deployment, each BEGIN/COMMIT pair consumes a pgxpool connection slot and a transaction lifecycle on the Postgres side. At moderate authenticated throughput (hundreds of requests/sec) this represents a material fraction of Postgres connection budget and round-trip latency added to every request.

**Confidence:** Heuristic — confirmed that `users` has no RLS in migrations; confirmed the 3-statement transaction via `withBypassTx`; cannot measure actual latency without runtime profiling.

**Effort:** Contained — requires adding a direct query path (without `withBypassTx`) for store methods whose target table genuinely has no RLS, and updating the callers. The architectural policy in `implementation-pitfalls.md §2.17` ("use `withBypassTx` even if target table has no RLS") would need to be revisited for this table — any change must preserve the invariant that future RLS addition to `users` doesn't silently break the auth path.

**Verification plan:** Add a migration that enables RLS on `users` and measure whether `withBypassTx` would have been needed retroactively; alternatively, profile `pgxpool` transaction wait time under load with and without the wrapping transaction. Correctness guard: `TestRequireAuthenticated_JWT_Valid` and `TestRequireAuthenticated_DisabledUser_JWT_401` must pass unchanged.

---

## Non-findings examined

- **`rejectAPIKeyQueryParams` O(params × 8) per request** — `sensitiveQueryParams` is a 8-element constant slice; actual query params are O(1) in practice. Bounded small constant; not a finding.
- **JWT dual-key rotation retry** — only executes on `ErrTokenSignatureInvalid`, which is the rare in-flight rotation window. Fast path (active secret) is a single `ParseWithClaims` call.
- **argon2id on login** — intentional cost, gated by a concurrency semaphore. Not a finding.
- **`rejectAPIKeyQueryParams` calls `r.URL.Query()`** — this parses the raw query string into a map on every request. In practice, most API requests carry no query params; Go's `url.ParseQuery` is cheap and the result is not memoized, but the n is bounded near zero for the authenticated API surface. Not significant.
- **`sensitiveQueryParams` linear scan vs. map lookup** — 8 elements; a map would be marginally faster but the difference is immeasurably small relative to any other request cost. Not a finding.
- **`buildMFARequiredReasons` at login** — runs 4 DB queries, but only at login when the user has no MFA enrolled and MFA is mandated. Not on the steady-state authenticated request path.
- **`withBypassTx` on `api_keys` (RLS-protected) for `LookupAPIKey`** — the transaction overhead is genuinely justified here; `api_keys` has `FORCE ROW LEVEL SECURITY`. Not a finding.

---

## Suspected Bugs (for follow-up)

None observed.
