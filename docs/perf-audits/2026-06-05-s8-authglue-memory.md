# S8 AuthN/MFA/SSO/OAuth Glue — Memory & Allocation Audit

**Slice:** S8 "AuthN/MFA/SSO/OAuth glue"
**Lane:** memory
**Date:** 2026-06-05
**Scope:** `internal/api/{auth,auth_mfa,auth_password_reset,auth_email_verification,sso,oauth_oidc,oauth_github,oauth_google,oauth_helpers,apikeys,lockout,middleware_auth,middleware_apikey_query,middleware_csrf}.go`, `internal/auth/**`, `internal/store/{auth,mfa,apikey,sso,password_reset,email_verification}.go`

---

## Findings

### MINOR `r.URL.Query()` parse-and-allocate on every request in `rejectAPIKeyQueryParams` middleware

**Location:** `internal/api/middleware_apikey_query.go:38`

**Problem:** `r.URL.Query()` re-parses `r.URL.RawQuery` and returns a freshly allocated `url.Values` (`map[string][]string`) on every call. This middleware is in the global middleware chain, so it runs on every API request — including the majority that carry no query parameters at all. On a no-query request, `RawQuery` is `""`, `url.ParseQuery` returns immediately, but the underlying map is still allocated (a non-nil empty map). On requests that do have query parameters, the allocations multiply by the number of keys and values parsed. Because the check needs only to look for specific names among query keys, the full `map[string][]string` parse is unnecessary overhead.

The fix is to scan `r.URL.RawQuery` directly using `strings.Contains` for a fast early-exit before any allocation (the sensitive param names have no ambiguous substrings in practice), or use `url.ParseQuery` only when `RawQuery` is non-empty.

**Impact:** Every API request through this middleware allocates at least one `map[string][]string` entry (the empty map itself escapes to the heap via the `url.Values` return). With typical API traffic this is a constant-size GC-contributing allocation per request. Not a throughput blocker for this auth-gated service, but it is the only pure-overhead allocation on the global middleware hot path.

**Confidence:** Strong-static

**Effort:** Localized — single function; no signature change needed.

**Verification plan:** Add a `go test -bench=. -benchmem` microbenchmark for `rejectAPIKeyQueryParams` with and without a query string. The allocation count should drop from ≥1 to 0 for no-query requests. Existing test coverage in `middleware_apikey_query_test.go` (if present) pins correct rejection behavior.

---

### MINOR `[]byte(srv.cfg.JWTSecret)` string-to-slice copy on every JWT-cookie request (fallback path)

**Location:** `internal/api/middleware_auth.go:27` (`jwtSecret` fallback), `middleware_auth.go:41` (`jwtPreviousSecretBytes` fallback)

**Problem:** When `srv.configHolder` is nil or holds no secret (the common non-hot-reload deployment), `jwtSecret()` returns `[]byte(srv.cfg.JWTSecret)`. In Go, converting a `string` to `[]byte` always allocates and copies — the compiler cannot elide this copy when the result escapes (it is passed to `jwt.ParseWithClaims` via an `interface{}` key-func, which forces it to escape). This allocation fires on every JWT-authenticated request through `RequireAuthenticated`, and also on every explicit `ParseAccessToken` / `ParseRefreshToken` call in handlers (logout, me, change-password, accept-invitation, etc.).

The fix is to store `JWTSecret` as `[]byte` in `config.Config` at startup, or cache the `[]byte` form once at server construction. The `configHolder` path already stores `JWTSecret []byte` directly in `ReloadableConfig`, so the structural pattern for the fix is already present.

**Impact:** On every cookie-authenticated request the fallback path issues one heap allocation of len(JWTSecret) bytes for the active secret, and potentially a second for the previous secret. These are small (32–64 bytes typical), short-lived, and easy for the GC to collect, but they are strictly unnecessary constant-factor overhead on the hottest path in the service.

**Confidence:** Strong-static

**Effort:** Localized — change `Config.JWTSecret` / `Config.JWTSecretPrevious` from `string` to `[]byte` (or pre-convert at server construction and store as a field), then simplify `jwtSecret()` and `jwtPreviousSecretBytes()` to return the pre-converted value. Callers are all in the same package.

**Verification plan:** `go build -gcflags='-m'` on `middleware_auth.go` before and after; confirm the `[]byte(...)` conversion no longer appears as an escape site. All existing auth middleware tests pin behavior.

---

## Caches reviewed — no eviction issue found

`srv.oidcProviders` (`sync.Map`) caches one `*oidc.Provider` per OIDC SSO connection issuer URL. The map grows only as enterprise orgs add SSO connections (bounded by customer count), and `patchSSOHandler` and `deleteSSOHandler` explicitly evict stale entries. No unbounded growth path found.

---

## What was not flagged

- All cold-path allocations (registration, password hashing, recovery code generation, OAuth init/callback, SSO CRUD). Per calibration rules, these are one-shot flows with no meaningful aggregate impact.
- `generateRecoveryCode` allocating `big.NewInt` per character — cold MFA enrollment path.
- The `withBypassTx` / `withOrgTx` closure pattern — the closure allocation is universal in this codebase and not specific to auth; addressed if taken up at a higher level.
- Context value injection (`context.WithValue`) in `tryAPIKeyAuth` — standard Go idiom; no alternative without changing the entire auth architecture.

---

## Suspected Bugs (for follow-up)

None.
