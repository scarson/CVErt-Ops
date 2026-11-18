# S8 AuthGlue — Data-Access Lane
<!-- ABOUTME: Performance audit report for the data-access lane of S8 (AuthN/MFA/SSO/OAuth glue). -->
<!-- ABOUTME: Cold sweep over auth middleware, login flow, API-key lookup, and lockout DB paths. -->

**Date:** 2026-06-05
**Lane:** data-access
**Slice:** S8 — AuthN/MFA/SSO/OAuth glue
**Scope:** `internal/api/{middleware_auth,auth,auth_mfa,lockout}.go` · `internal/store/{auth,apikey,mfa}.go` · `internal/store/queries/{auth,apikeys,mfa}.sql` · relevant DDL/indexes

---

## Summary

Two real findings. The dominant one is a per-authenticated-request overhead — every API-key request pays two independent `withBypassTx` round-trips (2× BEGIN + SET LOCAL + SELECT + COMMIT before the handler starts). The second is the login flow running up to five separate `withBypassTx` transactions for the non-MFA mandate check path, all of which could be collapsed.

---

### MAJOR — API-key path pays 2 independent `withBypassTx` transactions per authenticated request

**Location:** `internal/api/middleware_auth.go:100–138` (`tryAPIKeyAuth`); `internal/store/apikey.go:62–79` (`LookupAPIKey`); `internal/store/auth.go:205–218` (`IsUserEnabled`)

**Problem:**
Every request authenticated via `Authorization: Bearer <key>` runs two sequential `withBypassTx` calls:

1. `LookupAPIKey(hash)` — checks revocation + expiry; returns the key row.
2. `IsUserEnabled(key.CreatedByUserID)` — checks `disabled_at IS NULL`.

Each `withBypassTx` unconditionally opens a new `database/sql` transaction: `BeginTx` → `SET LOCAL app.bypass_rls = 'on'` → the SQL query → `Commit`. Over a pgxpool + stdlib adapter with PgBouncer in transaction mode, that is at minimum 4 server round-trips per call (BEGIN, SET, SELECT, COMMIT), 8 round-trips total before the actual handler does any work.

`IsUserEnabled` fetches a single boolean (`disabled_at IS NULL`) about the user who created the key. That information is already present on the key row itself — `api_keys` already carries `created_by_user_id`; the `users.disabled_at` flag only changes on admin action, which is rare. More concretely: the `LookupAPIKey` query (`SELECT * FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL …`) already filters out revoked keys; a disabled creator is a similar administrative state that could either be joined in the same query (`JOIN users u ON u.id = api_keys.created_by_user_id WHERE u.disabled_at IS NULL`) or kept as a single-transaction two-statement check.

Even without joining, wrapping both calls in a **single** `withBypassTx` would cut the transaction overhead in half: 4 round-trips instead of 8.

Additionally, there is an unconditional extra query when the primary lookup returns nil and `eventWriter != nil`: `LookupAPIKeyByHash` fires a third `withBypassTx` to look up revoked keys for security logging (lines 110–123). This path is hit on every invalid key attempt, including scanner probes — though it is slightly more defensible as an infrequent path.

**Impact:** Reachability = every API-key authenticated request (the primary machine-to-machine auth method). Frequency = per-request. Per-occurrence cost = 1 extra database transaction (4 server round-trips) beyond the minimum needed. For a service processing e.g. 100 req/s via API keys, this is 400 unnecessary round-trips per second, ahead of any handler logic.

**Confidence:** Strong-static

**Effort:** Contained — change involves `tryAPIKeyAuth` in `middleware_auth.go` and a new or modified `LookupAPIKeyAndCheckUser` store method. Callers: one.

**Verification plan:** The change reduces the transaction count from 2 to 1 for the success path. Correctness guard: existing `apikey_test.go` must still pass; the disabled-user rejection behavior is exercised there. Argument: `api_keys.created_by_user_id` is an FK to `users(id)`, so a single LEFT JOIN or sub-select yields the same result in one round-trip.

---

### MAJOR — Login flow runs up to 5 independent `withBypassTx` transactions for the non-MFA-enrolled, MFA-mandate-required path

**Location:** `internal/api/auth.go:271–539` (`loginHandler`); `internal/store/auth.go` and `internal/store/mfa.go` (multiple `withBypassTx` callers)

**Problem:**
The sequential DB call chain on the `loginHandler` success path is:

| # | Call | `withBypassTx`? | RTTs |
|---|------|-----------------|------|
| 1 | `GetUserByEmail` | no (uses `s.q` directly) | 1 |
| 2 | `GetLoginLockoutState` (via `lockout.Check`) | yes | 4 |
| 3 | `UserHasMFACredentials` | yes | 4 |
| 4 | If MFA enrolled + device token: `ValidateRememberDeviceToken` | yes | 4 |
| 4a | If MFA enrolled, no device token: `GetMFACredentialsByUserID` | yes | 4 |
| 5 | If no MFA: `IsSiteAdmin` | yes | 4 |
| 6 | If no MFA: `UserMFARequired` (up to 3 sub-calls, each `withBypassTx`) | 1–3 × yes | 4–12 |
| 7 | `UpdateLastLogin` | no (uses `s.q`) | 1 |
| 8 | `CreateRefreshToken` | no (uses `s.q`) | 1 |

`UserMFARequired` at `internal/store/mfa.go:620–652` is itself composed of up to three sequential `withBypassTx` calls: `IsOrgOwner`, `UserInMFARequiredOrg`, `UserHasMFARequirement`. Each is its own transaction.

For a normal user without MFA and with a site-wide `MFARequiredOrgOwners=true` config, steps 2+3+5+6 = 4 to 5 separate `withBypassTx` calls (16–20 round-trips) purely for the MFA mandate check, before any tokens are issued.

These are all reads against global (non-RLS) tables and could be consolidated — at minimum, a single read of the `users` row + a single cross-table query for org membership/requirements could replace the 3-sub-call chain inside `UserMFARequired`. The lockout state (`failed_login_count`, `locked_at`) is already on the `users` row (migration `000036`), meaning `GetUserByEmail` already fetches this data but `GetLoginLockoutState` re-fetches it via a separate query (`SELECT failed_login_count, locked_at FROM users WHERE email = @email`).

The most impactful consolidation: `GetUserByEmail` already selects `*` from `users`, which includes `failed_login_count` and `locked_at`. The lockout check in `lockoutManager.Check` (`GetLoginLockoutState`) makes a redundant second read of the same row.

**Impact:** Reachability = every successful login. Frequency = per-login (not per-request). Per-occurrence cost = 3–5 extra `withBypassTx` transactions (12–20 extra round-trips) on the non-MFA path. Login is lower frequency than per-request API-key checks but still a hot interactive path; on the MFA-mandate check alone, the overhead is disproportionate to the work done.

**Confidence:** Strong-static (the redundant `users` read for lockout state is structurally certain; the `UserMFARequired` decomposition is directly traceable in code)

**Effort:** Cross-cutting (low effort for lockout deduplication — one function change; moderate effort for `UserMFARequired` consolidation — requires a new combined SQL query and updated store method)

**Verification plan:** Lockout deduplication: `GetUserByEmail` returns the full `users` row including `failed_login_count` and `locked_at`; confirm `auth.sql` `GetUserByEmail` returns `*`. Correctness guard: `auth_test.go` lockout tests must pass. `UserMFARequired` consolidation: replace the three sub-calls with a single SQL query joining `org_members`, `organizations`, and `mfa_requirements`; verify `mfa_test.go` mandate tests pass.

---

### MINOR — `withBypassTx` wraps single-query reads that need no transaction semantics

**Location:** `internal/store/auth.go`: `GetUserByID` (line 41), `IsSiteAdmin` (line 191), `GetUserAuthStatus` (line 236); `internal/store/mfa.go`: `UserHasMFACredentials` (line 154), `IsOrgOwner` (line 655), etc.

**Problem:**
`GetUserByID` directly uses `s.q` (no transaction), but `IsSiteAdmin`, `GetUserAuthStatus`, `IsUserEnabled`, and several MFA check methods each wrap a single `SELECT` in a full `withBypassTx` (BEGIN + SET LOCAL + SELECT + COMMIT). The stated reason is "runs from middleware before org context is established" — which means they need `bypass_rls = 'on'`. However, these target global tables (`users`, `mfa_credentials`) that have **no RLS enabled** (confirmed in DDL: no `ALTER TABLE users ENABLE ROW LEVEL SECURITY`). The `SET LOCAL app.bypass_rls = 'on'` is unnecessary overhead for tables that have no RLS policies to bypass. The transaction wrapper produces 3 extra round-trips (BEGIN, SET LOCAL, COMMIT) around a query that could execute as a plain `s.q` call.

The pattern is consistent: `IsSiteAdmin` is called from `loginHandler` (in `withBypassTx`) and from `meHandler` (same). For JWT middleware, `GetUserAuthStatus` fires `withBypassTx` on every authenticated non-API-key request.

**Impact:** Reachability = every JWT-authenticated request (`GetUserAuthStatus` in `RequireAuthenticated`), every login (`IsSiteAdmin`, `UserHasMFACredentials`). Per-occurrence cost = 3 unnecessary round-trips per call. Individually small, but the middleware path (`GetUserAuthStatus`) hits it on every cookie-authenticated request.

**Confidence:** Strong-static (DDL confirms no RLS on `users` or `mfa_credentials`)

**Effort:** Contained — replace `withBypassTx` with direct `s.q` calls for global non-RLS tables; audit which tables have RLS (`api_keys` does, `mfa_requirements` does; `users`, `mfa_credentials`, `mfa_recovery_codes`, `mfa_challenges` do not).

**Verification plan:** Verify via DDL that no RLS policy exists on the target table before removing the bypass wrapper. Correctness guard: existing store tests; no behavioral change since the RLS bypass is a no-op on non-RLS tables.

---

## Suspected Bugs (for follow-up)

- `middleware_auth.go:110–123`: `LookupAPIKeyByHash` (the "detect revoked key" path) fires **unconditionally** whenever `LookupAPIKey` returns nil **and** `eventWriter != nil`. This means any unrecognized key (e.g., a typo, a scanner probe) triggers a second full DB transaction. If `eventWriter` is nil (prod config without security logging), this is skipped — so the bug is latent and config-dependent. Not a crash, but unexpected DB overhead on invalid-key requests. File: `internal/api/middleware_auth.go:109`.

- `loginHandler`: `RecordLoginSuccess` is called unconditionally at line 396 (after successful password verification) and again at line 241 in `mfaVerifyHandler` (after MFA success). For an MFA-enrolled user who completes both steps, `RecordLoginSuccess` writes to the DB twice — once after password, once after MFA. The second write is a no-op functionally (resets already-0 counters) but is still a `withBypassTx` round-trip. File: `internal/api/auth.go:396` and `internal/api/auth_mfa.go:241`.
