---
run_schema_version: 1
run_id: 2026-06-05-s8-authglue
date: 2026-06-05T03:35:00Z
scope: "S8 — AuthN/MFA/SSO/OAuth glue (COLD SWEEP)"
methodology: { skill: performance-audit-cycle, plugin_version: "superpowers-plus@0.2.0 (vendored; version per source repo)" }
dispatch: { model_requested: "sonnet (Claude Code Agent tool; COLD-sweep economy)", reasoning_effort: "default (harness exposes no knob)", overridden_by_user: false }
stack: [ { ecosystem: go, framework: "jwt/v5 + go-oidc + argon2id + pgx", version: "go1.26.2" } ]
currency_briefs: [ { framework: go, researched_on: null, status: "REDUCED/COLD — idiom-currency lane not run" } ]
lanes_run: [algorithmic, memory, data-access]
lanes_skipped: { concurrency: "COLD SWEEP — 3-lane batched pass", "idiom-currency/cost-map/payload/dynamic": "COLD SWEEP / no runtime" }
finding_counts: { by_impact: { critical: 0, major: 3, minor: 2 }, by_lane: { algorithmic: 1, memory: 2, data-access: 3 }, suspected_bugs: 0 }
regression: { prev_run_id: null, new: 5, persisting: 0, resolved: 0 }
---

# Performance Audit (COLD SWEEP, validated) — S8 AuthN/MFA/SSO/OAuth glue

**Tier:** COLD SWEEP (3 batched lanes, sonnet). **Verification:** static-only. **Regression:** 5 new.
This is cold CRUD/token-verification glue; the lanes correctly returned **mostly confirmed-cold**, with one
real, repeated hot-path theme. **Confirmed-cold non-findings (recorded):** argon2id login cost
(intentional), JWT dual-key fallback retry, `rejectAPIKeyQueryParams` O(q×8) loop (bounded), MFA-reason
assembly, `oidcProviders sync.Map` (bounded eviction), the goroutine-per-request `UpdateAPIKeyLastUsed`
(intentional, `context.WithoutCancel`), SSO hex-decode (cold SSO-only path).

## Major Findings — one root theme, three instances

### P1. `withBypassTx` does 3–4 round-trips (BEGIN + `SET LOCAL` + SELECT + COMMIT) for single-row reads on **non-RLS** tables — on every authenticated request
**Lanes:** data-access, algorithmic  **Location:** `internal/store/store.go:48` (`withBypassTx`); hottest caller `internal/store/auth.go:236` (`GetUserAuthStatus`, via `RequireAuthenticated` on every cookie-auth request); also `IsSiteAdmin`, `UserHasMFACredentials`, `IsOrgOwner`
**Fingerprint:** `data-access:store.go:withBypassTx:non-rls-single-read`  **Status:** new
**Problem:** `users`, `mfa_credentials`, `mfa_recovery_codes`, `mfa_challenges` have **no RLS** (confirmed by DDL), yet single-row reads against them are wrapped in a bypass transaction whose `SET LOCAL app.bypass_rls` is a no-op there — paying ~3 extra round-trips for a one-statement read. Under `QueryExecModeSimpleProtocol` each is also re-planned. **Impact:** 100% of authenticated requests (`GetUserAuthStatus`). **Confidence:** Strong-static  **Effort:** Contained — a direct (non-tx) read path for bypass-safe single-row reads (or session-default the bypass for the app role). **This is the auth-path instance of the repo-wide `withBypassTx` theme (also S5-P2).**

### P2. API-key auth runs **two** independent `withBypassTx` transactions per request (~8 round-trips before the handler)
**Lane:** data-access  **Location:** `internal/api/middleware_auth.go:100-138` (`tryAPIKeyAuth` → `LookupAPIKey` then `IsUserEnabled`)
**Fingerprint:** `data-access:middleware_auth.go:apikey-double-bypasstx`  **Status:** new
**Problem:** Every API-key request does `LookupAPIKey` and `IsUserEnabled` as **separate** bypass transactions. **Impact:** every API-key request. **Confidence:** Strong-static  **Effort:** Contained — join the enabled-check into the key lookup query, or one transaction. Subsumes into P1's fix direction.
**Verification plan:** round-trip argument (8 → ~2–3); guard = identical auth decision incl. disabled users.

### P3. Login runs 3–5 independent `withBypassTx` for the MFA-mandate check + a redundant lockout re-read
**Lane:** data-access  **Location:** `internal/api/auth.go:271-539`, `internal/store/mfa.go:620-652`
**Fingerprint:** `data-access:auth.go:login-bypasstx-fanout`  **Status:** new
**Problem:** `UserMFARequired` decomposes into up to 3 sequential bypass calls (`IsOrgOwner`, `UserInMFARequiredOrg`, `UserHasMFARequirement`), and `GetLoginLockoutState` re-reads the `users` row that `GetUserByEmail` already fetched (`failed_login_count`/`locked_at` are columns on `users`). ~12–20 unnecessary round-trips per login on the MFA-mandate path. **Impact:** every login. **Confidence:** Strong-static  **Effort:** Contained — fold the MFA-mandate predicates into one query; reuse the already-fetched `users` row for lockout state.
**Verification plan:** round-trip argument; guard = identical MFA-required + lockout decisions.

## Minor Findings
- **P4** `memory:middleware_apikey_query.go:url-query-alloc` — `middleware_apikey_query.go:38`: `r.URL.Query()` parses + allocates `url.Values` on **every** request (incl. no-query). Early-exit on empty `RawQuery`. Localized.
- **P5** `memory:middleware_auth.go:jwtsecret-copy` — `middleware_auth.go:27,41`: `[]byte(srv.cfg.JWTSecret)` copy on every cookie-auth request via the fallback path. Pre-convert at server construction. Localized.

---
**Disposition:** all 5 default to **FIX**. P1–P3 share the `withBypassTx`/per-request-transaction root —
fix together (see the cross-slice roll-up). No suspected bugs in this sweep.
