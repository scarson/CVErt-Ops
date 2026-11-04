# Code Review — Phases 2a & 2b

> **Date:** 2026-02-28
> **Commits:** `d758717` (Phase 2a fixes), `4643b59` (Phase 2b fixes)

Post-implementation code reviews found several issues across both phases.

## Phase 2a fixes (`d758717`)

- **Rate limiting:** Wired per-IP token bucket rate limiter into register, login, and refresh handlers with enforcement tests
- **RBAC:** Added caller-role cap to `createInvitationHandler` (defense-in-depth)
- **Invitation email match:** Added email match check in `acceptInvitationHandler`
- **Rate limiter cleanup:** Added shutdown mechanism (`done` channel + `Stop` method) to `ipRateLimiter`
- **Bootstrap atomicity:** Replaced racy `CountUsers` + `CreateOrgWithOwner` with atomic `BootstrapFirstUserOrg` using `pg_advisory_xact_lock`
- **OAuth parity:** Added `BootstrapFirstUserOrg` to GitHub and Google OAuth new-user paths; added `Name` claim to `googleClaims`
- **Cleanup:** Removed `NewRouter` shim, updated smoke tests to use `NewServer` directly
- Added 6 process guardrails to `dev/implementation-pitfalls.md` §8

## Phase 2b fixes (`4643b59`)

- **RLS bypass:** Added `withOrgRawTx` helper for squirrel queries needing `SET LOCAL app.org_id`; fixed `ListWatchlists`, `ListWatchlistItems`, `ListAlertRules`, `ListAlertEvents` — all now use `withOrgRawTx` instead of bare pool queries; added RLS isolation tests using `AppStore` (NOBYPASSRLS)
- **ILIKE escaping:** Escape `%`, `_`, `\` wildcards in text and `affected.package` DSL patterns
- **PATCH state machine:** Block DSL changes while activating (409), track status transitions (`draft→activating`, `active→disabled`, `error→activating`); cache eviction on DSL change, disable, and delete
- **API contract:** Create accepts `enabled:bool` (not status string), always returns 201; validate response includes warnings, `is_epss_only`, `has_epss_condition`; alert events include `material_hash`
- **Alert events:** Added `last_match_state` and `since` query filters; added keyset pagination (`first_fired_at DESC, id DESC`)
