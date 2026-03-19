# Pitfall Harvest: Late Bug Hunts (Phases 8, 8E, 9, 11)

**Date:** 2026-03-18
**Harvester:** harvest-late agent (Explore)
**Sources:** Phase 8, 8E, 9, 9-stage3, 11 consolidated bug hunt reports
**Cross-referenced against:** `dev/implementation-pitfalls.md`

---

## Summary

| Metric | Count |
|---|---|
| Total findings reviewed | ~45 |
| Already documented in pitfalls | ~8 |
| New pitfall candidates | 12 |
| Design decisions flagged | 3 |

---

## New Pitfall Candidates

### NP-1. Scheduler Ignores Administrative Flags
**Source:** Phase 8 — S1 (all 3 hunters found independently)
**Pattern:** Background scheduler/trigger code doesn't respect administrative feature flags (e.g., `paused_at`). The UI, API, store, and migration all work — but the scheduler (the only auto-triggering component) never reads the flag.
**Proposed Domain:** Architecture / Operations
**Severity:** High
**Already in pitfalls?** NO — searched for "paused", "scheduler", "ignore flag" — not found
**Proposed pitfall text:**
- **The Flaw:** Admin pause/resume feature implemented in migration, store, API, and UI — but the scheduler that auto-enqueues jobs never checks the pause flag.
- **Why It Matters:** Admin pauses a misbehaving feed → feed continues running. The entire pause/resume feature is non-functional despite appearing to work in the UI.
- **The Fix:** After implementing any admin control flag that gates automatic behavior, verify the automatic trigger (scheduler, cron, poller) reads and respects the flag. Test by setting the flag and confirming the automatic behavior stops.
- **The Lesson:** Features that span multiple layers (UI → API → store → scheduler) must be verified end-to-end. The flag is useless if the component that triggers the action doesn't read it. When adding an admin control, trace the flow to the actual trigger point.

### NP-2. Admin Endpoints Hardcode Resource Lists
**Source:** Phase 8 — S2
**Pattern:** Admin feed management endpoints iterate a hardcoded list of known feeds, excluding user-configured generic feeds from listing, triggering, and management.
**Proposed Domain:** API
**Severity:** High
**Already in pitfalls?** NO
**Proposed pitfall text:**
- **The Flaw:** Admin endpoints gate on `IsKnownFeed(feedName)` which is hardcoded to built-in feeds. Generic feeds loaded from YAML config are invisible.
- **Why It Matters:** Operators cannot list, trigger, pause, or resume user-configured feeds through the admin API or UI. A whole category of resources is invisible to management.
- **The Fix:** Either pass loaded generic feed names to the server at startup, or query the database (e.g., `feed_sync_state` rows) directly instead of iterating a hardcoded list.
- **The Lesson:** When a resource type can be extended by users (config files, plugins, dynamic registration), admin endpoints must discover resources from the source of truth — not from a compile-time constant.

### NP-3. Login Handler Omits Status Flag Checks
**Source:** Phase 8 — S3
**Pattern:** Login handler authenticates user (password check, token issuance) without checking `disabled_at`. Disabled users get valid tokens, and the response difference leaks account existence.
**Proposed Domain:** Auth / Security
**Severity:** High
**Already in pitfalls?** NO — related to 3.11 (identity matching) but different pattern
**Proposed pitfall text:**
- **The Flaw:** Login handler verifies password and issues tokens without checking user status flags (`disabled_at`, `force_password_reset`).
- **Why It Matters:** (1) Disabled users receive valid auth tokens. (2) Information leak — attacker confirms password is correct for a disabled account. (3) Admin expects immediate lockout but reality is deferred to middleware.
- **The Fix:** Check all user status flags BEFORE password verification. Return generic "invalid credentials" for disabled accounts. Check `force_password_reset` and issue restricted token if set.
- **The Lesson:** Authentication and authorization are separate concerns, but status checks belong in the auth flow — not deferred to downstream middleware. The login handler is the first line of defense.

### NP-4. Feature Flag Column Never Enforced
**Source:** Phase 8 — S4
**Pattern:** `force_password_reset` column exists in migration, admin API can set it, but login handler never reads it. Feature is a complete no-op.
**Proposed Domain:** Architecture
**Severity:** High
**Already in pitfalls?** NO — similar pattern to NP-1 but for auth flow
**Notes:** This is a variant of NP-1 (flag exists but enforcement point doesn't read it). Could be merged into a single "feature flags must be checked at enforcement points" pitfall.

### NP-5. In-Memory State Not Persisted — Lost on Restart
**Source:** Phase 8 — S6
**Pattern:** Login lockout state is purely in-memory (map), never reads/writes the DB columns that exist for it. State lost on restart; multi-instance deployment allows bypass by distributing attempts.
**Proposed Domain:** Architecture
**Severity:** High
**Already in pitfalls?** NO — 5.14 covers unbounded growth, but not the persistence/restart issue
**Proposed pitfall text:**
- **The Flaw:** Security-critical state (login lockout) stored in-memory only. DB columns exist but are never used by the enforcement code.
- **Why It Matters:** (1) Restart clears state — attacker waits for deploy. (2) Multi-instance: attempts spread across instances bypass per-instance lockout. (3) Admin "unlock" clears DB columns that enforcement never reads.
- **The Fix:** Security-critical rate limiting and lockout state MUST be persisted to the database or a shared store. In-memory state is acceptable only as a cache layer on top of persistent state.
- **The Lesson:** In-memory-only state is ephemeral. Any state that affects security decisions (lockout, rate limits, session validity) must survive process restart and be consistent across instances.

### NP-6. Hot-Reload Infrastructure Built But Disconnected
**Source:** Phase 8E — B1 (all 3 hunters, highest consensus)
**Pattern:** Config hot-reload pipeline (ConfigHolder, ReloadableConfig, atomic.Pointer, SIGHUP, admin API) is correctly built but no handler reads from it — all 30+ call sites read the static startup config.
**Proposed Domain:** Architecture
**Severity:** Critical
**Already in pitfalls?** NO
**Proposed pitfall text:**
- **The Flaw:** Hot-reload infrastructure is built and tested, but the consumers (handlers) still read the immutable startup config. Operators see "config reloaded" success but the old config remains active.
- **Why It Matters:** False sense of security. Operator rotates JWT secret via SIGHUP, sees success response, believes rotation is live — old key remains in use until process restart. Silent security gap.
- **The Fix:** After building reload infrastructure, verify consumers READ from the reloadable source. grep for the static config field name across all files. Each hit is a consumer that needs updating.
- **The Lesson:** Infrastructure without consumers is dead code that creates false confidence. When building any "configuration reload" or "feature flag" system, the last step is verifying every consumer reads from the new source — not the old one.
**Notes:** Noted as intentional phasing decision (Phase 8E ships infra, Phase 9 wires handlers). Fixed in bug hunt remediation.

### NP-7. Partial Secrets File Zeros Unmentioned Fields
**Source:** Phase 8E — B2 (all 3 hunters)
**Pattern:** Secrets file reload creates a fresh config struct and only populates fields present in the file. `holder.Store(newCfg)` replaces the entire config, zeroing fields from startup env vars that aren't in the file.
**Proposed Domain:** Architecture
**Severity:** Critical
**Already in pitfalls?** NO
**Proposed pitfall text:**
- **The Flaw:** `LoadFromSecretsFile` creates a new config and only populates fields in the file. Atomic replace zeros everything else.
- **Why It Matters:** A partial secrets file containing only `JWT_SECRET` produces a config where SSO, SMTP, and other fields are zeroed. A simple JWT rotation breaks SSO and email.
- **The Fix:** Merge reload values onto the current config rather than replacing. Read `holder.Load()` as baseline, overlay file values, store merged result.
- **The Lesson:** Config reload must be additive (merge), not destructive (replace). Any reload mechanism that starts from an empty struct will zero fields that weren't in the reload source.
**Notes:** Fixed in bug hunt remediation.

### NP-8. Infrastructure Code Never Wired at Startup
**Source:** Phase 8E — B3 (all 3 hunters)
**Pattern:** SIEM syslog writer is fully implemented but `NewSyslogWriter()` / `SetSyslog()` are never called in any startup path. Additionally, env vars for config only exist on the reloadable struct, not the startup struct.
**Proposed Domain:** Architecture
**Severity:** High
**Already in pitfalls?** NO — different from NP-6 (this is about wiring, not consumer reads)
**Notes:** Fixed in bug hunt remediation.

### NP-9. Post-Filter Applied After Pagination Silently Truncates Results
**Source:** Phase 9 consolidated (if present)
**Pattern:** Application-layer PostFilter (regex conditions) applied after SQL fetch with LIMIT. Pagination "has next page" decision uses post-filter count instead of pre-filter count, silently truncating results.
**Proposed Domain:** API / Alert
**Severity:** High
**Already in pitfalls?** NO — partially related to 5.18 (keyset pagination) but different failure mode
**Notes:** Documented in testing-pitfalls.md §2 but not in implementation-pitfalls.md.

### NP-10. Case-Sensitivity Divergence Between SQL and Application Layers
**Source:** Phase 9 consolidated
**Pattern:** SQL query uses `lower(column)` but PostFilterField returns raw-case value. Same regex rule produces different results depending on evaluation path (SQL vs app-layer).
**Proposed Domain:** Alert
**Severity:** High
**Already in pitfalls?** PARTIALLY — 5.5 covers case-sensitive DSL evaluation but not the SQL/app-layer divergence
**Notes:** Documented in testing-pitfalls.md §2 but not in implementation-pitfalls.md.

### NP-11. Pagination Cursor Format Inconsistency
**Source:** Phase 9 stage3 consolidated
**Pattern:** Most endpoints use opaque base64-encoded JSON cursors, but one or more endpoints use raw UUIDs. Client pagination helpers can't work generically.
**Proposed Domain:** API
**Severity:** Medium
**Already in pitfalls?** PARTIALLY — 13.3 covers API contract consistency but doesn't specifically call out cursor format divergence

### NP-12. Password Reset Bypasses MFA
**Source:** Phase 11 — B1 (critical)
**Pattern:** Forgot-password flow completes without checking MFA enrollment or mandate. Attacker with email access resets password and fully authenticates, bypassing TOTP.
**Proposed Domain:** Auth / Security
**Severity:** Critical
**Already in pitfalls?** NO — this is a new flow-level security gap, not a pattern-level pitfall
**Notes:** Fixed in bug hunt remediation.

---

## Findings Already Documented

| Source | Finding | Documented As |
|---|---|---|
| Phase 8 — M1 | Non-atomic PATCH | Related to 1.11 (pointer types) and 13.3 (contract consistency) |
| Phase 8E — B4 | TOTP enrollment decrypt | Related to crypto rotation patterns |
| Phase 9 | Status filter on rejected CVEs | 4.12 |
| Phase 11 — B2 | Stale token_version | Related to 3.4 (refresh token theft) |
| Phase 11 — B3 | Enrollment pending order | Design-specific, not generalizable |
| Phase 11 — B6 | Transaction helper compliance | 2.17 |

---

## Design Decisions Flagged for Sam

1. **Config holder wiring (8E-B1):** Fix ~30 call sites now or keep as Phase 9 follow-up? (Fixed in remediation)
2. **Secrets file merge strategy (8E-B2):** Full-replace vs merge-with-current? (Fixed in remediation)
3. **SetSyslog race condition (8E-B3):** Fix now or defer? (Fixed in remediation)

---

## Consolidation Notes

- NP-1 and NP-4 are the same meta-pattern: **feature flags that exist in the data model but are never checked at the enforcement point**. Could be a single pitfall with two examples.
- NP-6, NP-7, and NP-8 are all **infrastructure-without-consumers** patterns. Could be grouped under a single "verify the last mile" pitfall.
- NP-9 and NP-10 overlap with testing-pitfalls.md content. The implementation-pitfalls version should focus on the implementation fix, not the testing angle.
- Several findings (NP-6, NP-7, NP-8, NP-12) have been fixed via bug hunt remediation. They're still valuable as pitfalls because the PATTERNS recur.
