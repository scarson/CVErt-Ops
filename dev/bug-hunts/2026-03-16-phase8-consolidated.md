# Phase 8 Bug Hunt — Consolidated Findings

**Date:** 2026-03-16
**Scope:** Phase 8 PR #15 (commit a437c02d) — 8B Observe, 8C Operate, 8D Extend (139 files, 17.3k lines)
**Hunters:** Exploratory (depth-first), Holistic (read-all-reason), Multipass (5 typed passes)

---

## Significant Bugs

### S1. Scheduler ignores `paused_at` — feed pause feature is non-functional
**Consensus:** ALL THREE hunters found this independently
**Location:** `internal/ingest/scheduler.go:126-163`
**Evidence:** `maybeEnqueue` checks `BackoffUntil` and `LastSuccessAt` but never reads `state.PausedAt`. The migration, store methods, admin API endpoints, and frontend UI all exist and work correctly — but the scheduler (the only component that auto-enqueues jobs) ignores the flag entirely.
**Impact:** Admin pauses a misbehaving feed via UI → feed continues running on its normal schedule. The entire pause/resume feature is non-functional.
**Fix:** Add `if state.PausedAt != nil { return }` check in `maybeEnqueue` after the backoff check.

### S2. Admin feed endpoints reject generic feed names
**Found by:** Exploratory
**Location:** `internal/api/feeds.go:88,114,127,148`
**Evidence:** All admin feed management handlers gate on `ingest.IsKnownFeed(feedName)`, which is hardcoded to `{"nvd", "mitre", "kev", "ghsa", "osv", "epss", "msrc", "redhat"}`. Generic feeds loaded from YAML are never added to this list. `listFeedsHandler` only iterates `ingest.KnownFeeds`.
**Impact:** Generic feeds are invisible and unmanageable through the admin API/UI — can't be listed, triggered, paused, or resumed.
**Fix:** Either pass loaded generic feed names to the server, or query `feed_sync_state` rows directly instead of iterating a hardcoded list.

### S3. Login handler doesn't check `disabled_at` — information leak
**Found by:** Exploratory
**Location:** `internal/api/auth.go:221-308`
**Evidence:** Login handler retrieves user, verifies password, and issues tokens without checking `disabled_at`. The `RequireAuthenticated` middleware catches it on subsequent requests, but the login itself succeeds with a 200 + cookies.
**Impact:** (1) Disabled users receive valid auth tokens (immediately useless but still issued). (2) Information leak — attacker can confirm a disabled account's password is still correct. (3) Admin expects immediate lockout; reality is login succeeds, then subsequent calls fail.
**Fix:** Check `user.DisabledAt` before password verification; return generic "invalid credentials" for disabled accounts.

### S4. `force_password_reset` is never enforced — feature is a no-op
**Found by:** Exploratory
**Location:** `internal/api/auth.go` (absent), migration 000036
**Evidence:** Migration adds `force_password_reset boolean NOT NULL DEFAULT false`. Admin API has endpoint to set it. But the login handler never reads the flag, and no middleware checks it anywhere in the request lifecycle.
**Impact:** Admin forces password reset → user continues logging in with existing password indefinitely. The feature does nothing.
**Fix:** Check `force_password_reset` in login handler. If set, issue a limited-scope token that only permits the password change endpoint.

### S5. Doctor health check results discarded when system is unhealthy
**Found by:** Holistic
**Location:** `web/src/views/admin/AdminSystemView.vue:54,76`
**Evidence:** Uses `resp.ok` to gate JSON parsing, but doctor endpoint returns 503 with valid JSON when unhealthy. `resp.ok` is `false` for 503, so the response body is silently discarded.
**Impact:** The health check card only shows results when the system is *already healthy*. When unhealthy (when the admin needs it most), the card shows nothing or stale data.
**Fix:** Check `resp.status === 200 || resp.status === 503` instead of `resp.ok`, or check content-type and always parse JSON.

### S6. Lockout state disconnected from DB — in-memory only
**Found by:** Exploratory
**Location:** `internal/api/lockout.go`, migration 000036
**Evidence:** Migration adds `locked_at` and `failed_login_count` DB columns. Admin "unlock" endpoint clears these. But the `lockoutManager` is purely in-memory (`map[string]*loginAttempt`), never reads/writes DB columns.
**Impact:** (1) Lockout state lost on restart — brute-force attacker waits for deploy. (2) Multi-instance: lockout is per-instance, distribute attempts to bypass. (3) Admin "unlock" clears columns the login flow never writes.
**Fix:** Persist lockout state to DB, or at minimum have admin unlock also call `lockoutManager.RecordSuccess()`.

---

## Minor Bugs

### M1. Non-atomic PATCH for org tier + suspend
**Found by:** Exploratory, Multipass
**Location:** `internal/api/admin_orgs.go:89-168`
**Description:** Tier update and suspend/unsuspend run as separate `withBypassTx` transactions. Partial failure leaves inconsistent state.
**Fix:** Wrap both operations in a single transaction.

### M2. `readyz` and `MigrationCheck` don't check `dirty` flag
**Found by:** Multipass
**Location:** `internal/api/readyz.go:46-58`, `internal/doctor/checks.go:58-73`
**Description:** golang-migrate's `schema_migrations` has `(version, dirty)`. Current check queries only `version`. A partially-applied migration (`dirty=true`) could pass readiness probes or doctor checks.
**Fix:** Query `dirty` column; report failure if `dirty=true`.

### M3. List vs PATCH org endpoints return different response shapes
**Found by:** Multipass
**Location:** `internal/api/admin_orgs.go:85` vs `:167`
**Description:** List returns raw `AdminOrgRow` (includes `member_count`, `last_activity_at`); PATCH maps through `toAdminOrgResponse` (excludes them). Same resource, different shapes.

### M4. Generic feed adapter reads entire response body into memory (up to 50MB)
**Found by:** Multipass
**Location:** `internal/feed/generic/adapter.go:126`
**Description:** Uses `io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))` with 50MB limit. Deviates from project's streaming parse requirement, though `gjson` is lighter than `json.Decode(&slice)`.

### M5. Bulk retry accepts conflicting limits from query param and JSON body
**Found by:** Multipass
**Location:** `internal/api/admin_deliveries.go:113-148`
**Description:** Query param allows 1-200, JSON body allows 1-1000, JSON silently wins. Ambiguous contract.

### M6. `triggerFeedHandler` allows triggering paused feeds
**Found by:** Multipass, Holistic (design concern)
**Location:** `internal/api/feeds.go:84-108`
**Description:** Manual trigger doesn't check `paused_at`. Combined with S1, pause has zero effect. Arguably intentional for admin override, but not documented.

### M7. TOCTOU between org existence check and update
**Found by:** Multipass
**Location:** `internal/api/admin_orgs.go:106-157`
**Description:** Existence check and updates are separate transactions. Concurrent admin delete produces 500 instead of 404.

### M8. `validate-feeds --dry-run` silently no-ops
**Found by:** Multipass
**Location:** `cmd/cvert-ops/validate.go:49-51`
**Description:** Flag is documented as "fetch first page to verify connectivity" but logs "not yet implemented" and exits 0 with "OK" message. Misleading.

### M9. Admin disable user swallows "already disabled" information
**Found by:** Multipass
**Location:** `internal/api/admin_users.go:90-109`
**Description:** Idempotent 200 response doesn't indicate user was already disabled. Internally consistent but loses information.

---

## Cross-Hunter Agreement Matrix

| Bug | Exploratory | Holistic | Multipass |
|-----|:-----------:|:--------:|:---------:|
| S1 Scheduler ignores paused_at | **YES** | **YES** | **YES** |
| S2 Generic feeds invisible to admin | **YES** | | |
| S3 Login doesn't check disabled_at | **YES** | | |
| S4 force_password_reset is no-op | **YES** | | |
| S5 Doctor 503 discards results | | **YES** | |
| S6 Lockout in-memory only | **YES** | | |
| M1 Non-atomic org PATCH | **YES** | | **YES** |
| M2 readyz missing dirty check | | | **YES** |
| M3 Inconsistent org response shapes | | | **YES** |
| M4 50MB in-memory read | | | **YES** |
| M5 Conflicting limit inputs | | | **YES** |
| M6 Trigger ignores pause | | **YES** | **YES** |
| M7 TOCTOU in org PATCH | | | **YES** |
| M8 dry-run no-op | | | **YES** |
| M9 Already-disabled swallowed | | | **YES** |

**Unique finds per hunter:** Exploratory: 4 (S2, S3, S4, S6) · Holistic: 1 (S5) · Multipass: 6 (M2-M5, M7-M9)

---

## Priority Triage

**Fix immediately (significant, functional breakage):**
- S1 — Scheduler paused_at (all three hunters, core feature broken)
- S2 — Generic feeds invisible to admin (Extend pillar partially broken)
- S5 — Doctor 503 handling (health check defeats its own purpose)

**Fix before next release (significant, security/correctness):**
- S3 — Login disabled_at check (information leak, security)
- S4 — force_password_reset enforcement (security feature is no-op)
- S6 — Lockout persistence (security mechanism unreliable)

**Fix when convenient (minor, quality):**
- M1 — Atomic org PATCH
- M2 — readyz dirty flag check
- M8 — dry-run implementation or flag removal

**Track but low priority:**
- M3-M7, M9 — API contract consistency, edge cases
