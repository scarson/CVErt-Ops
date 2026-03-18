# Pitfall Harvest: Early Bug Hunts (Phases 6a, 6b, Vendor Feed, Feed Wiring)

**Date:** 2026-03-18
**Harvester:** harvest-early agent (Explore)
**Sources:** Phase 6a/6b, vendor-feed-adapters, feed-wiring consolidated + individual bug hunt reports
**Cross-referenced against:** `dev/implementation-pitfalls.md`

---

## Summary

| Metric | Count |
|---|---|
| Total findings reviewed | 47 |
| Already documented in pitfalls | 14 |
| New pitfall candidates | 28 |
| Not generalizable (one-off bugs) | 5 |

---

## New Pitfall Candidates

### Feed Wiring & Ingestion (8 findings)

#### NP-E1. SQL INSERT Omits Caller-Provided Columns, Falls Back to DEFAULT
**Source:** Feed-wiring reports (all 3 hunters)
**Pattern:** INSERT column list omits fields the caller intends to provide, silently using DEFAULT (e.g., now()) instead
**Domain:** Database / Feed Ingestion
**Severity:** Significant
**Proposed fix:** Always list every column the caller intends to provide. Verify generated code includes all fields.
**Lesson:** Omissions in INSERT column lists are silent — the query succeeds but discards data.

#### NP-E2. Sync State and Fetch Log Errors Silently Discarded on Success Path
**Source:** Feed-wiring reports (all 3 hunters)
**Pattern:** `_ = storeMethod(...)` on success paths discards errors from critical state writes (cursor persistence)
**Domain:** Feed Ingestion / Error Handling
**Severity:** Significant
**Proposed fix:** Propagate errors from critical state writes (cursor, sync state). Log at ERROR for best-effort writes (fetch log).
**Lesson:** Silent error suppression on success paths can cause worse outcomes than propagating — at least a retry gives another chance.

#### NP-E3. Streaming JSON Decoder State Corruption After Decode Error
**Source:** Feed-wiring exploratory
**Pattern:** `continue` after json.Decoder.Decode() error leaves decoder state undefined; subsequent records may be garbled
**Domain:** Feed Parsing / Go Stdlib
**Severity:** Minor
**Proposed fix:** Don't use `continue` after Decode error. Either abort or manually consume tokens to resync.
**Lesson:** json.Decoder error recovery requires manual token consumption; `continue` is not safe.

#### NP-E4. Adapter Fetches All Pages Internally — No Mid-Pagination Cursor Persistence
**Source:** Feed-wiring multipass
**Pattern:** GHSA adapter loops through ALL GitHub API pages internally, returns LastPage:true, defeating handler crash recovery
**Domain:** Feed Architecture / Contract Violations
**Severity:** Significant
**Proposed fix:** Restructure to return one page per Fetch() call, allowing handler to persist progress between pages.
**Lesson:** Internal pagination defeats the handler's recovery mechanism. Always return one logical page per adapter call.

#### NP-E5. KEV Hard-Fails on Malformed Record (Inconsistent with Siblings)
**Source:** Feed-wiring multipass
**Pattern:** KEV returns error on single malformed record while NVD/GHSA use `continue`
**Domain:** Feed Parsing / Pattern Consistency
**Severity:** Minor
**Proposed fix:** Use consistent error handling across all streaming adapters.
**Lesson:** When multiple adapters parse the same structure, use consistent error handling. Deviations become bugs in the outlier.

#### NP-E6. NVD Terminal-Page Cursor Loses One Window of Progress
**Source:** Feed-wiring multipass
**Pattern:** When final page returns nil NextCursor, handler saves previous-page cursor, causing one re-fetch per run
**Domain:** Feed Ingestion / Pagination
**Severity:** Minor
**Proposed fix:** On terminal page, advance cursor to "now()" so next run starts past all processed data.
**Lesson:** Cursor management must distinguish "point to next page" from "past end of data."

#### NP-E7. No Size Limit on ZIP Archive Downloads
**Source:** Feed-wiring exploratory
**Pattern:** DownloadToTemp uses io.Copy with no upper bound; misconfigured upstream could fill disk
**Domain:** Feed Ingestion / Resource Management
**Severity:** Minor
**Proposed fix:** Add reasonable cap (e.g., 5 GB) via io.LimitedReader.
**Lesson:** All outbound requests should have size limits, even for legitimately large responses.

#### NP-E8. Streaming Response Body Not Drained After json.Decoder
**Source:** Vendor-feed-adapters consolidated
**Pattern:** json.Decoder reads only enough for one value; remaining bytes prevent TCP connection reuse
**Domain:** HTTP / Resource Management
**Severity:** Minor
**Proposed fix:** After Decode, call io.Copy(io.Discard, resp.Body) before Close.
**Lesson:** json.Decoder doesn't consume the entire body. Always drain responses before closing.

### Authentication & Authorization (7 findings)

#### NP-E9. First-User Bootstrap Race in Invite-Only Mode
**Source:** Phase 6b (all 3 hunters)
**Pattern:** CountUsers==0 check not atomic with CreateUser; concurrent requests both pass the gate
**Domain:** Auth / Authorization
**Severity:** Significant
**Proposed fix:** Move CountUsers check into advisory-locked transaction with BootstrapFirstUserOrg.
**Lesson:** Gates that control authorization must be atomic with the gated action.

#### NP-E10. Lockout Map Grows Unbounded — No Eviction
**Source:** Phase 6a security (holistic, multipass)
**Pattern:** Map entries created per failed email, only deleted on success or expiry recheck for that exact email
**Domain:** Security / Rate Limiting
**Severity:** Significant
**Proposed fix:** Background cleanup every 15 minutes, deleting entries where lockedAt + duration < now().
**Lesson:** In-memory maps without cleanup are vulnerable to accumulation attacks.

#### NP-E11. Lockout Bypassed via Email Case Variation
**Source:** Phase 6a holistic
**Pattern:** Raw email string used as map key; no case normalization
**Domain:** Security / Rate Limiting
**Severity:** Significant
**Proposed fix:** Normalize to lowercase: `strings.ToLower(email)` before using as key.
**Lesson:** Email is case-insensitive. Always normalize at application boundary.

#### NP-E12. Password Reset Token Consumed Non-Atomically
**Source:** Phase 6a holistic
**Pattern:** Read token → update password → mark used across separate transactions; concurrent use possible
**Domain:** Auth / Token Management
**Severity:** Minor
**Proposed fix:** Combine token lookup and password update in single transaction with SELECT FOR UPDATE.
**Lesson:** One-time-use tokens must be marked consumed in the same transaction as the authorized action.

#### NP-E13. Argon2 Semaphore Not Released via defer — Panic Leak
**Source:** Phase 6a security multipass
**Pattern:** Explicit semaphore release without defer; panic in hash function permanently leaks slot
**Domain:** Security / Resource Management
**Severity:** Minor
**Proposed fix:** Use defer srv.releaseArgon2() immediately after acquire.
**Lesson:** Any resource acquire must be followed immediately by defer release(). Explicit release without defer is panic-unsafe.

#### NP-E14. No Per-User Rate Limit on Email Verification Resend
**Source:** Phase 6a holistic
**Pattern:** IP rate limit exists but no per-user throttle like password reset has
**Domain:** Auth / Rate Limiting
**Severity:** Minor
**Proposed fix:** Add CountRecentVerificationTokens check analogous to password reset.
**Lesson:** Similar flows must apply identical rate limiting patterns.

#### NP-E15. Password Reset Error Paths Leak User Existence
**Source:** Phase 6a security holistic
**Pattern:** 500 errors only execute for existing users; attacker observing 500 vs 200 infers existence
**Domain:** Security / Information Disclosure
**Severity:** Minor
**Proposed fix:** Return 200 for all errors in enumeration-safe endpoints.
**Lesson:** Audit every error path for existence-conditioning. A single conditional error leaks the whole guarantee.

### API Validation & Consistency (6 findings)

#### NP-E16. PATCH Handler Missing Name Validation Present in POST
**Source:** Phase 6b multipass
**Pattern:** POST validates TrimSpace(name)==""; PATCH allows empty/whitespace names
**Domain:** API / Validation
**Severity:** Significant
**Proposed fix:** Extract validation into shared function called from both handlers.
**Lesson:** PATCH must enforce same validation as POST. Check immediately when adding validation to create.

#### NP-E17. Duplicate Pending Invitations Exhaust Member Slots
**Source:** Phase 6b multipass
**Pattern:** No duplicate check; each invitation counts toward tier limit
**Domain:** API / Business Logic
**Severity:** Minor
**Proposed fix:** Check for existing pending invitation before creating. Return 409 or update existing.
**Lesson:** When creation is gated by a quota, check for duplicates before incrementing.

#### NP-E18. Org Create/Update Allow Whitespace-Only Names
**Source:** Phase 6b multipass
**Pattern:** Checks name=="" but not TrimSpace(name)==""
**Domain:** API / Validation
**Severity:** Minor
**Proposed fix:** Use strings.TrimSpace consistently.
**Lesson:** Trim first, then check empty. Create shared validation helper for all name fields.

#### NP-E19. Concurrent Invitation Accept Returns 500 Instead of Idempotent 200
**Source:** Phase 6b multipass
**Pattern:** Membership check and insert in separate transactions; concurrent accepts hit constraint violation
**Domain:** API / Idempotency
**Severity:** Significant
**Proposed fix:** INSERT ... ON CONFLICT (org_id, user_id) DO NOTHING.
**Lesson:** Idempotency guarantees must be atomic at the database level.

#### NP-E20. Cancel Invitation Silently Succeeds for Non-Existent Resources
**Source:** Phase 6b multipass
**Pattern:** DELETE affects 0 rows, returns nil, handler returns 204 regardless
**Domain:** API / Error Semantics
**Severity:** Minor
**Proposed fix:** Fetch first, return 404 if not found. Or choose idempotent-delete consistently.
**Lesson:** Choose one DELETE pattern and apply consistently across all handlers.

#### NP-E21. Email Verification Resend Claims "Sent" When Send Failed
**Source:** Phase 6a security multipass
**Pattern:** Error logged, 200 returned with "sent" message, but email was never sent
**Domain:** API / Response Semantics
**Severity:** Minor
**Proposed fix:** For authenticated flows (no enumeration risk), return error on send failure.
**Lesson:** Ambiguous responses prevent enumeration only for unauthenticated flows.

### Database & Schema (4 findings)

#### NP-E22. ListAllOrgs Omits Soft-Delete Filter
**Source:** Phase 6b holistic
**Pattern:** Bulk query missing WHERE deleted_at IS NULL while single-row queries have it
**Domain:** Database / Soft-Delete Pattern
**Severity:** Minor
**Proposed fix:** Add deleted_at IS NULL. Audit all queries on soft-delete tables.
**Lesson:** Bulk queries are easy to miss during review. Explicitly audit them for soft-delete consistency.

#### NP-E23. Expected Schema Version Stale — Startup Always Warns
**Source:** Feed-wiring holistic
**Pattern:** Hardcoded const expectedSchemaVersion doesn't match latest migration
**Domain:** Database / Configuration
**Severity:** Significant
**Proposed fix:** Make dynamic — read highest migration number from directory at startup.
**Lesson:** Hardcoded constants for dynamic system state become stale. Use queries or dynamic reads.

#### NP-E24. Registration Returns 500 After User Already Committed
**Source:** Phase 6b multipass
**Pattern:** Critical state writes across separate transactions; error after first commit leaves partial state
**Domain:** Error Handling / Transactional Consistency
**Severity:** Minor
**Proposed fix:** Wrap user creation and bootstrap in single transaction, or handle partial state gracefully.
**Lesson:** Order critical side effects so failures happen before data commits.

#### NP-E25. CountUsers/CreateUser Bypass Transaction Helpers
**Source:** Phase 6b holistic
**Pattern:** Store methods use s.q directly instead of withBypassTx
**Domain:** Database / Convention
**Severity:** Minor
**Proposed fix:** Use withBypassTx even for non-RLS tables, for consistency and future safety.
**Lesson:** Transaction helper patterns are defensive. Apply uniformly.

### Other (3 findings)

#### NP-E26. sendInvitationEmail Silently Swallows Nil Org/Inviter
**Source:** Phase 6b multipass
**Pattern:** Nil check with no logging, differs from surrounding error paths
**Domain:** Error Handling
**Severity:** Minor

#### NP-E27. Advisory Lock Comment-Code Mismatch
**Source:** Vendor-feed-adapters consolidated
**Pattern:** Comment says "lower key first" but code acquires newKey first
**Domain:** Database / Documentation
**Severity:** Minor

#### NP-E28. Feed Handler Crash-Recovery Gap (State Write After Loop)
**Source:** Feed-wiring exploratory
**Pattern:** Sync state written after all merges complete; crash between last merge and state write loses cursor
**Domain:** Feed Ingestion / Transaction Design
**Severity:** Significant
**Notes:** Architecturally intentional (per-row locks can't span handler). Mitigated by idempotent merge.

---

## Consolidation Notes

Many of these candidates overlap with harvest-late findings:
- NP-E10 (lockout unbounded) = harvest-late NP-5 (in-memory state not persisted)
- NP-E11 (email case) is closely related to NP-E10
- NP-E16 (PATCH validation) = harvest-late related to 9.2
- NP-E13 (semaphore defer) is a specific instance of a general "resource release on panic" pattern
- NP-E9 (bootstrap race) is a specific TOCTOU instance
- NP-E2 (silent error discard) is part of a broader "silent error swallowing" pattern

Several candidates are more specific bug fixes than generalizable patterns:
- NP-E6 (NVD terminal cursor), NP-E17 (duplicate invitations), NP-E20 (cancel 204), NP-E26 (nil org), NP-E27 (comment mismatch)

The strongest candidates for the reorganized document are the ones that generalize:
- **Silent error suppression** (NP-E2, NP-E21, NP-E26) — pattern
- **PATCH/POST validation parity** (NP-E16, NP-E18) — already partially in 9.2
- **Atomic token consumption** (NP-E12, NP-E19) — TOCTOU pattern
- **In-memory state without eviction/persistence** (NP-E10, NP-E11) — already partially in 5.14
- **Streaming decoder error recovery** (NP-E3) — extends 1.1
- **Internal pagination defeating recovery** (NP-E4) — new pattern
