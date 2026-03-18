# Pitfall Harvest: Health Reviews & Implementation Log

**Date:** 2026-03-18
**Harvester:** harvest-health agent (Explore)
**Sources:** March 10 health review, March 18 validated health review, implementation log gotchas
**Cross-referenced against:** `dev/implementation-pitfalls.md`

---

## Summary

| Metric | Count |
|---|---|
| Total findings reviewed | ~76 (45 from March 10, 31 from March 18) |
| Already documented in pitfalls | ~8 (§13 captures 5 meta-patterns from March 10) |
| New pitfall candidates | 7 |
| Impl log gotchas assessed | ~15 — mostly phase-specific, not generalizable |

---

## New Pitfall Candidates

### NP-H1. Unbounded Query Results Loaded Into Memory (No Pagination on Batch Operations)
**Source:** March 18 health review I1 (CRITICAL)
**Pattern:** Batch/cursor-based operations SELECT without LIMIT, scanning all rows into memory
**Proposed Domain:** Database / Architecture
**Severity:** Critical
**Already in pitfalls?** NO — 5.14 covers unbounded map growth, 4.7 covers activation scan OOM, but neither covers batch evaluator query pagination
**Proposed pitfall text:**
- **The Flaw:** Batch operations like alert evaluation use `SELECT cve_id FROM cves WHERE date_modified_canonical > cursor` with no LIMIT. On first run or stale cursor, this returns 250k+ rows scanned into a single `[]string`. IDs are then passed to `ANY($1)` where the database also processes the entire array.
- **Why It Matters:** Memory scales with corpus size, not batch size. At 500k CVEs with concurrent batch operations, a single background job can consume gigabytes. OOM or thrash before completing.
- **The Fix:** Apply keyset pagination to candidate fetches. Process in fixed-size batches (1000 rows), compute matches, write results, fetch next page. The correct pattern already exists in the same file (`getCVEsBatch`).
- **The Lesson:** Cursor-based batch jobs MUST paginate their result sets. "It works on my dev DB" fails at production scale. When the same file has both a paginated and unpaginated query, the unpaginated one is a bug.

### NP-H2. Detached Goroutines Without Join Points Block Graceful Shutdown
**Source:** March 18 health review I2 (MAJOR)
**Pattern:** `go worker.Start(ctx)` with no mechanism to await completion before closing resources
**Proposed Domain:** Architecture / Operations
**Severity:** Major
**Already in pitfalls?** NO — 1.5 covers WithoutCancel, 4.9 covers tarpitting, but neither covers shutdown coordination
**Proposed pitfall text:**
- **The Flaw:** Delivery worker spawned as `go deliveryWorker.Start(ctx)` with no join point. During shutdown, `db.Close()` is called without waiting for the worker. Worker uses `context.WithoutCancel` to survive cancellation but has no synchronization mechanism. In-flight HTTP calls and DB queries race against pool closure.
- **Why It Matters:** Notifications lost during graceful shutdown. Pending notification cancelled mid-delivery, marked failed, wasted after retry window expires.
- **The Fix:** Add a `done <-chan struct{}` or `sync.WaitGroup` to coordinate. Await worker completion before closing database.
- **The Lesson:** Any goroutine spawned with `context.WithoutCancel` MUST have an explicit synchronization point. Context cancellation alone is insufficient — `WithoutCancel` explicitly opts out of that mechanism.

### NP-H3. Unbounded Goroutines With context.WithoutCancel But No Timeout or Semaphore
**Source:** March 18 health review I3 (MAJOR)
**Pattern:** Per-call goroutine spawning with WithoutCancel and no concurrency limit or per-goroutine timeout
**Proposed Domain:** Architecture
**Severity:** Major
**Already in pitfalls?** PARTIALLY — 3.2/3.3 cover argon2 semaphore, 4.9/4.13 cover webhook limits, but not the general "WithoutCancel needs controls" pattern
**Proposed pitfall text:**
- **The Flaw:** Security event writer spawns a goroutine per Write() call with `context.WithoutCancel(ctx)` and no semaphore, timeout, or deadline. Under brute-force attack, goroutines accumulate. If any goroutine stalls on a slow DB insert, `Stop()` blocks indefinitely waiting for `wg.Wait()`.
- **Why It Matters:** Slow DB query blocks shutdown indefinitely — operator must SIGKILL. Under attack, goroutines consume memory until OOM.
- **The Fix:** (1) Semaphore to limit concurrent writers. (2) `context.WithTimeout` per goroutine. (3) Timeout on `Stop()` — if draining takes >30s, log and proceed.
- **The Lesson:** `context.WithoutCancel` detaches from lifecycle management. When you use it, you MUST add explicit resource controls: semaphore for concurrency, timeout for duration, join point for shutdown.

### NP-H4. Service Layer Bypasses Store Abstraction, Duplicating Transaction Management
**Source:** March 18 health review I6 (MAJOR)
**Pattern:** Business logic holds `*sql.DB` and reimplements store's transaction helpers without the safety features
**Proposed Domain:** Architecture / Database
**Severity:** Major
**Already in pitfalls?** PARTIALLY — 2.17 covers transaction helper selection, but not the abstraction bypass
**Proposed pitfall text:**
- **The Flaw:** Alert evaluator holds its own `*sql.DB` and implements `bypassTx()` identical to `store.withBypassRawTx()` but omits panic-recovery defer. Tests seed data via raw SQL, bypassing merge pipeline. Two independent transaction management paths exist.
- **Why It Matters:** (1) Transaction semantics diverge if one copy is fixed. (2) Panic in evaluator's bypassTx leaks transaction. (3) Tests don't exercise real data path, masking merge bugs.
- **The Fix:** (1) Add panic recovery immediately. (2) Move evaluator queries into a dedicated store interface. (3) Seed test data through merge pipeline.
- **The Lesson:** Business logic MUST NOT duplicate store layer abstractions. If a service needs store internals, define an interface. Duplication of transaction management is a bug, not a shortcut.

### NP-H5. Security-Critical Functions Copy-Pasted Without Shared Implementation
**Source:** March 18 health review I7 (MAJOR)
**Pattern:** Identical security logic copy-pasted across multiple functions; a fix to one must be applied to all
**Proposed Domain:** Auth / Security
**Severity:** Major
**Already in pitfalls?** NO — code duplication is a quality concern, but this is specifically about SECURITY code duplication
**Proposed pitfall text:**
- **The Flaw:** JWT parsing copy-pasted across four functions (ParseAccessToken, ParseRefreshToken, ParsePendingToken, ParseEnrollmentToken). All implement: try active secret → ErrTokenSignatureInvalid → retry with previous secret. A security fix must be applied four times.
- **Why It Matters:** Fix applied to 3 of 4 parse functions creates an authentication bypass or timing oracle. Delayed discovery of missed application is realistic given review fatigue.
- **The Fix:** Generic `parseToken[T jwt.Claims]` helper. Each public Parse function becomes a one-liner.
- **The Lesson:** Security-critical logic MUST NEVER be copy-pasted. Create shared helpers before writing the first implementation. If you find yourself copying auth/crypto/validation code, stop and extract.

### NP-H6. Tests Skip Production Client Configuration
**Source:** March 18 health review I15 (MAJOR)
**Pattern:** Tests use substitute HTTP clients because production client blocks test infrastructure (localhost), leaving production config untested
**Proposed Domain:** Testing / Security
**Severity:** Major
**Already in pitfalls?** NO — testing-pitfalls.md §8 covers this but implementation-pitfalls.md does not
**Proposed pitfall text:**
- **The Flaw:** Webhook delivery tests use plain `http.Client` because production `safeurl.Client` blocks 127.0.0.1. Tests pass but production client config (redirect disabled, MaxConnsPerHost=50, timeout) is never exercised.
- **Why It Matters:** Bug in production client config is invisible to tests. Redirect handling could be silently broken, timeout misconfigured — surfaces only in production.
- **The Fix:** At least one integration test using the real client against a non-loopback target, or verify all configuration properties on the built client object.
- **The Lesson:** Tests that skip critical production behavior provide false confidence. Test with the real dependency, or document why you can't and accept the risk.

### NP-H7. Related Configuration Constants Must Be Synchronized
**Source:** March 18 health review I16 (MAJOR)
**Pattern:** Two timeout constants that must maintain an invariant (staleThreshold >= maxJobDuration) are set independently
**Proposed Domain:** Architecture / Operations
**Severity:** Major
**Already in pitfalls?** NO — 5.4 covers NVD rate limit coordination but not the general pattern
**Proposed pitfall text:**
- **The Flaw:** Worker pool has `staleThreshold = 5m` and `maxJobDuration = 10m` as independent constants. Stale recovery reclaims jobs running >5 minutes, but jobs are allowed to run for 10 minutes. A legitimate 7-minute feed sync is reclaimed as stale.
- **Why It Matters:** Duplicate job processing: CVE data inserted twice, conflicting lock acquisitions, duplicate notifications. Hard to diagnose because the job did succeed before being killed.
- **The Fix:** Enforce `staleThreshold >= maxJobDuration`. Set both to 10 minutes or stale to 12 minutes with buffer. Add compile-time check or comment documenting the invariant.
- **The Lesson:** Related timeout/threshold constants are often set independently during development. When two constants have an ordering invariant, document it explicitly and consider deriving one from the other.

---

## Implementation Log Gotchas Assessment

Reviewed "Gotchas discovered" sections across all phases. Most are phase-specific:

| Gotcha | Generalizable? | Notes |
|---|---|---|
| Table naming (singular vs plural) | No | Convention, not a pitfall |
| Nil slice → JSON null | Partially | Covered by existing DB pitfalls |
| Stale LSP diagnostics in worktrees | No | Editor tooling quirk |
| Windows SIGHUP absence | No | OS platform difference, documented |
| Double-close risk with syslog | Partially | Covered by §13.4 resource lifecycle |
| Migration renumbering conflicts | No | Process issue for concurrent branches |
| `//nolint` inside function args | No | Syntax quirk |
| gosec G104 vs errcheck | No | Linter-specific |

**Recommendation:** Log gotchas are valuable for onboarding but don't warrant pitfall entries unless they generalize to a broader antipattern.

---

## Findings Already Documented in §13

| March 18 Finding | Pitfalls §13 | Notes |
|---|---|---|
| I9: serve/worker duplication | 13.4 (resource lifecycle) | Same root cause |
| I12: evaluator code duplication | 13.2 (pattern-level fixes) | Same pattern |
| API format inconsistencies | 13.3 (contract consistency) | Same root cause |
| RLS deployment config | 13.1 (deployment must match code) | Already captured |
