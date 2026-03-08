# Bug Hunt — Vendor Feed Adapters (Exploratory)

**Date:** 2026-03-06
**Status:** complete
**Skill:** code-bug-hunter-exploratory

## Starting Prompt

Use the `code-bug-hunter-exploratory` skill to find correctness bugs in the vendor feed adapter implementation.

**Scope:** The `feature/vendor-feed-adapters` branch in the worktree at `.worktrees/vendor-feed-adapters/`. This branch adds MSRC and Red Hat feed adapters, a shared CSAF 2.0 parser, a `cve_vendor_enrichment` table, and integrates vendor enrichment into the merge pipeline. ~4,400 lines of new/changed code across 15 commits.

## Scope Analyzed

**Deep exploration (all code read line-by-line):**
- `internal/merge/pipeline.go` (471 lines) — merge pipeline orchestrator, PK migration, vendor enrichment upsert
- `internal/merge/resolve.go` (376 lines) — field resolution with source precedence, union logic
- `internal/merge/advisory.go` — advisory lock key computation (FNV-1a hash)
- `internal/feed/msrc/adapter.go` (413 lines) — MSRC CSAF adapter, csafToPatches, vendor enrichment builder
- `internal/feed/redhat/adapter.go` (495 lines) — Red Hat adapter, pagination, detailToPatch, vendor enrichment
- `internal/feed/csaf/parser.go` (178 lines) — shared CSAF 2.0 parser, product tree walker
- `internal/feed/kev/adapter.go` (315 lines) — KEV adapter (for cursor/enrichment pattern comparison)
- `internal/feed/interface.go` (106 lines) — CanonicalPatch, VendorEnrichment, FetchResult contracts
- `internal/store/queries/vendor_enrichment.sql` (24 lines) — upsert SQL with IS DISTINCT FROM guard
- `migrations/000029_vendor_enrichment.up.sql` (44 lines) — schema migration
- `migrations/000029_vendor_enrichment.down.sql` (10 lines) — rollback migration

**Comparison reads (cursor semantics, pattern consistency):**
- `internal/feed/nvd/adapter.go` — NVD cursor pattern (nil on completion, like Red Hat)
- `internal/feed/osv/adapter.go` — OSV cursor pattern (always non-nil, like MSRC/KEV)
- `internal/store/generated/feed.sql.go` — feed_sync_state persistence layer
- `internal/feed/csaf/parser_test.go`, `internal/feed/msrc/adapter_test.go` — CSAF note type verification
- `dev/plans/2026-03-05-vendor-feed-adapters-design.md` — design decisions on field mapping

**Exploration strategy:** Started with the merge pipeline (cross-package orchestrator, highest blast radius), then followed threads into advisory lock ordering, cursor lifecycle across all adapters, CSAF field mapping completeness, and vendor enrichment data flow through PK migration paths.

## Bugs

### 1. Advisory lock ordering does not match comment — theoretical deadlock

**Location:** `internal/merge/pipeline.go:85-94`
**Severity:** minor

**Evidence:** The comment at line 85–86 states:

> Lock the old CVE ID too — prevents concurrent writers for the old ID from racing with the migration. Lock order is deterministic (lower key first) to prevent deadlocks.

But the code always acquires `newKey` first (step 1, line 64) then `oldKey` (line 91), regardless of their relative values:

```go
oldKey := CVEAdvisoryKey(oldCVEID)
newKey := CVEAdvisoryKey(patch.CVEID)
if oldKey != newKey {
    // newKey is already held (step 1). Only acquire oldKey if different.
    if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", oldKey); err != nil {
```

The actual order is "newKey first, then oldKey" — NOT "lower key first." This creates a deadlock scenario when two concurrent transactions perform PK migrations in opposite directions:

- TX1: locks newKey=A (step 1), then wants oldKey=B
- TX2: locks newKey=B (step 1), then wants oldKey=A
- Both hold the other's needed key → deadlock

**Impact:** Very low probability in practice — requires two concurrent PK migrations where each transaction's target CVE ID is the other's source ID (e.g., two GHSA aliases that cross-reference each other). PostgreSQL's deadlock detector would resolve it by aborting one transaction with a "deadlock detected" error, so the system doesn't hang permanently. But the aborted transaction would need retry logic to recover.

**Fix:** The code can't easily enforce "lower key first" because `newKey` is acquired in step 1 before the PK migration check. The fix requires restructuring: move the migration check before step 1, then acquire all needed locks in sorted order. Since `pg_advisory_xact_lock` can't be released mid-transaction, both locks must be planned upfront.

## Design Concerns

### MSRC exploitability not mapped to canonical ExploitAvailable flag

**Location:** `internal/feed/msrc/adapter.go:220-225`

MSRC's `threats[category=exploit_status]` is stored in vendor enrichment JSONB (`enrichment.exploitability`) but NOT mapped to `CanonicalPatch.ExploitAvailable`. The design doc (`dev/plans/2026-03-05-vendor-feed-adapters-design.md:241`) explicitly chose this — MSRC exploitability is multi-valued ("Exploitation Detected", "Exploitation More Likely", "Exploitation Less Likely", "Exploitation Unlikely"), not a boolean.

However, this means a CVE with MSRC's "Exploitation Detected" status will have `cves.exploit_available = false` unless KEV also lists it. Alert rules using `exploit_available = true` won't fire for MSRC-only exploit detections. For less well-known exploits that MSRC detects before CISA adds them to KEV, this creates a gap in alert coverage.

Worth considering: when MSRC exploitability equals "Exploitation Detected", also set `ExploitAvailable = true` on the CanonicalPatch.

### `append(globalVar, ...)` pattern in resolve.go is fragile

**Location:** `internal/merge/resolve.go:139, 153, 236`

The code uses `append(cvssPriority, otherSources(patches, cvssPriority)...)` where `cvssPriority` is a package-level `var`. This is currently safe because the slice literal initializer sets `len == cap`, forcing `append` to allocate a new backing array. But if anyone later modifies the global slice (e.g., `cvssPriority = append(cvssPriority, newSource)` in init or test setup), subsequent `append` calls would corrupt the global due to shared backing array.

Safer pattern: copy the slice before appending, or use `slices.Concat` (Go 1.22+).

### CSAF ProductStatus only handles 3 of 8 status types

**Location:** `internal/feed/csaf/parser.go:124-128`

The CSAF 2.0 `product_status` object supports 8 status types: `known_affected`, `known_not_affected`, `fixed`, `first_affected`, `first_fixed`, `last_affected`, `recommended`, `under_investigation`. The parser only deserializes three.

For MSRC, `known_affected` is the primary status type used, so this is adequate today. But if MSRC (or a future CSAF adapter like ICS-CERT) uses `first_affected` or `under_investigation`, those products would be silently dropped from the affected products list.
