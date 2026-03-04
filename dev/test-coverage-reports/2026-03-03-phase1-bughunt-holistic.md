# Bug Hunt Report

## Scope

Packages analyzed:
- `internal/feed/` — interface.go, util.go
- `internal/feed/nvd/` — adapter.go (569 lines)
- `internal/feed/mitre/` — adapter.go (419 lines)
- `internal/feed/kev/` — adapter.go (300 lines)
- `internal/feed/osv/` — adapter.go (382 lines)
- `internal/feed/ghsa/` — adapter.go (449 lines)
- `internal/feed/epss/` — adapter.go (302 lines)
- `internal/merge/` — hash.go, advisory.go, resolve.go, fts.go, pipeline.go
- `internal/worker/` — job.go, pool.go

Also read: relevant SQL queries (`internal/store/queries/cves.sql`) and schema (`migrations/000002_create_cve_core.up.sql`) to verify assumptions about FK constraints and query correctness.

**Approach:** Read all source files into context, then examined cross-cutting concerns: interface contracts, concurrency coordination, data flow through the merge pipeline, and failure modes in each adapter.

## Bugs

### 1. migrateCVEPK crashes when target CVE ID already exists in `cves`

**Location:** [pipeline.go:352-378](internal/merge/pipeline.go#L352-L378)

**Severity:** significant

**Evidence:** `migrateCVEPK` executes `UPDATE cves SET cve_id = $2 WHERE cve_id = $1` as its final step. The `cves` table has `cve_id text PRIMARY KEY`. If the target CVE ID already exists (e.g., NVD already ingested CVE-2024-1234 before the alias was added to a GHSA/OSV advisory), this UPDATE violates the PK constraint and the transaction fails.

Concrete scenario:
1. NVD ingests CVE-2024-1234 → creates `cves` row with `cve_id = 'CVE-2024-1234'`
2. OSV ingests GHSA-xxxx (no CVE alias yet) → creates `cves` row with `cve_id = 'GHSA-xxxx'`
3. GHSA-xxxx later gains CVE-2024-1234 alias. Next OSV sync resolves `patch.CVEID = 'CVE-2024-1234'`, `patch.SourceID = 'GHSA-xxxx'`
4. `FindCVEBySourceID` finds `oldCVEID = 'GHSA-xxxx'` ≠ `patch.CVEID` → triggers migration
5. `UPDATE cves SET cve_id = 'CVE-2024-1234' WHERE cve_id = 'GHSA-xxxx'` → **PK violation** because `CVE-2024-1234` already exists

The same issue affects `cve_references` (unique index on `(cve_id, url_canonical)`) and `cve_affected_cpes` (unique index on `(cve_id, cpe_normalized)`) if both the old and new IDs have overlapping child data.

**Impact:** Any CVE that was first ingested under a native advisory ID (GHSA-*/PYSEC-*) and later gains a CVE alias will permanently fail to ingest from OSV/GHSA once the canonical CVE ID already exists in `cves` from NVD/MITRE. The error propagates up through `Ingest` and the transaction rolls back. Retries hit the same failure. The CVE's OSV/GHSA source data is never merged.

The correct approach would be: re-parent child rows to the target ID (handling conflicts via ON CONFLICT or DELETE+INSERT), delete the orphaned `cves` row, then proceed with the normal merge. The current code assumes the target `cve_id` is unused, which is only true when no other source has ingested that CVE yet.

---

### 2. migrateCVEPK does not acquire advisory lock on old CVE ID

**Location:** [pipeline.go:60-63](internal/merge/pipeline.go#L60-L63) (lock acquisition), [pipeline.go:72-85](internal/merge/pipeline.go#L72-L85) (migration trigger)

**Severity:** significant

**Evidence:** Step 1 acquires `pg_advisory_xact_lock(CVEAdvisoryKey(patch.CVEID))` — the lock key for the **new** canonical ID. Step 1.5 then mutates rows keyed by `oldCVEID` (the native advisory ID). No lock is acquired for `oldCVEID`.

A concurrent worker ingesting a different source for the same advisory under `oldCVEID` (before alias resolution) would acquire `pg_advisory_xact_lock(CVEAdvisoryKey("GHSA-xxxx"))` — a completely different lock key. Both transactions can execute concurrently, with one renaming rows that the other is actively reading or writing.

**Impact:** Race condition during PK migration. The concurrent writer could insert child rows under the old cve_id while the migration is renaming rows to the new cve_id, leaving orphaned data behind. The window is narrow (requires two workers processing the same advisory with different alias states simultaneously) but the consequence is data inconsistency in the `cves` corpus.

---

### 3. Bulk/single-file adapters violate Adapter.Fetch interface contract on NextCursor

**Location:** [mitre/adapter.go:128-138](internal/feed/mitre/adapter.go#L128-L138), [osv/adapter.go:120-132](internal/feed/osv/adapter.go#L120-L132), [kev/adapter.go:99-121](internal/feed/kev/adapter.go#L99-L121), [ghsa/adapter.go:131-143](internal/feed/ghsa/adapter.go#L131-L143)

**Severity:** significant

**Evidence:** The `Adapter` interface contract states ([interface.go:33](internal/feed/interface.go#L33)):
```
// NextCursor is the opaque cursor for the next Fetch call.
// Nil means no additional pages
```

MITRE, OSV, KEV, and GHSA adapters all return **non-nil** `NextCursor` from `Fetch` even though they have no additional pages. They use NextCursor to convey the updated sync state (new `last_modified` timestamp, new `catalog_version`, etc.) for the caller to persist.

A generic caller following the interface contract:
```go
for result.NextCursor != nil {
    result, _ = adapter.Fetch(ctx, result.NextCursor)
}
```
would loop infinitely. Each iteration re-downloads the full bulk archive (MITRE: ~200MB ZIP, OSV: ~100MB ZIP) or re-fetches the entire catalog (KEV, GHSA). Each call processes few or zero new entries but returns yet another non-nil NextCursor.

**Impact:** Any generic feed orchestrator that trusts the interface contract will loop forever. The comments say "The handler MUST NOT call Fetch again in a tight loop" — which means callers need adapter-specific knowledge to use these adapters correctly, defeating the purpose of a uniform interface. NVD is the only adapter that correctly returns nil when done.

---

### 4. NVD Date header clock-skew fallback is dead code

**Location:** [nvd/adapter.go:194-196](internal/feed/nvd/adapter.go#L194-L196), [util.go:13-18](internal/feed/util.go#L13-L18)

**Severity:** minor

**Evidence:** The NVD adapter parses the HTTP `Date` response header via `feed.ParseTime(dateStr)` as a fallback for clock-skew safety (lines 127-135). HTTP Date headers use RFC 1123 format: `Mon, 02 Jan 2006 15:04:05 GMT`. But `feed.ParseTime` only handles RFC3339Nano, RFC3339, `2006-01-02T15:04:05`, and `2006-01-02`. None match RFC 1123.

`feed.ParseTime` returns `time.Time{}` (zero) for every HTTP Date header. The fallback chain at lines 129-135 always skips `nvdTimestamp` because it's always zero, falling through to `time.Now().UTC()`.

**Impact:** The Date header clock-skew protection documented in the code doesn't function. If the NVD response body omits the `timestamp` field (which appears unlikely for normal responses but could happen on error paths), the adapter uses local clock time instead of NVD's server time. For normal operation this is a non-issue because `responseTimestamp` from the body is the primary source.

---

### 5. OSV extractPackageRange loses multi-pair event data in convenience fields

**Location:** [osv/adapter.go:351-369](internal/feed/osv/adapter.go#L351-L369)

**Severity:** minor

**Evidence:** The function iterates through all events in a range, overwriting `introduced`, `fixed`, and `lastAffected` variables on each match. For a range with multiple introduced/fixed pairs (e.g., `[{introduced: "1.0"}, {fixed: "1.2"}, {introduced: "2.0"}, {fixed: "2.3"}]`), only the last pair (`introduced: "2.0"`, `fixed: "2.3"`) is stored in the `AffectedPackage` convenience fields.

The raw events JSON is preserved in `Events: rng.Events` (line 380), so no data is lost from the database. However, the `Introduced` and `Fixed` fields flow into `buildAffectedPkgKeys` ([pipeline.go:309-319](internal/merge/pipeline.go#L309-L319)), which feeds the material hash computation. Changes to the first pair in a multi-pair range would not change the hash, so no alert would fire.

**Impact:** For the subset of OSV advisories using multi-pair ranges within a single range entry, material hash computation uses incomplete data. The raw JSON is preserved correctly in the database, but the alerting pipeline may miss material changes to earlier version ranges.

---

### 6. Worker pool goroutines have no panic recovery

**Location:** [pool.go:74-79](internal/worker/pool.go#L74-L79)

**Severity:** significant

**Evidence:** The queue goroutines launched in `Start` do not have `recover()`:
```go
go func(queue string) {
    defer wg.Done()
    p.runQueue(ctx, queue)
}(q)
```

If a `Handler` function panics (e.g., nil pointer dereference, index out of bounds in response parsing), the panic propagates through `processOne` → `runQueue` → the goroutine, killing it. `wg.Done()` is called by the defer, but the queue stops processing permanently. No new jobs are claimed from that queue for the lifetime of the process. The `Start` method's comment promises "any in-flight job completes" on shutdown, but a panicking handler crashes the queue goroutine immediately.

**Impact:** A single handler panic permanently disables one queue's processing. Since each queue (feed sync, alert evaluation, notification delivery) has exactly one polling goroutine, a panic in any handler silently stops that entire subsystem. The stale recovery goroutine would eventually reclaim the panicked job, but no goroutine remains to process it. The process continues running with a dead queue — no error is surfaced beyond the goroutine's panic stack trace.


## Design Concerns

### Advisory lock coverage gap during PK migration

The merge pipeline acquires a per-CVE advisory lock using `CVEAdvisoryKey(cveID)` ([advisory.go:33-35](internal/merge/advisory.go#L33-L35)). This correctly serializes concurrent writers for the **same** CVE ID. But PK migration operates across two different CVE IDs (old native ID → new canonical ID), and only the new ID's lock is held. The old ID's lock space is unprotected.

This is a structural issue — the advisory lock scheme assumes a 1:1 mapping between CVE IDs and lock keys. PK migration breaks that assumption by atomically changing a row's identity. A proper fix would need to acquire locks on both the old and new IDs, with a consistent ordering to prevent deadlocks (e.g., always lock the lexicographically smaller ID first).

### Interface contract ambiguity on NextCursor semantics

The `FetchResult.NextCursor` field serves two purposes: (1) pagination signal ("are there more pages?") and (2) sync state carrier ("what cursor should be persisted for next run?"). These are conflated into a single field. NVD uses purpose 1 (nil = done). MITRE/OSV/KEV/GHSA use purpose 2 (always non-nil to carry new sync state). GHSA uses both simultaneously (pages internally, returns non-nil for sync state).

A cleaner design would separate these: `NextPageCursor` for pagination and `SyncState` for persistence. Alternatively, have a `HasMore bool` field to decouple the pagination signal from the cursor value.
