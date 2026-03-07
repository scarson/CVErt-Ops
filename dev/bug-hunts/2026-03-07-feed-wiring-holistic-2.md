# Bug Hunt Report — Feed Wiring Holistic Analysis (Round 2)

## Scope

Read all 21 source files in the feed wiring stack:
- Feed adapters: NVD, MITRE, KEV, GHSA, OSV, MSRC, Red Hat, EPSS
- Feed infrastructure: `feed/interface.go`, `feed/util.go`
- Ingest layer: `handler.go`, `epss.go`, `feeds.go`, `scheduler.go`
- Merge pipeline: `pipeline.go`
- Store layer: `feed.go`, `jobs.go`
- API layer: `feeds.go`, `middleware_site_admin.go`, `server.go`, `auth.go`
- Wiring: `cmd/cvert-ops/main.go`

Verified all 8 architectural invariants explicitly. Analyzed cross-cutting flows
for correctness: cursor lifecycle, pagination termination, error recovery,
lock coordination, queue dedup, and auth gating.

## Architectural Invariant Verification

| # | Invariant | Status | Evidence |
|---|-----------|--------|----------|
| 1 | EPSS advisory lock key matches merge pipeline | **PASS** | `epss/adapter.go:252` calls `merge.CVEAdvisoryKey(cveID)` directly |
| 2 | EPSS Apply never inspects RowsAffected | **PASS** | `epss/adapter.go:260-276` — both statements run unconditionally |
| 3 | Mid-page cursor persist does NOT set LastSuccessAt | **PASS** | `handler.go:125` passes `prevLastSuccess` (preserves old value) |
| 4 | Three-layer pagination termination | **PASS** | `handler.go:134-144` — LastPage, nil NextCursor, empty patches |
| 5 | Scheduler backoff check before not-due check | **PASS** | `scheduler.go:116` (backoff) before `scheduler.go:123` (not-due) |
| 6 | All feed adapters implement feed.Adapter | **PASS** | NVD, MITRE, KEV, GHSA, OSV, MSRC, Red Hat all have `Fetch()` |
| 7 | Admin endpoints require site_admin=true | **PASS** | `server.go:197-198` chains `RequireAuthenticated()` + `RequireSiteAdmin()` |
| 8 | Feed trigger uses lock_key dedup | **PASS** | Both `feeds.go:92` (API) and `scheduler.go:131` (scheduler) use `"feed:" + feedName`; `EnqueueJob` SQL has `ON CONFLICT (lock_key) WHERE status IN ('pending', 'running') DO NOTHING` |

## Bugs

### 1. Scheduler `NewSchedulerWithRegistry` has data race on global counter vars

**Location:** `ingest/scheduler.go:67-78`
**Severity:** minor (test-only; production creates one scheduler)
**Evidence:**

```go
func NewSchedulerWithRegistry(st SchedulerStore, reg prometheus.Registerer) *Scheduler {
    feedJobsEnqueued = promauto.With(reg).NewCounterVec(...)  // writes package-level var
    feedJobsSkipped = promauto.With(reg).NewCounterVec(...)   // writes package-level var
    return &Scheduler{...}
}
```

`feedJobsEnqueued` and `feedJobsSkipped` are package-level vars read by `maybeEnqueue` (line 143, 139, 117, 124) and written by `NewSchedulerWithRegistry`. If two test goroutines call `NewSchedulerWithRegistry` concurrently, or if one goroutine calls it while another scheduler is running `maybeEnqueue`, Go's race detector will flag this.

**Impact:** In tests using parallel subtests with isolated registries, this is a data race. In production, there's exactly one scheduler, so no issue. Fix: store counters as fields on the `Scheduler` struct instead of package-level vars.

### 2. NVD last-page cursor not advanced — causes redundant re-fetch on next run

**Location:** `ingest/handler.go:115-118` combined with `nvd/adapter.go:151-159`
**Severity:** minor (correctness preserved, idempotent merge handles duplicates)
**Evidence:**

When NVD exhausts all windows, `computeNextCursor` returns nil:
```go
// nvd/adapter.go:158
LastPage: nextCursorJSON == nil,  // true when all windows exhausted
```

In the handler:
```go
// handler.go:115-118
if result.NextCursor != nil {        // nil for NVD last page
    lastSuccessfulCursor = result.NextCursor  // NOT updated
}
cursor = result.NextCursor           // becomes nil
```

`lastSuccessfulCursor` retains the value from the penultimate Fetch call, which points at the last window's start+offset. On the next scheduler run, the adapter re-fetches that same page, finds 0 new results (time window overlap), and terminates via the empty-patches safety net.

**Impact:** One redundant API call to NVD per sync cycle after catching up. No data loss or corruption — the merge pipeline is idempotent. But it's unnecessary load on NVD's API, which has strict rate limits.

## Design Concerns

### MSRC document-level dates applied to all vulnerabilities in a CSAF document

**Location:** `msrc/adapter.go:146-147`

```go
p.DatePublished = feed.ParseTimePtr(doc.DocumentMeta.Tracking.InitialReleaseDate)
p.DateModified = feed.ParseTimePtr(doc.DocumentMeta.Tracking.CurrentReleaseDate)
```

All CVEs in a single CSAF document share the same DatePublished/DateModified. For Patch Tuesday releases with 100+ CVEs, every CVE gets the same modification timestamp. This means when ANY CVE in the document changes, re-fetching the document will re-merge ALL CVEs (though only changed ones will have new material hashes). This is a known limitation of the CSAF format — there are no per-vulnerability dates available.

### MSRC date comparison uses lexicographic string ordering

**Location:** `msrc/adapter.go:339`

```go
if cur.LastReleaseDate != "" && u.CurrentReleaseDate <= cur.LastReleaseDate {
    continue
}
```

This works correctly when dates are consistently formatted (ISO 8601 sorts lexicographically). If the MSRC API ever returns dates with varying precision (e.g., sometimes `2024-01-15` and sometimes `2024-01-15T00:00:00Z`), the comparison would silently produce wrong results. The `dateTimeRe` validator at line 38 constrains input format on the cursor side, but the API response side is unchecked.

### Job queue store methods bypass the `withBypassTx` convention

**Location:** `store/jobs.go:29,49,58,70,101`

All job queue store methods (`ClaimJob`, `CompleteJob`, `FailJob`, `RecoverStaleJobs`, `EnqueueJob`) use `s.q` directly instead of `withBypassTx`. The CLAUDE.md states "Never query `s.db` directly in store methods — always use a transaction helper." These are atomic single-statement operations on a non-RLS table, so correctness is preserved — but the pattern deviates from the documented convention. This appears to be an intentional exception (all job methods are consistent), but it should be explicitly documented as such.

### Red Hat adapter does not set DateModified

**Location:** `redhat/adapter.go:184-257`

`detailToPatch` sets `DatePublished` from `public_date` but does not set `DateModified`. The Red Hat API detail response doesn't have an explicit "last modified" field. This means Red Hat's contribution to `DateModifiedSourceMax` in the merge pipeline is always nil. If Red Hat is the only source that updates a CVE (e.g., severity change), `date_modified_source_max` won't reflect the change. The canonical `date_modified_canonical` is still bumped when `material_hash` changes, so alert evaluation is not affected — this is purely an informational field impact.