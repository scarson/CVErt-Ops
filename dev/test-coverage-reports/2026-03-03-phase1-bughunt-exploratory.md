# Bug Hunt Report

## Scope

**Packages analyzed:** `internal/feed/...`, `internal/merge/...`, `internal/worker/...`

**Deep-dive files (chosen by risk):**
1. `internal/merge/pipeline.go` — multi-step orchestrator with advisory locks, PK migration, and 10 sequential steps in a single transaction. Highest coordination complexity in Phase 1.
2. `internal/merge/resolve.go` — per-field precedence resolution across multiple sources; non-deterministic map iteration; deduplication logic.
3. `internal/feed/epss/adapter.go` — special two-statement EPSS pattern with advisory locks; coordinates with merge pipeline to prevent TOCTOU races.
4. `internal/feed/osv/adapter.go` — alias resolution, multi-event range parsing, ZIP streaming.
5. `internal/feed/ghsa/adapter.go` — alias resolution from multiple fields, streaming JSON parse.
6. `internal/feed/nvd/adapter.go` — windowed pagination, streaming parse, Date header parsing.
7. `internal/worker/pool.go` — goroutine lifecycle, context cancellation, stale recovery.
8. `internal/merge/hash.go` — material hash normalization and JCS canonicalization.

**Threads followed:**
- Advisory lock coordination between merge pipeline and EPSS adapter
- PK migration when OSV/GHSA aliases resolve to existing CVE IDs
- Tombstone ordering vs staged EPSS application
- Multi-event range parsing in OSV events arrays
- `ResolveCanonicalID` behavior with multiple CVE aliases
- NVD Date header parsing fallback chain
- Worker pool context cancellation and cleanup

## Bugs

### 1. migrateCVEPK fails when target CVE ID already exists in cves table

**Location:** `internal/merge/pipeline.go:352-378`
**Severity:** critical

**Evidence:** `migrateCVEPK` executes a sequence of `UPDATE ... SET cve_id = $2 WHERE cve_id = $1` statements to rename a CVE's primary key from an advisory ID (e.g., GHSA-xxxx) to a canonical CVE ID (e.g., CVE-2024-1234). These UPDATEs assume the target `cve_id` does not yet exist in any table.

When the target CVE ID already has a `cves` row (common — NVD typically publishes the CVE first), the migration fails at multiple points:

1. **`cve_references`** — `UNIQUE INDEX (cve_id, url_canonical)` (`migrations/000002:137-138`). NVD and GHSA/OSV frequently reference the same URLs (vendor advisories, GitHub commits). The UPDATE would produce duplicate `(newID, url_canonical)` rows, violating the constraint.

2. **`cve_affected_cpes`** — `UNIQUE INDEX (cve_id, cpe_normalized)` (`migrations/000002:178-179`). NVD-provided CPEs may overlap with OSV/GHSA CPEs.

3. **`cves`** — `PRIMARY KEY (cve_id)` (`migrations/000002:13`). The final `UPDATE cves SET cve_id = $2 WHERE cve_id = $1` always fails when a row for newID already exists.

The triggering scenario is routine:
1. NVD publishes CVE-2024-1234 → NVD adapter creates `cves(cve_id="CVE-2024-1234")`
2. OSV/GHSA publishes GHSA-xxxx without a CVE alias → adapter creates `cves(cve_id="GHSA-xxxx")`
3. Later, GHSA-xxxx gains CVE-2024-1234 as an alias
4. OSV re-ingests → `ResolveCanonicalID` returns "CVE-2024-1234" → `FindCVEBySourceID` finds old row under "GHSA-xxxx" → `migrateCVEPK("GHSA-xxxx", "CVE-2024-1234")` fails

**Impact:** The advisory enters a permanent failure loop — every ingest attempt triggers the same constraint violation. The GHSA/OSV data for that CVE is never merged into the canonical record. This affects any advisory that gains a CVE alias after initial ingest when that CVE already exists from another source. Given NVD's broad coverage, this is a common scenario for GHSA advisories published before their CVE IDs are assigned.

---

### 2. OSV extractPackageRange silently drops multi-event version ranges

**Location:** `internal/feed/osv/adapter.go:351-369`
**Severity:** significant

**Evidence:** The function iterates over all events in an OSV range and overwrites the `introduced`, `fixed`, and `lastAffected` variables on each match:

```go
for _, ev := range events {
    var obj map[string]string
    if err := json.Unmarshal(ev, &obj); err != nil { continue }
    if v, ok := obj["introduced"]; ok {
        introduced = strings.Clone(feed.StripNullBytes(v))
    }
    if v, ok := obj["fixed"]; ok {
        fixed = strings.Clone(feed.StripNullBytes(v))
    }
    // ...
}
```

OSV ranges commonly contain multiple introduced/fixed pairs representing discontinuous affected ranges:

```json
{"type": "SEMVER", "events": [
    {"introduced": "1.0.0"}, {"fixed": "1.2.3"},
    {"introduced": "2.0.0"}, {"fixed": "2.1.0"}
]}
```

After processing, only `introduced="2.0.0"` and `fixed="2.1.0"` survive. The `1.0.0–1.2.3` range is silently dropped.

**Impact:** The structured `Introduced`/`Fixed` fields in `AffectedPackage` only reflect the last event pair. This affects:
- The deduplication key in `resolve.go:241` (`pkg.Ecosystem + "\x00" + pkg.PackageName + "\x00" + pkg.Introduced`) — uses the wrong `Introduced` value
- The material hash via `buildAffectedPkgKeys` — hash reflects incomplete data, potentially missing material changes
- Any downstream consumer of the structured fields

The raw `Events` JSON is preserved (line 380), so the data isn't permanently lost, but the structured fields are wrong for any range with more than one event pair.

---

### 3. Staged EPSS score applied after tombstone, restoring NULLed field on withdrawn CVEs

**Location:** `internal/merge/pipeline.go:167-247` (step 7 at line 168, step 9 at line 230)
**Severity:** minor

**Evidence:** The pipeline executes steps in this order:
- Step 7 (line 168-172): `TombstoneCVE` sets `epss_score = NULL` for withdrawn CVEs
- Step 9 (line 230-247): `GetEPSSStaging` + `UpdateCVEEPSS` applies any staged EPSS score

If a staged EPSS score exists for a withdrawn CVE, step 9 restores a non-null `epss_score`, contradicting the tombstone's explicit NULL.

Scenario: EPSS adapter processes CVE-2024-1234 before the CVE is created → score goes to `epss_staging`. Later, MITRE publishes CVE-2024-1234 as REJECTED. During merge Ingest, step 7 tombstones (epss_score = NULL), then step 9 applies the staged score (epss_score = 0.03).

**Impact:** Withdrawn CVEs may have non-null EPSS scores until the next full EPSS refresh cycle. Low probability (requires EPSS to arrive before the CVE and the CVE to be withdrawn), but violates the tombstone design intent.

---

### 4. ResolveCanonicalID non-deterministic when advisory has multiple CVE aliases

**Location:** `internal/feed/util.go:67-74`
**Severity:** minor

**Evidence:** `ResolveCanonicalID` returns the first CVE ID match from the aliases slice:

```go
func ResolveCanonicalID(nativeID string, aliases []string) string {
    for _, alias := range aliases {
        if cveIDPattern.MatchString(alias) {
            return alias
        }
    }
    return nativeID
}
```

When an advisory has multiple CVE aliases (e.g., both CVE-2024-1234 and CVE-2024-5678), the function returns whichever appears first. OSV does not guarantee stable ordering of the `aliases` array across fetches.

**Impact:** If upstream alias ordering changes between syncs, the advisory flips canonical IDs, potentially creating split-brain records under different CVE IDs. Multiple CVE aliases per advisory is uncommon but happens — particularly for advisories that span multiple products or when CVE IDs are reassigned.

---

### 5. NVD Date header parsing always fails (dead fallback)

**Location:** `internal/feed/nvd/adapter.go:194-196`
**Severity:** minor

**Evidence:** The NVD adapter parses the HTTP `Date` response header as a clock-skew fallback:

```go
if dateStr := resp.Header.Get("Date"); dateStr != "" {
    nvdTime = feed.ParseTime(dateStr)
}
```

But `feed.ParseTime` only supports RFC3339 variants and `"2006-01-02"` layouts (`internal/feed/util.go:13-18`). The HTTP Date header uses RFC 7231 format: `Thu, 06 Nov 1997 08:49:37 GMT`. `feed.ParseTime` will always return zero for this format, making `nvdTimestamp` always zero.

The fallback chain at lines 129-135 then falls through to `time.Now().UTC()`, which the code was designed to avoid (the package doc says "Cursor upper bound from response JSON `timestamp` field (not time.Now())").

**Impact:** If the NVD response body ever omits its `timestamp` field, the adapter falls back to `time.Now().UTC()` instead of the NVD server's Date header — exactly the clock-skew scenario the fallback was designed to prevent. In practice, NVD always includes the body timestamp, so this path is currently dead. The fix is adding `time.RFC1123` to `timeLayouts`.

---

## Design Concerns

### Non-deterministic reference tag selection during merge

**Location:** `internal/merge/resolve.go:216-229`

The reference deduplication loop iterates over `patches` (a Go map) in non-deterministic order:

```go
for _, p := range patches {
    for _, ref := range p.References {
        canon := canonicalizeURL(ref.URL)
        if _, seen := refSeen[canon]; seen { continue }
        // ...
    }
}
```

When two sources provide a reference with the same canonical URL but different tags (e.g., NVD tags a URL as "Patch" while GHSA tags it as "ADVISORY"), whichever source is iterated first wins. The deduplicated set of URLs is deterministic, but the tag metadata per URL varies between runs.

The same pattern affects affected CPE deduplication (lines 252-267) — when two sources provide the same `cpe_normalized` but different original `CPE` strings, the stored `CPE` value is non-deterministic.

This doesn't cause data loss, but it means the same merge inputs can produce different stored rows across runs, which may trigger unnecessary IS DISTINCT FROM writes and confuse debugging.

### Worker pool context cancellation leaves jobs in "running" state

**Location:** `internal/worker/pool.go:136-148`

When the parent context is cancelled during handler execution, the handler returns `ctx.Err()`, and `processOne` calls `FailJob(ctx, ...)` with the already-cancelled context. The DB call in `FailJob` will likely fail, leaving the job stuck in "running" state. The stale recovery goroutine (`runStaleRecovery`) has also received `ctx.Done()` and is shutting down, so recovery only happens on the next process startup.

This is not a data corruption issue — stale recovery on restart handles it correctly — but causes unnecessary job re-execution after restarts. A dedicated cleanup context (e.g., `context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)`) for the FailJob call would improve graceful shutdown behavior.
