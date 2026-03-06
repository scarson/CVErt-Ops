# Bug Hunt Report — Vendor Feed Adapters (Multipass)

**Date:** 2026-03-06
**Status:** complete

## Scope

Files analyzed (source only — no test files read per skill rules):
- `internal/feed/msrc/adapter.go` (413 lines)
- `internal/feed/redhat/adapter.go` (495 lines)
- `internal/feed/csaf/parser.go` (178 lines)
- `internal/feed/interface.go` (106 lines)
- `internal/feed/kev/adapter.go` (315 lines)
- `internal/merge/pipeline.go` (471 lines)
- `internal/merge/resolve.go` (376 lines)
- `internal/store/queries/vendor_enrichment.sql` (24 lines)
- `internal/store/generated/vendor_enrichment.sql.go` (generated)
- `internal/store/generated/models.go` (generated)
- `migrations/000029_vendor_enrichment.up.sql` (44 lines)
- `migrations/000029_vendor_enrichment.down.sql` (11 lines)
- `internal/feed/util.go` (helper functions)

Reference files: `internal/feed/nvd/adapter.go` (canonical adapter pattern)

All five passes performed: Contract Violations, Cross-Sibling Pattern Violations, Failure Mode Reasoning, Concurrency Reasoning, Error Propagation.

## Bugs

### 1. Red Hat adapter never advances AfterDate cursor
**Location:** `internal/feed/redhat/adapter.go:469-485`
**Severity:** significant
**Evidence:** When the Red Hat adapter finishes processing all pages (last page has fewer than `listPageSize` entries), it returns `NextCursor = nil`. The cursor's `AfterDate` field is never updated to reflect the current sync position.

```go
// Red Hat: after last page, returns nil — AfterDate stays stale
if fullPage {
    next := Cursor{AfterDate: cur.AfterDate, Page: page + 1}
    nextCursor, err = json.Marshal(next)
    // ...
}
// else: nextCursor stays nil — no cursor for caller to persist
```

Compare with MSRC adapter (lines 336-348 and 394-398): even on the no-new-updates path, it always returns a non-nil NextCursor with `effectiveDate` advanced to the latest seen date. KEV also always returns non-nil NextCursor with the catalog version.

**Impact:** Every sync run re-processes all CVEs from the original `AfterDate` forward. The merge pipeline's IS DISTINCT FROM guards prevent duplicate DB writes, but the redundant HTTP calls (100+ detail fetches per run) waste bandwidth, increase latency, and risk upstream rate limiting. On a first-time sync with no AfterDate, every subsequent run does a full re-sync of the entire Red Hat CVE catalog.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

---

### 2. MSRC adapter silently drops CVSS score of 0.0
**Location:** `internal/feed/msrc/adapter.go:116,125`
**Severity:** minor
**Evidence:** The CVSS extraction loop uses `score.CVSSv3.BaseScore > bestV3Score` (line 116) where `bestV3Score` is initialized to `0`. A legitimate CVSS 0.0 score ("NONE" severity) fails the `> 0` guard on line 125. Same issue for v4 on lines 120 and 129.

```go
var bestV3Score float64  // initialized to 0
for _, score := range vuln.Scores {
    if score.CVSSv3 != nil && score.CVSSv3.BaseScore > bestV3Score {  // 0.0 > 0 is false
        bestV3Score = score.CVSSv3.BaseScore
    }
}
if bestV3Score > 0 {  // 0.0 > 0 is false — score dropped
    p.CVSSv3Score = &bestV3Score
}
```

Compare with NVD adapter (`applyNVDCVSS`, line 501) which checks `len(m.CVSSV31) > 0` and always sets the score if metric data exists, regardless of value.

**Impact:** CVEs with CVSS 0.0 from MSRC would have no CVSS data in the canonical record. Rare in practice (NONE severity is uncommon in MSRC advisories) but technically incorrect.
**Found in:** Pass 1 — Contract Violations

---

### 3. Red Hat detail responses not drained before Close
**Location:** `internal/feed/redhat/adapter.go:460-461`
**Severity:** minor
**Evidence:**
```go
detail, err := parseDetailResponse(io.LimitReader(resp.Body, maxDetailSize))
resp.Body.Close()
```
`parseDetailResponse` uses `json.NewDecoder(r).Decode(&detail)`, which reads only enough bytes to parse one JSON value. Remaining response bytes are left unread. `Close()` without draining prevents the HTTP connection from being returned to the transport's connection pool.

Compare with the non-200 error paths (lines 447, 455) which correctly drain with `io.Copy(io.Discard, resp.Body)` before Close.

**Impact:** Each of the 100+ detail fetches per Fetch call opens a new TCP connection instead of reusing one. Increases latency by TCP+TLS handshake overhead per request.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

---

### 4. MSRC /updates response body not drained on non-200
**Location:** `internal/feed/msrc/adapter.go:310-312`
**Severity:** minor
**Evidence:**
```go
if resp.StatusCode != http.StatusOK {
    return nil, fmt.Errorf("msrc: updates HTTP %d", resp.StatusCode)
}
```
The body is not drained before the deferred `Close()` fires. Compare with the CSAF non-200 path (line 374) which correctly drains:
```go
io.Copy(io.Discard, csafResp.Body)
csafResp.Body.Close()
```
**Impact:** On transient 5xx errors, the connection is dropped rather than reused. Minor since this is an error path.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

---

### 5. MSRC adapter silently swallows cursor marshal error on no-updates path
**Location:** `internal/feed/msrc/adapter.go:341`
**Severity:** minor
**Evidence:** On the no-new-updates short-circuit:
```go
nextCursorJSON, _ := json.Marshal(nextCursor)  // error discarded
```
Compare with the normal path (lines 400-402) which handles the error:
```go
nextCursorJSON, err := json.Marshal(nextCursor)
if err != nil {
    return nil, fmt.Errorf("msrc: marshal cursor: %w", err)
}
```
If marshal fails, `nextCursorJSON` is nil, signaling "no more pages" — the cursor is not persisted.

**Impact:** Extremely unlikely to trigger for a simple struct with string fields, but the inconsistent error handling could hide corruption if the Cursor struct evolves.
**Found in:** Pass 5 — Error Propagation

---

### 6. Red Hat error message double-prefixed
**Location:** `internal/feed/redhat/adapter.go:463` + `internal/feed/redhat/adapter.go:173`
**Severity:** minor
**Evidence:** `parseDetailResponse` wraps errors with `"redhat: parse detail: %w"` (line 173). The caller wraps again with `"redhat: parse detail %s: %w"` (line 463). Result:
```
redhat: parse detail CVE-2024-1234: redhat: parse detail: unexpected EOF
```
The `"redhat: parse detail"` prefix appears twice.

**Impact:** Redundant log noise. No functional impact.
**Found in:** Pass 5 — Error Propagation

---

## Design Concerns

### Neither MSRC nor Red Hat set `Severity` or `Status` on CanonicalPatch
Both new adapters populate CVSS scores but leave `patch.Severity` and `patch.Status` nil. NVD derives severity from `BaseSeverity` in CVSS data and sets status from `vulnStatus`. CSAF v3 data doesn't include a `BaseSeverity` field, and the Red Hat `ThreatSeverity` maps only to `VendorSeverity` in enrichment.

These adapters are low-priority in `statusPriority` and `cvssPriority` (positions 5-6), so they rarely win resolution. But for CVEs where MSRC or Red Hat is the sole source, the canonical record will have CVSS scores but no severity label and no status. Severity could be derived from the CVSS score using the standard CVSS-to-severity mapping (CVSS v3 spec Table 14).

### MSRC processes all pending releases in a single Fetch call
The MSRC adapter has no per-call limit on CSAF documents fetched. On initial backfill, every historical monthly release (~240+ documents × ~5MB each) would be fetched in a single Fetch call. NVD pages at 2000 results; Red Hat pages at 100; MSRC has no pagination boundary. In steady-state (monthly releases) this is 1-2 documents, but backfill could download >1GB.

### MSRC string-based date comparison for cursor advancement
`msrc/adapter.go:323-328` compares `CurrentReleaseDate` strings lexicographically. This works for ISO 8601 with consistent formatting but would silently mis-order dates if MSRC mixed `Z` and `+00:00` suffixes (ASCII `Z`=0x5A > `+`=0x2B). Parsing to `time.Time` would be more robust.

### Single CSAF document failure aborts entire MSRC Fetch
If one CSAF document out of N pending releases fails to parse (`msrc/adapter.go:387`), the entire Fetch returns an error with zero patches. The cursor is not advanced. On retry, all N documents are re-fetched — including the ones that previously succeeded. If the failing document is persistently malformed, no forward progress is possible. This is consistent with the NVD pattern (fail the whole page on error) but MSRC's multi-document fetch amplifies the blast radius.
