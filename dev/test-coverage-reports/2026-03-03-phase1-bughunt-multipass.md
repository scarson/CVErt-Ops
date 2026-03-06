# Bug Hunt Report

## Scope
Packages analyzed: `internal/feed/...` (8 source files), `internal/merge/...` (5 source files), `internal/worker/...` (2 source files).

All five passes performed: Contract Violations, Cross-Sibling Pattern Violations, Failure Mode Reasoning, Concurrency Reasoning, Error Propagation.

## Bugs

### NVD Date header parsing always returns zero — dead code for clock-skew safety
**Location:** internal/feed/nvd/adapter.go:194-196
**Severity:** minor
**Evidence:** `feed.ParseTime(dateStr)` is called on the HTTP `Date` response header (RFC 1123 format, e.g., `"Tue, 25 Feb 2025 14:30:00 GMT"`). But `feed.ParseTime` (internal/feed/util.go:13-18) only recognizes RFC3339Nano, RFC3339, `"2006-01-02T15:04:05"`, and `"2006-01-02"`. None match RFC 1123. The parse always fails, returning `time.Time{}` (zero).

The fallback chain in Fetch (lines 129-135) is:
```
effectiveNow := responseTimestamp   // from response body "timestamp" field
if effectiveNow.IsZero() {
    effectiveNow = nvdTimestamp     // ← always zero (ParseTime can't parse HTTP Date)
}
if effectiveNow.IsZero() {
    effectiveNow = time.Now().UTC() // ← final fallback
}
```
The `nvdTimestamp` variable never holds a valid time. The middle fallback is dead code.

**Impact:** When the NVD response body's `timestamp` field is absent or unparseable, `effectiveNow` silently falls through to `time.Now().UTC()` instead of using the NVD server's clock via the `Date` header. This defeats the clock-skew safety the code explicitly implements. In practice, the response body timestamp is almost always present, so the impact is low — but the safety net doesn't exist.
**Found in:** Pass 1 — Contract Violations

---

### MITRE and KEV Fetch doc promises nil NextCursor but implementation returns non-nil
**Location:** internal/feed/mitre/adapter.go:66 vs :138; internal/feed/kev/adapter.go:62 vs :110-121
**Severity:** significant
**Evidence:** The MITRE Fetch godoc (line 66) states: *"NextCursor is always nil."* The KEV Fetch godoc (line 62) states: *"NextCursor is always nil."* But both implementations return a non-nil `NextCursor` carrying the new cursor state for persistence.

The `Adapter` interface (internal/feed/interface.go:33) defines: *"Nil means no additional pages; the caller should persist the cursor as the new sync state."* A caller following the interface contract would interpret non-nil NextCursor as "more pages exist" and keep calling Fetch in a loop.

The MITRE adapter even has contradictory inline comments — line 66 says "always nil" while lines 135-138 say "NextCursor carries the new last-modified timestamp."

**Impact:** Any generic feed handler that follows the standard pagination loop `for result.NextCursor != nil { result = adapter.Fetch(ctx, result.NextCursor) }` would loop infinitely on MITRE, KEV, OSV, and GHSA adapters (all return non-nil NextCursor when done). Only the NVD adapter correctly returns nil when exhausted. The current code may work if the handler special-cases these adapters, but the contract is broken.
**Found in:** Pass 1 — Contract Violations

---

### OSV extractPackageRange silently drops all but the last event pair in a range
**Location:** internal/feed/osv/adapter.go:355-369
**Severity:** significant
**Evidence:** The events loop iterates all events in a single OSV range:
```go
for _, ev := range events {
    if v, ok := obj["introduced"]; ok {
        introduced = strings.Clone(...)  // overwrites previous value
    }
    if v, ok := obj["fixed"]; ok {
        fixed = strings.Clone(...)        // overwrites previous value
    }
}
```
An OSV range commonly contains multiple introduced/fixed pairs to express complex affected version sets. For example:
```json
{"events": [{"introduced":"0"}, {"fixed":"1.2.3"}, {"introduced":"2.0.0"}, {"fixed":"2.0.1"}]}
```
After the loop: `introduced="2.0.0"`, `fixed="2.0.1"` — the range 0→1.2.3 is lost.

The raw `Events` JSON is preserved in `AffectedPackage.Events`, so downstream consumers parsing the raw events would see all pairs. But the structured `Introduced` and `Fixed` fields reflect only the last pair.

**Impact:** For CVEs with multi-range version constraints, the extracted `Introduced` and `Fixed` fields are silently wrong. The material hash (which uses `Introduced` and `Fixed` from `affectedPkgKey`) is computed from the wrong data, so material change detection may miss or falsely trigger on real changes to the first range pair. Downstream consumers relying on the structured fields get incomplete version information.
**Found in:** Pass 1 — Contract Violations

---

### PK migration fails when target CVE ID already exists
**Location:** internal/merge/pipeline.go:352-378 (migrateCVEPK)
**Severity:** critical
**Evidence:** `migrateCVEPK` renames a CVE's primary key from oldID to newID by running UPDATE statements across all tables. It does not handle the case where a row with newID already exists.

Common production scenario:
1. NVD ingests CVE-2024-1234 → creates `cves(cve_id='CVE-2024-1234')` with references and CPEs
2. GHSA ingests GHSA-xxxx without CVE alias → creates `cves(cve_id='GHSA-xxxx')` with its own references
3. GHSA updates GHSA-xxxx, adds alias `CVE-2024-1234`
4. Next GHSA sync: `migrateCVEPK("GHSA-xxxx", "CVE-2024-1234")` runs:
   - `UPDATE cve_references SET cve_id = 'CVE-2024-1234' WHERE cve_id = 'GHSA-xxxx'`
     → **UNIQUE constraint violation** on `(cve_id, url_canonical)` for any reference URL shared between both records (e.g., the NVD page for CVE-2024-1234)
   - `UPDATE cve_affected_cpes SET cve_id = 'CVE-2024-1234' WHERE cve_id = 'GHSA-xxxx'`
     → **UNIQUE constraint violation** on `(cve_id, cpe_normalized)` for any shared CPE
   - `UPDATE cves SET cve_id = 'CVE-2024-1234' WHERE cve_id = 'GHSA-xxxx'`
     → **PRIMARY KEY violation** because CVE-2024-1234 already exists

Schema evidence: `cve_references` has `UNIQUE(cve_id, url_canonical)` (migration 000002, line 137). `cve_affected_cpes` has `UNIQUE(cve_id, cpe_normalized)` (line 178). `cves` has `PRIMARY KEY(cve_id)` (line 13).

The transaction rolls back cleanly (no orphaned state), but the operation fails permanently — every subsequent sync attempt hits the same constraint violation.

**Impact:** Any GHSA or OSV advisory that gains a CVE alias after its initial ingest — when a cves row already exists for that CVE ID from NVD/MITRE — triggers a permanent sync failure for that CVE. The advisory cannot be properly merged. This is a common scenario: many GHSA advisories initially lack CVE aliases and gain them days or weeks after initial publication.
**Found in:** Pass 3 — Failure Mode Reasoning

---

### MITRE and GHSA adapters reject valid zero CVSS base scores
**Location:** internal/feed/mitre/adapter.go:377-380; internal/feed/ghsa/adapter.go:364,371
**Severity:** minor
**Evidence:** MITRE checks `m.CVSSV31.BaseScore > 0` (line 377) and GHSA checks `v4.Score > 0` (line 364), `v3.Score > 0` (line 371). CVSS v3.x base scores range from 0.0 to 10.0 per the CVSS specification, and 0.0 is a valid (if rare) score. The NVD adapter does NOT filter on `> 0` and correctly accepts zero scores.

This is a cross-sibling pattern violation: two of three CVSS-handling adapters silently drop valid zero scores while one (NVD) does not.

**Impact:** Extremely low in practice — a CVSS base score of exactly 0.0 is near-theoretical. Since NVD has the highest CVSS precedence and handles zero correctly, the canonical CVE would still get the right score. But if NVD lacks a score and MITRE/GHSA has a legitimate 0.0, it would be silently dropped.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

---

## Design Concerns

### Adapter interface NextCursor contract is ambiguous and violated by 4 of 5 adapters
The `FetchResult.NextCursor` comment (internal/feed/interface.go:33) states: *"Nil means no additional pages."* This implies non-nil means more pages exist. But MITRE, KEV, OSV, and GHSA all return non-nil NextCursor when there are no more pages — they repurpose it to carry the cursor state for persistence. Only NVD follows the interface literally (returns nil when done).

Any generic pagination loop (`while NextCursor != nil, keep fetching`) would loop infinitely on 4 of 5 adapters. The interface contract needs to be clarified: either (a) all adapters should return nil when done and communicate cursor state through SourceMeta, or (b) the interface comment should explain that non-nil NextCursor does not imply more pages.

### Silent data loss when upstream feed schema changes break JSON decode
All feed adapters (NVD, MITRE, OSV, GHSA) silently `continue` past decode errors on individual records with no logging (e.g., internal/feed/nvd/adapter.go:392-394). If an upstream feed changes its JSON schema in a breaking way, all records would fail to decode. The adapter would return an empty patches slice with no error. The cursor would advance past the data window, and the missed records would never be retried.

Adding slog.Warn on decode failures and/or checking `len(patches) == 0 && totalResults > 0` (for NVD) would provide early detection.

### Worker pool cancels in-flight jobs during shutdown
The `Pool.Start` doc (internal/worker/pool.go:63) says *"any in-flight job completes"* during shutdown. But the implementation passes the cancellable `ctx` to handlers. When ctx is cancelled, in-flight database operations fail, the handler returns an error, and the job is left in 'running' state for stale recovery (5-minute delay). Using `context.WithoutCancel` for in-flight job execution would match the documented behavior.

### EPSS rate limiter blocks retries for 24 hours after partial failure
The EPSS adapter rate limiter (`rate.Every(24*time.Hour)`, burst 1) prevents immediate retry after a partial failure. If row 200,001 of 250,000 fails, the cursor isn't updated, and the retry attempt blocks on the rate limiter for ~24 hours. Previously committed rows are safe (idempotent writes), but the scoring gap persists until the rate limiter token replenishes.

### resolve() silently swallows all source JSON parse errors
`resolve()` (internal/merge/resolve.go:87-89) catches `json.Unmarshal` errors on `normalized_json` with `continue` — no logging. If all sources for a CVE somehow have malformed JSON, resolve returns an empty `ResolvedCVE` with zero values, and `Ingest` writes a nearly-empty canonical CVE. In practice, `normalized_json` is machine-generated by `json.Marshal` so this is unlikely, but a slog.Warn on unmarshal failure would aid debugging.

