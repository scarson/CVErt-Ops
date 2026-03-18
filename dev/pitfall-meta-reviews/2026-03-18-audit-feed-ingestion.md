# Pitfall Audit: Feed & Ingestion

**Date:** 2026-03-18
**Auditor:** audit-feed agent (Explore)
**Scope:** 17 pitfalls across feed adapters, ingestion, merge pipeline
**Code paths:** `internal/feed/*`, `internal/ingest/*`, `internal/merge/*`, `cmd/cvert-ops/`

---

## Summary Table

| ID | Title | Status | Evidence |
|---|---|---|---|
| 1.1 | JSON Wire Format (Token+More) | VALIDATED | `feed/nvd/adapter.go:350-431` |
| 1.2 | archive/zip Seekable Reader | VALIDATED | `feed/osv/adapter.go:84`, `feed/mitre/adapter.go:84` |
| 1.6 | Timestamp Fallback Parser | VALIDATED | `feed/util.go:18-41` |
| 1.7 | Polymorphic JSON Fields | NOT NEEDED | YAGNI — feeds are spec-compliant; pattern available if needed |
| 1.8 | defer in ZIP Loop | VALIDATED | `feed/osv/adapter.go:150-151`, `feed/mitre/adapter.go:160-161` |
| 1.9 | URL Query + Encoding | VALIDATED | `feed/nvd/adapter.go:173-187` |
| 1.10 | OSV FileHeader Pre-filter | VALIDATED | `feed/osv/adapter.go:108-111`, `feed/mitre/adapter.go:108-113` |
| 7.1 | NVD API Key Header | VALIDATED | `feed/nvd/adapter.go:169-171` |
| 7.2 | NVD Overlap Cursor Gap | VALIDATED | `feed/nvd/adapter.go:251`, overlapDuration=15min at line 50 |
| 7.3 | NVD Cursor Upper Bound | VALIDATED | `feed/nvd/adapter.go:194-198` (Date header extraction) |
| 7.4 | Withdrawn Field Check | VALIDATED | `feed/osv/adapter.go:245-247`, `feed/ghsa/adapter.go:354-359` |
| 7.5 | Late-binding Alias PK Migration | VALIDATED | `merge/pipeline.go:67-97`, `feed/util.go:191-203` |
| 7.6 | GHSA Rate Limiting | VALIDATED | `feed/ghsa/adapter.go:84-87` (1 req/sec) |
| 5.2 | Bulk Import Required | UNIMPLEMENTED | CLI stub at `cmd/cvert-ops/main.go:671-678` — Phase 2 |
| 5.3 | NVD 120-Day Window | VALIDATED | `feed/nvd/adapter.go:47,234-272` |
| 5.4 | NVD Dual Rate Limits | VALIDATED | `feed/nvd/adapter.go:74-87` (0.6s w/key, 6s without) |
| 5.13 | OSV/GHSA Native IDs as PKs | VALIDATED | `feed/util.go:191-203` (ResolveCanonicalID) |

**Totals:** 15 VALIDATED, 1 UNIMPLEMENTED (expected Phase 2), 1 NOT NEEDED (YAGNI)

---

## Detailed Findings

### 1.1 JSON Feed Wire Format Assumption
**Status:** VALIDATED
**Evidence:** `internal/feed/nvd/adapter.go:350-431` (parseNVDResponse)
**All instances checked:** NVD streaming (lines 360-420), GHSA top-level array (ghsa/adapter.go:200-207)
**Notes:** Correctly navigates top-level JSON object using Token(), finds "vulnerabilities" key, consumes '[' and ']' explicitly, never uses Decode(&slice). GHSA uses a different pattern (paginated GraphQL) but also avoids Decode(&slice).

### 1.2 archive/zip Requires Seekable Reader
**Status:** VALIDATED
**Evidence:** `internal/feed/osv/adapter.go:84`, `internal/feed/mitre/adapter.go:84` (DownloadToTemp)
**All instances checked:** OSV (lines 84-96), MITRE (lines 84-96)
**Notes:** All ZIP-based adapters use DownloadToTemp to temp file first, then pass os.File to zip.NewReader. No io.ReadAll into memory anywhere.

### 1.6 Custom Timestamp Fallback Parser
**Status:** VALIDATED
**Evidence:** `internal/feed/util.go:18-41` (ParseTime, ParseTimePtr)
**All instances checked:** Used in all adapters (NVD, MITRE, OSV, GHSA feed.ParseTime calls throughout)
**Notes:** Multi-layout parser with graceful zero-value return. Layouts: RFC3339Nano, RFC3339, ISO date-time (no tz), date only, RFC1123, RFC1123Z.

### 1.7 Polymorphic JSON Field Type Variance
**Status:** NOT NEEDED
**Evidence:** No json.RawMessage dispatch pattern found in feed adapters
**Notes:** Feed data in current adapters appears spec-compliant. Pattern available in feed/util.go if encountered. Correct YAGNI decision.

### 1.8 defer Inside Loop Exhausts File Descriptors
**Status:** VALIDATED
**Evidence:** `internal/feed/osv/adapter.go:150-151`, `internal/feed/mitre/adapter.go:160-161`
**All instances checked:** OSV parseEntry (line 150), MITRE parseEntry (line 161)
**Notes:** Both use explicit `_ = rc.Close()` with comments warning against defer in loops.

### 1.9 URL Query + Parsed as Space
**Status:** VALIDATED
**Evidence:** `internal/feed/nvd/adapter.go:173-187` (doRequest)
**All instances checked:** NVD timestamp encoding (lines 182, 185), GHSA query encoding (ghsa/adapter.go:166)
**Notes:** url.Values.Encode() used. Timestamp format uses 'Z' suffix to avoid '+' entirely.

### 1.10 OSV ZIP FileHeader Pre-filter
**Status:** VALIDATED
**Evidence:** `internal/feed/osv/adapter.go:108-111`, `internal/feed/mitre/adapter.go:108-113`
**All instances checked:** OSV pre-filter (lines 109-110), MITRE pre-filter (lines 111-112)
**Notes:** Checks entry.FileHeader.Modified.After(lastCursor) BEFORE calling entry.Open().

### 7.1 NVD API Key Header
**Status:** VALIDATED
**Evidence:** `internal/feed/nvd/adapter.go:169-171`
**Notes:** Exact case-sensitive `req.Header.Set("apiKey", a.apiKey)` with nolint comment.

### 7.2 NVD Overlapping Cursor Gap
**Status:** VALIDATED
**Evidence:** `internal/feed/nvd/adapter.go:251`
**Notes:** `nextWindowStart := cur.WindowEnd.Add(-overlapDuration)` where overlapDuration = 15min. Also in GHSA adapter with same 15-minute overlap.

### 7.3 NVD Cursor Upper Bound from time.Now() Drift
**Status:** VALIDATED
**Evidence:** `internal/feed/nvd/adapter.go:194-198`
**Notes:** Extracts Date response header, uses as effectiveNow fallback. Priority: responseTimestamp (JSON) > Date header > time.Now().

### 7.4 OSV/GHSA Withdrawn Field Not Checked
**Status:** VALIDATED
**Evidence:** `internal/feed/osv/adapter.go:245-247`, `internal/feed/ghsa/adapter.go:354-359`
**Notes:** Both check withdrawn field, set patch.IsWithdrawn + patch.Status = "withdrawn". Merge Step 7 tombstones withdrawn CVEs.

### 7.5 Late-binding Alias Split-brain
**Status:** VALIDATED
**Evidence:** `internal/merge/pipeline.go:67-97` (Step 1.5), `internal/feed/util.go:191-203`
**Notes:** Two-part: ResolveCanonicalID() selects CVE ID from aliases, migrateCVEPK() performs atomic PK rename. Used in OSV (line 234) and GHSA (line 347).

### 7.6 GHSA Rate Limiting
**Status:** VALIDATED
**Evidence:** `internal/feed/ghsa/adapter.go:84-87`
**Notes:** 1 req/sec rate limiter. Well below 5,000 req/hr limit. No Retry-After handling needed at this rate.

### 5.2 Bulk Import Required
**Status:** UNIMPLEMENTED (expected)
**Evidence:** `cmd/cvert-ops/main.go:671-678`
**Notes:** CLI stub exists: "import-bulk not yet implemented — coming in Phase 2". Documented and on roadmap.

### 5.3 NVD 120-Day Query Window
**Status:** VALIDATED
**Evidence:** `internal/feed/nvd/adapter.go:47,234-272`
**Notes:** Hard-coded windowMax = 120 days. Chunking logic ensures windows ≤ 120 days.

### 5.4 NVD Dual Rate Limits
**Status:** VALIDATED
**Evidence:** `internal/feed/nvd/adapter.go:74-87`
**Notes:** With API key: 0.6s/req. Without: 6s/req. Dynamic at adapter init.

### 5.13 OSV/GHSA Native IDs as PKs
**Status:** VALIDATED
**Evidence:** `internal/feed/util.go:191-203` (ResolveCanonicalID)
**Notes:** Checks aliases for CVE ID, returns as canonical PK. Native ID stored as source_id. Called in both OSV and GHSA adapters.

---

## Cross-Cutting Observations

1. **Null byte handling (2.10):** Properly implemented across feed layer — StripNullBytes() on strings, bytes.ReplaceAll on raw payloads
2. **Array sorting for hash determinism (11.5):** CWE IDs, CPEs, affected packages all sorted in hash.go
3. **IS DISTINCT FROM guards:** Present in merge pipeline SQL for cve_sources, cves, search index upserts
4. **EPSS staging lifecycle (2.7):** Fully implemented — GetEPSSStaging + UpdateCVEEPSS + DeleteEPSSStaging
5. **Material hash excludes EPSS:** Confirmed in hash.go MaterialFields struct
6. **Advisory lock sharing:** EPSS and merge share advisoryKey domain "cve"

## New Discoveries

None — the feed ingestion layer appears comprehensively covered by existing pitfalls.

---

## Assessment

The feed & ingestion implementation is **production-ready**. All critical pitfalls addressed. The two gaps (bulk import stub, polymorphic fields) are expected/YAGNI respectively.
