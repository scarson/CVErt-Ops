# Bug Hunt Report — Vendor Feed Adapters (Holistic)

**Date:** 2026-03-06
**Skill:** `code-bug-hunter-holistic`
**Status:** complete

## Scope

Read all 11 source files in the vendor feed adapter implementation across the `feature/vendor-feed-adapters` worktree:

- `internal/feed/interface.go` — CanonicalPatch + VendorEnrichment types
- `internal/feed/csaf/parser.go` — shared CSAF 2.0 parser
- `internal/feed/msrc/adapter.go` — MSRC CSAF feed adapter
- `internal/feed/redhat/adapter.go` — Red Hat Security Data API adapter
- `internal/feed/kev/adapter.go` — KEV adapter (vendor enrichment retrofit)
- `internal/merge/pipeline.go` — merge pipeline (vendor enrichment upsert step)
- `internal/merge/resolve.go` — field resolution with source priority
- `internal/store/queries/vendor_enrichment.sql` — sqlc upsert query
- `internal/store/generated/vendor_enrichment.sql.go` — generated sqlc code
- `internal/store/generated/models.go` — generated models
- `migrations/000029_vendor_enrichment.up.sql` — schema migration

Also read the NVD adapter, design doc, and feed utility functions as reference.

**Approach:** loaded all source files into context, then traced data flow end-to-end: adapter → CanonicalPatch → merge pipeline → database. Focused on cross-cutting patterns, sanitization consistency, and contract adherence.

## Bugs

### 1. KEV enrichment data bypasses null-byte sanitization

**Location:** `internal/feed/kev/adapter.go:281-288`
**Severity:** significant

**Evidence:** The KEV adapter marshals enrichment data from raw record fields without calling `feed.StripNullBytes()`:

```go
enrichmentData, err := json.Marshal(map[string]any{
    "required_action": rec.RequiredAction,   // NOT stripped
    "due_date":        rec.DueDate,           // NOT stripped
    "ransomware_use":  rec.KnownRansomwareCampaignUse == "Known",
    "vendor_project":  rec.VendorProject,     // NOT stripped
    "product":         rec.Product,           // NOT stripped
    "notes":           rec.Notes,             // NOT stripped
})
```

Compare with the MSRC adapter (`adapter.go:222-248`) and Red Hat adapter (`adapter.go:283-325`), which `feed.StripNullBytes()` every string before marshaling enrichment data. The KEV adapter strips standard CanonicalPatch fields (CVEID at line 256, ShortDescription at line 273) but does NOT strip the enrichment data fields.

If the KEV JSON feed contains a null byte (`\u0000`) in any of these fields, `json.Marshal` preserves it as `\u0000` in the output. This reaches `cve_vendor_enrichment.enrichment` (JSONB column) via `pipeline.go:249`, where Postgres rejects it — JSONB does not accept `\u0000`.

**Impact:** A null byte in any KEV enrichment field causes the entire merge transaction to fail for that CVE, silently preventing ingestion.

### 2. Merge pipeline does not sanitize vendor enrichment JSONB

**Location:** `internal/merge/pipeline.go:244-257`
**Severity:** minor (defense-in-depth gap)

**Evidence:** The merge pipeline strips null bytes from `normalizedJSON` (line 51) and `rawPayload` (line 53), but the vendor enrichment data goes directly to the database without sanitization:

```go
if patch.VendorEnrichment != nil {
    enrichmentJSON := patch.VendorEnrichment.Data  // NOT stripped
    if enrichmentJSON == nil {
        enrichmentJSON = json.RawMessage(`{}`)
    }
    if err := q.UpsertVendorEnrichment(ctx, generated.UpsertVendorEnrichmentParams{
        ...
        Enrichment: enrichmentJSON,  // directly to Postgres JSONB
    })
```

The pipeline relies entirely on adapter-side sanitization. MSRC and Red Hat adapters do sanitize correctly, but KEV does not (bug #1 above). Even if bug #1 is fixed, the pipeline lacks the defense-in-depth pattern it applies to `normalizedJSON` and `rawPayload`.

**Impact:** Any adapter that fails to strip null bytes from enrichment data will cause a Postgres error. The pipeline should be the last line of defense, consistent with how it handles `normalizedJSON`.

### 3. MSRC adapter drops CVSS base score of 0.0

**Location:** `internal/feed/msrc/adapter.go:125-133`
**Severity:** minor

**Evidence:** The "best score" selection uses `> 0` as the threshold:

```go
if bestV3Score > 0 {
    p.CVSSv3Score = &bestV3Score
    vec := strings.Clone(feed.StripNullBytes(bestV3Vector))
    p.CVSSv3Vector = &vec
}
if bestV4Score > 0 {
    p.CVSSv4Score = &bestV4Score
    ...
```

`bestV3Score` is initialized to `0`. The selection loop uses `score.CVSSv3.BaseScore > bestV3Score` (line 116). A legitimate CVSS base score of 0.0 would fail both the selection check (0.0 is not > 0.0) and the emission check (0.0 is not > 0). The vector string associated with a 0.0 score is also silently dropped.

CVSS 0.0 is valid per the specification — it represents a vulnerability with no impact (e.g., informational or when all impact metrics are "None").

**Impact:** A CVE with a legitimate CVSS 0.0 score from MSRC would have no CVSS data in the canonical record, unless another source (NVD, GHSA) provides it. Practically rare — CVSS 0.0 is extremely uncommon in MSRC data — but the pattern differs from how other adapters handle this (NVD checks `CVSSv3Score == nil`, which correctly handles 0.0).

## Design Concerns

### Lock ordering comment is misleading in migrateCVEPK

**Location:** `internal/merge/pipeline.go:86-93`

The comment says "Lock order is deterministic (lower key first) to prevent deadlocks" but the code does not implement ordered locking. It always acquires `newKey` first (from step 1, line 64) then `oldKey` (line 91), regardless of which has a lower advisory lock key value:

```go
oldKey := CVEAdvisoryKey(oldCVEID)
newKey := CVEAdvisoryKey(patch.CVEID)
if oldKey != newKey {
    // newKey is already held (step 1). Only acquire oldKey if different.
    if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", oldKey); err != nil {
```

In practice, migration is always from advisory-ID → CVE-ID (never the reverse), so the deadlock scenario requires two concurrent transactions migrating in opposite directions, which shouldn't occur. But the comment creates a false sense of safety — a future developer could introduce a reverse migration path and trust the "ordered locking" claim.

### MSRC document-level dates applied to all CVEs

**Location:** `internal/feed/msrc/adapter.go:137-138`

All CVEs within a CSAF document receive the same `DatePublished` and `DateModified` — the document's `tracking.initial_release_date` and `tracking.current_release_date`. A March 2026 monthly release could contain CVEs first published in January 2026, which would receive an incorrect `DatePublished`.

This is a fundamental limitation of the CSAF format (no per-vulnerability dates), not a code defect. The merge pipeline's "earliest DatePublished across all sources" resolution (resolve.go:129-136) mitigates this when NVD or MITRE provide the per-CVE date. But for CVEs only present in MSRC, the date will be wrong.
