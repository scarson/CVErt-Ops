# FIRST.org EPSS — Research Findings

> **Researched:** 2026-02-25
> **Agent:** feed-researcher (aa949c0) — relied on training data (web access uncertain); key URLs verified via `curl` (see verification notes)
> **Sources:** Live verification via `curl -s -L` + `gunzip -c | head -3`

---

## CRITICAL: Domain Change Verified

The research brief cited `epss.cyentia.com` — this domain now **redirects (HTTP 301)** to:

**`https://epss.empiricalsecurity.com/`**

Both old and new domains work (Go's HTTP client follows redirects automatically), but the canonical URL to use in the adapter is the new domain. Verified 2026-02-25.

## API Overview

EPSS exposes two access methods: a daily bulk CSV download (primary ingest path) and a per-CVE JSON query API (not needed for bulk ingest).

**Bulk CSV (primary — use this)**
- **Current file:** `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`
- **Dated file:** `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz`
- `current` redirects (HTTP 302) to today's dated file — Go's default HTTP client follows this automatically
- Authentication: none
- Required headers: none

**JSON query API (per-CVE, not for bulk)**
- `https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXXX`

## Rate Limits

- No documented rate limit for the CDN-hosted bulk CSV
- One download per day is the expected usage pattern
- No inter-request delay needed beyond the once-per-day cadence
- Auth header: N/A

## CSV Format (live-verified 2026-02-25)

```
#model_version:v2025.03.14,score_date:2026-02-25T12:55:00Z    ← line 1: comment
cve,epss,percentile                                              ← line 2: column header
CVE-1999-0001,0.01025,0.76951                                    ← line 3+: data rows
CVE-1999-0002,0.00487,0.58234
...
```

**Critical details:**
- Line 1 starts with `#` — NOT a CSV header. Contains model version and score date.
- `score_date` is a **full RFC3339 timestamp** (`2026-02-25T12:55:00Z`), not just a date — parse with multi-layout parser
- Line 2 is the actual CSV header: `cve,epss,percentile`
- Columns: `cve` (string), `epss` (float string), `percentile` (float string)
- Delimiter: comma
- Compression: always gzip; no plain-text URL exists
- Size: ~250,000 rows as of 2026 (full daily snapshot of all scored CVEs)

## Parsing Line 1

```go
// line1 example: "#model_version:v2025.03.14,score_date:2026-02-25T12:55:00Z"
parts := strings.Split(strings.TrimPrefix(line1, "#"), ",")
// parts[0] = "model_version:v2025.03.14"
// parts[1] = "score_date:2026-02-25T12:55:00Z"
for _, part := range parts {
    if kv := strings.SplitN(part, ":", 2); len(kv) == 2 {
        switch kv[0] {
        case "score_date":
            asOfDate = feed.ParseTime(kv[1]) // returns time.Time
        }
    }
}
```

Note: `score_date` uses RFC3339 — the multi-layout parser handles it. The model version string (`v2025.03.14`) also contains colons, so parse conservatively.

## Timestamp Fields

| Field | Location | Format | Example |
|---|---|---|---|
| `score_date` | Line 1 comment | RFC3339 | `2026-02-25T12:55:00Z` |
| `model_version` | Line 1 comment | `vYYYY.MM.DD` | `v2025.03.14` |

No per-row timestamp. All rows share the single `score_date`.

## Incremental Sync

- **Cursor field:** `score_date` from line 1 (stored as `{"score_date": "2026-02-25T12:55:00Z"}`)
- **New file detection:** Compare stored cursor date against current UTC date; if different, download
- **No true incremental:** Full daily snapshot every day; process all ~250k rows through the two-statement pattern
- **File publication time:** Approximately 12:00–14:00 UTC based on observed `score_date` timestamps (but no documented SLA)
- **Recommended schedule:** 15:00 UTC daily to avoid racing publication
- **Occasional re-publication:** FIRST sometimes corrects and republishes a same-date file. Detect via `ETag`/`Last-Modified` response headers; the `IS DISTINCT FROM` guard in Statement 1 handles DB writes correctly regardless.

## Known Quirks

1. **`epss.cyentia.com` redirects to `epss.empiricalsecurity.com`** — use the new domain. Go follows redirects automatically.
2. **Line 1 is a comment, not a CSV header** — `encoding/csv` must not see line 1. Read it separately with `bufio.Reader` or `bufio.Scanner`, parse it, then pass remainder of reader to `csv.NewReader`.
3. **`score_date` includes time, not just date** — full RFC3339 timestamp, not `YYYY-MM-DD`. Use `feed.ParseTime()` multi-layout parser.
4. **`current` URL redirects (302) to a relative URL** — Go's default client resolves this correctly against the base URL.
5. **No `percentile` needed** — CVErt Ops stores `epss_score` only. Discard percentile column.
6. **Score range `[0.0, 1.0]`** — values like `0.00001` are valid and must not be treated as zero or NULL.
7. **Model version changes cause all scores to shift** — not incremental drift. Log a warning when `model_version` changes between runs.
8. **Historical files available** — `epss_scores-YYYY-MM-DD.csv.gz` going back to EPSS v1 launch (~2021). Not needed for MVP but useful for backfill.

## Bulk Source

The daily CSV IS the bulk source. No separate initial-load artifact.

- **URL:** `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` ✅ VERIFIED (HTTP 302 → dated file)
- **Format:** gzip-compressed CSV, ~250k rows
- **Cursor after bulk import:** `{"score_date": "<score_date from line 1>"}` stored in `feed_sync_state`

## CVErt Ops Patterns Required

- [ ] Alias resolution — NOT required; bare CVE IDs match cve_id PK directly
- [ ] Withdrawn tombstoning — NOT required; EPSS has no retraction concept
- [ ] ZIP temp-file — NOT required; single gzip CSV, not a ZIP
- [ ] NVD-specific patterns — NOT applicable
- [x] **EPSS two-statement pattern (§5.3)** — required; does NOT implement `feed.Adapter`
  - Statement 1: `UPDATE cves SET epss_score = $2, date_epss_updated = now() WHERE cve_id = $1 AND epss_score IS DISTINCT FROM $2`
  - Statement 2: `INSERT INTO epss_staging ... WHERE NOT EXISTS (SELECT 1 FROM cves WHERE cve_id = t.cve_id) ON CONFLICT DO UPDATE ...`
  - Both run unconditionally per row. Do NOT inspect `RowsAffected`.
- [x] **Advisory lock per CVE** — `SELECT pg_advisory_xact_lock($1)` with `cveAdvisoryKey("cve:"+cveID)` before both statements, inside a transaction (PLAN.md §5.3)
- [x] **Gzip decompression** — `gzip.NewReader(resp.Body)` wrapping HTTP response
- [x] **Line 1 special parsing** — read separately with `bufio.Reader`, extract `score_date`, then feed remainder to `encoding/csv`
- [x] **`score_date` as cursor** — stored in `feed_sync_state.cursor_json`
- [x] **Per-adapter rate limiter** — one download per day; `rate.NewLimiter(rate.Every(24*time.Hour), 1)` or scheduler-gated

## Implementation Notes

The adapter does NOT implement `feed.Adapter`. It is an enrichment adapter that writes directly to the DB via the two-statement EPSS pattern. See PLAN.md §5.3 for the full specification.

`EnrichmentPatch` type (add to `internal/feed/interface.go`):
```go
type EnrichmentPatch struct {
    CVEID     string    `json:"cve_id"`
    EPSSScore float64   `json:"epss_score"`
    AsOfDate  time.Time `json:"as_of_date"`
}
```
