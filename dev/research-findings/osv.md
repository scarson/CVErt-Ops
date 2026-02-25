# OSV (Open Source Vulnerabilities) — Research Findings

> **Researched:** 2026-02-25
> **Agent:** feed-researcher (aa7dcb2 and a1df16c) — **web access blocked in both runs; findings derived from codebase + training data**
> **Critical verification:** `all.zip` URL confirmed via `curl -I` — HTTP 200, 1.09 GB, updated continuously (see below)

---

## API Overview

- **Feed type:** Google Cloud Storage (GCS) public bucket — not a REST API
- **Base URL:** `https://osv-vulnerabilities.storage.googleapis.com`
- **Authentication:** None. Fully public bucket.
- **Required headers:** None.
- **Schema spec:** OSV Schema v1 — `https://ossf.github.io/osv-schema/`

## Critical: all.zip URL Verification

**`https://osv-vulnerabilities.storage.googleapis.com/all.zip` — CONFIRMED VALID**

```
HTTP/1.1 200 OK
Content-Type: application/zip
Content-Length: 1095695120  (1.09 GB)
Last-Modified: Wed, 25 Feb 2026 21:57:24 GMT
```

Verified via `curl -I` on 2026-02-25. The archive is updated continuously (~hourly based on `Last-Modified` header). PLAN.md §3.3's description of "per-ecosystem archives" is inaccurate — a single all-ecosystems ZIP exists and is the correct download target.

Per-ecosystem ZIPs also exist (e.g., `PyPI.zip`, `Go.zip`) as alternatives but are not needed when `all.zip` is available.

## Rate Limits

- No documented rate limit for GCS public bucket reads.
- Adapter uses `rate.Every(5*time.Second)` as a courtesy limit (fires once per `Fetch()` call since only one HTTP request is made per run).
- GCS returns HTTP 429 on throttling. No `Retry-After` header guaranteed.

## ZIP Structure

- **ZIP entry path:** `ECOSYSTEM/ADVISORY_ID.json` (subdirectory per ecosystem)
  - Examples: `PyPI/PYSEC-2024-1.json`, `Go/GO-2024-1234.json`, `npm/GHSA-xxxx.json`
- **Each ZIP entry:** Single advisory JSON object (not wrapped, not an array)
- **Filter:** `strings.HasSuffix(name, ".json")` — correctly handles subdirectory paths
- **Total entries:** ~100,000+ advisories across all ecosystems

## Advisory JSON Schema (OSV Schema v1)

| Field | Type | Notes |
|---|---|---|
| `id` | string | Native advisory ID (GHSA-*, PYSEC-*, GO-*, RUSTSEC-*, etc.) |
| `aliases` | `[]string` | May contain CVE IDs — used for alias resolution |
| `published` | string | RFC3339 timestamp |
| `modified` | string | RFC3339 timestamp — authoritative cursor value |
| `withdrawn` | string | RFC3339 timestamp when withdrawn; **absent (not empty string) when active** |
| `summary` | string | Short one-line description |
| `details` | string | Long Markdown description — may contain null bytes |
| `severity` | `[]object` | `{type, score}` — score is FULL CVSS VECTOR STRING (not a numeric float) |
| `severity[].type` | string | `"CVSS_V3"`, `"CVSS_V4"`, `"CVSS_V2"` |
| `severity[].score` | string | e.g., `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"` |
| `affected[].package` | object | `{ecosystem, name, purl}` |
| `affected[].ranges[].type` | string | `"SEMVER"`, `"ECOSYSTEM"`, `"GIT"` |
| `affected[].ranges[].events` | `json.RawMessage` | Polymorphic — see below |

## Polymorphic `events` Array

Each element in `events` is a single-key object with a variable key name:
- `{"introduced": "1.0.0"}`
- `{"fixed": "1.2.3"}`
- `{"last_affected": "1.2.2"}`
- For GIT ranges: values are commit SHAs (not version strings)

Must use `json.RawMessage` for the whole events array, then `map[string]string` per element. Fixed struct type causes `json.UnmarshalTypeError`.

## Timestamp Fields

- `published`, `modified`, `withdrawn`: RFC3339, typically with `Z` suffix
- Use `feed.ParseTimePtr()` multi-layout parser (not `time.Parse(time.RFC3339, ...)` directly)

## Incremental Sync

- **Pre-filter:** `zip.FileHeader.Modified` — skip entries where `entry.Modified <= cursor.LastModified` (avoid opening unchanged files)
- **Cursor stored:** `fetchedAt` (time of the archive download), not advisory `modified` timestamps
- **Authoritative field:** `record.Modified` (JSON) — use for `source_date_modified` in `cve_sources`
- **No window limit:** Archive is a full current-state snapshot; no date-range restrictions

## Known Quirks

1. **`withdrawn` is absent when not withdrawn, not an empty string** — check `adv.Withdrawn != ""` after JSON decode
2. **OSV provides ONLY CVSS vectors, not numeric scores** — store in `CVSSv3Vector`/`CVSSv4Vector`, leave `CVSSv3Score`/`CVSSv4Score` nil; NVD/MITRE provide authoritative scores
3. **GIT ranges contain commit SHAs** — `RangeType == "GIT"` entries not suitable for semver comparison
4. **`affected[].versions` can have thousands of entries** — skip this field; use `ranges` only
5. **Late-binding alias migration** — OSV publishes before CVE ID is minted; adapter + pipeline handle this via `FindCVEBySourceID` + `MigrateCVEPK`
6. **`defer rc.Close()` inside ZIP loop is forbidden** — 100k+ entries would exhaust OS file descriptor limit. Adapter uses explicit `rc.Close()` per iteration.
7. **Null bytes in `summary`/`details`** — apply `feed.StripNullBytes()` on all string fields

## Bulk Source

The OSV feed IS the bulk source. No separate bulk-import step needed.

- **URL:** `https://osv-vulnerabilities.storage.googleapis.com/all.zip` ✅ VERIFIED
- **Size:** ~1.09 GB (2026-02-25)
- **Format:** ZIP containing ECOSYSTEM/ID.json per advisory
- **Update frequency:** ~hourly (based on `Last-Modified` headers)

## CVErt Ops Patterns Required

- [x] Alias resolution — `feed.ResolveCanonicalID(nativeID, aliases)` promotes CVE ID from `aliases[]`
- [x] Withdrawn tombstoning — non-empty `withdrawn` → `IsWithdrawn = true` + `Status = "withdrawn"`
- [x] ZIP temp-file + explicit loop close — `os.CreateTemp` → `io.Copy` → `zip.NewReader`; explicit `rc.Close()` per entry (never defer inside loop)
- [ ] NVD-specific patterns — not applicable
- [ ] EPSS two-statement pattern — not applicable
- [x] Late-binding PK migration — `FindCVEBySourceID` + `MigrateCVEPK` in merge pipeline Step 1.5
- [x] Null byte stripping — `feed.StripNullBytes()` on all string fields
- [x] Multi-layout timestamp fallback — `feed.ParseTimePtr()` for all timestamp fields

## Research Limitations

Both research agents were blocked from web access in this environment. The `all.zip` URL was verified via `curl -I` through the Bash tool. The OSV Schema field details are based on the existing implementation code (`internal/feed/osv/adapter.go`) and training data. Cross-reference against `https://ossf.github.io/osv-schema/` if schema discrepancies are suspected.
