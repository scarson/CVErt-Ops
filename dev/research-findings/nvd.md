# NVD API 2.0 — Research Findings

> **Researched:** 2026-02-25
> **Agent:** feed-researcher (ae5b848) — web-verified via WebSearch + WebFetch
> **Sources:** nvd.nist.gov/developers/vulnerabilities, nvd.nist.gov/developers/start-here, nvd.nist.gov/developers/terms-of-use, nvdlib Python library (confirmed field names)

---

## API Overview

- **Base URL:** `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Auth header:** `apiKey` — **case-sensitive, lowercase `a`**. `apikey` and `ApiKey` are silently ignored and the request is treated as unauthenticated.
- **Auth format:** `req.Header.Set("apiKey", keyValue)` — no "Bearer" prefix, no brackets.
- **Env var:** `NVD_API_KEY`

## Rate Limits

- **Unauthenticated:** 5 req / 30-second rolling window → 6-second inter-request delay
- **Authenticated:** 50 req / 30-second rolling window → 0.6-second inter-request delay
- **Rate limit exceeded:** HTTP **403** (not 429). Response body has `"message"` JSON field. No `Retry-After` header documented — use exponential backoff.
- **NVD sync guidance:** No more than one automated incremental sync per 2 hours.

## Response Structure

- **Top-level:** JSON object (not array)
- **Data array key:** `"vulnerabilities"`
- **Record wrapper:** Each element is `{"cve": {...}}` — the CVE data is one level deeper at `item.cve`
- **Record ID field:** `cve.id`
- **Uses native IDs:** Yes (standard CVE IDs). No alias resolution needed.
- **Optional fields are absent, not null:** If a CVE has no CVSS data, the `metrics` key is absent entirely. Struct fields must handle missing keys gracefully.

## CVSS Metric Structure (critical)

```
metrics: {
  cvssMetricV2: [{
    cvssData: { version, vectorString, baseScore, ... },
    baseSeverity: string,       // <-- OUTSIDE cvssData for V2
    ...
  }],
  cvssMetricV31: [{
    cvssData: {
      version, vectorString, baseScore,
      baseSeverity: string,     // <-- INSIDE cvssData for V3.x and V4
      ...
    },
    ...
  }],
  cvssMetricV30: [...],   // same structure as V31
  cvssMetricV40: [...],   // same structure as V31
}
```

**Critical distinctions:**
- Field names: `cvssMetricV31`, `cvssMetricV30`, `cvssMetricV40` — no underscores, two-digit suffix
- V2: `baseSeverity` is OUTSIDE `cvssData` (sibling of `cvssData`)
- V3.0, V3.1, V4.0: `baseSeverity` is INSIDE `cvssData`
- Prefer `type == "Primary"` when multiple entries; fall back to first entry
- Priority: V4.0 → V3.1 → V3.0 → V2

## Other CVE Fields

| Field | Type | Notes |
|---|---|---|
| `cve.id` | string | e.g., `"CVE-2021-44228"` |
| `cve.vulnStatus` | string | `"Analyzed"`, `"Rejected"`, `"Modified"`, etc. — free string, not enum |
| `cve.published` | string | ISO-8601, no fractional seconds, no `Z` on some records |
| `cve.lastModified` | string | Same format |
| `cve.descriptions[]` | array | Filter `lang=="en"` for DescriptionPrimary |
| `cve.weaknesses[].description[]` | array | Filter `lang=="en"` for CWE IDs |
| `cve.configurations[].nodes[].cpeMatch[]` | nested | AffectedCPEs |
| `cve.references[]` | array | `{url, source, tags[]}` |

## Timestamp Fields

| Field | Format | Notes |
|---|---|---|
| `cve.published` | ISO-8601, often no `Z` | Use multi-layout parser |
| `cve.lastModified` | ISO-8601, often no `Z` | Use multi-layout parser |
| `response.timestamp` | ISO-8601 with ms | Use as cursor upper bound (not `time.Now()`) |
| HTTP `Date` header | RFC 1123 | Alternative cursor bound |

## Pagination

- **Mechanism:** Zero-based integer offset (`startIndex`)
- **Max page size:** 2000 (set `resultsPerPage=2000`)
- **Last page:** `startIndex + resultsPerPage >= totalResults`
- **Per-page cursor persistence required:** Save both the date-window position AND `startIndex` to resume mid-window failures

## Incremental Sync

- **Cursor field:** `cve.lastModified`
- **Query params:** `lastModStartDate` / `lastModEndDate`
- **Timestamp format for params:** `2006-01-02T15:04:05.000Z` (Z suffix avoids `+` encoding) via `url.Values.Set()` + `url.Values.Encode()`
- **15-minute lookback:** `lastModStartDate = lastCursor - 15min`
- **120-day hard limit:** Queries spanning >120 days return 403. Chunk into sequential ≤120-day windows.
- **Cursor upper bound:** Use `response.timestamp` from JSON body (not `time.Now()` — clock skew in Docker)

## Known Quirks

1. **`apiKey` header case-sensitive** — `apikey`/`ApiKey` silently ignored → requests treated as unauthenticated → immediate 403 blocks at authenticated rate
2. **`+` in timestamp params must be percent-encoded** — use `url.Values` not string concat
3. **`baseSeverity` location differs by CVSS version** — V2: outside `cvssData`; V3+: inside
4. **Rate limit returns HTTP 403, not 429** — check `message` header/body to distinguish from auth error
5. **`vulnerabilities` array elements are wrapped** — `{"cve": {...}}`, not raw CVE objects
6. **`Rejected` status requires tombstone** — exact string, title case, `IsWithdrawn = true`
7. **NVD enrichment backlog** — recently published CVEs may have no CVSS for weeks/months
8. **`noRejected` parameter** — do NOT use; adapter needs rejected CVEs to tombstone existing records
9. **Null bytes in older NVD records** — apply `feed.StripNullBytes()` to all string fields
10. **`lastModified` not updated on CPE-only changes** — minor gap in incremental coverage; acceptable for MVP

## Attribution Requirement (NVD ToU)

> **"This product uses the NVD API but is not endorsed or certified by the NVD."**

This notice MUST appear in the frontend (Phase 6+). Tracked via `TODO(attribution)` comment in `internal/feed/nvd/adapter.go` package doc.

## Bulk Source

- Annual `.json.gz` files: `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-[YEAR].json.gz` (2002–present)
- Same JSON structure as API response (`{"vulnerabilities":[...]}`)
- Stream with `compress/gzip.NewReader` (not ZIP; not temp file needed)
- Meta files: `nvdcve-2.0-[YEAR].meta` — SHA256 + last-modified for change detection

## CVErt Ops Patterns Required

- [ ] Alias resolution — NOT required (NVD uses standard CVE IDs natively)
- [x] Withdrawn tombstoning — `vulnStatus == "Rejected"` (title case) → `IsWithdrawn = true`
- [ ] ZIP temp-file — NOT required for API responses; gzip streaming for bulk `.json.gz` files
- [x] NVD-specific patterns — all required (rate limiting, `apiKey` header, URL encoding, 120-day chunking, 15-min overlap, cursor upper bound from response)
- [ ] EPSS two-statement pattern — NOT applicable
