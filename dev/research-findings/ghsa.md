# GHSA (GitHub Security Advisory) — Research Findings

> **Researched:** 2026-02-25
> **Agent:** feed-researcher (aee0846) — **web-verified** via WebSearch + WebFetch
> **Sources:** GitHub REST API docs, GraphQL docs, rate limit docs, pagination docs, advisory-database repo

---

## API Overview

Two viable API surfaces exist. **REST API is recommended** over GraphQL for this adapter (see quirks #1).

**REST API (recommended)**
- **Endpoint:** `GET https://api.github.com/advisories`
- **API version header:** `X-GitHub-Api-Version: 2022-11-28`
- **Accept header:** `Accept: application/vnd.github+json`
- **Auth:** `Authorization: Bearer <token>` — PAT, GitHub App token, or OAuth token

**GraphQL API (available but not recommended)**
- **Endpoint:** `POST https://api.github.com/graphql`
- **Auth:** Same token types

## Rate Limits

| | Unauthenticated | Authenticated | Enterprise Cloud |
|---|---|---|---|
| REST | 60 req/hr (~1/min) | 5,000 req/hr (~1.39/sec) | 15,000 req/hr |
| GraphQL | N/A | 5,000 points/hr | — |

- **Secondary limit:** 900 points/minute, 80 content-generating req/minute
- **Safe adapter rate:** 1 req/sec (well within limits)
- **Rate limit exceeded:** HTTP 403 or 429
- **Response headers:** `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-reset` (Unix timestamp), `retry-after` (seconds, on secondary limit)
- **Env var:** `GITHUB_TOKEN`

## REST API Response Structure

- **Top-level:** JSON **array** (not a wrapper object — this is unusual; stream directly)
- **Record ID fields:** `ghsa_id` (native) + `cve_id` (alias, may be null)
- **Uses native IDs with aliases:** Yes — `cve_id` is a direct top-level field AND in `identifiers[]`

### Key Fields per Record

| Field | Type | Notes |
|---|---|---|
| `ghsa_id` | string | Native GHSA ID e.g. `"GHSA-xxxx-xxxx-xxxx"` |
| `cve_id` | string\|null | Null when no CVE assigned yet |
| `summary` | string | Max 1024 chars |
| `description` | string\|null | Max 65535 chars; may contain null bytes |
| `type` | string | `"reviewed"`, `"unreviewed"`, `"malware"` |
| `severity` | string | `"critical"`, `"high"`, `"medium"`, `"low"`, `"unknown"` |
| `published_at` | string | ISO 8601 UTC |
| `updated_at` | string | ISO 8601 UTC |
| `withdrawn_at` | string\|null | ISO 8601 UTC or null |
| `cvss` | object\|null | `{score: float, vector_string: string}` — no version distinction |
| `cvss_severities` | object | `{cvss_v3: {score, vector_string}, cvss_v4: {score, vector_string}}` |
| `cwes` | array | `[{cwe_id: "CWE-79", name: "..."}]` |
| `vulnerabilities` | array | Inline (not paginated); `[{package: {ecosystem, name}, vulnerable_version_range, first_patched_version, vulnerable_functions}]` |
| `references` | array | `[{url: string}]` |
| `identifiers` | array | `[{type: "GHSA"\|"CVE", value: "..."}]` |
| `html_url` | string | Advisory page URL |

## Timestamp Fields

All use ISO 8601 UTC (`Z` suffix in practice). Use multi-layout fallback parser regardless.

| Field | Notes |
|---|---|
| `published_at` | Use `feed.ParseTimePtr()` |
| `updated_at` | Use `feed.ParseTimePtr()` — incremental cursor field |
| `withdrawn_at` | Use `feed.ParseTimePtr()` — null when not withdrawn |

## Pagination (REST)

- **Mechanism:** Link response header (RFC 5988) — `<URL>; rel="next"`
- **Page size:** `per_page=100` (max 100)
- **Cursor:** `after` query parameter extracted from the rel="next" URL
- **Last page:** Link header absent or no `rel="next"` entry
- **Implementation:** `parseLinkHeader(resp.Header.Get("Link"))` extracts `after` value from next-page URL

```
Link: <https://api.github.com/advisories?after=Y3Vyc29y...&per_page=100>; rel="next"
```

## GraphQL API Fields (for reference)

```graphql
ghsaId, identifiers { type value }, publishedAt, updatedAt, withdrawnAt,
severity, cvss { score vectorString }, cwe { ... }, description, summary,
vulnerabilities(first: N) { nodes { package { ecosystem name }
  vulnerableVersionRange firstPatchedVersion { identifier } } }
```

## Incremental Sync

- **Cursor field:** `updated_at`
- **Filter param:** `updated=>=TIMESTAMP` (GitHub search date range syntax)
- **URL encoding:** `url.Values.Set("updated", ">="+since)` + `.Encode()` — percent-encodes `>=` and `:` correctly
- **Sort:** `sort=updated&direction=asc` — ascending so cursor advances monotonically
- **15-minute lookback:** Apply `since = lastCursor - 15min` before each sync
- **No window limit:** Unlike NVD, no date-range restriction

## Known Quirks

1. **REST over GraphQL** — REST response is a top-level array (simpler streaming); `cve_id` is a direct field; `vulnerabilities[]` is inline (no nested pagination). GraphQL requires navigating nested wrapper objects and has nested `vulnerabilities` connection requiring its own pagination.
2. **Top-level response is a JSON array** — unlike NVD. Open `[` with `Token()`, enter `More()` loop directly (no key to navigate past).
3. **`cve_id` top-level field simplifies alias resolution** — use `cve_id` directly when non-null; scan `identifiers[]` as fallback.
4. **`withdrawn_at` non-null → tombstone** — set `IsWithdrawn = true` + `Status = "withdrawn"`.
5. **`type=reviewed` filter** — default returns only reviewed advisories. Unreviewed lack structured CVE data. Do NOT use `type=unreviewed` for the CVErt Ops corpus.
6. **`description` may contain null bytes** — GHSA descriptions are explicitly called out in PLAN.md §3.2 as a null-byte source. Apply `feed.StripNullBytes()`.
7. **`cvss_severities` preferred over top-level `cvss`** — `cvss_severities` has explicit `cvss_v3`/`cvss_v4` split; top-level `cvss` has no version distinction (treat as V3 fallback).
8. **Late-binding CVE alias migration** — GHSA publishes before MITRE mints the CVE ID. Subsequent sync will have `cve_id` populated where it was null. Pipeline Step 1.5 handles migration transparently.
9. **`updated` parameter uses GitHub search syntax** — `url.Values.Set("updated", ">=TIMESTAMP")` — the `>=` and `:` must be percent-encoded (handled by `.Encode()`).
10. **`sort=updated direction=asc` required** — descending (default) makes mid-page cursor position ambiguous on retry.

## Bulk Source

`github.com/github/advisory-database` git repo — 100,000+ advisories in OSV JSON format. PLAN.md §3.3 notes: "GraphQL pagination — acceptable at current volume. No bulk alternative needed." Bulk import not required for MVP.

## CVErt Ops Patterns Required

- [x] Alias resolution — `cve_id` top-level field first; `identifiers[]` fallback; `feed.ResolveCanonicalID(ghsaId, aliases)`
- [x] Withdrawn tombstoning — `withdrawn_at` non-null → `IsWithdrawn = true` + `Status = "withdrawn"`
- [x] Late-binding PK migration — `FindCVEBySourceID` + `MigrateCVEPK` in merge pipeline Step 1.5
- [ ] ZIP temp-file — NOT required; REST API returns JSON array
- [ ] NVD-specific patterns — NOT applicable
- [ ] EPSS two-statement pattern — NOT applicable
- [x] Null byte stripping — required; GHSA descriptions are a known null-byte source
- [x] Streaming JSON — top-level array: `Token()` → `[` → `More()` + `Decode(&rec)` loop
- [x] Multi-layout timestamp fallback — `feed.ParseTimePtr()` for all timestamp fields
- [x] `url.Values` for param encoding — `updated=>=TIMESTAMP` must be percent-encoded
