# Microsoft MSRC (Security Response Center) — Research Findings

> **Researched:** 2026-03-05
> **Agent:** manual research via WebSearch + WebFetch (feed-researcher agents blocked from web tools)
> **Sources:** [MSRC API 3.0 Announcement](https://www.microsoft.com/en-us/msrc/blog/2024/07/announcing-the-cvrf-api-3-0-upgrade), [GitHub Repo](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API), [Swagger spec](https://api.msrc.microsoft.com/cvrf/v3.0/swagger/v3/swagger.json), [PublicAPI.dev](https://publicapi.dev/microsoft-security-response-center-msrc-api)

---

## API Overview

- **Base URL:** `https://api.msrc.microsoft.com/cvrf/v3.0/`
- **Auth:** None required — v3.0 removed the API key requirement. Freely accessible.
- **CORS:** Not supported (server-side consumption only)
- **Protocol:** HTTPS only
- **Data formats:** CVRF (XML/JSON, legacy) + CSAF (JSON, newer) — both available per release

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/updates` | List all security update summaries |
| GET | `/updates/$count` | Total count of security updates |
| GET | `/updates/{key}` | Search by update ID (`yyyy-mmm`), CVE number, or year |
| GET | `/cvrf/{id}` | Detailed security update in CVRF format |
| GET | `/csaf/{id}` | Security advisory in CSAF 2.0 format |
| GET | `/$metadata` | OData service metadata |

- **Key format:** `{id}` is `yyyy-mmm` (e.g., `2025-Jan`, `2026-Feb`) for monthly Patch Tuesday releases
- **OData support:** Query filtering via `$filter` on `CurrentReleaseDate` and `InitialReleaseDate`

## Rate Limits

- **Documented limits:** Poorly documented. Error message "Too many follow-up requests: 21" is returned when exceeded.
- **Recommended strategy:** 1 req/sec with exponential backoff on errors. Monthly cadence means low volume anyway.
- **HTTP status on limit:** Unknown — likely 429 or 503 based on error message format.

## Response Structure — `/updates`

- **Top-level:** JSON object with OData metadata
- **Data array key:** `"value"` (OData convention)
- **Each record:** Summary with `ID`, `Alias` (CVE ID), `DocumentTitle`, `Severity`, `InitialReleaseDate`, `CurrentReleaseDate`

## Response Structure — `/cvrf/{id}`

CVRF (Common Vulnerability Reporting Framework) document containing the full Patch Tuesday release.

### Key sections within a CVRF document:

| Section | Contents |
|---|---|
| `DocumentTitle` | Release title (e.g., "February 2026 Security Updates") |
| `DocumentType` | `"Security Update"` |
| `Vulnerability[]` | Array of individual vulnerabilities |
| `ProductTree` | Hierarchical product/version taxonomy |

### Per-Vulnerability fields:

| Field | Type | Notes |
|---|---|---|
| `CVE` | string | CVE ID (e.g., `"CVE-2026-12345"`) |
| `Title` | string | Vulnerability title |
| `Notes[]` | array | Description, FAQ, impact details |
| `CVSSScoreSets[]` | array | Base/temporal scores and vectors per product |
| `Remediations[]` | array | KB articles, download URLs, product-specific fixes |
| `Threats[]` | array | Exploitability assessment, impact severity |
| `Acknowledgments[]` | array | Credit information |
| `RevisionHistory[]` | array | Advisory revision tracking |
| `ProductStatuses[]` | array | Per-product affected/fixed status |

### Remediation fields (unique value):

| Field | Notes |
|---|---|
| `Description` | KB article number or action |
| `URL` | Direct download link for the patch |
| `ProductID[]` | Which products this remediation applies to |
| `Type` | `"Vendor Fix"`, `"Workaround"`, `"Mitigation"` |
| `Supercedence` | KB article this supersedes |

### Threats/Exploitability fields (unique value):

| Field | Notes |
|---|---|
| `Type` | `"Impact"`, `"Exploit Status"` |
| `Description` | e.g., `"Exploitation Less Likely"`, `"Exploitation More Likely"`, `"Exploitation Detected"` |
| `ProductID[]` | Per-product exploitability assessment |

## Response Structure — `/csaf/{id}`

CSAF 2.0 JSON advisory. Same data as CVRF but in the OASIS CSAF standard format. Preferred for new implementations as Microsoft has signaled CSAF as the forward path.

## Timestamp Fields

| Field | Format | Notes |
|---|---|---|
| `InitialReleaseDate` | ISO 8601 | When advisory was first published |
| `CurrentReleaseDate` | ISO 8601 | Last revision date — use as cursor |
| `RevisionHistory[].Date` | ISO 8601 | Per-revision timestamps |

## Pagination

- **Mechanism:** OData-style; `/updates` returns all summaries in one response (volume is manageable — ~12 releases/year plus out-of-band updates)
- **No traditional pagination needed:** Monthly releases mean the `/updates` list is small (~300 total entries across all years)
- **Per-release detail:** Each `/cvrf/{id}` call returns the full monthly release (can be large — 100+ CVEs per Patch Tuesday)

## Incremental Sync

- **Strategy:** Poll `/updates` for new/updated release IDs, then fetch `/cvrf/{id}` or `/csaf/{id}` for changed releases
- **Cursor field:** `CurrentReleaseDate` on the update summary
- **Cadence:** Monthly (second Tuesday) + occasional out-of-band releases
- **OData filter:** `$filter=CurrentReleaseDate gt 2026-01-01T00:00:00Z` to get only recently modified releases
- **Re-processing:** Microsoft revises existing releases (adds CVEs, updates scores). Must re-fetch and re-process any release where `CurrentReleaseDate` > last sync.

## Known Quirks

1. **Monthly batch releases** — unlike NVD's per-CVE granularity, MSRC publishes by month. A single `/cvrf/2026-Feb` response contains all ~100+ CVEs from that Patch Tuesday. Adapter must split into individual CVE records.
2. **Product taxonomy is hierarchical** — `ProductTree` uses nested `Branch` elements. Product IDs in vulnerability sections reference this tree. Need to build a lookup map to resolve product names.
3. **Per-product CVSS scores** — same CVE can have different CVSS scores for different products/versions. CVErt Ops needs a strategy: take the highest score? Store per-product? PLAN.md §5.1 merge rules apply.
4. **Exploitability assessment is Microsoft-proprietary** — "Exploitation More Likely" / "Exploitation Less Likely" / "Exploitation Detected" — valuable enrichment but doesn't map to standard CVSS temporal metrics directly.
5. **Out-of-band releases** — emergency patches outside Patch Tuesday cycle get their own release ID. Polling must not assume monthly cadence only.
6. **CVRF format may be deprecated** — Microsoft added CSAF in late 2025. CVRF still works but CSAF is the forward path. Consider implementing CSAF parser for future-proofing (also reusable for Red Hat and CISA ICS feeds).
7. **API key removal in v3.0** — documentation and older tools may still reference API key auth. It's no longer needed.
8. **"Too many follow-up requests" error** — rate limit error message format differs from standard HTTP 429 patterns.
9. **No `Retry-After` header documented** — use exponential backoff starting at 5 seconds.
10. **OData query syntax** — filter expressions use OData conventions (`gt`, `lt`, `eq`), not standard query params.

## Bulk Source

No documented bulk download. The `/updates` endpoint returns all release summaries, and each release's full data is available via `/cvrf/{id}`. Historical data goes back to ~2016. Initial sync requires iterating all release IDs.

## Assessment for CVErt Ops

**Unique value:** Microsoft-specific remediation details (KB articles, download URLs), per-product exploitability assessments, per-product CVSS scores. NVD has the CVE but not the Microsoft-specific remediation chain.

**Implementation priority:** Tier 1 — Windows/Azure/Office vulnerabilities are the #1 concern for most enterprise users.

**Recommended approach:** CSAF format preferred over CVRF for new implementations. Treat as vendor enrichment feed that adds Microsoft-specific context to existing CVE records rather than a primary CVE source.

## CVErt Ops Patterns Required

- [ ] Alias resolution — NOT required (uses standard CVE IDs natively)
- [x] Withdrawn tombstoning — check `RevisionHistory` for retraction notices
- [ ] ZIP temp-file — NOT required
- [ ] NVD-specific patterns — NOT applicable
- [ ] EPSS two-statement pattern — NOT applicable
- [x] Streaming JSON — CSAF responses can be large (~100+ CVEs per release); stream if using CSAF format
- [x] Multi-layout timestamp fallback — `feed.ParseTimePtr()` for all timestamp fields
- [x] Vendor-specific enrichment — KB articles, exploitability assessments, per-product fix status
- [x] CSAF parser — reusable across MSRC, Red Hat, and CISA ICS feeds
