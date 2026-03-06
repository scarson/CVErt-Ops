# Red Hat Security Data API — Research Findings

> **Researched:** 2026-03-05
> **Agent:** manual research via WebSearch + WebFetch (feed-researcher agents blocked from web tools)
> **Sources:** [Security Data Portal](https://access.redhat.com/security/data), [API Docs](https://docs.redhat.com/en/documentation/red_hat_security_data_api/1.0/html-single/red_hat_security_data_api/index), [CSAF/VEX Guidelines](https://redhatproductsecurity.github.io/security-data-guidelines/csaf-vex/), [Blog: Gathering Security Data](https://www.redhat.com/en/blog/gathering-security-data-using-red-hat-security-data-api), [rhsecapi CLI](https://github.com/RedHatOfficial/rhsecapi)

---

## API Overview

Two complementary data sources:

**1. Security Data REST API (structured CVE queries)**
- **Base URL:** `https://access.redhat.com/hydra/rest/securitydata/`
- **Auth:** None required — publicly accessible
- **Formats:** JSON (`.json`), XML (`.xml`) — append extension to URL

**2. CSAF/VEX Static Files (per-advisory and per-CVE documents)**
- **Advisory CSAF:** `https://security.access.redhat.com/data/csaf/v2/advisories/`
- **Per-CVE VEX:** `https://security.access.redhat.com/data/csaf/v2/vex/`
- **OSV records:** `https://security.access.redhat.com/data/osv/all.json`
- **License:** Creative Commons Attribution 4.0 International

## REST API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/cve.json` | List CVEs with filters (paginated) |
| GET | `/cve/{CVE-ID}.json` | Detailed CVE record |
| GET | `/csaf/{RHSA-ID}.json` | CSAF advisory document |
| GET | `/oval/v2/` | OVAL definitions (maintenance mode, deprecation planned) |

## REST API Query Parameters

| Param | Example | Notes |
|---|---|---|
| `after` | `2026-03-01` | CVEs modified after date |
| `before` | `2026-03-05` | CVEs modified before date |
| `created_days_ago` | `7` | Alternative to date range |
| `severity` | `important` | Red Hat severity: `low`, `moderate`, `important`, `critical` |
| `product` | `Red Hat Enterprise Linux 9` | Filter by product name |
| `package` | `openssl` | Filter by package name |
| `advisory` | `RHSA-2026:1234` | Filter by advisory ID |
| `per_page` | `100` | Results per page |
| `page` | `2` | Page number (1-indexed) |
| `isCompressed` | `false` | Disable gzip response (default: compressed) |

## Rate Limits

- **Not officially documented.** Appears generous for automated consumption.
- **Recommended strategy:** 1–2 req/sec with exponential backoff on 5xx errors.
- **No known rate limit headers** in responses.

## Response Structure — `/cve.json` (List)

- **Top-level:** JSON array of CVE summary objects
- **Per-record fields:**

| Field | Type | Notes |
|---|---|---|
| `CVE` | string | CVE ID (e.g., `"CVE-2026-12345"`) |
| `severity` | string | Red Hat severity: `low`, `moderate`, `important`, `critical` |
| `public_date` | string | ISO 8601 date when CVE was made public |
| `advisories` | array | List of RHSA advisory IDs |
| `bugzilla` | string | Bugzilla URL |
| `bugzilla_description` | string | Bug title |
| `cvss_score` | float | CVSS base score (version varies) |
| `cvss_scoring_vector` | string | CVSS vector string |
| `CWE` | string | CWE ID |
| `affected_packages` | array | Package NEVRA strings |
| `resource_url` | string | URL to detailed CVE endpoint |

## Response Structure — `/cve/{CVE-ID}.json` (Detail)

Richer record with per-product impact assessment:

| Field | Type | Notes |
|---|---|---|
| `name` | string | CVE ID |
| `threat_severity` | string | Red Hat severity rating |
| `public_date` | string | ISO 8601 |
| `bugzilla.id` | string | Bug ID |
| `bugzilla.url` | string | Bug URL |
| `bugzilla.description` | string | Bug title |
| `cvss3.cvss3_base_score` | string | CVSS v3 base score |
| `cvss3.cvss3_scoring_vector` | string | CVSS v3 vector |
| `cvss3.status` | string | `"verified"`, `"draft"` |
| `cwe` | string | CWE ID (e.g., `"CWE-79"`) |
| `details` | array | Description text(s) |
| `acknowledgement` | string | Credit |
| `affected_release[]` | array | Products where fix is available |
| `package_state[]` | array | Products and their fix status |
| `upstream_fix` | string | Upstream version containing fix |
| `references` | array | Reference URLs |
| `mitigation` | string | Mitigation guidance (if no fix available) |

### `affected_release[]` fields (fix available):

| Field | Notes |
|---|---|
| `product_name` | e.g., `"Red Hat Enterprise Linux 9"` |
| `release_date` | When the fix was released |
| `advisory` | RHSA advisory ID |
| `cpe` | CPE string for the product |
| `package` | Fixed package NEVRA |

### `package_state[]` fields (fix status per product):

| Field | Notes |
|---|---|
| `product_name` | Product name |
| `fix_state` | `"Affected"`, `"Fix deferred"`, `"Not affected"`, `"Will not fix"`, `"Under investigation"`, `"New"` |
| `package_name` | Package name |
| `cpe` | CPE string |

## CSAF/VEX Files

Published since July 2024 for every RHSA and every CVE record:

- **RHSA CSAF:** One file per advisory — covers `fixed` and `not affected` statuses for a specific product release
- **Per-CVE VEX:** One file per CVE — covers ALL statuses for ALL products in one file
- **Format:** OASIS CSAF 2.0 standard JSON
- **Discovery:** Directory listing at the base URLs; no ROLIE feed index documented

### VEX unique value:

VEX files provide authoritative vendor declarations of:
- **"Not affected"** — this product is not vulnerable (with justification)
- **"Under investigation"** — status not yet determined
- **"Affected"** with remediation details
- **"Fixed"** with specific version information

## Timestamp Fields

| Field | Format | Notes |
|---|---|---|
| `public_date` | ISO 8601 | When CVE was publicly disclosed |
| `release_date` (in `affected_release`) | ISO 8601 | When fix was released |
| List endpoint filtering | `YYYY-MM-DD` | Date-only format for `after`/`before` params |

## Pagination

- **Mechanism:** Page-number based (`page` + `per_page` params)
- **Default page size:** Unknown (likely 20-50)
- **Max page size:** Not documented — test with `per_page=1000`
- **Last page:** Empty array response or fewer results than `per_page`

## Incremental Sync

- **Cursor field:** `public_date` or modification date via `after` parameter
- **Strategy:** Poll `/cve.json?after=YYYY-MM-DD&per_page=100` for recently modified CVEs
- **Granularity:** Date-only (no time component in `after`/`before`) — means ≤24h overlap possible
- **CSAF/VEX sync:** Monitor directory listings for new files, or use `created_days_ago=1` on the REST API and fetch corresponding VEX files

## Known Quirks

1. **Red Hat severity differs from NVD** — Red Hat performs independent severity assessment. A CVE rated "High" by NVD may be "Moderate" by Red Hat (and vice versa) based on default configuration impact. Both ratings are valuable.
2. **`fix_state` is Red Hat-specific vocabulary** — `"Will not fix"`, `"Fix deferred"`, `"Not affected"` are authoritative vendor declarations. Map to appropriate CVErt Ops status fields.
3. **Responses are gzip-compressed by default** — add `isCompressed=false` query param if not handling compression, or set `Accept-Encoding: gzip` and decompress.
4. **`package_state` vs `affected_release`** — these are complementary: `affected_release` lists products WITH fixes; `package_state` lists products and their current status (including "Will not fix"). Both needed for complete picture.
5. **Date-only granularity on filters** — `after` and `before` params accept `YYYY-MM-DD` only, not timestamps. Incremental sync has ≤24h overlap potential. Dedup by CVE ID.
6. **CVSS version ambiguity** — list endpoint has `cvss_score` with no version indicator. Detail endpoint has explicit `cvss3` block. Always prefer the detail endpoint for CVSS data.
7. **OSV records available** — Red Hat publishes OSV-format records at `security.access.redhat.com/data/osv/all.json`, but recommends consuming via OSV.dev instead. Our OSV adapter may already ingest this data.
8. **OVAL definitions in maintenance mode** — OVAL v2 still available but deprecated. Don't build against it.
9. **CPE strings provided per-product** — `affected_release` and `package_state` include CPE strings, enabling precise product matching in CVErt Ops.
10. **No webhook/push mechanism** — polling only. RSS feed available at `security.access.redhat.com/data/meta/v1/rhsa.rss` for advisory notifications.

## Bulk Source

- **OSV bulk:** `https://security.access.redhat.com/data/osv/all.json` — all Red Hat OSV records in one file
- **CSAF/VEX directories:** Browsable directories with all historical files. Initial sync can walk the directory listing.
- **No single-file CVE dump** — must paginate through the REST API or walk CSAF/VEX directories.

## Assessment for CVErt Ops

**Unique value:** Per-product fix status (`"Not affected"`, `"Will not fix"`, `"Fix deferred"`), Red Hat independent severity ratings, package-level impact for RHEL/CentOS/Fedora, CSAF/VEX vendor declarations.

**Implementation priority:** Tier 1 — RHEL is the dominant enterprise Linux. Red Hat's per-product status declarations are authoritative data that NVD doesn't provide.

**Recommended approach:** Primary consumption via REST API (`/cve.json` for incremental discovery, `/cve/{id}.json` for detail). CSAF/VEX files as supplementary enrichment. Treat as vendor enrichment feed that adds Red Hat-specific context to existing CVE records.

## CVErt Ops Patterns Required

- [ ] Alias resolution — NOT required (uses standard CVE IDs natively)
- [ ] Withdrawn tombstoning — Red Hat doesn't publish withdrawn CVEs; NVD handles this
- [ ] ZIP temp-file — NOT required
- [ ] NVD-specific patterns — NOT applicable
- [ ] EPSS two-statement pattern — NOT applicable
- [x] Streaming JSON — list endpoint returns JSON array; stream for large result sets
- [x] Multi-layout timestamp fallback — `feed.ParseTimePtr()` for all timestamp fields
- [x] Vendor-specific enrichment — per-product fix status, Red Hat severity, package-level impact
- [x] CSAF parser — reusable across MSRC, Red Hat, and CISA ICS feeds (if consuming VEX files)
- [x] Dedup by CVE ID — date-only filter granularity means overlap on incremental sync
