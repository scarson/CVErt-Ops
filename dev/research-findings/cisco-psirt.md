# Cisco PSIRT openVuln API — Research Findings

> **Researched:** 2026-03-05
> **Agent:** manual research via WebSearch + WebFetch (feed-researcher agents blocked from web tools)
> **Sources:** [Cisco DevNet PSIRT](https://developer.cisco.com/docs/psirt/), [openVulnAPI GitHub](https://github.com/CiscoPSIRT/openVulnAPI), [openVulnQuery Python client](https://github.com/CiscoPSIRT/openVulnQuery), [Go example](https://pkg.go.dev/github.com/CiscoPSIRT/openVulnAPI/example_code/go_examples), [PSIRT Resources](https://sec.cloudapps.cisco.com/security/center/resources/openvulnapi)

---

## API Overview

- **Base URL:** `https://apix.cisco.com/security/advisories/v2/` (inferred from documentation patterns)
- **Auth:** OAuth2 client credentials flow — requires Cisco developer account
- **Access:** Open to registered Cisco customers and partners
- **Format:** JSON or XML (`.json` / `.xml` extension)

## Authentication

- **Flow:** OAuth2 Client Credentials
- **Registration:** Cisco API Console — register an application to get `client_id` and `client_secret`
- **Token endpoint:** Cisco's OAuth2 token server (exact URL from Cisco API Console docs)
- **Token type:** Bearer token generated per API call (automatically by client libraries)
- **Env vars:** `CISCO_CLIENT_ID`, `CISCO_CLIENT_SECRET`

## Rate Limits

| Scope | Limit |
|---|---|
| Per second | 5 requests |
| Per minute | 30 requests |
| Per day | 5,000 requests |

- **Enforcement:** Transaction quotas applied to ensure performance and prevent abuse
- **Recommended strategy:** 1 req/2sec with exponential backoff. Daily limit is the binding constraint for bulk operations.

## Endpoints

### Current Endpoints:

| Path | Description |
|---|---|
| `/all` | All published advisories |
| `/advisory/{advisoryId}` | Single advisory by ID |
| `/cve/{cve_id}` | Advisories by CVE ID |
| `/bugid/{bug_id}` | Advisory by Cisco bug ID |
| `/latest/{number}` | N most recent advisories |
| `/severity/{severity}` | Advisories by severity level |
| `/product` | Advisories by product |
| `/year/{year}` | Advisories by publication year |
| `/OSType/{OSType}` | By operating system type |
| `/OS_version/OS_data` | By OS version |
| `/platforms` | By platform |

### Sunset/Deprecated:

- `/ios`, `/iosxe`, `/aci`, `/nxos` — replaced by product/OS endpoints
- CVRF format endpoints — deprecated in favor of CSAF (CVRF sunset: Dec 31, 2023)

## Response Structure

- **Format:** JSON (or XML)
- **Advisory format:** CSAF (CVRF deprecated)
- **Dates:** All in UTC

### Key fields per advisory (based on API examples and Go client):

| Field | Type | Notes |
|---|---|---|
| `advisoryId` | string | Cisco advisory ID (e.g., `cisco-sa-...`) |
| `advisoryTitle` | string | Advisory title |
| `cves` | array | List of CVE IDs |
| `bugIDs` | array | Cisco bug IDs |
| `cvssBaseScore` | string | CVSS base score |
| `sir` | string | Security Impact Rating: `Critical`, `High`, `Medium`, `Low` |
| `firstPublished` | string | ISO 8601 UTC |
| `lastUpdated` | string | ISO 8601 UTC |
| `productNames` | array | Affected product names |
| `publicationUrl` | string | URL to full advisory |
| `summary` | string | Advisory summary |
| `cvrfUrl` / `csafUrl` | string | URL to structured advisory document |

## Timestamp Fields

| Field | Format | Notes |
|---|---|---|
| `firstPublished` | ISO 8601 UTC | Original publication date |
| `lastUpdated` | ISO 8601 UTC | Last revision — use as cursor |

## Pagination

- **Mechanism:** Documented but details not fully extracted from search results
- **Likely:** Offset-based or cursor-based with page size parameter
- **Note:** `/all` endpoint may return large result sets requiring pagination

## Incremental Sync

- **Cursor field:** `lastUpdated`
- **Strategy:** Poll `/latest/{number}` for recent advisories, then fetch detail by ID for any new/updated entries
- **Alternative:** Use `/all` with date filtering (if supported) or walk `/year/{year}` for the current year
- **Cadence:** Cisco publishes advisories as needed — no fixed schedule like Patch Tuesday

## Known Quirks

1. **OAuth2 required** — unlike MSRC and Red Hat, auth is mandatory. Requires Cisco developer account registration and client credential management.
2. **Restrictive daily rate limit** — 5,000 req/day is the binding constraint. Initial sync of all historical advisories will take multiple days if not paginated efficiently.
3. **CVRF deprecated** — CSAF is the only supported format going forward. CVRF URLs may still appear in older advisories.
4. **Advisory-centric, not CVE-centric** — one advisory can cover multiple CVEs. Must split for CVErt Ops merge pipeline.
5. **Cisco-specific severity rating (SIR)** — "Security Impact Rating" uses Critical/High/Medium/Low but is Cisco's independent assessment, not necessarily matching NVD CVSS.
6. **Bug ID cross-reference** — Cisco bug IDs (CSCxx) provide additional context for Cisco TAC cases. Unique enrichment for Cisco shops.
7. **Registered customers/partners only** — API access requires Cisco account. Not suitable for anonymous/open consumption.
8. **OS-specific endpoints** — filtering by IOS/IOS-XE/NX-OS/ACI provides targeted results for network device teams.
9. **Go example code available** — official Go examples in the GitHub repo may accelerate adapter development.
10. **No webhook/push mechanism** — polling only.

## Bulk Source

- No documented bulk download mechanism
- `/all` endpoint returns all advisories but is rate-limited
- `/year/{year}` can be used to batch by year for initial sync

## Assessment for CVErt Ops

**Unique value:** Cisco-specific bug IDs, per-product/OS impact, Security Impact Ratings for network infrastructure. Valuable for organizations with significant Cisco infrastructure.

**Implementation priority:** Tier 3 (Defer) — OAuth2 auth barrier, restrictive rate limits, niche audience (Cisco shops only). CVEs flow to NVD regardless. Cisco-specific data (bug IDs, SIR) is valuable only in Cisco-centric environments.

**Recommended approach:** If implemented, treat as opt-in vendor enrichment feed. Require user-provided OAuth2 credentials. Share CSAF parser with MSRC, Red Hat, and CISA ICS adapters.

## CVErt Ops Patterns Required

- [ ] Alias resolution — NOT required (references standard CVE IDs)
- [x] Withdrawn tombstoning — check advisory status for retracted advisories
- [ ] ZIP temp-file — NOT required
- [ ] NVD-specific patterns — NOT applicable
- [ ] EPSS two-statement pattern — NOT applicable
- [x] OAuth2 token management — client credentials flow, token refresh
- [x] CSAF parser — shared with MSRC, Red Hat, CISA ICS adapters
- [x] Advisory-to-CVE splitting — one advisory → multiple CVE records
- [x] Multi-layout timestamp fallback — `feed.ParseTimePtr()` for all timestamps
- [x] Opt-in configuration — requires user-provided Cisco credentials
