# VulnCheck API — Research Findings

> **Researched:** 2026-03-05
> **Agent:** manual research via WebSearch + WebFetch (feed-researcher agents blocked from web tools)
> **Sources:** [API Overview](https://docs.vulncheck.com/api), [Vulnerability Enrichment](https://docs.vulncheck.com/products/exploit-and-vulnerability-intelligence/vulnerability-enrichment), [Exploit Intelligence](https://docs.vulncheck.com/products/exploit-and-vulnerability-intelligence/exploit-intelligence), [VulnCheck KEV](https://www.vulncheck.com/kev), [NVD++ Blog](https://www.vulncheck.com/blog/nvd-plus-plus)

---

## API Overview

- **Base URL:** `https://api.vulncheck.com/v3/`
- **Auth:** Bearer token (required) — `Authorization: Bearer <token>`
- **Alternative auth:** URL query parameter or JavaScript cookie
- **Token management:** Generated via dashboard; tokens expire after 30 days of inactivity
- **Pricing:** Free community tier available; paid tiers for full access

## Rate Limits

| Tier | Limit | Notes |
|---|---|---|
| Community (free) | 1,000 req/min | Sufficient for incremental sync |
| Paid | Higher (unspecified) | Contact sales |

- **Rate limit exceeded:** HTTP 429 "Too Many Requests"
- **Recommended strategy:** Exponential backoff on 429
- **Unlicensed index access:** HTTP 402 "Payment Required"
- **Auth errors:** HTTP 403 "Forbidden" (valid token, insufficient permissions)

## Major Endpoint Categories

| Path | Description |
|---|---|
| `/v3/index` | List all available indices |
| `/v3/index/{index}` | Browse paginated index data |
| `/v3/backup` | List available backup indices |
| `/v3/backup/{index}` | Download full index backup (paid only) |
| `/v3/purl` | Query by Package URL |
| `/v3/purls` | Batch PURL query |
| `/v3/cpe` | Query by CPE |
| `/v3/search/cpe` | CPE search |
| `/v3/rules/initial-access/{rules}` | Initial access detection rules |
| `/v3/tags/{filter}` | IP intelligence |
| `/v3/pdns/{filter}` | Protective DNS |
| `/v3/openapi` | OpenAPI spec |

### Key indices for CVErt Ops:

| Index | Description | Tier |
|---|---|---|
| `vulncheck-nvd` / `vulncheck-nvd2` | NVD++ enriched CVE data | Community |
| `vulncheck-kev` | VulnCheck KEV (broader than CISA KEV) | Community |
| `exploits` | Exploit intelligence per CVE | Paid |
| `botnets` | Botnet exploitation data | Paid |
| `threat-actors` | Threat actor to CVE mappings | Paid |
| `initial-access` | Initial access vulnerability intelligence | Paid |

## Response Structure

- **Format:** JSON
- **Wrapper:** `{"data": [...], "_meta": {...}}`
- **Data array key:** `"data"`
- **Default page size:** 100 documents per page
- **Batch queries:** POST endpoints support up to 1,000 CVE IDs per request

### Error response:
```json
{"error": true, "errors": ["message"]}
```

## Unique Enrichment Data (beyond NVD/MITRE/EPSS)

This is VulnCheck's primary value — data we can't get elsewhere:

| Data Type | Description | Free? |
|---|---|---|
| **Temporal CVSS** | CVSS V2, V3, V3.1, V4 temporal/threat scores | Partial |
| **Threat actor attribution** | Named threat groups mapped to CVEs (MITRE, MISP, CrowdStrike, Mandiant, Microsoft naming schemes) | Paid |
| **Botnet/ransomware exploitation** | CVEs known to be used by botnets | Paid |
| **MITRE ATT&CK mappings** | Tactics, mitigations, detections, D3FEND techniques | Partial |
| **SSVC decisions** | CISA and VulnCheck stakeholder-specific categorization | Partial |
| **Exploit chain identification** | Multi-CVE exploit chains from intelligence sources | Paid |
| **VulnCheck KEV** | Broader than CISA KEV — more CVEs, faster updates | Community |
| **NVD++** | Faster NVD data processing (addresses NVD enrichment backlog) | Community |
| **Vulnerability categorization** | ICS/OT, IoT, and sector-specific tags | Partial |

## Timestamp Fields

- **Format:** RFC3339Nano — but with inconsistent trailing zeros
- **Example:** `2024-02-14T16:15:00Z` (zeros stripped variably)
- **Parsing:** Use multi-layout parser; don't rely on fixed nanosecond precision

## Pagination

- **Mechanism:** Cursor-based (details vary by endpoint)
- **Default:** 100 documents per page
- **Page size param:** Controllable (exact param name varies by endpoint)
- **Last page:** Empty `data` array or fewer results than page size

## Incremental Sync

- **Strategy:** Poll relevant indices with date-based filtering
- **NVD++ index:** Mirrors NVD's `lastModStartDate`/`lastModEndDate` pattern
- **VulnCheck KEV:** Poll for new entries since last sync
- **Exploit data:** Poll `exploits` index by CVE or date range

## Known Quirks

1. **RFC3339Nano timestamp inconsistency** — trailing zeros stripped variably from timestamps. `2024-02-14T16:15:00Z` vs `2024-02-14T16:15:00.000Z`. Use flexible parser.
2. **Token visibility** — tokens are only visible at creation time. Must regenerate if lost. Store securely.
3. **30-day inactivity expiry** — tokens expire after 30 days without use. Automated sync keeps tokens alive, but test environments may hit this.
4. **402 for unlicensed indices** — accessing paid-only indices with a community token returns 402, not 403. Handle distinctly.
5. **Community tier limitations** — no backup/bulk downloads, limited indices. Free tier covers NVD++ and VulnCheck KEV but not exploit intelligence or threat actor data.
6. **Multiple naming schemes for threat actors** — same group may appear under MITRE, MISP, CrowdStrike, Mandiant, and Microsoft names. Need normalization strategy.
7. **Vulnerability status field** — records include status: `Confirmed`, `Disputed`, `Pending`, `Rejected`, `Reserved`, `Unsupported`, `Unverifiable`. Map to CVErt Ops status enum.
8. **Commercial dependency** — free tier may change terms. Open-source project dependency on commercial API requires consideration.
9. **No webhook/push mechanism** — polling only.
10. **Batch POST endpoints** — up to 1,000 CVEs per request for enrichment lookups. Use this for bulk enrichment rather than per-CVE GET calls.

## Bulk Source

- **Backup downloads:** Available for paid tier only via `/v3/backup/{index}`
- **No community bulk download** — community tier must paginate through the API
- **NVD++:** Can serve as faster alternative to NVD API for initial corpus load

## Assessment for CVErt Ops

**Unique value:** Temporal CVSS, threat actor attribution, exploit chain data, broader KEV catalog, faster NVD processing. The enrichment data is genuinely novel — no other free source provides temporal CVSS or threat actor mappings.

**Implementation priority:** Tier 2 — valuable enrichment but commercial dependency is a concern for an open-source project. Community tier (NVD++ and VulnCheck KEV) is useful without paid subscription.

**Recommended approach:** Treat as optional enrichment source (like EPSS). Implement community-tier endpoints first (NVD++ for faster NVD data, VulnCheck KEV for broader exploitation signals). Paid-tier exploit intelligence as premium feature.

**Open question:** Whether to use NVD++ as a REPLACEMENT for direct NVD API consumption (faster, same data + enrichment) or as a supplementary source. Replacing NVD with VulnCheck introduces vendor lock-in.

## CVErt Ops Patterns Required

- [ ] Alias resolution — NOT required (uses standard CVE IDs)
- [x] Withdrawn tombstoning — `status == "Rejected"` → tombstone
- [ ] ZIP temp-file — NOT required
- [ ] NVD-specific patterns — NOT applicable (but NVD++ mirrors NVD structure)
- [ ] EPSS two-statement pattern — NOT applicable
- [x] Streaming JSON — paginated responses; stream large result sets
- [x] Multi-layout timestamp fallback — RFC3339Nano with variable precision
- [x] Enrichment-only mode — like EPSS, may update existing CVE records without creating new ones
- [x] Token management — secure storage, rotation on expiry, 30-day keepalive
