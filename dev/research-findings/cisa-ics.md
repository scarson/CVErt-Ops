# CISA ICS-CERT Advisories (CSAF) — Research Findings

> **Researched:** 2026-03-05
> **Agent:** manual research via WebSearch + WebFetch (feed-researcher agents blocked from web tools)
> **Sources:** [CISA ICS Advisories](https://www.cisa.gov/news-events/ics-advisories), [cisagov/CSAF GitHub](https://github.com/cisagov/CSAF), [CSAF Provider Metadata](https://www.cisa.gov/sites/default/files/csaf/provider-metadata.json), [CISA CSAF Announcement](https://www.cisa.gov/news-events/news/transforming-vulnerability-management-cisa-adds-oasis-csaf-20-standard-ics-advisories)

---

## API Overview

No REST API. Data is published as static CSAF 2.0 JSON files via a GitHub repository and ROLIE feed indexes.

- **GitHub repo:** `https://github.com/cisagov/CSAF`
- **Provider role:** `csaf_trusted_provider` (OASIS CSAF standard)
- **Auth:** None — public GitHub repository, TLP:WHITE classification
- **PGP signing:** Public key provided (fingerprint: `144AED0A57BE7D4AE835D9D8CAC5AC4F74164B17`)

## Feed Discovery (ROLIE)

Two ROLIE (Resource Oriented Lightweight Information Exchange) feed indexes:

| Category | Feed URL |
|---|---|
| **OT (Operational Technology)** | `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json` |
| **IT (Information Technology)** | `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/cisa-csaf-it-feed-tlp-white.json` |

Each feed index is a JSON file listing all available advisories with their URLs and metadata.

## Repository Structure

```
csaf_files/
├── OT/
│   └── white/
│       ├── cisa-csaf-ot-feed-tlp-white.json   (ROLIE feed index)
│       ├── 2017/
│       ├── 2018/
│       │   ...
│       └── 2026/
│           ├── icsa-26-001-01.json
│           └── ...
├── IT/
│   └── white/
│       ├── cisa-csaf-it-feed-tlp-white.json   (ROLIE feed index)
│       └── ...
tools/
└── csaf2md/                                    (JSON to Markdown converter)
```

- **Organization:** By category (OT/IT), then by year
- **File naming:** Advisory ID-based (e.g., `icsa-23-264-06.json`)
- **History:** Advisories dating back to 2017
- **Volume:** ~772 commits as of research date

## CSAF 2.0 Document Structure

Each advisory is a standard OASIS CSAF 2.0 JSON document:

| Section | Contents |
|---|---|
| `document` | Metadata: title, publisher, tracking, distribution |
| `document.tracking` | Version, status, dates, revision history |
| `product_tree` | Product taxonomy (vendor → product → version) |
| `vulnerabilities[]` | CVE details, scores, remediations, threats |

### Per-vulnerability fields:

| Field | Type | Notes |
|---|---|---|
| `cve` | string | CVE ID |
| `title` | string | Vulnerability title |
| `notes[]` | array | Description, summary |
| `scores[]` | array | CVSS scores per product |
| `remediations[]` | array | Vendor fixes, mitigations, workarounds |
| `threats[]` | array | Exploitability, impact |
| `references[]` | array | External links |
| `product_status` | object | `known_affected`, `known_not_affected`, `fixed` product lists |

## Rate Limits

- **GitHub raw content:** Standard GitHub rate limits apply (60/hr unauthenticated, 5,000/hr authenticated)
- **Feed indexes:** Single JSON file per category — one fetch per sync
- **Individual advisories:** One file per advisory — fetch only new/updated files

## Timestamp Fields

| Field | Format | Notes |
|---|---|---|
| `document.tracking.current_release_date` | ISO 8601 | Last revision — use as cursor |
| `document.tracking.initial_release_date` | ISO 8601 | Original publication date |
| `document.tracking.revision_history[].date` | ISO 8601 | Per-revision timestamps |
| ROLIE feed entry dates | ISO 8601 | In feed index metadata |

## Pagination

Not applicable — ROLIE feed index contains all advisory references in a single JSON file. Individual advisories are standalone files.

## Incremental Sync

- **Strategy:** Fetch ROLIE feed index, compare `current_release_date` for each entry against last sync cursor, fetch only new/updated advisory files
- **Cursor field:** `current_release_date` from ROLIE feed entries
- **Change detection:** Compare advisory IDs and dates in feed index against local state
- **Alternative:** Use GitHub API to detect commits to the `csaf_files/` directory since last sync
- **Cadence:** CISA publishes ICS advisories weekly (Tuesdays), with ad-hoc additions

## Known Quirks

1. **Git-based, not REST API** — no traditional API. Consumption is via raw GitHub URLs or git clone. GitHub API can be used for change detection but adds complexity.
2. **Two separate feed categories** — OT and IT advisories are in separate directories with separate ROLIE indexes. Must poll both.
3. **CSAF 2.0 standard format** — same format as Red Hat CSAF/VEX and Microsoft CSAF. Parser is reusable across all three sources.
4. **ICS/OT vendor taxonomy** — product trees reference ICS vendors (Siemens, Schneider Electric, Rockwell Automation, ABB, etc.) with ICS-specific product lines. Different from IT vendor naming.
5. **Advisory-centric, not CVE-centric** — one advisory may cover multiple CVEs. Must split into individual CVE records for merge pipeline.
6. **TLP:WHITE classification** — all published advisories are unrestricted. No access control concerns.
7. **PGP signatures available** — advisories can be verified against CISA's public PGP key. Optional but adds integrity verification.
8. **GitHub raw URL stability** — using `raw.githubusercontent.com` URLs on the `develop` branch. Branch rename or repo restructure would break URLs. Consider using GitHub API for more stable access.
9. **Volume is relatively low** — ICS advisories number in hundreds per year, not thousands. Sync is lightweight.
10. **Niche audience** — primarily valuable for organizations in critical infrastructure sectors (energy, water, manufacturing, transportation). Consider making this an opt-in feed.

## Bulk Source

- **Git clone:** `git clone https://github.com/cisagov/CSAF` provides all historical advisories
- **ROLIE feed indexes:** Each index file lists all advisories with URLs for full download
- **Initial sync:** Walk ROLIE feed index and fetch all advisory files

## Assessment for CVErt Ops

**Unique value:** ICS/SCADA/OT vulnerability advisories from the authoritative US government source. Covers vendor-specific impact assessments for industrial control systems that don't appear in general CVE feeds.

**Implementation priority:** Tier 2 — valuable for critical infrastructure users but niche. CSAF parser reusability with MSRC and Red Hat increases the return on investment.

**Recommended approach:** Implement as an opt-in feed. Share CSAF parser with MSRC and Red Hat adapters. Use ROLIE feed indexes for discovery, GitHub raw URLs for individual advisory files.

## CVErt Ops Patterns Required

- [ ] Alias resolution — NOT required (uses standard CVE IDs within CSAF documents)
- [x] Withdrawn tombstoning — check `document.tracking.status` for `"final"` vs retracted
- [ ] ZIP temp-file — NOT required
- [ ] NVD-specific patterns — NOT applicable
- [ ] EPSS two-statement pattern — NOT applicable
- [x] Streaming JSON — individual CSAF files are small; ROLIE index could be larger
- [x] Multi-layout timestamp fallback — `feed.ParseTimePtr()` for all timestamps
- [x] CSAF 2.0 parser — shared with MSRC and Red Hat adapters
- [x] Advisory-to-CVE splitting — one advisory → multiple CVE records
- [x] Opt-in configuration — not all users need ICS/OT data
