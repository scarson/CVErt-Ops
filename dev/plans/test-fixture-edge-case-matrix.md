# Test Fixture Edge Case Matrix

This document defines the corpus record categories needed for the test fixture corpus.
The selection agent reads this document, then filters captured feed data locally
to find real feed records matching each category.

## Target: 30-50 corpus records total

Most records should be CVE-backed. A small number may be feed-native advisories
without a CVE ID when required by the matrix (currently GHSA F1).

All categories are required unless explicitly marked optional.

Many records will cover multiple categories. Prefer records that hit 2+
categories simultaneously — this maximizes coverage with fewer fixtures.

## Categories

### Data Completeness
| ID | Category | What it tests | How to find in captured data |
|----|----------|--------------|----------------------------|
| C1 | Complete, well-formed | Happy path parsing | Any CVE with all fields populated |
| C2 | Missing CVSS entirely | Null/absent score handling | NVD pages: CVE with no `cvssMetricV31` or `cvssMetricV40` block |
| C3 | CVSS v4.0 present | v4 parsing path | NVD pages: CVE with `cvssMetricV40` block |
| C4 | CVSS v4.0 only (no v3) | v4 fallback when v3 absent | NVD pages: `cvssMetricV40` present, no `cvssMetricV31` or `cvssMetricV30` |
| C4A | CVSS score = 0.0 | Falsy-value preservation | GHSA pages, MSRC CSAF docs, OSV ZIP, or NVD pages: score exactly `0.0` |
| C5 | Multiple CWE IDs | CWE array handling | NVD pages: `weaknesses` array with 2+ entries |
| C6 | No description | Empty/null description | NVD pages: empty `descriptions` array or status=RESERVED |
| C7 | Multiple references (10+) | Large reference array | NVD pages: `references` array length >= 10 |
| C8 | CPE data present | AffectedCPEs parsing | NVD pages: `configurations` block populated |
| C9 | Unicode in description | String handling edge case | NVD pages: description containing non-ASCII characters |

### Status Edge Cases
| ID | Category | What it tests | How to find in captured data |
|----|----------|--------------|----------------------------|
| S1 | Rejected status | Alert evaluation status filter | NVD pages: `vulnStatus: "Rejected"` |
| S2 | RESERVED status | Incomplete CVE handling | MITRE ZIP: CVE with `state: "RESERVED"` |
| S3 | Disputed | Dispute flag handling | NVD pages: description containing `** DISPUTED **` |
| S4 | Withdrawn GHSA | Withdrawn status | GHSA pages: `withdrawn_at` non-null |

### Cross-Feed Overlap
| ID | Category | What it tests | How to find in captured data |
|----|----------|--------------|----------------------------|
| X1 | In NVD + GHSA + OSV | Multi-source merge | Cross-reference: CVE ID appears in NVD pages AND GHSA pages AND OSV ZIP |
| X2 | In NVD + KEV | KEV flag + merge | Cross-reference: CVE ID in NVD pages AND KEV catalog |
| X3 | In NVD + MSRC | CSAF parsing + merge | Cross-reference: CVE ID in NVD pages AND MSRC CSAF docs |
| X4 | In NVD + Red Hat | Vendor enrichment + merge | Cross-reference: CVE ID in NVD pages AND Red Hat details |
| X5 | In NVD + GHSA + OSV + KEV | Maximum overlap | Cross-reference across all four |

### Feed-Specific Edge Cases
| ID | Category | What it tests | How to find in captured data |
|----|----------|--------------|----------------------------|
| F1 | GHSA without CVE ID | Alias resolution, native ID as PK | GHSA pages: advisory where `cve_id` is null |
| F2 | OSV with non-CVE primary ID | Alias resolution, RUSTSEC/PYSEC as source_id | OSV ZIP: entry with ID like `RUSTSEC-*` and CVE in `aliases` |
| F3 | MSRC CSAF document | CSAF 2.0 parsing | MSRC captured CSAF doc (any) |
| F4 | Red Hat with fix available | Vendor enrichment fix_state | Red Hat details: `fix_state` non-empty |
| F5 | KEV entry with action required | KEV vendor enrichment | KEV catalog: entry with `requiredAction` field |

### EPSS Scoring
| ID | Category | What it tests | How to find in captured data |
|----|----------|--------------|----------------------------|
| E1 | High EPSS (>0.9) | EPSS evaluator threshold | EPSS CSV: sort by score descending, take top entries |
| E2 | Very low EPSS (<0.01) | Boundary behavior | EPSS CSV: entries with score < 0.01 |
| E3 | EPSS score = 0 (optional) | Zero-value handling | EPSS CSV: entry with score exactly 0 (if any exist) |

## Output Format

The agent produces the canonical manifest file at `dev/plans/test-fixture-manifest.json`:

```json
{
  "generated": "2026-03-11T14:30:00Z",
  "capture_date": "2026-03-11",
  "records": [
    {
      "cve_id": "CVE-2024-3094",
      "categories": ["X1", "X2", "X5", "E1"],
      "feeds": ["nvd", "mitre", "ghsa", "osv", "kev", "epss"],
      "why": "xz backdoor — maximum cross-feed overlap, KEV-listed, high EPSS"
    },
    {
      "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
      "categories": ["F1"],
      "feeds": ["ghsa"],
      "why": "GHSA advisory without a CVE ID; exercises feed-native selector path"
    }
  ],
  "category_coverage": {
    "C1": ["CVE-2024-3094"],
    "C2": ["CVE-..."]
  }
}
```

Each manifest record MUST set at least one selector. For this plan, that means
`cve_id` for normal CVE-backed records and `ghsa_id` for GHSA-native advisories
whose `cve_id` is null.

## Verification

After selection, every required category MUST have at least one record. Optional
categories should be covered when present in the captured data. The agent should
print a coverage summary showing required gaps separately from optional misses
and attempt to fill the required ones.
