# Vendor Feed Adapters Design — MSRC + Red Hat + Vendor Enrichment

> **Date:** 2026-03-05
> **Scope:** MSRC adapter, Red Hat adapter, shared CSAF parser, vendor enrichment table, KEV retrofit, merge pipeline changes

---

## Overview

Add two new vendor-specific feed adapters (Microsoft MSRC and Red Hat Security Data) and a vendor enrichment system to store vendor-specific metadata that doesn't fit the existing `CanonicalPatch` schema.

**Key decisions made during design:**
1. **Hybrid approach** — adapters implement `feed.Adapter` interface (standard fields through merge pipeline) AND store vendor-specific data in a new `cve_vendor_enrichment` table
2. **MSRC uses CSAF 2.0** format via a shared parser (`internal/feed/csaf/`)
3. **Red Hat uses REST API** (`/hydra/rest/securitydata/`) for better incremental sync
4. **Source precedence** — MSRC and Red Hat go at the end of all priority lists (after existing sources)
5. **KEV retrofit** — stop discarding vendor data, populate `VendorEnrichment` field

---

## 1. Vendor Enrichment Table

### Schema

```sql
-- migrate:no-transaction
-- ABOUTME: Creates cve_vendor_enrichment for vendor-specific CVE metadata.
-- ABOUTME: Global table — no RLS. Stores data from KEV, MSRC, Red Hat, etc.

CREATE TABLE IF NOT EXISTS cve_vendor_enrichment (
  id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id            TEXT        NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  source_name       TEXT        NOT NULL
                    CHECK (source_name IN ('kev', 'msrc', 'redhat')),
  vendor_severity   TEXT,
  vendor_fix_state  TEXT,
  enrichment        JSONB       NOT NULL DEFAULT '{}',
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(cve_id, source_name)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cve_vendor_enrichment_severity
    ON cve_vendor_enrichment (vendor_severity);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cve_vendor_enrichment_fix_state
    ON cve_vendor_enrichment (vendor_fix_state);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cve_vendor_enrichment_enrichment
    ON cve_vendor_enrichment USING gin (enrichment);

ALTER TABLE cve_vendor_enrichment SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_vacuum_cost_delay   = 2,
    fillfactor                     = 80
);

GRANT SELECT, INSERT, UPDATE ON cve_vendor_enrichment TO cvert_ops_app;
```

### Same migration adds CHECK constraint to existing `cve_sources`

```sql
ALTER TABLE cve_sources ADD CONSTRAINT cve_sources_source_name_check
    CHECK (source_name IN ('mitre', 'nvd', 'osv', 'ghsa', 'kev', 'msrc', 'redhat'));
```

### Design rationale

- **Common columns** (`vendor_severity`, `vendor_fix_state`) are indexed and queryable across all vendors
- **JSONB `enrichment`** stores per-vendor flexible data (KB articles, package NEVRAs, due dates, etc.)
- **No `org_id` / no RLS** — CVE data is global, same as `cves`, `cve_sources`, `cve_raw_payloads`
- **`ON DELETE CASCADE` from `cves`** — vendor enrichment cleaned up when CVE is deleted
- **Autovacuum tuned** for upsert workload (scale_factor=0.01, fillfactor=80)
- **GIN index on enrichment** — enables JSONB queries from day one

### Per-vendor enrichment JSONB contents

| Source | `vendor_severity` | `vendor_fix_state` | `enrichment` JSONB |
|---|---|---|---|
| KEV | — | — | `required_action`, `due_date`, `ransomware_use`, `vendor_project`, `product`, `notes` |
| MSRC | `"Critical"` etc | `"Vendor Fix"` etc | `kb_articles[]`, `exploitability`, `remediation_urls[]`, `supersedence`, `product_statuses{}` |
| Red Hat | `"important"` etc | `"Will not fix"` etc | `errata_id`, `fixed_package_nevra`, `bugzilla_url`, `mitigation`, `upstream_fix`, `cpe`, `affected_releases[]`, `package_states[]` |

---

## 2. CanonicalPatch Extension

```go
type CanonicalPatch struct {
    // ... all existing fields unchanged ...

    // VendorEnrichment holds vendor-specific data for the
    // cve_vendor_enrichment table. Only populated by vendor-specific
    // adapters (KEV, MSRC, Red Hat). Nil for generic feeds.
    VendorEnrichment *VendorEnrichment `json:"vendor_enrichment,omitempty"`
}

type VendorEnrichment struct {
    VendorSeverity *string         `json:"vendor_severity,omitempty"`
    VendorFixState *string         `json:"vendor_fix_state,omitempty"`
    Data           json.RawMessage `json:"data"`
}
```

- **Pointer field** — nil by default, existing adapters unaffected
- **NOT included in material_hash** — vendor data changes don't trigger alert re-evaluation
- **Stored in `cve_sources.normalized_json`** alongside standard fields (audit trail)
- **Written to `cve_vendor_enrichment`** by merge pipeline (structured queries)

---

## 3. Shared CSAF 2.0 Parser

**Package:** `internal/feed/csaf/`

Parses OASIS CSAF 2.0 JSON documents into typed Go structs. Consumed by MSRC adapter now and CISA ICS-CERT adapter later.

### Types

```go
type Document struct {
    DocumentMeta  DocumentMeta        `json:"document"`
    ProductTree   ProductTree         `json:"product_tree"`
    Vulnerabilities []Vulnerability   `json:"vulnerabilities"`
}

type DocumentMeta struct {
    Title      string   `json:"title"`
    Type       string   `json:"type"`
    Publisher  Publisher `json:"publisher"`
    Tracking   Tracking `json:"tracking"`
}

type Tracking struct {
    ID                string           `json:"id"`
    Status            string           `json:"status"`
    Version           string           `json:"version"`
    InitialReleaseDate string          `json:"initial_release_date"`
    CurrentReleaseDate string          `json:"current_release_date"`
    RevisionHistory   []RevisionEntry  `json:"revision_history"`
}

type ProductTree struct {
    Branches []Branch `json:"branches"`
}

type Branch struct {
    Category string   `json:"category"`
    Name     string   `json:"name"`
    Product  *Product `json:"product,omitempty"`
    Branches []Branch `json:"branches,omitempty"` // recursive
}

type Product struct {
    ProductID string `json:"product_id"`
    Name      string `json:"name"`
}

type Vulnerability struct {
    CVE             string          `json:"cve"`
    Title           string          `json:"title"`
    Notes           []Note          `json:"notes"`
    Scores          []Score         `json:"scores"`
    Remediations    []Remediation   `json:"remediations"`
    Threats         []Threat        `json:"threats"`
    ProductStatus   ProductStatus   `json:"product_status"`
    References      []Reference     `json:"references"`
    Acknowledgments []Acknowledgment `json:"acknowledgments"`
}
```

### API

```go
// Parse reads a CSAF 2.0 JSON document and returns the parsed structure.
// Reads the full document into memory (CSAF documents are typically <1MB).
func Parse(r io.Reader) (*Document, error)

// ProductTree.Lookup builds a map[ProductID]ProductName from the
// recursive branch tree. Call once after parsing.
func (pt *ProductTree) Lookup() map[string]string
```

**Full document read, not streaming:** CSAF documents require the product tree to be parsed before vulnerabilities can be resolved. At ~200-500KB per monthly release, reading into memory is appropriate.

---

## 4. MSRC Adapter

**Package:** `internal/feed/msrc/`

### Data flow

1. Poll `GET /updates` with OData filter `$filter=CurrentReleaseDate gt <cursor>` for new/updated releases
2. For each changed release ID (e.g., `2026-Mar`), fetch `GET /csaf/{id}` for CSAF 2.0 document
3. Parse with shared CSAF parser
4. Build product tree lookup map
5. Split into individual `CanonicalPatch` records (one per CVE)
6. Each patch includes `VendorEnrichment` with KB articles, exploitability, remediations

### Cursor

```json
{
  "last_release_date": "2026-03-10T00:00:00Z",
  "pending_release_ids": ["2026-Mar"]
}
```

Two-phase: first poll `/updates` for changed release IDs, then fetch CSAF for each. `pending_release_ids` enables mid-batch resumption.

### Configuration

- **Base URL:** `https://api.msrc.microsoft.com/cvrf/v3.0/`
- **Auth:** None
- **Rate limiter:** 1 req/sec with exponential backoff
- **Error detection:** Parse response body for "Too many follow-up requests" pattern (non-standard error format, HTTP status uncertain — handle both 429 and 503)

### Field mapping

| CSAF field | CanonicalPatch field | Notes |
|---|---|---|
| `vulnerability.cve` | `CVEID` | Standard CVE ID |
| `"msrc"` | `SourceID` | Constant |
| `vulnerability.notes[type=description]` | `DescriptionPrimary` | English description |
| `vulnerability.scores[].cvss_v3.baseScore` | `CVSSv3Score` | Take highest across products |
| `vulnerability.scores[].cvss_v3.vectorString` | `CVSSv3Vector` | Corresponding vector |
| `vulnerability.scores[].cvss_v4.baseScore` | `CVSSv4Score` | If available |
| `vulnerability.references[]` | `References` | Advisory URLs |
| `product_status.known_affected` | `AffectedCPEs` | Via product tree lookup |
| `tracking.current_release_date` | `DateModified` | Release revision date |

### Vendor enrichment mapping

| CSAF field | VendorEnrichment field |
|---|---|
| `threats[type=impact].description` | `VendorSeverity` (e.g., "Critical") |
| `remediations[type=vendor_fix].description` | `enrichment.kb_articles[]` |
| `remediations[].url` | `enrichment.remediation_urls[]` |
| `threats[type=exploit_status].description` | `enrichment.exploitability` (e.g., "Exploitation More Likely") |
| `remediations[].product_ids` | `enrichment.product_statuses` |

---

## 5. Red Hat Adapter

**Package:** `internal/feed/redhat/`

### Data flow

1. Poll `GET /cve.json?after=<cursor_date>&per_page=100&page=N` for recently modified CVEs
2. Paginate through all results (page-number pagination)
3. For each CVE in the list, fetch `GET /cve/{CVE-ID}.json` for detail record
4. Convert to `CanonicalPatch` with `VendorEnrichment`

### Cursor

```json
{
  "after_date": "2026-03-04",
  "detail_queue": ["CVE-2026-1234", "CVE-2026-1235"]
}
```

Two-phase: list discovers CVEs, detail fetches enrichment. `detail_queue` enables mid-batch resumption.

### Configuration

- **Base URL:** `https://access.redhat.com/hydra/rest/securitydata/`
- **Auth:** None
- **Rate limiter:** 2 req/sec with exponential backoff on 5xx
- **Compression:** Go's default HTTP client handles gzip automatically

### Field mapping

| REST API field | CanonicalPatch field | Notes |
|---|---|---|
| `name` / `CVE` | `CVEID` | Standard CVE ID |
| `"redhat"` | `SourceID` | Constant |
| `details[0]` | `DescriptionPrimary` | First description text |
| `cvss3.cvss3_base_score` | `CVSSv3Score` | Parsed from string |
| `cvss3.cvss3_scoring_vector` | `CVSSv3Vector` | CVSS v3 vector |
| `cwe` | `CWEIDs` | Single CWE ID |
| `public_date` | `DatePublished` | ISO 8601 |
| `bugzilla.url`, `references[]` | `References` | Bugzilla + external refs |
| `affected_release[].cpe` | `AffectedCPEs` | Per-product CPEs |

### Vendor enrichment mapping

| REST API field | VendorEnrichment field |
|---|---|
| `threat_severity` | `VendorSeverity` (e.g., "important") |
| `package_state[0].fix_state` | `VendorFixState` (primary/worst-case status) |
| `package_state[]` | `enrichment.package_states[]` (full per-product array) |
| `affected_release[]` | `enrichment.affected_releases[]` (errata, packages, CPEs) |
| `bugzilla.id`, `bugzilla.url` | `enrichment.bugzilla_id`, `enrichment.bugzilla_url` |
| `mitigation` | `enrichment.mitigation` |
| `upstream_fix` | `enrichment.upstream_fix` |

### Edge case handling

- **Detail endpoint 404:** Log warning and skip CVE (timing issue between list and detail fetch). Don't abort the sync.
- **Date-only cursor granularity:** `after` param accepts `YYYY-MM-DD` only. ≤24h overlap possible. Dedup handled by merge pipeline's upsert.
- **`VendorFixState` with mixed statuses:** When multiple products have different fix states, use the most severe: Affected > Will not fix > Fix deferred > Under investigation > Not affected.

---

## 6. Merge Pipeline Changes

### Source precedence update

```go
const SourceMSRC   = "msrc"
const SourceRedHat = "redhat"

statusPriority = [MITRE, NVD, OSV, GHSA, MSRC, REDHAT]
cvssPriority   = [NVD, OSV, GHSA, MITRE, MSRC, REDHAT]
pkgPriority    = [OSV, GHSA, NVD, MITRE, REDHAT, MSRC]
```

MSRC and Red Hat at the end — vendor assessments, not authoritative CVE analysis.

### Vendor enrichment upsert

Added to the merge pipeline transaction, after `cves` upsert:

```go
if patch.VendorEnrichment != nil {
    // INSERT INTO cve_vendor_enrichment (cve_id, source_name, vendor_severity, vendor_fix_state, enrichment)
    // VALUES ($1, $2, $3, $4, $5)
    // ON CONFLICT (cve_id, source_name) DO UPDATE SET
    //   vendor_severity = EXCLUDED.vendor_severity,
    //   vendor_fix_state = EXCLUDED.vendor_fix_state,
    //   enrichment = EXCLUDED.enrichment,
    //   updated_at = now()
    // WHERE enrichment IS DISTINCT FROM EXCLUDED.enrichment
    //    OR vendor_severity IS DISTINCT FROM EXCLUDED.vendor_severity
    //    OR vendor_fix_state IS DISTINCT FROM EXCLUDED.vendor_fix_state
}
```

Inside the advisory-lock transaction — ensures atomicity with the `cves` upsert.

---

## 7. KEV Retrofit

Minimal change — stop discarding vendor data:

```go
patch.VendorEnrichment = &feed.VendorEnrichment{
    Data: mustMarshal(map[string]any{
        "required_action":  rec.RequiredAction,
        "due_date":         rec.DueDate,
        "ransomware_use":   rec.KnownRansomwareCampaignUse == "Known",
        "vendor_project":   rec.VendorProject,
        "product":          rec.Product,
        "notes":            rec.Notes,
    }),
}
```

Existing KEV tests updated to verify `VendorEnrichment` is populated. No changes to existing test assertions for standard fields.

---

## 8. File Layout

```
internal/feed/
  ├── interface.go              # + VendorEnrichment type
  ├── csaf/
  │   ├── parser.go             # Shared CSAF 2.0 parser
  │   └── parser_test.go
  ├── msrc/
  │   ├── adapter.go            # MSRC CSAF adapter
  │   └── adapter_test.go
  ├── redhat/
  │   ├── adapter.go            # Red Hat REST API adapter
  │   └── adapter_test.go
  ├── kev/
  │   └── adapter.go            # + VendorEnrichment population (retrofit)
internal/merge/
  └── pipeline.go               # + vendor enrichment upsert step
internal/store/
  └── vendor_enrichment.go      # sqlc queries for cve_vendor_enrichment
migrations/
  └── 000NNN_*.up.sql           # New table + CHECK constraint on cve_sources
```

---

## 9. Testing Strategy

- **CSAF parser:** Unit tests with fixture CSAF documents (MSRC and CISA ICS samples)
- **MSRC adapter:** Unit tests with httptest server returning mock CSAF responses
- **Red Hat adapter:** Unit tests with httptest server returning mock list + detail responses
- **KEV retrofit:** Update existing tests for VendorEnrichment field
- **Merge pipeline:** Integration tests for vendor enrichment upsert
- **Migration:** Verify CHECK constraints, indexes, grants in integration tests

---

## 10. Non-Goals (Deferred)

- API endpoint for vendor enrichment data
- Vendor-specific alert DSL conditions
- Red Hat CSAF/VEX file consumption (REST API is primary)
- CISA ICS-CERT adapter (shared CSAF parser is ready for it)
- Cisco PSIRT, VulnCheck, ExploitDB, Linux Kernel CVE adapters
