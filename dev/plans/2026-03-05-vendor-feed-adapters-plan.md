# Vendor Feed Adapters Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.
> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for every task — write failing tests first, verify failure, implement, verify pass.

**Goal:** Add MSRC and Red Hat vendor feed adapters with a shared vendor enrichment system, including a CSAF 2.0 parser, database migration, merge pipeline integration, and KEV retrofit.

**Architecture:** Hybrid approach — adapters implement `feed.Adapter` for standard CVE fields (flowing through the merge pipeline) and populate a `VendorEnrichment` struct for vendor-specific data (written to a new `cve_vendor_enrichment` table). A shared CSAF 2.0 parser (`internal/feed/csaf/`) serves the MSRC adapter now and future CISA ICS-CERT adapter later.

**Tech Stack:** Go 1.26, PostgreSQL 15+, sqlc, golang-migrate, `golang.org/x/time/rate`, `net/http/httptest`

**Design doc:** `dev/plans/2026-03-05-vendor-feed-adapters-design.md`

---

### Task 1: VendorEnrichment type on CanonicalPatch

Add the `VendorEnrichment` struct and field to `CanonicalPatch` in `internal/feed/interface.go`. This is the foundational type that all subsequent tasks depend on.

**Files:**
- Modify: `internal/feed/interface.go:49-68` (CanonicalPatch struct)
- Test: `internal/feed/util_test.go` (verify nil VendorEnrichment doesn't break existing JSON round-trip)

**Step 1: Write the failing test**

Add to `internal/feed/util_test.go`:

```go
func TestCanonicalPatch_VendorEnrichmentRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("nil vendor enrichment omitted from JSON", func(t *testing.T) {
		t.Parallel()
		p := feed.CanonicalPatch{CVEID: "CVE-2025-0001"}
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if strings.Contains(string(data), "vendor_enrichment") {
			t.Errorf("nil VendorEnrichment should be omitted, got %s", data)
		}
	})

	t.Run("populated vendor enrichment round-trips", func(t *testing.T) {
		t.Parallel()
		sev := "Critical"
		p := feed.CanonicalPatch{
			CVEID: "CVE-2025-0002",
			VendorEnrichment: &feed.VendorEnrichment{
				VendorSeverity: &sev,
				Data:           json.RawMessage(`{"kb":"KB12345"}`),
			},
		}
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var decoded feed.CanonicalPatch
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if decoded.VendorEnrichment == nil {
			t.Fatal("VendorEnrichment should not be nil after round-trip")
		}
		if decoded.VendorEnrichment.VendorSeverity == nil || *decoded.VendorEnrichment.VendorSeverity != "Critical" {
			t.Errorf("VendorSeverity = %v, want Critical", decoded.VendorEnrichment.VendorSeverity)
		}
	})
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/feed/ -run TestCanonicalPatch_VendorEnrichmentRoundTrip -v`
Expected: FAIL — `feed.VendorEnrichment` type does not exist

**Step 3: Write minimal implementation**

In `internal/feed/interface.go`, add after the `CanonicalPatch` struct (after line 68):

```go
// VendorEnrichment holds vendor-specific metadata that doesn't map to
// standard CanonicalPatch fields. Written to cve_vendor_enrichment by
// the merge pipeline. Only populated by vendor-specific adapters
// (KEV, MSRC, Red Hat).
type VendorEnrichment struct {
	VendorSeverity *string         `json:"vendor_severity,omitempty"`
	VendorFixState *string         `json:"vendor_fix_state,omitempty"`
	Data           json.RawMessage `json:"data"`
}
```

And add the field to `CanonicalPatch` (before `IsWithdrawn`):

```go
	VendorEnrichment *VendorEnrichment `json:"vendor_enrichment,omitempty"`
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/feed/ -run TestCanonicalPatch_VendorEnrichmentRoundTrip -v`
Expected: PASS

**Step 5: Run all existing feed tests to verify no regressions**

Run: `go test ./internal/feed/... -v`
Expected: All PASS — nil pointer field is backward compatible

**Step 6: Commit**

```bash
git add internal/feed/interface.go internal/feed/util_test.go
git commit -m "feat(feed): add VendorEnrichment type to CanonicalPatch"
```

---

### Task 2: Database migration — cve_vendor_enrichment table

Create the migration that adds the `cve_vendor_enrichment` table and a CHECK constraint on the existing `cve_sources.source_name` column.

**Files:**
- Create: `migrations/000029_vendor_enrichment.up.sql`
- Create: `migrations/000029_vendor_enrichment.down.sql`

**Step 1: Write the up migration**

Create `migrations/000029_vendor_enrichment.up.sql`:

```sql
-- migrate:no-transaction
-- ABOUTME: Creates cve_vendor_enrichment for vendor-specific CVE metadata.
-- ABOUTME: Adds CHECK constraints on source_name for both new and existing tables.

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

-- Add CHECK constraint to existing cve_sources table (validates existing source names).
ALTER TABLE cve_sources ADD CONSTRAINT cve_sources_source_name_check
    CHECK (source_name IN ('mitre', 'nvd', 'osv', 'ghsa', 'kev', 'epss', 'msrc', 'redhat'));
```

**Step 2: Write the down migration**

Create `migrations/000029_vendor_enrichment.down.sql`:

```sql
-- migrate:no-transaction
-- ABOUTME: Drops cve_vendor_enrichment and the CHECK constraint on cve_sources.

ALTER TABLE cve_sources DROP CONSTRAINT IF EXISTS cve_sources_source_name_check;

DROP INDEX CONCURRENTLY IF EXISTS idx_cve_vendor_enrichment_enrichment;
DROP INDEX CONCURRENTLY IF EXISTS idx_cve_vendor_enrichment_fix_state;
DROP INDEX CONCURRENTLY IF EXISTS idx_cve_vendor_enrichment_severity;

DROP TABLE IF EXISTS cve_vendor_enrichment;
```

**Step 3: Run the up migration**

Run: `migrate -path migrations -database "$DATABASE_URL" up`
Expected: Success, no errors

**Step 4: Verify table and constraints exist**

Run: `psql "$DATABASE_URL" -c "\d cve_vendor_enrichment"` and `psql "$DATABASE_URL" -c "\d cve_sources"` (or equivalent via the PostgreSQL MCP tool)
Expected: Table exists with all columns, indexes, and CHECK constraints

**Step 5: Test the down migration**

Run: `migrate -path migrations -database "$DATABASE_URL" down 1`
Expected: Table dropped, constraint removed

**Step 6: Re-run the up migration**

Run: `migrate -path migrations -database "$DATABASE_URL" up`
Expected: Success

**Step 7: Regenerate sqlc**

Run: `sqlc generate`
Expected: Success — sqlc reads migration files for schema awareness

**Step 8: Commit**

```bash
git add migrations/000029_vendor_enrichment.up.sql migrations/000029_vendor_enrichment.down.sql
git commit -m "feat(db): add cve_vendor_enrichment table and source_name CHECK constraints"
```

---

### Task 3: sqlc query for vendor enrichment upsert

Add the sqlc query that the merge pipeline will use to upsert vendor enrichment data.

**Files:**
- Create: `internal/store/queries/vendor_enrichment.sql`
- Modify: (auto-generated by sqlc) `internal/store/generated/`

**Step 1: Write the sqlc query file**

Create `internal/store/queries/vendor_enrichment.sql`:

```sql
-- name: UpsertVendorEnrichment :exec
-- ABOUTME: Upserts vendor-specific CVE enrichment data.
-- ABOUTME: IS DISTINCT FROM guard prevents dead tuples on no-op updates.
INSERT INTO cve_vendor_enrichment (
    cve_id, source_name, vendor_severity, vendor_fix_state, enrichment
)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (cve_id, source_name) DO UPDATE
    SET vendor_severity  = EXCLUDED.vendor_severity,
        vendor_fix_state = EXCLUDED.vendor_fix_state,
        enrichment       = EXCLUDED.enrichment,
        updated_at       = now()
    WHERE cve_vendor_enrichment.enrichment IS DISTINCT FROM EXCLUDED.enrichment
       OR cve_vendor_enrichment.vendor_severity IS DISTINCT FROM EXCLUDED.vendor_severity
       OR cve_vendor_enrichment.vendor_fix_state IS DISTINCT FROM EXCLUDED.vendor_fix_state;

-- name: GetVendorEnrichment :one
SELECT * FROM cve_vendor_enrichment
WHERE cve_id = $1 AND source_name = $2;

-- name: ListVendorEnrichmentByCVE :many
SELECT * FROM cve_vendor_enrichment
WHERE cve_id = $1
ORDER BY source_name;
```

**Step 2: Regenerate sqlc**

Run: `sqlc generate`
Expected: Success — new generated code in `internal/store/generated/`

**Step 3: Verify generated code compiles**

Run: `go build ./internal/store/...`
Expected: Success

**Step 4: Commit**

```bash
git add internal/store/queries/vendor_enrichment.sql internal/store/generated/
git commit -m "feat(store): add sqlc queries for cve_vendor_enrichment upsert"
```

---

### Task 4: Merge pipeline — vendor enrichment upsert step

Add the vendor enrichment upsert to the merge pipeline, between the CPE insert step (line 238) and the EPSS staging step (line 240).

**Files:**
- Modify: `internal/merge/pipeline.go:238-240` (insert new step between CPE and EPSS)
- Test: `internal/merge/pipeline_test.go` (or create if it doesn't exist)

**Step 1: Write the failing test**

The test should verify that when a `CanonicalPatch` has `VendorEnrichment` populated, the merge pipeline writes to `cve_vendor_enrichment`. This is an integration test that requires a real database. Check if `internal/merge/pipeline_test.go` exists. If there are existing integration tests for the pipeline, add a new test case. If not, write a focused unit-level test that verifies the pipeline calls the upsert.

The key assertion: after `Ingest()` with a patch containing `VendorEnrichment`, the `cve_vendor_enrichment` table has the correct row.

```go
func TestIngest_VendorEnrichment(t *testing.T) {
	// ... database setup ...
	sev := "Critical"
	patch := feed.CanonicalPatch{
		CVEID:    "CVE-2025-9999",
		SourceID: "CVE-2025-9999",
		VendorEnrichment: &feed.VendorEnrichment{
			VendorSeverity: &sev,
			Data:           json.RawMessage(`{"kb_articles":["KB12345"]}`),
		},
	}
	err := merge.Ingest(ctx, store, patch, "msrc", nil)
	// ... assert no error, then query cve_vendor_enrichment ...
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/merge/ -run TestIngest_VendorEnrichment -v`
Expected: FAIL — pipeline doesn't yet upsert vendor enrichment

**Step 3: Write the implementation**

In `internal/merge/pipeline.go`, add after the CPE insert loop (after line 238, before the EPSS staging comment):

```go
	// Step 8.5: upsert vendor enrichment (optional — only vendor-specific adapters populate this).
	if patch.VendorEnrichment != nil {
		enrichmentJSON := patch.VendorEnrichment.Data
		if enrichmentJSON == nil {
			enrichmentJSON = json.RawMessage(`{}`)
		}
		if err := q.UpsertVendorEnrichment(ctx, generated.UpsertVendorEnrichmentParams{
			CveID:           patch.CVEID,
			SourceName:      sourceName,
			VendorSeverity:  toNullString(derefString(patch.VendorEnrichment.VendorSeverity)),
			VendorFixState:  toNullString(derefString(patch.VendorEnrichment.VendorFixState)),
			Enrichment:      enrichmentJSON,
		}); err != nil {
			return fmt.Errorf("merge: upsert vendor enrichment: %w", err)
		}
	}
```

Note: `derefString` already exists in pipeline.go. `toNullString` already exists at the bottom of pipeline.go. The `generated.UpsertVendorEnrichmentParams` type is auto-generated from the sqlc query in Task 3. Check generated types — the JSONB column may map to `pqtype.NullRawMessage` or `json.RawMessage`; match accordingly.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/merge/ -run TestIngest_VendorEnrichment -v`
Expected: PASS

**Step 5: Run all merge tests**

Run: `go test ./internal/merge/... -v`
Expected: All PASS

**Step 6: Commit**

```bash
git add internal/merge/pipeline.go internal/merge/pipeline_test.go
git commit -m "feat(merge): add vendor enrichment upsert step to pipeline"
```

---

### Task 5: Source precedence update

Add MSRC and Red Hat source constants and update the priority lists.

**Files:**
- Modify: `internal/merge/resolve.go:17-37` (source constants and priority lists)
- Test: `internal/merge/resolve_test.go` (if it exists — verify resolution with new sources)

**Step 1: Write the failing test**

```go
func TestResolve_MSRCAndRedHatSourcesAtLowPriority(t *testing.T) {
	t.Parallel()

	// When MSRC and NVD both provide CVSS, NVD should win (higher priority).
	msrcScore := 9.8
	nvdScore := 8.1
	sources := []generated.CveSource{
		{SourceName: "msrc", NormalizedJson: mustMarshalJSON(feed.CanonicalPatch{
			CVEID: "CVE-2025-0001", CVSSv3Score: &msrcScore,
		})},
		{SourceName: "nvd", NormalizedJson: mustMarshalJSON(feed.CanonicalPatch{
			CVEID: "CVE-2025-0001", CVSSv3Score: &nvdScore,
		})},
	}
	resolved := resolve(sources)
	if resolved.CVSSv3Score == nil || *resolved.CVSSv3Score != 8.1 {
		t.Errorf("CVSSv3Score = %v, want 8.1 (NVD should take priority over MSRC)", resolved.CVSSv3Score)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/merge/ -run TestResolve_MSRCAndRedHatSourcesAtLowPriority -v`
Expected: FAIL — `SourceMSRC` and `SourceRedHat` constants don't exist, "msrc" not in priority lists

**Step 3: Write the implementation**

In `internal/merge/resolve.go`, add to the source constants block (after line 23):

```go
	SourceMSRC   = "msrc"
	SourceRedHat = "redhat"
```

Update the priority lists (lines 30-36):

```go
	statusPriority = []string{SourceMITRE, SourceNVD, SourceOSV, SourceGHSA, SourceMSRC, SourceRedHat}
	cvssPriority   = []string{SourceNVD, SourceOSV, SourceGHSA, SourceMITRE, SourceMSRC, SourceRedHat}
	pkgPriority    = []string{SourceOSV, SourceGHSA, SourceNVD, SourceMITRE, SourceRedHat, SourceMSRC}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/merge/ -run TestResolve_MSRCAndRedHatSourcesAtLowPriority -v`
Expected: PASS

**Step 5: Run all merge tests**

Run: `go test ./internal/merge/... -v`
Expected: All PASS

**Step 6: Commit**

```bash
git add internal/merge/resolve.go internal/merge/resolve_test.go
git commit -m "feat(merge): add MSRC and Red Hat source constants and priority"
```

---

### Task 6: KEV adapter retrofit — populate VendorEnrichment

Stop discarding KEV vendor data (VendorProject, Product, RequiredAction, DueDate, KnownRansomwareCampaignUse, Notes).

**Files:**
- Modify: `internal/feed/kev/adapter.go:251-281` (recordToPatch function)
- Modify: `internal/feed/kev/adapter_test.go` (update existing tests, add VendorEnrichment assertions)

**Step 1: Write the failing test**

Add a new test case to `TestRecordToPatch` in `internal/feed/kev/adapter_test.go`:

```go
{
	name: "vendor enrichment populated",
	rec: kevRecord{
		CVEID:                       "CVE-2024-5555",
		VendorProject:               "Acme",
		Product:                     "Widget",
		DateAdded:                   "2024-06-15",
		ShortDescription:            "RCE in Widget",
		RequiredAction:              "Apply update per vendor instructions",
		DueDate:                     "2024-07-15",
		KnownRansomwareCampaignUse:  "Known",
		Notes:                       "Patch available from vendor",
	},
	check: func(t *testing.T, p *feed.CanonicalPatch) {
		t.Helper()
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		if p.VendorEnrichment == nil {
			t.Fatal("VendorEnrichment should not be nil")
		}
		if p.VendorEnrichment.VendorSeverity != nil {
			t.Error("KEV does not set VendorSeverity")
		}
		if p.VendorEnrichment.VendorFixState != nil {
			t.Error("KEV does not set VendorFixState")
		}

		var data map[string]any
		if err := json.Unmarshal(p.VendorEnrichment.Data, &data); err != nil {
			t.Fatalf("unmarshal enrichment data: %v", err)
		}
		if data["required_action"] != "Apply update per vendor instructions" {
			t.Errorf("required_action = %v, want %q", data["required_action"], "Apply update per vendor instructions")
		}
		if data["due_date"] != "2024-07-15" {
			t.Errorf("due_date = %v, want %q", data["due_date"], "2024-07-15")
		}
		if data["ransomware_use"] != true {
			t.Errorf("ransomware_use = %v, want true", data["ransomware_use"])
		}
		if data["vendor_project"] != "Acme" {
			t.Errorf("vendor_project = %v, want %q", data["vendor_project"], "Acme")
		}
		if data["product"] != "Widget" {
			t.Errorf("product = %v, want %q", data["product"], "Widget")
		}
		if data["notes"] != "Patch available from vendor" {
			t.Errorf("notes = %v, want %q", data["notes"], "Patch available from vendor")
		}
	},
},
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/feed/kev/ -run TestRecordToPatch/vendor_enrichment_populated -v`
Expected: FAIL — `p.VendorEnrichment` is nil

**Step 3: Write the implementation**

In `internal/feed/kev/adapter.go`, add to the `recordToPatch` function (before the final `return patch`):

```go
	// Vendor enrichment — preserve KEV-specific fields that don't map to CanonicalPatch.
	enrichmentData, err := json.Marshal(map[string]any{
		"required_action": rec.RequiredAction,
		"due_date":        rec.DueDate,
		"ransomware_use":  rec.KnownRansomwareCampaignUse == "Known",
		"vendor_project":  rec.VendorProject,
		"product":         rec.Product,
		"notes":           rec.Notes,
	})
	if err == nil {
		patch.VendorEnrichment = &feed.VendorEnrichment{
			Data: enrichmentData,
		}
	}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/feed/kev/ -run TestRecordToPatch/vendor_enrichment_populated -v`
Expected: PASS

**Step 5: Run all KEV tests**

Run: `go test ./internal/feed/kev/ -v`
Expected: All PASS — existing tests shouldn't break (they don't assert `VendorEnrichment == nil`)

**Step 6: Commit**

```bash
git add internal/feed/kev/adapter.go internal/feed/kev/adapter_test.go
git commit -m "feat(kev): populate VendorEnrichment with KEV-specific data"
```

---

### Task 7: Shared CSAF 2.0 parser

Build the reusable CSAF 2.0 parser in `internal/feed/csaf/`. This is consumed by the MSRC adapter and will later be reused by CISA ICS-CERT.

**Files:**
- Create: `internal/feed/csaf/parser.go`
- Create: `internal/feed/csaf/parser_test.go`

**Step 1: Write the failing test**

Create `internal/feed/csaf/parser_test.go` with a test that parses a minimal CSAF document:

```go
// ABOUTME: Unit tests for the shared CSAF 2.0 parser.
// ABOUTME: Verifies document parsing and product tree lookup map construction.
package csaf

import (
	"strings"
	"testing"
)

const minimalCSAF = `{
  "document": {
    "title": "Test Advisory",
    "type": "csaf_security_advisory",
    "publisher": {"name": "Test Vendor", "namespace": "https://test.example.com"},
    "tracking": {
      "id": "TEST-2025-001",
      "status": "final",
      "version": "1.0",
      "initial_release_date": "2025-01-15T00:00:00Z",
      "current_release_date": "2025-02-01T00:00:00Z",
      "revision_history": [
        {"date": "2025-01-15T00:00:00Z", "number": "1.0", "summary": "Initial release"}
      ]
    }
  },
  "product_tree": {
    "branches": [
      {
        "category": "vendor",
        "name": "Test Vendor",
        "branches": [
          {
            "category": "product_name",
            "name": "Widget Pro",
            "branches": [
              {
                "category": "product_version",
                "name": "1.0",
                "product": {
                  "product_id": "WIDGET-PRO-1.0",
                  "name": "Test Vendor Widget Pro 1.0"
                }
              }
            ]
          }
        ]
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2025-0001",
      "title": "Widget Pro Remote Code Execution",
      "notes": [
        {"type": "description", "text": "A remote code execution vulnerability exists."}
      ],
      "scores": [
        {
          "cvss_v3": {
            "version": "3.1",
            "baseScore": 9.8,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "products": ["WIDGET-PRO-1.0"]
        }
      ],
      "product_status": {
        "known_affected": ["WIDGET-PRO-1.0"]
      },
      "remediations": [
        {
          "category": "vendor_fix",
          "details": "Update to version 1.1",
          "url": "https://test.example.com/advisory/001",
          "product_ids": ["WIDGET-PRO-1.0"]
        }
      ],
      "threats": [
        {
          "category": "impact",
          "details": "Critical"
        }
      ],
      "references": [
        {"url": "https://test.example.com/cve/2025-0001", "summary": "Advisory page"}
      ]
    }
  ]
}`

func TestParse_MinimalDocument(t *testing.T) {
	t.Parallel()

	doc, err := Parse(strings.NewReader(minimalCSAF))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if doc.DocumentMeta.Title != "Test Advisory" {
		t.Errorf("Title = %q, want %q", doc.DocumentMeta.Title, "Test Advisory")
	}
	if doc.DocumentMeta.Tracking.ID != "TEST-2025-001" {
		t.Errorf("Tracking.ID = %q, want %q", doc.DocumentMeta.Tracking.ID, "TEST-2025-001")
	}
	if doc.DocumentMeta.Tracking.Status != "final" {
		t.Errorf("Tracking.Status = %q, want %q", doc.DocumentMeta.Tracking.Status, "final")
	}
	if doc.DocumentMeta.Tracking.CurrentReleaseDate != "2025-02-01T00:00:00Z" {
		t.Errorf("CurrentReleaseDate = %q, want %q", doc.DocumentMeta.Tracking.CurrentReleaseDate, "2025-02-01T00:00:00Z")
	}
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("len(Vulnerabilities) = %d, want 1", len(doc.Vulnerabilities))
	}
	vuln := doc.Vulnerabilities[0]
	if vuln.CVE != "CVE-2025-0001" {
		t.Errorf("CVE = %q, want %q", vuln.CVE, "CVE-2025-0001")
	}
	if vuln.Title != "Widget Pro Remote Code Execution" {
		t.Errorf("Title = %q, want %q", vuln.Title, "Widget Pro Remote Code Execution")
	}
	if len(vuln.Scores) != 1 {
		t.Fatalf("len(Scores) = %d, want 1", len(vuln.Scores))
	}
	if vuln.Scores[0].CVSSv3.BaseScore != 9.8 {
		t.Errorf("CVSSv3.BaseScore = %v, want 9.8", vuln.Scores[0].CVSSv3.BaseScore)
	}
}

func TestProductTree_Lookup(t *testing.T) {
	t.Parallel()

	doc, err := Parse(strings.NewReader(minimalCSAF))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	lookup := doc.ProductTree.Lookup()
	name, ok := lookup["WIDGET-PRO-1.0"]
	if !ok {
		t.Fatal("product WIDGET-PRO-1.0 not found in lookup")
	}
	if name != "Test Vendor Widget Pro 1.0" {
		t.Errorf("product name = %q, want %q", name, "Test Vendor Widget Pro 1.0")
	}
}

func TestParse_EmptyDocument(t *testing.T) {
	t.Parallel()

	doc, err := Parse(strings.NewReader(`{"document":{"title":"Empty","tracking":{"id":"E"}}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.DocumentMeta.Title != "Empty" {
		t.Errorf("Title = %q, want %q", doc.DocumentMeta.Title, "Empty")
	}
	if len(doc.Vulnerabilities) != 0 {
		t.Errorf("len(Vulnerabilities) = %d, want 0", len(doc.Vulnerabilities))
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := Parse(strings.NewReader(`{not valid json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestProductTree_NestedBranches(t *testing.T) {
	t.Parallel()

	// Test deeply nested branches (vendor > product_family > product_name > product_version)
	doc, err := Parse(strings.NewReader(`{
		"document": {"title": "T", "tracking": {"id": "T"}},
		"product_tree": {
			"branches": [{
				"category": "vendor",
				"name": "Vendor A",
				"branches": [{
					"category": "product_family",
					"name": "Family X",
					"branches": [
						{
							"category": "product_name",
							"name": "Product Y",
							"product": {"product_id": "PY", "name": "Vendor A Family X Product Y"}
						},
						{
							"category": "product_name",
							"name": "Product Z",
							"branches": [{
								"category": "product_version",
								"name": "2.0",
								"product": {"product_id": "PZ-2.0", "name": "Vendor A Family X Product Z 2.0"}
							}]
						}
					]
				}]
			}]
		}
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	lookup := doc.ProductTree.Lookup()
	if len(lookup) != 2 {
		t.Fatalf("len(lookup) = %d, want 2", len(lookup))
	}
	if lookup["PY"] != "Vendor A Family X Product Y" {
		t.Errorf("PY = %q, want %q", lookup["PY"], "Vendor A Family X Product Y")
	}
	if lookup["PZ-2.0"] != "Vendor A Family X Product Z 2.0" {
		t.Errorf("PZ-2.0 = %q, want %q", lookup["PZ-2.0"], "Vendor A Family X Product Z 2.0")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/feed/csaf/ -v`
Expected: FAIL — package doesn't exist

**Step 3: Write the implementation**

Create `internal/feed/csaf/parser.go`:

```go
// ABOUTME: Shared OASIS CSAF 2.0 JSON document parser.
// ABOUTME: Consumed by MSRC adapter (and later CISA ICS-CERT).
package csaf

import (
	"encoding/json"
	"fmt"
	"io"
)

// Document is the top-level CSAF 2.0 JSON structure.
type Document struct {
	DocumentMeta    DocumentMeta    `json:"document"`
	ProductTree     ProductTree     `json:"product_tree"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// DocumentMeta holds CSAF document-level metadata.
type DocumentMeta struct {
	Title     string   `json:"title"`
	Type      string   `json:"type"`
	Publisher Publisher `json:"publisher"`
	Tracking  Tracking `json:"tracking"`
}

// Publisher identifies the advisory issuer.
type Publisher struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// Tracking holds document versioning and release dates.
type Tracking struct {
	ID                 string          `json:"id"`
	Status             string          `json:"status"`
	Version            string          `json:"version"`
	InitialReleaseDate string          `json:"initial_release_date"`
	CurrentReleaseDate string          `json:"current_release_date"`
	RevisionHistory    []RevisionEntry `json:"revision_history"`
}

// RevisionEntry records a single revision in the document history.
type RevisionEntry struct {
	Date    string `json:"date"`
	Number  string `json:"number"`
	Summary string `json:"summary"`
}

// ProductTree contains the hierarchical product taxonomy.
type ProductTree struct {
	Branches []Branch `json:"branches"`
}

// Branch is a recursive node in the product tree.
type Branch struct {
	Category string   `json:"category"`
	Name     string   `json:"name"`
	Product  *Product `json:"product,omitempty"`
	Branches []Branch `json:"branches,omitempty"`
}

// Product is a leaf node in the product tree with a unique ID.
type Product struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
}

// Vulnerability describes a single CVE within the CSAF document.
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

// Note is a typed text annotation on a vulnerability.
type Note struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Score holds CVSS scoring data for a set of products.
type Score struct {
	CVSSv3   *CVSSv3  `json:"cvss_v3,omitempty"`
	CVSSv4   *CVSSv4  `json:"cvss_v4,omitempty"`
	Products []string `json:"products"`
}

// CVSSv3 holds CVSS v3.x scoring.
type CVSSv3 struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
}

// CVSSv4 holds CVSS v4.0 scoring.
type CVSSv4 struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
}

// Remediation describes a fix or workaround.
type Remediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	URL        string   `json:"url"`
	ProductIDs []string `json:"product_ids"`
}

// Threat describes impact or exploit status for a vulnerability.
type Threat struct {
	Category string `json:"category"`
	Details  string `json:"details"`
}

// ProductStatus groups product IDs by their vulnerability status.
type ProductStatus struct {
	KnownAffected    []string `json:"known_affected"`
	KnownNotAffected []string `json:"known_not_affected"`
	Fixed            []string `json:"fixed"`
}

// Reference is an external link related to a vulnerability.
type Reference struct {
	URL     string `json:"url"`
	Summary string `json:"summary"`
}

// Acknowledgment credits a reporter or contributor.
type Acknowledgment struct {
	Names []string `json:"names"`
}

// Parse reads a CSAF 2.0 JSON document from r and returns the parsed structure.
// CSAF documents are typically <1MB; reading into memory is appropriate.
func Parse(r io.Reader) (*Document, error) {
	var doc Document
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("csaf: parse document: %w", err)
	}
	return &doc, nil
}

// Lookup builds a map from ProductID to product Name by walking the recursive
// branch tree. Call once after parsing to resolve product IDs referenced in
// vulnerability sections.
func (pt *ProductTree) Lookup() map[string]string {
	m := make(map[string]string)
	for _, b := range pt.Branches {
		walkBranches(b, m)
	}
	return m
}

// walkBranches recursively walks a branch tree, collecting product ID → name
// mappings from leaf nodes.
func walkBranches(b Branch, m map[string]string) {
	if b.Product != nil {
		m[b.Product.ProductID] = b.Product.Name
	}
	for _, child := range b.Branches {
		walkBranches(child, m)
	}
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/feed/csaf/ -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add internal/feed/csaf/parser.go internal/feed/csaf/parser_test.go
git commit -m "feat(csaf): add shared OASIS CSAF 2.0 parser"
```

---

### Task 8: MSRC adapter

Implement the Microsoft Security Response Center feed adapter using the CSAF 2.0 parser.

**Files:**
- Create: `internal/feed/msrc/adapter.go`
- Create: `internal/feed/msrc/adapter_test.go`

This is the largest task. Break it into sub-steps:

**Step 1: Write the failing test for update discovery**

Create `internal/feed/msrc/adapter_test.go`:

```go
// ABOUTME: Unit tests for the MSRC CSAF feed adapter.
// ABOUTME: Covers update discovery, CSAF parsing, and CanonicalPatch conversion.
package msrc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed"
)

func TestParseUpdates(t *testing.T) {
	t.Parallel()

	body := `{"@odata.context":"...","value":[
		{"ID":"2025-Jan","Alias":"2025-Jan","DocumentTitle":"January 2025","Severity":null,
		 "InitialReleaseDate":"2025-01-14T08:00:00Z","CurrentReleaseDate":"2025-01-16T08:00:00Z",
		 "CvrfUrl":"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2025-Jan"},
		{"ID":"2025-Feb","Alias":"2025-Feb","DocumentTitle":"February 2025","Severity":null,
		 "InitialReleaseDate":"2025-02-11T08:00:00Z","CurrentReleaseDate":"2025-02-11T08:00:00Z",
		 "CvrfUrl":"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2025-Feb"}
	]}`

	updates, err := parseUpdates([]byte(body))
	if err != nil {
		t.Fatalf("parseUpdates: %v", err)
	}
	if len(updates) != 2 {
		t.Fatalf("len(updates) = %d, want 2", len(updates))
	}
	if updates[0].ID != "2025-Jan" {
		t.Errorf("updates[0].ID = %q, want %q", updates[0].ID, "2025-Jan")
	}
	if updates[1].ID != "2025-Feb" {
		t.Errorf("updates[1].ID = %q, want %q", updates[1].ID, "2025-Feb")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/feed/msrc/ -v`
Expected: FAIL — package doesn't exist

**Step 3: Write the MSRC adapter implementation**

Create `internal/feed/msrc/adapter.go`. This is a substantial file — key sections:

1. **Constants and types**: `SourceName = "msrc"`, `Cursor` struct (two-phase: `LastReleaseDate` + `PendingReleaseIDs`), `Adapter` struct with `client` and `limiter`
2. **Constructor**: `New(client *http.Client) *Adapter` — creates rate limiter (1 req/sec)
3. **Fetch method**: Two-phase — first poll `/updates` filtered by cursor date for changed release IDs, then fetch `GET /csaf/{id}` for each, parse with CSAF parser, convert to patches
4. **parseUpdates**: Parses the `/updates` OData JSON response
5. **csafToPatches**: Converts a parsed CSAF Document into `[]CanonicalPatch`, each with `VendorEnrichment`

Key implementation details:
- Base URL: `https://api.msrc.microsoft.com/cvrf/v3.0/`
- No auth required
- Rate limiter: `rate.NewLimiter(rate.Every(time.Second), 1)`
- CSAF endpoint: `GET /csaf/{releaseID}` (not `/cvrf/`)
- Updates endpoint: `GET /updates` with OData `$filter=CurrentReleaseDate gt datetime'{cursor}'`
- Error detection: Check for "Too many follow-up requests" in response body on both 429 and 503
- Backoff: Exponential with jitter on rate limit errors

Field mapping in `csafToPatches`:
- `vuln.CVE` → `CVEID`
- `SourceName` → `SourceID`
- `vuln.Notes[type=description]` → `DescriptionPrimary`
- `vuln.Scores[].CVSSv3.BaseScore` → `CVSSv3Score` (take highest across products)
- `vuln.Scores[].CVSSv3.VectorString` → `CVSSv3Vector`
- `vuln.Threats[category=impact].Details` → `VendorEnrichment.VendorSeverity`
- `vuln.Threats[category=exploit_status].Details` → `enrichment.exploitability`
- `vuln.Remediations[]` → `enrichment.kb_articles[]`, `enrichment.remediation_urls[]`
- `vuln.ProductStatus.KnownAffected` → `AffectedCPEs` (via product tree lookup)
- `tracking.CurrentReleaseDate` → `DateModified`
- `tracking.InitialReleaseDate` → `DatePublished`

**Step 4: Write more tests**

Add to `adapter_test.go`:
- `TestCSAFToPatches` — test conversion of a minimal CSAF document with one vulnerability
- `TestCSAFToPatches_MultipleVulnerabilities` — multiple CVEs in one CSAF doc
- `TestCSAFToPatches_VendorEnrichment` — verify KB articles, exploitability, severity in enrichment
- `TestCSAFToPatches_HighestCVSSAcrossProducts` — when multiple scores exist, take highest
- `TestFetch_Success` — httptest server returning updates + CSAF, verify end-to-end
- `TestFetch_ShortCircuit` — cursor matches latest release date, no work done
- `TestFetch_HTTPError` — server returns 500

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/feed/msrc/ -v`
Expected: All PASS

**Step 6: Run lint**

Run: `golangci-lint run ./internal/feed/msrc/...`
Expected: Clean

**Step 7: Commit**

```bash
git add internal/feed/msrc/adapter.go internal/feed/msrc/adapter_test.go
git commit -m "feat(msrc): add MSRC CSAF feed adapter"
```

---

### Task 9: Red Hat adapter

Implement the Red Hat Security Data API feed adapter using the REST API.

**Files:**
- Create: `internal/feed/redhat/adapter.go`
- Create: `internal/feed/redhat/adapter_test.go`

**Step 1: Write the failing test for list parsing**

Create `internal/feed/redhat/adapter_test.go`:

```go
// ABOUTME: Unit tests for the Red Hat Security Data API feed adapter.
// ABOUTME: Covers list parsing, detail parsing, CanonicalPatch conversion, and Fetch end-to-end.
package redhat

import (
	"encoding/json"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed"
)

func TestParseListResponse(t *testing.T) {
	t.Parallel()

	body := `[
		{"CVE":"CVE-2025-0001","severity":"important","public_date":"2025-01-15T00:00:00Z",
		 "advisories":["RHSA-2025:0001"],"cvss_score":8.8,"resource_url":"https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2025-0001.json"},
		{"CVE":"CVE-2025-0002","severity":"moderate","public_date":"2025-01-16T00:00:00Z",
		 "advisories":[],"cvss_score":5.5,"resource_url":"https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2025-0002.json"}
	]`

	entries, err := parseListResponse([]byte(body))
	if err != nil {
		t.Fatalf("parseListResponse: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].CVE != "CVE-2025-0001" {
		t.Errorf("entries[0].CVE = %q, want %q", entries[0].CVE, "CVE-2025-0001")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/feed/redhat/ -v`
Expected: FAIL — package doesn't exist

**Step 3: Write the Red Hat adapter implementation**

Create `internal/feed/redhat/adapter.go`. Key sections:

1. **Constants and types**: `SourceName = "redhat"`, `Cursor` struct (two-phase: `AfterDate` + `DetailQueue` + `Page`), `Adapter` struct
2. **Constructor**: `New(client *http.Client) *Adapter`
3. **Fetch method**: Two-phase — paginate through `GET /cve.json?after={date}&per_page=100&page=N` for list, then fetch `GET /cve/{CVE-ID}.json` for each; `DetailQueue` enables mid-batch resumption
4. **parseListResponse**: Parses the list endpoint JSON array
5. **parseDetailResponse**: Parses the detail endpoint JSON object
6. **detailToPatches**: Converts a detail response into a `CanonicalPatch` with `VendorEnrichment`

Key implementation details:
- Base URL: `https://access.redhat.com/hydra/rest/securitydata/`
- No auth required
- Rate limiter: `rate.NewLimiter(rate.Every(500*time.Millisecond), 1)` (2 req/sec)
- List endpoint: `GET /cve.json?after={YYYY-MM-DD}&per_page=100&page={N}`
- Detail endpoint: `GET /cve/{CVE-ID}.json`
- Handle 404 on detail endpoint: log warning, skip CVE
- VendorFixState priority: Affected > Will not fix > Fix deferred > Under investigation > Not affected

Field mapping in `detailToPatch`:
- `name` → `CVEID`
- `SourceName` → `SourceID`
- `details[0]` → `DescriptionPrimary`
- `cvss3.cvss3_base_score` → `CVSSv3Score` (parse from string)
- `cvss3.cvss3_scoring_vector` → `CVSSv3Vector`
- `cwe` → `CWEIDs` (single element)
- `public_date` → `DatePublished`
- `threat_severity` → `VendorEnrichment.VendorSeverity`
- `package_state[].fix_state` → `VendorEnrichment.VendorFixState` (worst-case)
- `bugzilla`, `affected_release[]`, `package_state[]`, `mitigation`, `upstream_fix` → `VendorEnrichment.Data`

**Step 4: Write more tests**

Add to `adapter_test.go`:
- `TestParseDetailResponse` — parse a full detail JSON with all fields
- `TestDetailToPatch` — verify CanonicalPatch field mapping
- `TestDetailToPatch_VendorEnrichment` — verify vendor severity, fix state, enrichment data
- `TestDetailToPatch_WorstCaseFixState` — mixed package states, "Affected" wins
- `TestDetailToPatch_CVSSParsing` — CVSS score from string, vector string
- `TestDetailToPatch_MissingFields` — graceful handling of absent optional fields
- `TestFetch_Success` — httptest server, list + detail endpoints, verify end-to-end
- `TestFetch_DetailNotFound` — 404 on detail endpoint skips CVE without error
- `TestFetch_Pagination` — multiple pages from list endpoint

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/feed/redhat/ -v`
Expected: All PASS

**Step 6: Run lint**

Run: `golangci-lint run ./internal/feed/redhat/...`
Expected: Clean

**Step 7: Commit**

```bash
git add internal/feed/redhat/adapter.go internal/feed/redhat/adapter_test.go
git commit -m "feat(redhat): add Red Hat Security Data API feed adapter"
```

---

### Task 10: Configuration — feed registration

Add MSRC and Red Hat to the feed registration system so the worker knows about them.

**Files:**
- Modify: The file that registers feed adapters with the worker/scheduler (find by searching for where existing adapters like `kev.New` are called)

**Step 1: Find the feed registration code**

Search for where `kev.New(` or `nvd.New(` is called to register adapters. This is likely in `cmd/cvert-ops/` or `internal/worker/`.

**Step 2: Register new adapters**

Add imports for `internal/feed/msrc` and `internal/feed/redhat`, then register them alongside existing adapters:

```go
import (
	"github.com/scarson/cvert-ops/internal/feed/msrc"
	"github.com/scarson/cvert-ops/internal/feed/redhat"
)

// In the adapter registration section:
adapters["msrc"] = msrc.New(httpClient)
adapters["redhat"] = redhat.New(httpClient)
```

**Step 3: Verify the application builds**

Run: `go build ./cmd/cvert-ops/`
Expected: Success

**Step 4: Commit**

```bash
git add <modified files>
git commit -m "feat(worker): register MSRC and Red Hat feed adapters"
```

---

### Task 11: Integration smoke test

Run the full test suite and lint to verify everything works together.

**Step 1: Run all tests**

Run: `go test ./... -count=1`
Expected: All PASS

**Step 2: Run linter**

Run: `golangci-lint run`
Expected: Clean (or only pre-existing issues)

**Step 3: Verify build**

Run: `go build ./cmd/cvert-ops/`
Expected: Success

**Step 4: Commit any remaining fixes**

If any tests or lint issues were found and fixed, commit the fixes.

---

### Dependency Order

```
Task 1 (VendorEnrichment type)
  ├── Task 2 (migration) ─── Task 3 (sqlc queries) ─── Task 4 (merge pipeline upsert)
  ├── Task 5 (source precedence)
  ├── Task 6 (KEV retrofit)
  ├── Task 7 (CSAF parser) ─── Task 8 (MSRC adapter)
  └── Task 9 (Red Hat adapter)

Task 10 (feed registration) depends on Tasks 8 and 9
Task 11 (integration) depends on all above
```

Tasks 2+3+4, 5, 6, 7, and 9 are independent of each other after Task 1 completes. Tasks 7→8 are sequential (MSRC depends on CSAF parser). Task 10 needs both adapters.
