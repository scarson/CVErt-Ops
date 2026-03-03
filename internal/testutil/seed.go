// ABOUTME: Test helpers for seeding CVE rows and other global test fixtures.
// ABOUTME: Use SeedTestCVE on *TestDB to insert minimal CVE rows for integration tests.
package testutil

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// SeedCVEOpts provides optional overrides when seeding a test CVE row.
// All fields default to sensible test values when nil/zero.
type SeedCVEOpts struct {
	Status                string
	DescriptionPrimary    string
	CvssV3Score           *float64
	EpssScore             *float64
	ExploitAvailable      bool
	InCisaKev             bool
	DateModifiedCanonical *time.Time
	MaterialHash          string
}

// SeedTestCVE inserts a minimal CVE row via the superuser connection.
// The cves table is global (no org_id, no RLS), so no bypass transaction is needed.
// Pass nil for opts to use defaults.
func (tdb *TestDB) SeedTestCVE(t *testing.T, cveID, severity string, opts *SeedCVEOpts) {
	t.Helper()
	ctx := context.Background()

	o := SeedCVEOpts{
		Status:             "published",
		DescriptionPrimary: "test description for " + cveID,
		MaterialHash:       "hash-" + cveID,
	}
	if opts != nil {
		if opts.Status != "" {
			o.Status = opts.Status
		}
		if opts.DescriptionPrimary != "" {
			o.DescriptionPrimary = opts.DescriptionPrimary
		}
		if opts.CvssV3Score != nil {
			o.CvssV3Score = opts.CvssV3Score
		}
		if opts.EpssScore != nil {
			o.EpssScore = opts.EpssScore
		}
		o.ExploitAvailable = opts.ExploitAvailable
		o.InCisaKev = opts.InCisaKev
		if opts.DateModifiedCanonical != nil {
			o.DateModifiedCanonical = opts.DateModifiedCanonical
		}
		if opts.MaterialHash != "" {
			o.MaterialHash = opts.MaterialHash
		}
	}

	var dateModCanonical time.Time
	if o.DateModifiedCanonical != nil {
		dateModCanonical = *o.DateModifiedCanonical
	} else {
		dateModCanonical = time.Now()
	}

	var cvssScore sql.NullFloat64
	if o.CvssV3Score != nil {
		cvssScore = sql.NullFloat64{Float64: *o.CvssV3Score, Valid: true}
	}
	var epssScore sql.NullFloat64
	if o.EpssScore != nil {
		epssScore = sql.NullFloat64{Float64: *o.EpssScore, Valid: true}
	}

	_, err := tdb.DB().ExecContext(ctx, `
		INSERT INTO cves (
			cve_id, status, severity, description_primary,
			cvss_v3_score, epss_score, exploit_available, in_cisa_kev,
			material_hash, date_modified_canonical
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (cve_id) DO UPDATE SET
			status = EXCLUDED.status,
			severity = EXCLUDED.severity,
			description_primary = EXCLUDED.description_primary,
			cvss_v3_score = EXCLUDED.cvss_v3_score,
			epss_score = EXCLUDED.epss_score,
			exploit_available = EXCLUDED.exploit_available,
			in_cisa_kev = EXCLUDED.in_cisa_kev,
			material_hash = EXCLUDED.material_hash,
			date_modified_canonical = EXCLUDED.date_modified_canonical`,
		cveID, o.Status, severity, o.DescriptionPrimary,
		cvssScore, epssScore, o.ExploitAvailable, o.InCisaKev,
		o.MaterialHash, dateModCanonical,
	)
	if err != nil {
		t.Fatalf("SeedTestCVE(%s): %v", cveID, err)
	}

	// Populate cve_search_index so FTS integration tests work with seeded CVEs.
	_, err = tdb.DB().ExecContext(ctx, `
		INSERT INTO cve_search_index (cve_id, fts_document)
		VALUES (
			$1,
			setweight(to_tsvector('english', coalesce($2::text, '')), 'A') ||
			setweight(to_tsvector($1::text), 'D')
		)
		ON CONFLICT (cve_id) DO UPDATE
			SET fts_document = EXCLUDED.fts_document
			WHERE cve_search_index.fts_document IS DISTINCT FROM EXCLUDED.fts_document`,
		cveID, o.DescriptionPrimary,
	)
	if err != nil {
		t.Fatalf("SeedTestCVE(%s) FTS index: %v", cveID, err)
	}
}
