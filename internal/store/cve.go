package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/lib/pq"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// GetCVE returns the canonical CVE row for the given ID, or (nil, nil) if
// the CVE does not exist.
func (s *Store) GetCVE(ctx context.Context, cveID string) (*generated.Cfe, error) {
	row, err := s.q.GetCVE(ctx, cveID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// GetCVEDetail fetches the canonical CVE row plus all child tables in parallel
// queries. Returns (nil, nil, nil, nil, nil) when the CVE does not exist.
func (s *Store) GetCVEDetail(ctx context.Context, cveID string) (
	cve *generated.Cfe,
	refs []generated.CveReference,
	pkgs []generated.CveAffectedPackage,
	cpes []generated.CveAffectedCpe,
	err error,
) {
	cve, err = s.GetCVE(ctx, cveID)
	if err != nil || cve == nil {
		return nil, nil, nil, nil, err
	}
	refs, err = s.q.GetCVEReferences(ctx, cveID)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("get references: %w", err)
	}
	pkgs, err = s.q.GetCVEAffectedPackages(ctx, cveID)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("get affected packages: %w", err)
	}
	cpes, err = s.q.GetCVEAffectedCPEs(ctx, cveID)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("get affected CPEs: %w", err)
	}
	return cve, refs, pkgs, cpes, nil
}

// ListCVEs returns a page of CVE rows ordered by date_modified_canonical desc,
// cve_id. This is the base query for the no-filter paginated case; the API
// layer uses squirrel for dynamic filter queries.
func (s *Store) ListCVEs(ctx context.Context, limit, offset int32) ([]generated.Cfe, error) {
	return s.q.ListCVEs(ctx, generated.ListCVEsParams{Limit: limit, Offset: offset})
}

// GetCVESources returns all source rows for the given CVE, ordered by
// source_name. Used by the GET /cves/{id}/sources endpoint.
func (s *Store) GetCVESources(ctx context.Context, cveID string) ([]generated.CveSource, error) {
	return s.q.GetAllCVESources(ctx, cveID)
}

// SearchParams holds the parsed filter and pagination parameters for
// SearchCVEs. Cursor fields are pre-parsed from the opaque base64 cursor.
type SearchParams struct {
	Q            string
	Severity     []string
	CVSSMin      *float64
	CVSSMax      *float64
	DateFrom     *time.Time
	DateTo       *time.Time
	CWEID        *string
	Ecosystem    *string
	PackageName  *string
	InCISAKEV    *bool
	ExploitAvail *bool
	EPSSMin      *float64
	EPSSMax      *float64

	// Parsed from cursor: position of last item on previous page.
	// When non-nil, results start after this item.
	CursorDate  *time.Time
	CursorCVEID string

	// Limit is the page size. The caller may request Limit+1 rows to detect
	// whether a next page exists, then truncate to Limit before returning.
	Limit int
}

// SearchCVEs executes a dynamic filtered query using squirrel. It returns
// up to Limit+1 rows (caller detects next page by checking len > Limit).
//
// All filters are optional; a zero-value SearchParams returns the first page
// of all CVEs ordered by date_modified_canonical DESC, cve_id DESC.
//
// Keyset pagination: CursorDate + CursorCVEID encode the last seen row's sort
// position. For the nullable EPSS/date_published columns a COALESCE sentinel
// is applied to prevent NULL rows from disappearing (pitfall §pagination).
func (s *Store) SearchCVEs(ctx context.Context, p SearchParams) ([]generated.Cfe, error) {
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
	sb := psql.Select("c.*").From("cves c")

	// FTS search via cve_search_index.
	if p.Q != "" {
		sb = sb.
			Join("cve_search_index si ON c.cve_id = si.cve_id").
			Where("si.fts_document @@ websearch_to_tsquery('english', ?)", p.Q)
	}

	// Severity filter — IN ($1, $2, ...) is safe since severity has 5 possible values.
	if len(p.Severity) > 0 {
		sb = sb.Where(sq.Eq{"c.severity": p.Severity})
	}

	// CVSS score range.
	if p.CVSSMin != nil {
		// Prefer v4 score, fall back to v3. COALESCE so NULLs don't silently drop rows.
		sb = sb.Where("COALESCE(c.cvss_v4_score, c.cvss_v3_score) >= ?", *p.CVSSMin)
	}
	if p.CVSSMax != nil {
		sb = sb.Where("COALESCE(c.cvss_v4_score, c.cvss_v3_score) <= ?", *p.CVSSMax)
	}

	// Date range on date_modified_canonical.
	if p.DateFrom != nil {
		sb = sb.Where("c.date_modified_canonical >= ?", *p.DateFrom)
	}
	if p.DateTo != nil {
		sb = sb.Where("c.date_modified_canonical <= ?", *p.DateTo)
	}

	// CWE ID — array containment: $1 = ANY(c.cwe_ids).
	if p.CWEID != nil {
		sb = sb.Where("? = ANY(c.cwe_ids)", *p.CWEID)
	}

	// Ecosystem / package filter via EXISTS subquery to avoid duplicate rows
	// when a CVE affects multiple packages in the same ecosystem.
	if p.Ecosystem != nil {
		if p.PackageName != nil {
			sb = sb.Where(
				"EXISTS (SELECT 1 FROM cve_affected_packages p WHERE p.cve_id = c.cve_id AND p.ecosystem = ? AND p.package_name = ?)",
				*p.Ecosystem, *p.PackageName,
			)
		} else {
			sb = sb.Where(
				"EXISTS (SELECT 1 FROM cve_affected_packages p WHERE p.cve_id = c.cve_id AND p.ecosystem = ?)",
				*p.Ecosystem,
			)
		}
	}

	// Boolean flags.
	if p.InCISAKEV != nil {
		sb = sb.Where(sq.Eq{"c.in_cisa_kev": *p.InCISAKEV})
	}
	if p.ExploitAvail != nil {
		sb = sb.Where(sq.Eq{"c.exploit_available": *p.ExploitAvail})
	}

	// EPSS score range. COALESCE guards against NULL rows being dropped (pitfall §pagination).
	if p.EPSSMin != nil {
		sb = sb.Where("COALESCE(c.epss_score, -1) >= ?", *p.EPSSMin)
	}
	if p.EPSSMax != nil {
		sb = sb.Where("COALESCE(c.epss_score, 2) <= ?", *p.EPSSMax)
	}

	// Keyset cursor: WHERE (date_modified_canonical, cve_id) < (last_date, last_id)
	// Both columns are DESC; row comparison handles the composite tiebreak correctly.
	// (A, B) < (C, D) ≡ A < C OR (A = C AND B < D).
	if p.CursorDate != nil && p.CursorCVEID != "" {
		sb = sb.Where("(c.date_modified_canonical, c.cve_id) < (?, ?)", *p.CursorDate, p.CursorCVEID)
	}

	sb = sb.
		OrderBy("c.date_modified_canonical DESC, c.cve_id DESC").
		Limit(uint64(p.Limit)) //nolint:gosec // G115: Limit is validated as 1-101 by huma before reaching here

	query, args, err := sb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("store: build search query: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: search cves: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var results []generated.Cfe
	for rows.Next() {
		var c generated.Cfe
		if err := rows.Scan(
			&c.CveID,
			&c.Status,
			&c.DatePublished,
			&c.DateModifiedSourceMax,
			&c.DateModifiedCanonical,
			&c.DateFirstSeen,
			&c.DescriptionPrimary,
			&c.Severity,
			&c.CvssV3Score,
			&c.CvssV3Vector,
			&c.CvssV3Source,
			&c.CvssV4Score,
			&c.CvssV4Vector,
			&c.CvssV4Source,
			&c.CvssScoreDiverges,
			pq.Array(&c.CweIds),
			&c.ExploitAvailable,
			&c.InCisaKev,
			&c.EpssScore,
			&c.DateEpssUpdated,
			&c.MaterialHash,
		); err != nil {
			return nil, fmt.Errorf("store: scan cve row: %w", err)
		}
		results = append(results, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: rows error: %w", err)
	}

	return results, nil
}
