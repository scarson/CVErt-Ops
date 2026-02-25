package store

import (
	"context"
	"database/sql"
	"errors"

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
