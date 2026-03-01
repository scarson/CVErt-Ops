// ABOUTME: Store methods for saved search CRUD with soft-delete.
// ABOUTME: Supports private (user-only) and org-shared visibility with RLS.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// SavedSearchRow is the saved search record returned by store methods.
type SavedSearchRow struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	UserID    uuid.NullUUID
	Name      string
	QueryJSON json.RawMessage
	NlQuery   sql.NullString
	IsShared  bool
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt sql.NullTime
}

// CreateSavedSearchParams holds the fields for creating a saved search.
type CreateSavedSearchParams struct {
	UserID    uuid.NullUUID
	Name      string
	QueryJSON json.RawMessage
	NlQuery   *string
	IsShared  bool
}

// UpdateSavedSearchParams holds the fields for updating a saved search.
type UpdateSavedSearchParams struct {
	Name      string
	QueryJSON json.RawMessage
	NlQuery   *string
	IsShared  bool
}

func savedSearchFromGenerated(g generated.SavedSearch) SavedSearchRow {
	return SavedSearchRow{
		ID:        g.ID,
		OrgID:     g.OrgID,
		UserID:    g.UserID,
		Name:      g.Name,
		QueryJSON: g.QueryJson,
		NlQuery:   g.NlQuery,
		IsShared:  g.IsShared,
		CreatedAt: g.CreatedAt,
		UpdatedAt: g.UpdatedAt,
		DeletedAt: g.DeletedAt,
	}
}

// CreateSavedSearch inserts a new saved search for the given org.
func (s *Store) CreateSavedSearch(ctx context.Context, orgID uuid.UUID, p CreateSavedSearchParams) (*SavedSearchRow, error) {
	var result *SavedSearchRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.CreateSavedSearch(ctx, generated.CreateSavedSearchParams{
			OrgID:     orgID,
			UserID:    p.UserID,
			Name:      p.Name,
			QueryJson: p.QueryJSON,
			NlQuery:   nullString(p.NlQuery),
			IsShared:  p.IsShared,
		})
		if err != nil {
			return fmt.Errorf("create saved search: %w", err)
		}
		r := savedSearchFromGenerated(row)
		result = &r
		return nil
	})
	return result, err
}

// GetSavedSearch returns the saved search with the given id within orgID,
// or (nil, nil) if not found or soft-deleted.
func (s *Store) GetSavedSearch(ctx context.Context, orgID, id uuid.UUID) (*SavedSearchRow, error) {
	var result *SavedSearchRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.GetSavedSearch(ctx, generated.GetSavedSearchParams{
			ID:    id,
			OrgID: orgID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get saved search: %w", err)
		}
		r := savedSearchFromGenerated(row)
		result = &r
		return nil
	})
	return result, err
}

// ListSavedSearches returns saved searches visible to the given user.
// visibility must be "private", "shared", or "all". limit caps the result count.
func (s *Store) ListSavedSearches(ctx context.Context, orgID, userID uuid.UUID, visibility string, limit int) ([]SavedSearchRow, error) {
	var result []SavedSearchRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		rows, err := q.ListSavedSearches(ctx, generated.ListSavedSearchesParams{
			OrgID:       orgID,
			UserID:      userID,
			Visibility:  visibility,
			ResultLimit: int32(limit), //nolint:gosec // G115: limit is validated as 1-200 by handler
		})
		if err != nil {
			return fmt.Errorf("list saved searches: %w", err)
		}
		result = make([]SavedSearchRow, len(rows))
		for i, r := range rows {
			result[i] = savedSearchFromGenerated(r)
		}
		return nil
	})
	return result, err
}

// UpdateSavedSearch updates a saved search. Returns (nil, nil) if not found or soft-deleted.
func (s *Store) UpdateSavedSearch(ctx context.Context, orgID, id uuid.UUID, p UpdateSavedSearchParams) (*SavedSearchRow, error) {
	var result *SavedSearchRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.UpdateSavedSearch(ctx, generated.UpdateSavedSearchParams{
			ID:        id,
			OrgID:     orgID,
			Name:      p.Name,
			QueryJson: p.QueryJSON,
			NlQuery:   nullString(p.NlQuery),
			IsShared:  p.IsShared,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("update saved search: %w", err)
		}
		r := savedSearchFromGenerated(row)
		result = &r
		return nil
	})
	return result, err
}

// SoftDeleteSavedSearch marks a saved search as deleted.
func (s *Store) SoftDeleteSavedSearch(ctx context.Context, orgID, id uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.SoftDeleteSavedSearch(ctx, generated.SoftDeleteSavedSearchParams{
			ID:    id,
			OrgID: orgID,
		})
	})
}

// CleanupOrphanedPrivateSavedSearches hard-deletes all private saved searches
// owned by the given user. Uses bypass-RLS (worker/CLI path) since it operates
// across orgs.
func (s *Store) CleanupOrphanedPrivateSavedSearches(ctx context.Context, userID uuid.UUID) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.CleanupOrphanedPrivateSavedSearches(ctx, uuid.NullUUID{UUID: userID, Valid: true})
	})
}
