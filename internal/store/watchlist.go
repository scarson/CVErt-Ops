// ABOUTME: Store methods for watchlist and watchlist item management.
// ABOUTME: All methods are org-scoped; soft-delete preserves items for audit trails.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// WatchlistItemType re-exports the generated enum so callers only need to import this package.
type WatchlistItemType = generated.WatchlistItemType

// WatchlistItemRow is the watchlist item record returned by store methods.
type WatchlistItemRow = generated.WatchlistItem

// WatchlistRow extends a Watchlist with the count of active (non-deleted) items.
type WatchlistRow struct {
	generated.Watchlist
	ItemCount int64
}

// UpdateWatchlistParams holds the mutable fields for updating a watchlist.
type UpdateWatchlistParams struct {
	Name        string
	Description sql.NullString
	GroupID     uuid.NullUUID
}

// CreateWatchlistItemParams holds the fields for creating a watchlist item.
// Field validation (type-guard, ecosystem whitelist, CPE prefix) is the caller's responsibility.
type CreateWatchlistItemParams struct {
	ItemType      generated.WatchlistItemType
	Ecosystem     *string
	PackageName   *string
	Namespace     *string
	CpeNormalized *string
}

// WatchlistStore defines the DB operations needed by watchlist HTTP handlers.
type WatchlistStore interface {
	CreateWatchlist(ctx context.Context, orgID uuid.UUID, groupID uuid.NullUUID, name string, description sql.NullString) (*WatchlistRow, error)
	GetWatchlist(ctx context.Context, orgID, id uuid.UUID) (*WatchlistRow, error)
	ListWatchlists(ctx context.Context, orgID uuid.UUID, afterTime *time.Time, afterID *uuid.UUID, limit int) ([]WatchlistRow, error)
	UpdateWatchlist(ctx context.Context, orgID, id uuid.UUID, p UpdateWatchlistParams) (*generated.Watchlist, error)
	DeleteWatchlist(ctx context.Context, orgID, id uuid.UUID) error
	CountWatchlistItems(ctx context.Context, orgID, watchlistID uuid.UUID) (int64, error)
	CreateWatchlistItem(ctx context.Context, orgID, watchlistID uuid.UUID, p CreateWatchlistItemParams) (*generated.WatchlistItem, error)
	ListWatchlistItems(ctx context.Context, orgID, watchlistID uuid.UUID, itemType *WatchlistItemType, afterID *uuid.UUID, limit int) ([]generated.WatchlistItem, error)
	DeleteWatchlistItem(ctx context.Context, orgID, watchlistID, itemID uuid.UUID) error
	ValidateWatchlistsOwnership(ctx context.Context, orgID uuid.UUID, ids []uuid.UUID) (bool, error)
}

// CreateWatchlist inserts a new watchlist for the given org. Returns the created watchlist
// with ItemCount = 0.
func (s *Store) CreateWatchlist(ctx context.Context, orgID uuid.UUID, groupID uuid.NullUUID, name string, description sql.NullString) (*WatchlistRow, error) {
	var row generated.Watchlist
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		row, err = q.CreateWatchlist(ctx, generated.CreateWatchlistParams{
			OrgID:       orgID,
			GroupID:     groupID,
			Name:        name,
			Description: description,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create watchlist: %w", err)
	}
	return &WatchlistRow{Watchlist: row}, nil
}

// GetWatchlist returns the watchlist with the given id within orgID (including active item count),
// or (nil, nil) if not found or soft-deleted.
func (s *Store) GetWatchlist(ctx context.Context, orgID, id uuid.UUID) (*WatchlistRow, error) {
	var result *WatchlistRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.GetWatchlist(ctx, generated.GetWatchlistParams{ID: id, OrgID: orgID})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get watchlist: %w", err)
		}
		count, err := q.CountWatchlistItems(ctx, row.ID)
		if err != nil {
			return fmt.Errorf("count watchlist items: %w", err)
		}
		result = &WatchlistRow{Watchlist: row, ItemCount: count}
		return nil
	})
	return result, err
}

// ListWatchlists returns a page of non-deleted watchlists for an org ordered by
// created_at DESC, id DESC. Caller passes Limit+1 to detect whether a next page exists.
// afterTime and afterID are the cursor from the last item on the previous page.
func (s *Store) ListWatchlists(ctx context.Context, orgID uuid.UUID, afterTime *time.Time, afterID *uuid.UUID, limit int) ([]WatchlistRow, error) {
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
	sb := psql.
		Select("w.id, w.org_id, w.group_id, w.name, w.description, w.created_at, w.updated_at, w.deleted_at",
			"COUNT(wi.id) AS item_count").
		From("watchlists w").
		LeftJoin("watchlist_items wi ON wi.watchlist_id = w.id AND wi.deleted_at IS NULL").
		Where(sq.Eq{"w.org_id": orgID}).
		Where("w.deleted_at IS NULL").
		GroupBy("w.id").
		OrderBy("w.created_at DESC, w.id DESC").
		Limit(uint64(limit)) //nolint:gosec // G115: limit validated by caller

	if afterTime != nil && afterID != nil {
		sb = sb.Where("(w.created_at, w.id) < (?, ?)", *afterTime, *afterID)
	}

	query, args, err := sb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("list watchlists: build query: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list watchlists: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var result []WatchlistRow
	for rows.Next() {
		var r WatchlistRow
		if err := rows.Scan(
			&r.ID, &r.OrgID, &r.GroupID, &r.Name, &r.Description,
			&r.CreatedAt, &r.UpdatedAt, &r.DeletedAt,
			&r.ItemCount,
		); err != nil {
			return nil, fmt.Errorf("list watchlists: scan: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// UpdateWatchlist updates the mutable fields of a watchlist. Returns (nil, nil) if the
// watchlist is not found or has been soft-deleted.
func (s *Store) UpdateWatchlist(ctx context.Context, orgID, id uuid.UUID, p UpdateWatchlistParams) (*generated.Watchlist, error) {
	var result *generated.Watchlist
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.UpdateWatchlist(ctx, generated.UpdateWatchlistParams{
			ID:          id,
			OrgID:       orgID,
			Name:        p.Name,
			Description: p.Description,
			GroupID:     p.GroupID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("update watchlist: %w", err)
		}
		result = &row
		return nil
	})
	return result, err
}

// DeleteWatchlist soft-deletes a watchlist by setting deleted_at.
func (s *Store) DeleteWatchlist(ctx context.Context, orgID, id uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.SoftDeleteWatchlist(ctx, generated.SoftDeleteWatchlistParams{
			ID:    id,
			OrgID: orgID,
		}); err != nil {
			return fmt.Errorf("delete watchlist: %w", err)
		}
		return nil
	})
}

// CountWatchlistItems returns the number of active (non-deleted) items in a watchlist.
func (s *Store) CountWatchlistItems(ctx context.Context, orgID, watchlistID uuid.UUID) (int64, error) {
	var count int64
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		count, err = q.CountWatchlistItems(ctx, watchlistID)
		return err
	})
	return count, err
}

// CreateWatchlistItem inserts a new item into a watchlist. Returns the created item.
// The database partial unique index enforces item-level deduplication per watchlist.
func (s *Store) CreateWatchlistItem(ctx context.Context, orgID, watchlistID uuid.UUID, p CreateWatchlistItemParams) (*generated.WatchlistItem, error) {
	var row generated.WatchlistItem
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		row, err = q.CreateWatchlistItem(ctx, generated.CreateWatchlistItemParams{
			WatchlistID:   watchlistID,
			OrgID:         orgID,
			ItemType:      p.ItemType,
			Ecosystem:     nullString(p.Ecosystem),
			PackageName:   nullString(p.PackageName),
			Namespace:     nullString(p.Namespace),
			CpeNormalized: nullString(p.CpeNormalized),
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create watchlist item: %w", err)
	}
	return &row, nil
}

// ListWatchlistItems returns items for a watchlist, with an optional item_type filter.
// Paginated by id ASC; caller passes afterID from the last item to get the next page.
// Caller passes Limit+1 to detect whether a next page exists.
func (s *Store) ListWatchlistItems(ctx context.Context, orgID, watchlistID uuid.UUID, itemType *WatchlistItemType, afterID *uuid.UUID, limit int) ([]generated.WatchlistItem, error) {
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
	sb := psql.Select("id, watchlist_id, org_id, item_type, ecosystem, package_name, namespace, cpe_normalized, created_at, deleted_at").
		From("watchlist_items").
		Where(sq.Eq{"watchlist_id": watchlistID, "org_id": orgID}).
		Where("deleted_at IS NULL").
		OrderBy("id ASC").
		Limit(uint64(limit)) //nolint:gosec // G115: limit validated by caller

	if itemType != nil {
		sb = sb.Where(sq.Eq{"item_type": string(*itemType)})
	}
	if afterID != nil {
		sb = sb.Where(sq.Gt{"id": *afterID})
	}

	query, args, err := sb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("list watchlist items: build query: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list watchlist items: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var result []generated.WatchlistItem
	for rows.Next() {
		var item generated.WatchlistItem
		if err := rows.Scan(
			&item.ID, &item.WatchlistID, &item.OrgID, &item.ItemType,
			&item.Ecosystem, &item.PackageName, &item.Namespace, &item.CpeNormalized,
			&item.CreatedAt, &item.DeletedAt,
		); err != nil {
			return nil, fmt.Errorf("list watchlist items: scan: %w", err)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

// DeleteWatchlistItem soft-deletes an item from a watchlist.
func (s *Store) DeleteWatchlistItem(ctx context.Context, orgID, watchlistID, itemID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.SoftDeleteWatchlistItem(ctx, generated.SoftDeleteWatchlistItemParams{
			ID:          itemID,
			WatchlistID: watchlistID,
			OrgID:       orgID,
		}); err != nil {
			return fmt.Errorf("delete watchlist item: %w", err)
		}
		return nil
	})
}

// ValidateWatchlistsOwnership returns true if all given watchlist IDs belong to orgID
// and are not deleted. An empty slice returns true (vacuous truth).
func (s *Store) ValidateWatchlistsOwnership(ctx context.Context, orgID uuid.UUID, ids []uuid.UUID) (bool, error) {
	if len(ids) == 0 {
		return true, nil
	}
	var count int64
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		count, err = q.CountOwnedWatchlistsByIDs(ctx, generated.CountOwnedWatchlistsByIDsParams{
			Column1: ids,
			OrgID:   orgID,
		})
		return err
	})
	if err != nil {
		return false, fmt.Errorf("validate watchlists ownership: %w", err)
	}
	return count == int64(len(ids)), nil
}

// nullString converts a *string pointer to a sql.NullString.
func nullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{Valid: true, String: *s}
}
