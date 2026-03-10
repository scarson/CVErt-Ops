// ABOUTME: Store methods for site admin system endpoints (cross-org).
// ABOUTME: Cross-org audit log listing. All methods use withBypassTx.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// AdminAuditListParams holds the filter and pagination parameters for admin audit listing.
type AdminAuditListParams struct {
	OrgID           *uuid.UUID
	EntityType      string // empty = all
	Action          string // empty = all
	ActorID         *uuid.UUID
	CursorCreatedAt *time.Time
	CursorID        *uuid.UUID
	PageSize        int
}

// AdminListAuditEntries returns audit rows across all orgs with optional filters
// and keyset cursor pagination.
func (s *Store) AdminListAuditEntries(ctx context.Context, p AdminAuditListParams) ([]AuditRow, error) {
	var cursorCreatedAt sql.NullTime
	var cursorID uuid.NullUUID
	if p.CursorCreatedAt != nil {
		cursorCreatedAt = sql.NullTime{Time: *p.CursorCreatedAt, Valid: true}
	}
	if p.CursorID != nil {
		cursorID = uuid.NullUUID{UUID: *p.CursorID, Valid: true}
	}

	var result []AuditRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		rows, err := q.AdminListAuditEntries(ctx, generated.AdminListAuditEntriesParams{
			EntityType:      p.EntityType,
			Action:          p.Action,
			OrgID:           toNullUUID(p.OrgID),
			ActorID:         toNullUUID(p.ActorID),
			CursorCreatedAt: cursorCreatedAt,
			CursorID:        cursorID,
			PageSize:        int32(p.PageSize), //nolint:gosec // G115: page size is always small
		})
		if err != nil {
			return err
		}
		result = make([]AuditRow, len(rows))
		for i, r := range rows {
			result[i] = AuditRow{
				ID:         r.ID,
				OrgID:      r.OrgID,
				ActorID:    fromNullUUID(r.ActorID),
				ActorEmail: r.ActorEmail.String,
				Action:     r.Action,
				EntityType: r.EntityType,
				EntityID:   r.EntityID,
				EntityName: r.EntityName.String,
				Success:    r.Success,
				OldState:   r.OldState.RawMessage,
				NewState:   r.NewState.RawMessage,
				Metadata:   r.Metadata.RawMessage,
				CreatedAt:  r.CreatedAt,
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("admin list audit entries: %w", err)
	}
	return result, nil
}
