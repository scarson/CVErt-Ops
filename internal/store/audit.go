// ABOUTME: Store methods for the append-only audit log.
// ABOUTME: Wraps sqlc-generated queries with org-scoped transaction helpers.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"

	"github.com/scarson/cvert-ops/internal/dbutil"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// AuditEntry holds the parameters for inserting an audit log row.
type AuditEntry struct {
	OrgID      uuid.UUID
	ActorID    *uuid.UUID
	ActorEmail string
	Action     string
	EntityType string
	EntityID   string
	EntityName string
	Success    bool
	OldState   json.RawMessage // nil means NULL
	NewState   json.RawMessage // nil means NULL
	Metadata   json.RawMessage // nil means NULL
}

// AuditRow represents a single audit log row returned from a query.
type AuditRow struct {
	ID         uuid.UUID       `json:"id"`
	OrgID      uuid.UUID       `json:"org_id"`
	ActorID    *uuid.UUID      `json:"actor_id,omitempty"`
	ActorEmail string          `json:"actor_email,omitempty"`
	Action     string          `json:"action"`
	EntityType string          `json:"entity_type"`
	EntityID   string          `json:"entity_id"`
	EntityName string          `json:"entity_name,omitempty"`
	Success    bool            `json:"success"`
	OldState   json.RawMessage `json:"old_state,omitempty"`
	NewState   json.RawMessage `json:"new_state,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
}

// AuditListParams holds the filter and pagination parameters for listing audit entries.
type AuditListParams struct {
	OrgID           uuid.UUID
	EntityType      string // empty = all
	Action          string // empty = all
	ActorID         *uuid.UUID
	After           time.Time
	Before          time.Time
	CursorCreatedAt *time.Time
	CursorID        *uuid.UUID
	PageSize        int
}

// InsertAuditEntry appends a single audit log row inside an org-scoped transaction.
func (s *Store) InsertAuditEntry(ctx context.Context, e AuditEntry) error {
	return s.withOrgTx(ctx, e.OrgID, func(q *generated.Queries) error {
		return q.InsertAuditEntry(ctx, generated.InsertAuditEntryParams{
			OrgID:      e.OrgID,
			ActorID:    toNullUUID(e.ActorID),
			ActorEmail: dbutil.NullString(e.ActorEmail),
			Action:     e.Action,
			EntityType: e.EntityType,
			EntityID:   e.EntityID,
			EntityName: dbutil.NullString(e.EntityName),
			Success:    e.Success,
			OldState:   toNullRawMessage(e.OldState),
			NewState:   toNullRawMessage(e.NewState),
			Metadata:   toNullRawMessage(e.Metadata),
		})
	})
}

// ListAuditEntries returns audit rows matching the given filters with keyset cursor pagination.
func (s *Store) ListAuditEntries(ctx context.Context, p AuditListParams) ([]AuditRow, error) {
	var cursorCreatedAt sql.NullTime
	var cursorID uuid.NullUUID
	if p.CursorCreatedAt != nil {
		cursorCreatedAt = sql.NullTime{Time: *p.CursorCreatedAt, Valid: true}
	}
	if p.CursorID != nil {
		cursorID = uuid.NullUUID{UUID: *p.CursorID, Valid: true}
	}

	var result []AuditRow
	err := s.withOrgTx(ctx, p.OrgID, func(q *generated.Queries) error {
		rows, err := q.ListAuditEntries(ctx, generated.ListAuditEntriesParams{
			OrgID:           p.OrgID,
			EntityType:      p.EntityType,
			Action:          p.Action,
			ActorID:         toNullUUID(p.ActorID),
			After:           p.After,
			Before:          p.Before,
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
		return nil, fmt.Errorf("list audit entries: %w", err)
	}
	return result, nil
}

// toNullUUID converts a *uuid.UUID to uuid.NullUUID.
func toNullUUID(v *uuid.UUID) uuid.NullUUID {
	if v == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *v, Valid: true}
}

// fromNullUUID converts uuid.NullUUID to *uuid.UUID.
func fromNullUUID(v uuid.NullUUID) *uuid.UUID {
	if !v.Valid {
		return nil
	}
	return &v.UUID
}

// toNullRawMessage converts json.RawMessage to pqtype.NullRawMessage.
func toNullRawMessage(v json.RawMessage) pqtype.NullRawMessage {
	if v == nil {
		return pqtype.NullRawMessage{}
	}
	return pqtype.NullRawMessage{RawMessage: v, Valid: true}
}
