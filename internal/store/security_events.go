// ABOUTME: Store methods for inserting security events via withBypassTx.
// ABOUTME: Security events are not org-scoped by RLS, so bypass is appropriate.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// InsertSecurityEventParams holds the domain-level parameters for a security event.
type InsertSecurityEventParams struct {
	EventType  string
	Severity   string
	ActorIP    string
	ActorEmail string
	UserID     *uuid.UUID
	OrgID      *uuid.UUID
	Details    map[string]any
}

// InsertSecurityEvent writes a security event row. Uses withBypassTx because
// security_events is a global table without org-scoped RLS.
func (s *Store) InsertSecurityEvent(ctx context.Context, p InsertSecurityEventParams) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		var details pqtype.NullRawMessage
		if p.Details != nil {
			raw, err := json.Marshal(p.Details)
			if err != nil {
				return err
			}
			details = pqtype.NullRawMessage{RawMessage: raw, Valid: true}
		}

		return q.InsertSecurityEvent(ctx, generated.InsertSecurityEventParams{
			EventType: p.EventType,
			Severity:  p.Severity,
			ActorIp: sql.NullString{
				String: p.ActorIP,
				Valid:  p.ActorIP != "",
			},
			ActorEmail: sql.NullString{
				String: p.ActorEmail,
				Valid:  p.ActorEmail != "",
			},
			UserID: uuid.NullUUID{
				UUID:  uuidOrZero(p.UserID),
				Valid: p.UserID != nil,
			},
			OrgID: uuid.NullUUID{
				UUID:  uuidOrZero(p.OrgID),
				Valid: p.OrgID != nil,
			},
			Details: details,
		})
	})
}

// SecurityEventRow is the API-friendly representation of a security event.
type SecurityEventRow struct {
	ID         uuid.UUID        `json:"id"`
	EventType  string           `json:"event_type"`
	Severity   string           `json:"severity"`
	ActorIP    string           `json:"actor_ip,omitempty"`
	ActorEmail string           `json:"actor_email,omitempty"`
	UserID     *uuid.UUID       `json:"user_id,omitempty"`
	OrgID      *uuid.UUID       `json:"org_id,omitempty"`
	Details    json.RawMessage  `json:"details,omitempty"`
	CreatedAt  time.Time        `json:"created_at"`
}

// listSecurityEventsQuery is the raw SQL for listing security events.
// Uses nullable parameters so that unset filters correctly evaluate to NULL.
// Keyset pagination uses composite cursor (created_at, id) to avoid skipping
// rows with identical timestamps.
const listSecurityEventsQuery = `
SELECT id, event_type, severity, actor_ip, actor_email, user_id, org_id, details, created_at
FROM security_events
WHERE
    ($1::text IS NULL OR event_type = $1) AND
    ($2::text IS NULL OR severity = $2) AND
    ($3::text IS NULL OR actor_email = $3) AND
    ($4::timestamptz IS NULL OR created_at >= $4) AND
    ($5::timestamptz IS NULL OR created_at <= $5) AND
    ($6::timestamptz IS NULL OR (created_at < $6 OR (created_at = $6 AND id < $7)))
ORDER BY created_at DESC, id DESC
LIMIT $8
`

// ListSecurityEvents returns security events with optional filters and cursor pagination.
// Uses withBypassRawTx with nullable params because the sqlc-generated types
// use non-nullable Go types that don't produce SQL NULL in simple protocol mode.
func (s *Store) ListSecurityEvents(ctx context.Context, eventType, severity, actorEmail string, since, until, cursorTime *time.Time, cursorID *uuid.UUID, limit int) ([]SecurityEventRow, error) {
	// Convert Go strings/times to sql.Null* so empty/nil values become SQL NULL.
	eventTypeP := sql.NullString{String: eventType, Valid: eventType != ""}
	severityP := sql.NullString{String: severity, Valid: severity != ""}
	actorEmailP := sql.NullString{String: actorEmail, Valid: actorEmail != ""}
	sinceP := sql.NullTime{}
	if since != nil {
		sinceP = sql.NullTime{Time: *since, Valid: true}
	}
	untilP := sql.NullTime{}
	if until != nil {
		untilP = sql.NullTime{Time: *until, Valid: true}
	}
	cursorP := sql.NullTime{}
	if cursorTime != nil {
		cursorP = sql.NullTime{Time: *cursorTime, Valid: true}
	}
	cursorIDP := uuid.NullUUID{}
	if cursorID != nil {
		cursorIDP = uuid.NullUUID{UUID: *cursorID, Valid: true}
	}

	var result []SecurityEventRow
	err := s.withBypassRawTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, listSecurityEventsQuery,
			eventTypeP, severityP, actorEmailP, sinceP, untilP, cursorP, cursorIDP, limit)
		if err != nil {
			return err
		}
		defer rows.Close() //nolint:errcheck // best-effort close in deferred position

		for rows.Next() {
			var (
				row        SecurityEventRow
				actorIP    sql.NullString
				actorEmail sql.NullString
				userID     uuid.NullUUID
				orgID      uuid.NullUUID
				details    pqtype.NullRawMessage
			)
			if err := rows.Scan(&row.ID, &row.EventType, &row.Severity,
				&actorIP, &actorEmail, &userID, &orgID, &details, &row.CreatedAt); err != nil {
				return err
			}
			row.ActorIP = actorIP.String
			row.ActorEmail = actorEmail.String
			if userID.Valid {
				uid := userID.UUID
				row.UserID = &uid
			}
			if orgID.Valid {
				oid := orgID.UUID
				row.OrgID = &oid
			}
			if details.Valid {
				row.Details = details.RawMessage
			}
			result = append(result, row)
		}
		return rows.Err()
	})
	return result, err
}

// uuidOrZero dereferences a *uuid.UUID, returning uuid.Nil if nil.
func uuidOrZero(u *uuid.UUID) uuid.UUID {
	if u == nil {
		return uuid.Nil
	}
	return *u
}
