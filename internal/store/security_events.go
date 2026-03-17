// ABOUTME: Store methods for inserting security events via withBypassTx.
// ABOUTME: Security events are not org-scoped by RLS, so bypass is appropriate.
package store

import (
	"context"
	"database/sql"
	"encoding/json"

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

// uuidOrZero dereferences a *uuid.UUID, returning uuid.Nil if nil.
func uuidOrZero(u *uuid.UUID) uuid.UUID {
	if u == nil {
		return uuid.Nil
	}
	return *u
}
