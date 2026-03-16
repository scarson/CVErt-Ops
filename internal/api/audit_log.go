// ABOUTME: HTTP handler for listing audit log entries with RBAC and enterprise tier gating.
// ABOUTME: Supports keyset cursor pagination and filtering by entity_type, action, actor_id, and date range.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/tier"
)

type auditLogListEntry struct {
	ID         string          `json:"id"`
	ActorID    *string         `json:"actor_id,omitempty"`
	ActorEmail string          `json:"actor_email"`
	Action     string          `json:"action"`
	EntityType string          `json:"entity_type"`
	EntityID   string          `json:"entity_id"`
	EntityName string          `json:"entity_name,omitempty"`
	Success    bool            `json:"success"`
	OldState   json.RawMessage `json:"old_state,omitempty"`
	NewState   json.RawMessage `json:"new_state,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	CreatedAt  string          `json:"created_at"`
}

// auditLogCursor is the JSON-encoded keyset cursor for audit log pagination.
type auditLogCursor struct {
	T  string `json:"t"`  // created_at RFC3339Nano
	ID string `json:"id"` // UUID tiebreaker
}

// listAuditLogHandler handles GET /api/v1/orgs/{org_id}/audit-log.
// Requires admin+ role and enterprise tier. Supports keyset cursor pagination.
func (srv *Server) listAuditLogHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	// Enterprise tier gating.
	resolver, ok := r.Context().Value(ctxTierResolver).(*tier.Resolver)
	if !ok {
		slog.ErrorContext(r.Context(), "audit log: tier resolver missing from context")
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if resolver.Tier != "enterprise" {
		writeProblemTyped(w, http.StatusForbidden, problemTypeTierLimit, "audit log requires enterprise tier")
		return
	}

	// Parse pagination limit.
	limit := 100
	if s := r.URL.Query().Get("limit"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 {
			writeProblem(w, http.StatusBadRequest, "invalid limit")
			return
		}
		if v > 200 {
			v = 200
		}
		limit = v
	}

	p := store.AuditListParams{
		OrgID:    orgID,
		PageSize: limit + 1, // fetch one extra to detect next page
	}

	// Parse optional filters.
	if s := r.URL.Query().Get("entity_type"); s != "" {
		p.EntityType = s
	}
	if s := r.URL.Query().Get("action"); s != "" {
		p.Action = s
	}
	if s := r.URL.Query().Get("actor_id"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid actor_id")
			return
		}
		p.ActorID = &id
	}

	// Parse date range (defaults to last 30 days).
	if s := r.URL.Query().Get("after"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid after (RFC3339)")
			return
		}
		p.After = t
	} else {
		p.After = time.Now().Add(-30 * 24 * time.Hour)
	}
	if s := r.URL.Query().Get("before"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid before (RFC3339)")
			return
		}
		p.Before = t
	} else {
		p.Before = time.Now().Add(1 * time.Hour)
	}

	// Parse keyset cursor.
	if c := r.URL.Query().Get("cursor"); c != "" {
		var cur auditLogCursor
		if err := decodePageCursor(c, &cur); err == nil {
			t, tErr := time.Parse(time.RFC3339Nano, cur.T)
			id, idErr := uuid.Parse(cur.ID)
			if tErr == nil && idErr == nil {
				p.CursorCreatedAt = &t
				p.CursorID = &id
			}
		}
	}

	rows, err := srv.store.ListAuditEntries(r.Context(), p)
	if err != nil {
		slog.ErrorContext(r.Context(), "list audit entries", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Detect next page.
	var nextCursor string
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		nextCursor = encodePageCursor(auditLogCursor{
			T:  last.CreatedAt.UTC().Format(time.RFC3339Nano),
			ID: last.ID.String(),
		})
	}

	items := make([]auditLogListEntry, 0, len(rows))
	for _, row := range rows {
		entry := auditLogListEntry{
			ID:         row.ID.String(),
			ActorEmail: row.ActorEmail,
			Action:     row.Action,
			EntityType: row.EntityType,
			EntityID:   row.EntityID,
			EntityName: row.EntityName,
			Success:    row.Success,
			OldState:   row.OldState,
			NewState:   row.NewState,
			Metadata:   row.Metadata,
			CreatedAt:  row.CreatedAt.Format(time.RFC3339),
		}
		if row.ActorID != nil {
			s := row.ActorID.String()
			entry.ActorID = &s
		}
		items = append(items, entry)
	}

	writeList(w, items, nextCursor)
}
