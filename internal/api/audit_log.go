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

type auditLogListResponse struct {
	Items      []auditLogListEntry `json:"items"`
	NextCursor *string             `json:"next_cursor,omitempty"`
}

// listAuditLogHandler handles GET /api/v1/orgs/{org_id}/audit-log.
// Requires admin+ role and enterprise tier. Supports keyset cursor pagination.
func (srv *Server) listAuditLogHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Enterprise tier gating.
	resolver, ok := r.Context().Value(ctxTierResolver).(*tier.Resolver)
	if !ok {
		slog.ErrorContext(r.Context(), "audit log: tier resolver missing from context")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if resolver.Tier != "enterprise" {
		http.Error(w, "audit log requires enterprise tier", http.StatusForbidden)
		return
	}

	// Parse pagination limit.
	limit := 100
	if s := r.URL.Query().Get("limit"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
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
			http.Error(w, "invalid actor_id", http.StatusBadRequest)
			return
		}
		p.ActorID = &id
	}

	// Parse date range (defaults to last 30 days).
	if s := r.URL.Query().Get("after"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			http.Error(w, "invalid after (RFC3339)", http.StatusBadRequest)
			return
		}
		p.After = t
	} else {
		p.After = time.Now().Add(-30 * 24 * time.Hour)
	}
	if s := r.URL.Query().Get("before"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			http.Error(w, "invalid before (RFC3339)", http.StatusBadRequest)
			return
		}
		p.Before = t
	} else {
		p.Before = time.Now().Add(1 * time.Hour)
	}

	// Parse keyset cursor.
	if c := r.URL.Query().Get("cursor"); c != "" {
		t, id, err := decodeTimeCursor(c)
		if err == nil {
			p.CursorCreatedAt = &t
			p.CursorID = &id
		}
	}

	rows, err := srv.store.ListAuditEntries(r.Context(), p)
	if err != nil {
		slog.ErrorContext(r.Context(), "list audit entries", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Detect next page.
	var nextCursor *string
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		c := encodeTimeCursor(last.CreatedAt, last.ID)
		nextCursor = &c
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

	writeJSON(w, http.StatusOK, auditLogListResponse{Items: items, NextCursor: nextCursor})
}
