// ABOUTME: HTTP handler for listing alert events with optional rule_id and cve_id filters.
// ABOUTME: Alert events are created by the evaluator worker; this handler provides read-only access.
package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/store"
)

type alertEventEntry struct {
	ID               string `json:"id"`
	RuleID           string `json:"rule_id"`
	CveID            string `json:"cve_id"`
	LastMatchState   bool   `json:"last_match_state"`
	SuppressDelivery bool   `json:"suppress_delivery"`
	FirstFiredAt     string `json:"first_fired_at"`
	LastFiredAt      string `json:"last_fired_at"`
	TimesFired       int32  `json:"times_fired"`
}

type alertEventsListResponse struct {
	Items []alertEventEntry `json:"items"`
}

// listAlertEventsHandler handles GET /api/v1/orgs/{org_id}/alert-events.
// Optional ?rule_id= and ?cve_id= query filters. Requires viewer+.
func (srv *Server) listAlertEventsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	p := store.ListAlertEventsParams{Limit: 100}

	if s := r.URL.Query().Get("rule_id"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			http.Error(w, "invalid rule_id", http.StatusBadRequest)
			return
		}
		p.RuleID = &id
	}
	if s := r.URL.Query().Get("cve_id"); s != "" {
		p.CveID = &s
	}

	events, err := srv.store.ListAlertEvents(r.Context(), orgID, p)
	if err != nil {
		slog.ErrorContext(r.Context(), "list alert events", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	entries := make([]alertEventEntry, 0, len(events))
	for _, e := range events {
		entries = append(entries, alertEventEntry{
			ID:               e.ID.String(),
			RuleID:           e.RuleID.String(),
			CveID:            e.CveID,
			LastMatchState:   e.LastMatchState,
			SuppressDelivery: e.SuppressDelivery,
			FirstFiredAt:     e.FirstFiredAt.Format(time.RFC3339),
			LastFiredAt:      e.LastFiredAt.Format(time.RFC3339),
			TimesFired:       e.TimesFired,
		})
	}
	writeJSON(w, http.StatusOK, alertEventsListResponse{Items: entries})
}
