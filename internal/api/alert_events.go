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
	MaterialHash     string `json:"material_hash"`
	LastMatchState   bool   `json:"last_match_state"`
	SuppressDelivery bool   `json:"suppress_delivery"`
	FirstFiredAt     string `json:"first_fired_at"`
	LastFiredAt      string `json:"last_fired_at"`
	TimesFired       int32  `json:"times_fired"`
}

type alertEventCursor struct {
	T  string `json:"t"`  // first_fired_at RFC3339Nano
	ID string `json:"id"` // UUID tiebreaker
}

// listAlertEventsHandler handles GET /api/v1/orgs/{org_id}/alert-events.
// Optional filters: ?rule_id=, ?cve_id=, ?last_match_state=, ?since=.
// Cursor-based pagination on (first_fired_at DESC, id DESC) via ?cursor= parameter.
func (srv *Server) listAlertEventsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	const limit = 100
	p := store.ListAlertEventsParams{Limit: limit + 1}

	if s := r.URL.Query().Get("rule_id"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid rule_id")
			return
		}
		p.RuleID = &id
	}
	if s := r.URL.Query().Get("cve_id"); s != "" {
		p.CveID = &s
	}
	if s := r.URL.Query().Get("last_match_state"); s != "" {
		v := s == "true"
		p.LastMatchState = &v
	}
	if s := r.URL.Query().Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid since (RFC3339)")
			return
		}
		p.Since = &t
	}
	if c := r.URL.Query().Get("cursor"); c != "" {
		var cur alertEventCursor
		if err := decodePageCursor(c, &cur); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		t, err := time.Parse(time.RFC3339Nano, cur.T)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		id, err := uuid.Parse(cur.ID)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		p.AfterTime = &t
		p.AfterID = &id
	}

	events, err := srv.store.ListAlertEvents(r.Context(), orgID, p)
	if err != nil {
		slog.ErrorContext(r.Context(), "list alert events", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	var cursor string
	if len(events) > limit {
		events = events[:limit]
		last := events[len(events)-1]
		cursor = encodePageCursor(alertEventCursor{
			T:  last.FirstFiredAt.UTC().Format(time.RFC3339Nano),
			ID: last.ID.String(),
		})
	}

	entries := make([]alertEventEntry, 0, len(events))
	for _, e := range events {
		entries = append(entries, alertEventEntry{
			ID:               e.ID.String(),
			RuleID:           e.RuleID.String(),
			CveID:            e.CveID,
			MaterialHash:     e.MaterialHash,
			LastMatchState:   e.LastMatchState,
			SuppressDelivery: e.SuppressDelivery,
			FirstFiredAt:     e.FirstFiredAt.Format(time.RFC3339),
			LastFiredAt:      e.LastFiredAt.Format(time.RFC3339),
			TimesFired:       e.TimesFired,
		})
	}
	writeList(w, entries, cursor)
}
