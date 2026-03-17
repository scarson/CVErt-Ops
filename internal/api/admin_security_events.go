// ABOUTME: Site admin API handler for listing security events (cross-org).
// ABOUTME: Filterable by event_type, severity, actor_email, date range with keyset pagination.
package api

import (
	"log/slog"
	"net/http"
	"time"
)

// securityEventCursor is the opaque cursor for security event list pagination.
type securityEventCursor struct {
	T  string `json:"t"`  // created_at as RFC3339Nano
	ID string `json:"id"` // event UUID
}

// adminSecurityEventsHandler handles GET /api/v1/admin/security-events.
// Lists security events with optional filters and keyset pagination.
func (srv *Server) adminSecurityEventsHandler(w http.ResponseWriter, r *http.Request) {
	limit, ok := parseLimitParam(w, r, 50, 100)
	if !ok {
		return
	}

	q := r.URL.Query()

	// Parse cursor.
	var cursorTime *time.Time
	if c := q.Get("cursor"); c != "" {
		var cur securityEventCursor
		if err := decodePageCursor(c, &cur); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		t, err := time.Parse(time.RFC3339Nano, cur.T)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		cursorTime = &t
	}

	// Parse optional date range filters.
	var since, until *time.Time
	if s := q.Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid since: must be RFC3339")
			return
		}
		since = &t
	}
	if u := q.Get("until"); u != "" {
		t, err := time.Parse(time.RFC3339, u)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid until: must be RFC3339")
			return
		}
		until = &t
	}

	rows, err := srv.store.ListSecurityEvents(r.Context(), q.Get("event_type"), q.Get("severity"), q.Get("actor_email"), since, until, cursorTime, limit+1)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin security events", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	var nextCursor string
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		nextCursor = encodePageCursor(securityEventCursor{
			T:  last.CreatedAt.Format(time.RFC3339Nano),
			ID: last.ID.String(),
		})
	}

	writeList(w, rows, nextCursor)
}
