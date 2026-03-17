// ABOUTME: HTTP handlers for delivery history list, detail, and replay endpoints.
// ABOUTME: Replay uses an in-memory per-org rate limiter: max 10 replays per hour.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ── Rate limiter ──────────────────────────────────────────────────────────────

// replayBucket tracks replay calls for a single org within the current window.
type replayBucket struct {
	mu      sync.Mutex
	count   int
	resetAt time.Time
}

// replayBuckets is a package-level map of orgID → *replayBucket.
// Keyed by orgID.String(). Package-level so rate limit state persists within a process.
var replayBuckets sync.Map

const replayMaxPerHour = 10

// checkReplayLimit returns true if the org is within the rate limit and increments the
// counter. Returns false (caller should respond 429) if the limit is exceeded.
func checkReplayLimit(orgID uuid.UUID) bool {
	key := orgID.String()
	val, _ := replayBuckets.LoadOrStore(key, &replayBucket{})
	bucket := val.(*replayBucket) //nolint:forcetypeassert // type is always *replayBucket

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	now := time.Now()
	if now.After(bucket.resetAt) {
		// Window has elapsed — start a new window.
		bucket.count = 0
		bucket.resetAt = now.Add(time.Hour)
	}
	if bucket.count >= replayMaxPerHour {
		return false
	}
	bucket.count++
	return true
}

// ── Response types ────────────────────────────────────────────────────────────

// deliveryEntry is the list item shape (no payload to keep list responses small).
type deliveryEntry struct {
	ID              string  `json:"id"`
	OrgID           string  `json:"org_id"`
	RuleID          string  `json:"rule_id"`
	ChannelID       string  `json:"channel_id"`
	Kind            string  `json:"kind"`
	ReportID        *string `json:"report_id,omitempty"`
	Status          string  `json:"status"`
	AttemptCount    int32   `json:"attempt_count"`
	SendAfter       string  `json:"send_after"`
	LastAttemptedAt *string `json:"last_attempted_at,omitempty"`
	DeliveredAt     *string `json:"delivered_at,omitempty"`
	LastError       *string `json:"last_error,omitempty"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
}

// deliveryDetail extends deliveryEntry with the full payload.
type deliveryDetail struct {
	deliveryEntry
	Payload json.RawMessage `json:"payload"`
}

// deliveryCursor encodes the keyset pagination position for delivery lists.
type deliveryCursor struct {
	T  string `json:"t"`  // created_at RFC3339Nano
	ID string `json:"id"` // UUID tiebreaker
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// listDeliveriesHandler handles GET /api/v1/orgs/{org_id}/deliveries.
// Supports optional filters: rule_id, channel_id, status, limit, cursor.
func (srv *Server) listDeliveriesHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	q := r.URL.Query()

	// Optional UUID filters.
	ruleID := uuid.Nil
	if s := q.Get("rule_id"); s != "" {
		parsed, err := uuid.Parse(s)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid rule_id")
			return
		}
		ruleID = parsed
	}

	channelID := uuid.Nil
	if s := q.Get("channel_id"); s != "" {
		parsed, err := uuid.Parse(s)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid channel_id")
			return
		}
		channelID = parsed
	}

	status := q.Get("status")

	limit, ok := parseLimitParam(w, r, 50, 200)
	if !ok {
		return
	}

	// Keyset cursor.
	cursorTime := time.Now().UTC()
	cursorID := uuid.Max
	if c := q.Get("cursor"); c != "" {
		var cur deliveryCursor
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
		cursorTime = t
		cursorID = id
	}

	// Fetch limit+1 rows to detect if more pages exist without a phantom last page.
	rows, err := srv.store.ListDeliveries(r.Context(), orgID, ruleID, channelID, status, cursorTime, cursorID, limit+1)
	if err != nil {
		slog.ErrorContext(r.Context(), "list deliveries", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}

	items := make([]deliveryEntry, len(rows))
	for i, row := range rows {
		entry := deliveryEntry{
			ID:           row.ID.String(),
			OrgID:        row.OrgID.String(),
			RuleID:       row.RuleID.UUID.String(),
			ChannelID:    row.ChannelID.String(),
			Kind:         row.Kind,
			Status:       row.Status,
			AttemptCount: row.AttemptCount,
			SendAfter:    row.SendAfter.Format(time.RFC3339),
			CreatedAt:    row.CreatedAt.Format(time.RFC3339),
			UpdatedAt:    row.UpdatedAt.Format(time.RFC3339),
		}
		if row.ReportID.Valid {
			s := row.ReportID.UUID.String()
			entry.ReportID = &s
		}
		if row.LastAttemptedAt.Valid {
			s := row.LastAttemptedAt.Time.Format(time.RFC3339)
			entry.LastAttemptedAt = &s
		}
		if row.DeliveredAt.Valid {
			s := row.DeliveredAt.Time.Format(time.RFC3339)
			entry.DeliveredAt = &s
		}
		if row.LastError.Valid {
			s := row.LastError.String
			entry.LastError = &s
		}
		items[i] = entry
	}

	var nextCursor string
	if hasMore {
		last := rows[len(rows)-1]
		nextCursor = encodePageCursor(deliveryCursor{
			T:  last.CreatedAt.UTC().Format(time.RFC3339Nano),
			ID: last.ID.String(),
		})
	}

	writeList(w, items, nextCursor)
}

// getDeliveryHandler handles GET /api/v1/orgs/{org_id}/deliveries/{id}.
// Returns 404 if the delivery does not exist or belongs to a different org.
func (srv *Server) getDeliveryHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}

	row, err := srv.store.GetDelivery(r.Context(), id, orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "get delivery", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if row == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	entry := deliveryEntry{
		ID:           row.ID.String(),
		OrgID:        row.OrgID.String(),
		RuleID:       row.RuleID.UUID.String(),
		ChannelID:    row.ChannelID.String(),
		Kind:         row.Kind,
		Status:       row.Status,
		AttemptCount: row.AttemptCount,
		SendAfter:    row.SendAfter.Format(time.RFC3339),
		CreatedAt:    row.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    row.UpdatedAt.Format(time.RFC3339),
	}
	if row.ReportID.Valid {
		s := row.ReportID.UUID.String()
		entry.ReportID = &s
	}
	if row.LastAttemptedAt.Valid {
		s := row.LastAttemptedAt.Time.Format(time.RFC3339)
		entry.LastAttemptedAt = &s
	}
	if row.DeliveredAt.Valid {
		s := row.DeliveredAt.Time.Format(time.RFC3339)
		entry.DeliveredAt = &s
	}
	if row.LastError.Valid {
		s := row.LastError.String
		entry.LastError = &s
	}

	writeJSON(w, http.StatusOK, deliveryDetail{
		deliveryEntry: entry,
		Payload:       row.Payload,
	})
}

// replayDeliveryHandler handles POST /api/v1/orgs/{org_id}/deliveries/{id}/replay.
// Requires RoleAdmin (enforced at route registration). Rate-limited to 10 per org per hour.
func (srv *Server) replayDeliveryHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}

	// Verify delivery exists before consuming a rate-limit token.
	delivery, err := srv.store.GetDelivery(r.Context(), id, orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "get delivery for replay", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if delivery == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	if !checkReplayLimit(orgID) {
		writeProblem(w, http.StatusTooManyRequests, "rate limit exceeded: max 10 replays per hour per org")
		return
	}

	if err := srv.store.ReplayDelivery(r.Context(), id, orgID); err != nil {
		slog.ErrorContext(r.Context(), "replay delivery", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
