// ABOUTME: HTTP handlers for delivery history list, detail, and replay endpoints.
// ABOUTME: Replay uses an in-memory per-org rate limiter: max 10 replays per hour.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
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
	ID              string   `json:"id"`
	OrgID           string   `json:"org_id"`
	RuleID          string   `json:"rule_id"`
	ChannelID       string   `json:"channel_id"`
	Status          string   `json:"status"`
	AttemptCount    int32    `json:"attempt_count"`
	SendAfter       string   `json:"send_after"`
	LastAttemptedAt *string  `json:"last_attempted_at,omitempty"`
	DeliveredAt     *string  `json:"delivered_at,omitempty"`
	LastError       *string  `json:"last_error,omitempty"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
}

// deliveryDetail extends deliveryEntry with the full payload.
type deliveryDetail struct {
	deliveryEntry
	Payload json.RawMessage `json:"payload"`
}

type deliveryListResponse struct {
	Items      []deliveryEntry `json:"items"`
	NextCursor *string         `json:"next_cursor,omitempty"`
}

// encodeDeliveryCursor encodes (time, uuid) as a stable string cursor.
// Format: <RFC3339Nano>/<uuid>
func encodeDeliveryCursor(t time.Time, id uuid.UUID) string {
	return t.UTC().Format(time.RFC3339Nano) + "/" + id.String()
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// listDeliveriesHandler handles GET /api/v1/orgs/{org_id}/deliveries.
// Supports optional filters: rule_id, channel_id, status, limit, after_created_at, after_id.
func (srv *Server) listDeliveriesHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	q := r.URL.Query()

	// Optional UUID filters.
	ruleID := uuid.Nil
	if s := q.Get("rule_id"); s != "" {
		parsed, err := uuid.Parse(s)
		if err != nil {
			http.Error(w, "invalid rule_id", http.StatusBadRequest)
			return
		}
		ruleID = parsed
	}

	channelID := uuid.Nil
	if s := q.Get("channel_id"); s != "" {
		parsed, err := uuid.Parse(s)
		if err != nil {
			http.Error(w, "invalid channel_id", http.StatusBadRequest)
			return
		}
		channelID = parsed
	}

	status := q.Get("status")

	// Limit (default 50, max 200).
	limit := 50
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		if n > 200 {
			n = 200
		}
		limit = n
	}

	// Keyset cursor.
	cursorTime := time.Now().UTC()
	cursorID := uuid.Max
	if afterCreatedAt := q.Get("after_created_at"); afterCreatedAt != "" {
		if afterID := q.Get("after_id"); afterID != "" {
			t, err := time.Parse(time.RFC3339, afterCreatedAt)
			if err != nil {
				http.Error(w, "invalid after_created_at: must be RFC3339", http.StatusBadRequest)
				return
			}
			id, err := uuid.Parse(afterID)
			if err != nil {
				http.Error(w, "invalid after_id", http.StatusBadRequest)
				return
			}
			cursorTime = t
			cursorID = id
		}
	}

	rows, err := srv.store.ListDeliveries(r.Context(), orgID, ruleID, channelID, status, cursorTime, cursorID, limit)
	if err != nil {
		slog.ErrorContext(r.Context(), "list deliveries", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	items := make([]deliveryEntry, len(rows))
	for i, row := range rows {
		entry := deliveryEntry{
			ID:           row.ID.String(),
			OrgID:        row.OrgID.String(),
			RuleID:       row.RuleID.String(),
			ChannelID:    row.ChannelID.String(),
			Status:       row.Status,
			AttemptCount: row.AttemptCount,
			SendAfter:    row.SendAfter.Format(time.RFC3339),
			CreatedAt:    row.CreatedAt.Format(time.RFC3339),
			UpdatedAt:    row.UpdatedAt.Format(time.RFC3339),
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

	resp := deliveryListResponse{Items: items}
	if len(rows) == limit {
		last := rows[len(rows)-1]
		cursor := encodeDeliveryCursor(last.CreatedAt, last.ID)
		resp.NextCursor = &cursor
	}

	writeJSON(w, http.StatusOK, resp)
}

// getDeliveryHandler handles GET /api/v1/orgs/{org_id}/deliveries/{id}.
// Returns 404 if the delivery does not exist or belongs to a different org.
func (srv *Server) getDeliveryHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	row, err := srv.store.GetDelivery(r.Context(), id, orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "get delivery", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if row == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	entry := deliveryEntry{
		ID:           row.ID.String(),
		OrgID:        row.OrgID.String(),
		RuleID:       row.RuleID.String(),
		ChannelID:    row.ChannelID.String(),
		Status:       row.Status,
		AttemptCount: row.AttemptCount,
		SendAfter:    row.SendAfter.Format(time.RFC3339),
		CreatedAt:    row.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    row.UpdatedAt.Format(time.RFC3339),
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
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	if !checkReplayLimit(orgID) {
		http.Error(w, "rate limit exceeded: max 10 replays per hour per org", http.StatusTooManyRequests)
		return
	}

	if err := srv.store.ReplayDelivery(r.Context(), id, orgID); err != nil {
		slog.ErrorContext(r.Context(), "replay delivery", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
