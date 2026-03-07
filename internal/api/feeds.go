// ABOUTME: Admin API handlers for feed status monitoring and manual triggering.
// ABOUTME: Exposes feed_sync_state and feed_fetch_log data; enqueues manual re-run jobs.
package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/ingest"
	"github.com/scarson/cvert-ops/internal/store"
)

// ── Response types ────────────────────────────────────────────────────────────

// FeedStatusEntry represents one feed's sync state and recent fetch history.
type FeedStatusEntry struct {
	FeedName            string         `json:"feed_name"`
	LastSuccessAt       *time.Time     `json:"last_success_at,omitempty"`
	LastAttemptAt       *time.Time     `json:"last_attempt_at,omitempty"`
	ConsecutiveFailures int32          `json:"consecutive_failures"`
	LastError           string         `json:"last_error,omitempty"`
	BackoffUntil        *time.Time     `json:"backoff_until,omitempty"`
	RecentLogs          []FeedLogEntry `json:"recent_logs"`
}

// FeedLogEntry is a single fetch log row.
type FeedLogEntry struct {
	ID            uuid.UUID  `json:"id"`
	StartedAt     time.Time  `json:"started_at"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	Status        string     `json:"status"`
	ItemsFetched  int32      `json:"items_fetched"`
	ItemsUpserted int32      `json:"items_upserted"`
	ErrorSummary  string     `json:"error_summary,omitempty"`
}

// ── List feeds handler ────────────────────────────────────────────────────────

func (srv *Server) listFeedsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	states, err := srv.store.ListFeedSyncStates(ctx)
	if err != nil {
		slog.Error("list feed sync states", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	entries := make([]FeedStatusEntry, len(states))
	for i, s := range states {
		logs, err := srv.store.ListRecentFeedFetchLogs(ctx, s.FeedName, 5)
		if err != nil {
			slog.Error("list feed fetch logs", "feed", s.FeedName, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		entries[i] = feedStatusFromState(s, logs)
	}

	writeJSON(w, http.StatusOK, map[string]any{"feeds": entries})
}

// ── Trigger feed handler ──────────────────────────────────────────────────────

func (srv *Server) triggerFeedHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	feedName := chi.URLParam(r, "feed")

	if !ingest.IsKnownFeed(feedName) {
		http.Error(w, fmt.Sprintf("unknown feed: %q", feedName), http.StatusBadRequest)
		return
	}

	lockKey := "feed:" + feedName
	queue := ingest.QueueForFeed(feedName)
	payload, _ := json.Marshal(ingest.Payload{FeedName: feedName})
	jobID, err := srv.store.EnqueueJob(ctx, queue, 0, payload, &lockKey, 3, nil)
	if err != nil {
		slog.Error("enqueue feed job", "feed", feedName, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if jobID == uuid.Nil {
		http.Error(w, "feed job already pending", http.StatusConflict)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID.String()})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func feedStatusFromState(s store.FeedSyncState, logs []store.FeedFetchLog) FeedStatusEntry {
	logEntries := make([]FeedLogEntry, len(logs))
	for i, l := range logs {
		logEntries[i] = FeedLogEntry{
			ID:            l.ID,
			StartedAt:     l.StartedAt,
			EndedAt:       l.EndedAt,
			Status:        l.Status,
			ItemsFetched:  l.ItemsFetched,
			ItemsUpserted: l.ItemsUpserted,
			ErrorSummary:  l.ErrorSummary,
		}
	}
	return FeedStatusEntry{
		FeedName:            s.FeedName,
		LastSuccessAt:       s.LastSuccessAt,
		LastAttemptAt:       s.LastAttemptAt,
		ConsecutiveFailures: s.ConsecutiveFailures,
		LastError:           s.LastError,
		BackoffUntil:        s.BackoffUntil,
		RecentLogs:          logEntries,
	}
}
