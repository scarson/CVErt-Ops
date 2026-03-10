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
	PausedAt            *time.Time     `json:"paused_at,omitempty"`
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

	stateMap := make(map[string]store.FeedSyncState, len(states))
	for _, s := range states {
		stateMap[s.FeedName] = s
	}

	entries := make([]FeedStatusEntry, 0, len(ingest.KnownFeeds))
	for _, feedName := range ingest.KnownFeeds {
		if s, ok := stateMap[feedName]; ok {
			logs, err := srv.store.ListRecentFeedFetchLogs(ctx, feedName, 5)
			if err != nil {
				slog.Error("list feed fetch logs", "feed", feedName, "error", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			entries = append(entries, feedStatusFromState(s, logs))
		} else {
			entries = append(entries, FeedStatusEntry{
				FeedName:   feedName,
				RecentLogs: []FeedLogEntry{},
			})
		}
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
		slog.Error("enqueue feed job", "feed", feedName, "error", err) //nolint:gosec // G706: feedName is validated by IsKnownFeed; slog structured fields escape values
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if jobID == uuid.Nil {
		http.Error(w, "feed job already pending", http.StatusConflict)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID.String()})
}

// ── Pause/Resume/Logs handlers ───────────────────────────────────────────────

func (srv *Server) pauseFeedHandler(w http.ResponseWriter, r *http.Request) {
	feedName := chi.URLParam(r, "feed")
	if !ingest.IsKnownFeed(feedName) {
		http.Error(w, fmt.Sprintf("unknown feed: %q", feedName), http.StatusBadRequest)
		return
	}
	if err := srv.store.PauseFeed(r.Context(), feedName); err != nil {
		slog.Error("pause feed", "feed", feedName, "error", err) //nolint:gosec // G706: feedName validated
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "paused", "feed": feedName})
}

func (srv *Server) resumeFeedHandler(w http.ResponseWriter, r *http.Request) {
	feedName := chi.URLParam(r, "feed")
	if !ingest.IsKnownFeed(feedName) {
		http.Error(w, fmt.Sprintf("unknown feed: %q", feedName), http.StatusBadRequest)
		return
	}
	if err := srv.store.ResumeFeed(r.Context(), feedName); err != nil {
		slog.Error("resume feed", "feed", feedName, "error", err) //nolint:gosec // G706: feedName validated
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "resumed", "feed": feedName})
}

func (srv *Server) feedLogsHandler(w http.ResponseWriter, r *http.Request) {
	feedName := chi.URLParam(r, "feed")
	if !ingest.IsKnownFeed(feedName) {
		http.Error(w, fmt.Sprintf("unknown feed: %q", feedName), http.StatusBadRequest)
		return
	}

	limit, afterTime, afterID, ok := parseKeysetParams(w, r)
	if !ok {
		return
	}

	logs, err := srv.store.ListFeedFetchLogsPaginated(r.Context(), feedName, afterTime, afterID, limit+1)
	if err != nil {
		slog.Error("feed logs", "feed", feedName, "error", err) //nolint:gosec // G706: feedName validated
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	hasMore := len(logs) > limit
	if hasMore {
		logs = logs[:limit]
	}

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

	writeJSON(w, http.StatusOK, map[string]any{
		"items":    logEntries,
		"has_more": hasMore,
	})
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
		PausedAt:            s.PausedAt,
		RecentLogs:          logEntries,
	}
}
