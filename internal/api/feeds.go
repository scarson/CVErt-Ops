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
		slog.ErrorContext(ctx, "list feed sync states", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
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
				slog.ErrorContext(ctx, "list feed fetch logs", "feed", feedName, "error", err)
				writeProblem(w, http.StatusInternalServerError, "internal error")
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

	writeList(w, entries, "")
}

// ── Trigger feed handler ──────────────────────────────────────────────────────

func (srv *Server) triggerFeedHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	feedName := chi.URLParam(r, "feed")

	if !ingest.IsKnownFeed(feedName) {
		writeProblem(w, http.StatusBadRequest, fmt.Sprintf("unknown feed: %q", feedName))
		return
	}

	lockKey := "feed:" + feedName
	queue := ingest.QueueForFeed(feedName)
	payload, _ := json.Marshal(ingest.Payload{FeedName: feedName})
	jobID, err := srv.store.EnqueueJob(ctx, queue, 0, payload, &lockKey, 3, nil)
	if err != nil {
		slog.ErrorContext(ctx, "enqueue feed job", "feed", feedName, "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if jobID == uuid.Nil {
		writeProblem(w, http.StatusConflict, "feed job already pending")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID.String()})
}

// ── Pause/Resume/Logs handlers ───────────────────────────────────────────────

func (srv *Server) pauseFeedHandler(w http.ResponseWriter, r *http.Request) {
	feedName := chi.URLParam(r, "feed")
	if !ingest.IsKnownFeed(feedName) {
		writeProblem(w, http.StatusBadRequest, fmt.Sprintf("unknown feed: %q", feedName))
		return
	}
	if err := srv.store.PauseFeed(r.Context(), feedName); err != nil {
		slog.ErrorContext(r.Context(), "pause feed", "feed", feedName, "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "paused", "feed": feedName})
}

func (srv *Server) resumeFeedHandler(w http.ResponseWriter, r *http.Request) {
	feedName := chi.URLParam(r, "feed")
	if !ingest.IsKnownFeed(feedName) {
		writeProblem(w, http.StatusBadRequest, fmt.Sprintf("unknown feed: %q", feedName))
		return
	}
	if err := srv.store.ResumeFeed(r.Context(), feedName); err != nil {
		slog.ErrorContext(r.Context(), "resume feed", "feed", feedName, "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "resumed", "feed": feedName})
}

// feedLogCursor is the opaque cursor for feed log pagination.
type feedLogCursor struct {
	T  time.Time `json:"t"`
	ID string    `json:"id"`
}

func (srv *Server) feedLogsHandler(w http.ResponseWriter, r *http.Request) {
	feedName := chi.URLParam(r, "feed")
	if !ingest.IsKnownFeed(feedName) {
		writeProblem(w, http.StatusBadRequest, fmt.Sprintf("unknown feed: %q", feedName))
		return
	}

	limit, ok := parseLimitParam(w, r, 50, 200)
	if !ok {
		return
	}

	var afterTime *time.Time
	var afterID *uuid.UUID
	if c := r.URL.Query().Get("cursor"); c != "" {
		var cur feedLogCursor
		if err := decodePageCursor(c, &cur); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		afterTime = &cur.T
		id, err := uuid.Parse(cur.ID)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		afterID = &id
	}

	logs, err := srv.store.ListFeedFetchLogsPaginated(r.Context(), feedName, afterTime, afterID, limit+1)
	if err != nil {
		slog.ErrorContext(r.Context(), "feed logs", "feed", feedName, "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	var nextCursor string
	if len(logs) > limit {
		logs = logs[:limit]
		last := logs[len(logs)-1]
		nextCursor = encodePageCursor(feedLogCursor{T: last.StartedAt, ID: last.ID.String()})
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

	writeList(w, logEntries, nextCursor)
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
