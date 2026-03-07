// ABOUTME: EPSS feed handler for the worker pool — applies daily EPSS scores to the CVE corpus.
// ABOUTME: Wraps the EPSS adapter's Apply() method with sync state tracking and fetch logging.
package ingest

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/worker"
)

// ApplyFunc matches the signature of epss.Adapter.Apply. Defined as a type for test injection.
type ApplyFunc func(ctx context.Context, s *store.Store, cursor json.RawMessage) (json.RawMessage, error)

// EPSSHandler returns a worker.Handler that runs the EPSS adapter and persists sync state.
// In production, pass epssAdapter.Apply as applyFn.
func EPSSHandler(st *store.Store, applyFn ApplyFunc) worker.Handler {
	return func(ctx context.Context, _ json.RawMessage) error {
		start := time.Now()
		slog.Info("epss ingest started")

		// Read current cursor from sync state.
		state, err := st.GetFeedSyncState(ctx, "epss")
		if err != nil {
			return err
		}

		var cursor json.RawMessage
		var prevFailures int32
		var prevLastSuccess *time.Time
		if state != nil {
			cursor = state.CursorJSON
			prevFailures = state.ConsecutiveFailures
			prevLastSuccess = state.LastSuccessAt
		}
		cursorBefore := cursor

		// Run the EPSS adapter.
		newCursor, applyErr := applyFn(ctx, st, cursor)

		now := time.Now()

		if applyErr != nil {
			failures := prevFailures + 1
			backoff := now.Add(backoffDuration(failures))
			_ = st.UpsertFeedSyncState(ctx, store.FeedSyncState{
				FeedName:            "epss",
				CursorJSON:          cursor,
				LastSuccessAt:       prevLastSuccess,
				LastAttemptAt:       &now,
				ConsecutiveFailures: failures,
				LastError:           applyErr.Error(),
				BackoffUntil:        &backoff,
			})
			_, _ = st.InsertFeedFetchLog(ctx, store.FeedFetchLog{
				FeedName:     "epss",
				StartedAt:    start,
				EndedAt:      &now,
				Status:       "error",
				CursorBefore: cursorBefore,
				CursorAfter:  cursor,
				ErrorSummary: applyErr.Error(),
			})
			slog.Error("epss ingest failed", "error", applyErr, "duration", time.Since(start))
			return applyErr
		}

		// Success: persist new cursor and reset failure counters.
		_ = st.UpsertFeedSyncState(ctx, store.FeedSyncState{
			FeedName:            "epss",
			CursorJSON:          newCursor,
			LastSuccessAt:       &now,
			LastAttemptAt:       &now,
			ConsecutiveFailures: 0,
			LastError:           "",
		})
		_, _ = st.InsertFeedFetchLog(ctx, store.FeedFetchLog{
			FeedName:     "epss",
			StartedAt:    start,
			EndedAt:      &now,
			Status:       "success",
			CursorBefore: cursorBefore,
			CursorAfter:  newCursor,
		})
		slog.Info("epss ingest completed", "duration", time.Since(start))
		return nil
	}
}
