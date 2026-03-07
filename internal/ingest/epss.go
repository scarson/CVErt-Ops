// ABOUTME: EPSS feed handler for the worker pool — applies daily EPSS scores to the CVE corpus.
// ABOUTME: Wraps the EPSS adapter's Apply() method with sync state tracking and fetch logging.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"database/sql"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/worker"
)

// ApplyFunc matches the signature of epss.Adapter.Apply. Defined as a type for test injection.
type ApplyFunc func(ctx context.Context, db *sql.DB, cursor json.RawMessage) (json.RawMessage, error)

// EPSSHandler returns a worker.Handler that runs the EPSS adapter and persists sync state.
// In production, pass epssAdapter.Apply as applyFn.
func EPSSHandler(st *store.Store, applyFn ApplyFunc) worker.Handler {
	return epssHandlerWithStore(st, st, applyFn)
}

// epssHandlerWithStore is the internal implementation that accepts a separate HandlerStore
// for sync state operations. This enables testing error paths without mocking the full store.
func epssHandlerWithStore(syncSt HandlerStore, mergeSt *store.Store, applyFn ApplyFunc) worker.Handler {
	return func(ctx context.Context, _ json.RawMessage) error {
		start := time.Now()
		slog.Info("epss ingest started")

		// Read current cursor from sync state.
		state, err := syncSt.GetFeedSyncState(ctx, "epss")
		if err != nil {
			return fmt.Errorf("get feed sync state: %w", err)
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
		newCursor, applyErr := applyFn(ctx, mergeSt.DB(), cursor)

		now := time.Now()

		if applyErr != nil {
			failures := prevFailures + 1
			backoff := now.Add(backoffDuration(failures))
			if syncErr := syncSt.UpsertFeedSyncState(ctx, store.FeedSyncState{
				FeedName:            "epss",
				CursorJSON:          cursor,
				LastSuccessAt:       prevLastSuccess,
				LastAttemptAt:       &now,
				ConsecutiveFailures: failures,
				LastError:           applyErr.Error(),
				BackoffUntil:        &backoff,
			}); syncErr != nil {
				slog.Error("epss sync state write failed on error path", "error", syncErr)
			}
			if _, logErr := syncSt.InsertFeedFetchLog(ctx, store.FeedFetchLog{
				FeedName:     "epss",
				StartedAt:    start,
				EndedAt:      &now,
				Status:       "error",
				CursorBefore: cursorBefore,
				CursorAfter:  cursor,
				ErrorSummary: applyErr.Error(),
			}); logErr != nil {
				slog.Error("epss fetch log write failed", "error", logErr)
			}
			slog.Error("epss ingest failed", "error", applyErr, "duration", time.Since(start))
			return applyErr
		}

		// Success: persist new cursor and reset failure counters.
		if syncErr := syncSt.UpsertFeedSyncState(ctx, store.FeedSyncState{
			FeedName:            "epss",
			CursorJSON:          newCursor,
			LastSuccessAt:       &now,
			LastAttemptAt:       &now,
			ConsecutiveFailures: 0,
			LastError:           "",
		}); syncErr != nil {
			slog.Error("epss sync state write failed on success path", "error", syncErr)
			return fmt.Errorf("persist sync state for epss: %w", syncErr)
		}
		if _, logErr := syncSt.InsertFeedFetchLog(ctx, store.FeedFetchLog{
			FeedName:     "epss",
			StartedAt:    start,
			EndedAt:      &now,
			Status:       "success",
			CursorBefore: cursorBefore,
			CursorAfter:  newCursor,
		}); logErr != nil {
			slog.Error("epss fetch log write failed", "error", logErr)
		}
		slog.Info("epss ingest completed", "duration", time.Since(start))
		return nil
	}
}
