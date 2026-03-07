// ABOUTME: Feed ingestion handler for the worker pool — fetches from adapters and merges into CVE corpus.
// ABOUTME: Handles cursor persistence, sync state tracking, and fetch logging for all standard adapters.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/worker"
)

// Payload is the JSON payload for feed_ingest jobs.
type Payload struct {
	FeedName string `json:"feed_name"`
}

// HandlerStore defines the store operations needed by feed ingest handlers.
type HandlerStore interface {
	GetFeedSyncState(ctx context.Context, feedName string) (*store.FeedSyncState, error)
	UpsertFeedSyncState(ctx context.Context, state store.FeedSyncState) error
	InsertFeedFetchLog(ctx context.Context, log store.FeedFetchLog) (uuid.UUID, error)
}

// MergeFunc matches the signature of merge.Ingest. Defined as a type for test injection.
type MergeFunc func(ctx context.Context, s *store.Store, patch feed.CanonicalPatch, sourceName string) error

// Handler returns a worker.Handler that fetches from the named feed adapter,
// merges each patch into the CVE corpus, and persists cursor/sync state.
func Handler(st *store.Store, client *http.Client, mergeFn MergeFunc) worker.Handler {
	return handlerWithStore(st, st, client, mergeFn)
}

// handlerWithStore is the internal implementation that accepts a separate HandlerStore
// for sync state operations. This enables testing error paths without mocking the full store.
func handlerWithStore(syncSt HandlerStore, mergeSt *store.Store, client *http.Client, mergeFn MergeFunc) worker.Handler {
	return func(ctx context.Context, payload json.RawMessage) error {
		var p Payload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal feed ingest payload: %w", err)
		}

		start := time.Now()
		slog.Info("feed ingest started", "feed", p.FeedName)

		adapter, err := adapterFactory(p.FeedName, client)
		if err != nil {
			return fmt.Errorf("create adapter for %q: %w", p.FeedName, err)
		}

		// Read current cursor from sync state.
		state, err := syncSt.GetFeedSyncState(ctx, p.FeedName)
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

		// Track the last successful cursor for mid-pagination error recovery.
		lastSuccessfulCursor := cursor
		var itemsFetched int32
		var itemsUpserted int32

		// Pagination loop with three-layer termination.
		var fetchErr error
		for {
			var result *feed.FetchResult
			result, fetchErr = adapter.Fetch(ctx, cursor)
			if fetchErr != nil {
				slog.Error("feed fetch failed", "feed", p.FeedName, "error", fetchErr)
				break
			}

			itemsFetched += int32(len(result.Patches)) //nolint:gosec // G115: page sizes are always small

			slog.Info("feed page fetched",
				"feed", p.FeedName,
				"page_items", len(result.Patches),
				"total_fetched", itemsFetched,
				"last_page", result.LastPage,
			)

			// Merge each patch.
			for _, patch := range result.Patches {
				if mergeErr := mergeFn(ctx, mergeSt, patch, result.SourceMeta.SourceName); mergeErr != nil {
					slog.Error("feed merge failed",
						"feed", p.FeedName,
						"cve_id", patch.CVEID,
						"error", mergeErr,
					)
					fetchErr = fmt.Errorf("merge %s: %w", patch.CVEID, mergeErr)
					break
				}
				itemsUpserted++
			}
			if fetchErr != nil {
				break
			}

			// Update last successful cursor after a fully-processed page.
			if result.NextCursor != nil {
				lastSuccessfulCursor = result.NextCursor
			}
			cursor = result.NextCursor

			// Persist cursor progress after each page for crash recovery.
			pageNow := time.Now()
			if syncErr := syncSt.UpsertFeedSyncState(ctx, store.FeedSyncState{
				FeedName:      p.FeedName,
				CursorJSON:    lastSuccessfulCursor,
				LastSuccessAt: prevLastSuccess,
				LastAttemptAt: &pageNow,
			}); syncErr != nil {
				slog.Error("mid-pagination cursor persist failed",
					"feed", p.FeedName, "error", syncErr)
			}

			// Three-layer loop termination:
			// 1. LastPage — adapter explicitly signals final page
			if result.LastPage {
				break
			}
			// 2. Nil NextCursor — legacy/fallback signal
			if result.NextCursor == nil {
				break
			}
			// 3. Empty patches — safety net against infinite loops
			if len(result.Patches) == 0 {
				break
			}
		}

		now := time.Now()

		if fetchErr != nil {
			// Persist failure state with last successful cursor.
			failures := prevFailures + 1
			backoff := now.Add(backoffDuration(failures))
			if syncErr := syncSt.UpsertFeedSyncState(ctx, store.FeedSyncState{
				FeedName:            p.FeedName,
				CursorJSON:          lastSuccessfulCursor,
				LastSuccessAt:       prevLastSuccess,
				LastAttemptAt:       &now,
				ConsecutiveFailures: failures,
				LastError:           fetchErr.Error(),
				BackoffUntil:        &backoff,
			}); syncErr != nil {
				slog.Error("feed sync state write failed on error path",
					"feed", p.FeedName, "error", syncErr)
			}
			if _, logErr := syncSt.InsertFeedFetchLog(ctx, store.FeedFetchLog{
				FeedName:      p.FeedName,
				StartedAt:     start,
				EndedAt:       &now,
				Status:        "error",
				ItemsFetched:  itemsFetched,
				ItemsUpserted: itemsUpserted,
				CursorBefore:  cursorBefore,
				CursorAfter:   lastSuccessfulCursor,
				ErrorSummary:  fetchErr.Error(),
			}); logErr != nil {
				slog.Error("feed fetch log write failed",
					"feed", p.FeedName, "error", logErr)
			}
			slog.Error("feed ingest failed",
				"feed", p.FeedName,
				"items_fetched", itemsFetched,
				"error", fetchErr,
				"duration", time.Since(start),
			)
			return fetchErr
		}

		// Success: persist final cursor and reset failure counters.
		if syncErr := syncSt.UpsertFeedSyncState(ctx, store.FeedSyncState{
			FeedName:            p.FeedName,
			CursorJSON:          lastSuccessfulCursor,
			LastSuccessAt:       &now,
			LastAttemptAt:       &now,
			ConsecutiveFailures: 0,
			LastError:           "",
		}); syncErr != nil {
			slog.Error("feed sync state write failed on success path",
				"feed", p.FeedName, "error", syncErr)
			return fmt.Errorf("persist sync state for %s: %w", p.FeedName, syncErr)
		}
		if _, logErr := syncSt.InsertFeedFetchLog(ctx, store.FeedFetchLog{
			FeedName:      p.FeedName,
			StartedAt:     start,
			EndedAt:       &now,
			Status:        "success",
			ItemsFetched:  itemsFetched,
			ItemsUpserted: itemsUpserted,
			CursorBefore:  cursorBefore,
			CursorAfter:   lastSuccessfulCursor,
		}); logErr != nil {
			slog.Error("feed fetch log write failed",
				"feed", p.FeedName, "error", logErr)
		}
		slog.Info("feed ingest completed",
			"feed", p.FeedName,
			"items_fetched", itemsFetched,
			"items_upserted", itemsUpserted,
			"duration", time.Since(start),
		)
		return nil
	}
}

// backoffDuration computes exponential backoff: 30s * 2^min(failures, 10),
// capping at ~8.5 hours.
func backoffDuration(failures int32) time.Duration {
	base := 30 * time.Second
	return base * time.Duration(1<<min(max(failures, 0), 10))
}
