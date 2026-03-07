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

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/worker"
)

// IngestPayload is the JSON payload for feed_ingest jobs.
type IngestPayload struct {
	FeedName string `json:"feed_name"`
}

// MergeFunc matches the signature of merge.Ingest. Defined as a type for test injection.
type MergeFunc func(ctx context.Context, s *store.Store, patch feed.CanonicalPatch, sourceName string) error

// IngestHandler returns a worker.Handler that fetches from the named feed adapter,
// merges each patch into the CVE corpus, and persists cursor/sync state.
func IngestHandler(st *store.Store, client *http.Client, mergeFn MergeFunc) worker.Handler {
	return func(ctx context.Context, payload json.RawMessage) error {
		var p IngestPayload
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
		state, err := st.GetFeedSyncState(ctx, p.FeedName)
		if err != nil {
			return fmt.Errorf("get feed sync state: %w", err)
		}

		var cursor json.RawMessage
		var prevFailures int32
		if state != nil {
			cursor = state.CursorJSON
			prevFailures = state.ConsecutiveFailures
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

			slog.Info("feed page fetched",
				"feed", p.FeedName,
				"page_items", len(result.Patches),
				"total_fetched", itemsFetched+int32(len(result.Patches)),
				"last_page", result.LastPage,
			)

			// Merge each patch.
			for _, patch := range result.Patches {
				if mergeErr := mergeFn(ctx, st, patch, result.SourceMeta.SourceName); mergeErr != nil {
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

			itemsFetched += int32(len(result.Patches))

			// Update last successful cursor after a fully-processed page.
			if result.NextCursor != nil {
				lastSuccessfulCursor = result.NextCursor
			}
			cursor = result.NextCursor

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
			_ = st.UpsertFeedSyncState(ctx, store.FeedSyncState{
				FeedName:            p.FeedName,
				CursorJSON:          lastSuccessfulCursor,
				LastAttemptAt:       &now,
				ConsecutiveFailures: failures,
				LastError:           fetchErr.Error(),
				BackoffUntil:        &backoff,
			})
			_, _ = st.InsertFeedFetchLog(ctx, store.FeedFetchLog{
				FeedName:      p.FeedName,
				StartedAt:     start,
				EndedAt:       &now,
				Status:        "error",
				ItemsFetched:  itemsFetched,
				ItemsUpserted: itemsUpserted,
				CursorBefore:  cursorBefore,
				CursorAfter:   lastSuccessfulCursor,
				ErrorSummary:  fetchErr.Error(),
			})
			slog.Error("feed ingest failed",
				"feed", p.FeedName,
				"items_fetched", itemsFetched,
				"error", fetchErr,
				"duration", time.Since(start),
			)
			return fetchErr
		}

		// Success: persist final cursor and reset failure counters.
		_ = st.UpsertFeedSyncState(ctx, store.FeedSyncState{
			FeedName:            p.FeedName,
			CursorJSON:          lastSuccessfulCursor,
			LastSuccessAt:       &now,
			LastAttemptAt:       &now,
			ConsecutiveFailures: 0,
			LastError:           "",
		})
		_, _ = st.InsertFeedFetchLog(ctx, store.FeedFetchLog{
			FeedName:      p.FeedName,
			StartedAt:     start,
			EndedAt:       &now,
			Status:        "success",
			ItemsFetched:  itemsFetched,
			ItemsUpserted: itemsUpserted,
			CursorBefore:  cursorBefore,
			CursorAfter:   lastSuccessfulCursor,
		})
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
	return base * time.Duration(1<<min(failures, 10))
}
