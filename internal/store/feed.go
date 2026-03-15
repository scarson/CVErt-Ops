// ABOUTME: Store methods for feed sync state and fetch log persistence.
// ABOUTME: Wraps sqlc-generated queries with domain types for use by feed handlers and admin API.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/dbutil"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
	"github.com/sqlc-dev/pqtype"
)

// FeedSyncState represents the persistent sync cursor and health state for a feed.
type FeedSyncState struct {
	FeedName            string
	CursorJSON          json.RawMessage
	LastSuccessAt       *time.Time
	LastAttemptAt       *time.Time
	ConsecutiveFailures int32
	LastError           string
	BackoffUntil        *time.Time
	PausedAt            *time.Time
}

// FeedFetchLog represents a single fetch attempt for a feed.
type FeedFetchLog struct {
	ID            uuid.UUID
	FeedName      string
	StartedAt     time.Time
	EndedAt       *time.Time
	Status        string
	ItemsFetched  int32
	ItemsUpserted int32
	CursorBefore  json.RawMessage
	CursorAfter   json.RawMessage
	ErrorSummary  string
}

// GetFeedSyncState returns the sync state for a feed, or nil if not found.
func (s *Store) GetFeedSyncState(ctx context.Context, feedName string) (*FeedSyncState, error) {
	var row generated.FeedSyncState
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		row, err = q.GetFeedSyncState(ctx, feedName)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get feed sync state: %w", err)
	}
	return syncStateFromRow(row), nil
}

// UpsertFeedSyncState creates or updates the sync state for a feed.
func (s *Store) UpsertFeedSyncState(ctx context.Context, state FeedSyncState) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.UpsertFeedSyncState(ctx, generated.UpsertFeedSyncStateParams{
			FeedName:            state.FeedName,
			CursorJson:          toNullRawMessage(state.CursorJSON),
			LastSuccessAt:       toNullTime(state.LastSuccessAt),
			LastAttemptAt:       toNullTime(state.LastAttemptAt),
			ConsecutiveFailures: state.ConsecutiveFailures,
			LastError:           dbutil.NullString(state.LastError),
			BackoffUntil:        toNullTime(state.BackoffUntil),
		})
	})
}

// InsertFeedFetchLog records a fetch attempt and returns the generated log ID.
func (s *Store) InsertFeedFetchLog(ctx context.Context, log FeedFetchLog) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		id, err = q.InsertFeedFetchLog(ctx, generated.InsertFeedFetchLogParams{
			FeedName:      log.FeedName,
			StartedAt:     log.StartedAt,
			EndedAt:       toNullTime(log.EndedAt),
			Status:        log.Status,
			ItemsFetched:  log.ItemsFetched,
			ItemsUpserted: log.ItemsUpserted,
			CursorBefore:  toNullRawMessage(log.CursorBefore),
			CursorAfter:   toNullRawMessage(log.CursorAfter),
			ErrorSummary:  dbutil.NullString(log.ErrorSummary),
		})
		return err
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert feed fetch log: %w", err)
	}
	return id, nil
}

// ListFeedSyncStates returns all feed sync states ordered by feed name.
func (s *Store) ListFeedSyncStates(ctx context.Context) ([]FeedSyncState, error) {
	var rows []generated.FeedSyncState
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		rows, err = q.ListFeedSyncStates(ctx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list feed sync states: %w", err)
	}
	states := make([]FeedSyncState, len(rows))
	for i, r := range rows {
		states[i] = *syncStateFromRow(r)
	}
	return states, nil
}

// ListRecentFeedFetchLogs returns the most recent fetch logs for a feed.
func (s *Store) ListRecentFeedFetchLogs(ctx context.Context, feedName string, limit int) ([]FeedFetchLog, error) {
	var rows []generated.FeedFetchLog
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		rows, err = q.ListRecentFeedFetchLogs(ctx, generated.ListRecentFeedFetchLogsParams{
			FeedName: feedName,
			Limit:    int32(limit), //nolint:gosec // G115: limit values are always small
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list recent feed fetch logs: %w", err)
	}
	logs := make([]FeedFetchLog, len(rows))
	for i, r := range rows {
		logs[i] = fetchLogFromRow(r)
	}
	return logs, nil
}

// --- conversion helpers ---

func syncStateFromRow(r generated.FeedSyncState) *FeedSyncState {
	return &FeedSyncState{
		FeedName:            r.FeedName,
		CursorJSON:          fromNullRawMessage(r.CursorJson),
		LastSuccessAt:       fromNullTime(r.LastSuccessAt),
		LastAttemptAt:       fromNullTime(r.LastAttemptAt),
		ConsecutiveFailures: r.ConsecutiveFailures,
		LastError:           fromNullString(r.LastError),
		BackoffUntil:        fromNullTime(r.BackoffUntil),
		PausedAt:            fromNullTime(r.PausedAt),
	}
}

func fetchLogFromRow(r generated.FeedFetchLog) FeedFetchLog {
	return FeedFetchLog{
		ID:            r.ID,
		FeedName:      r.FeedName,
		StartedAt:     r.StartedAt,
		EndedAt:       fromNullTime(r.EndedAt),
		Status:        r.Status,
		ItemsFetched:  r.ItemsFetched,
		ItemsUpserted: r.ItemsUpserted,
		CursorBefore:  fromNullRawMessage(r.CursorBefore),
		CursorAfter:   fromNullRawMessage(r.CursorAfter),
		ErrorSummary:  fromNullString(r.ErrorSummary),
	}
}

func toNullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

func fromNullTime(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	t := nt.Time
	return &t
}

func fromNullString(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return ns.String
}

func fromNullRawMessage(nrm pqtype.NullRawMessage) json.RawMessage {
	if !nrm.Valid {
		return nil
	}
	return nrm.RawMessage
}

// PauseFeed marks a feed as paused. No-ops if already paused.
func (s *Store) PauseFeed(ctx context.Context, feedName string) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.PauseFeed(ctx, feedName)
	})
}

// ResumeFeed clears the paused flag on a feed. No-ops if not paused.
func (s *Store) ResumeFeed(ctx context.Context, feedName string) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.ResumeFeed(ctx, feedName)
	})
}

// ListFeedFetchLogsPaginated returns paginated fetch logs for a single feed.
func (s *Store) ListFeedFetchLogsPaginated(ctx context.Context, feedName string, afterStartedAt *time.Time, afterID *uuid.UUID, limit int) ([]FeedFetchLog, error) {
	var rows []generated.FeedFetchLog
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		rows, err = q.ListFeedFetchLogs(ctx, generated.ListFeedFetchLogsParams{
			FeedName:       feedName,
			Limit:          int32(limit), //nolint:gosec // G115: limit validated by caller
			AfterStartedAt: toNullTime(afterStartedAt),
			AfterID:        toNullUUID(afterID),
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list feed fetch logs paginated: %w", err)
	}
	logs := make([]FeedFetchLog, len(rows))
	for i, r := range rows {
		logs[i] = fetchLogFromRow(r)
	}
	return logs, nil
}
