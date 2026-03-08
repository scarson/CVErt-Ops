// ABOUTME: Integration tests for feed sync state and fetch log store methods against real Postgres.
// ABOUTME: Validates upsert/get round-trip, list ordering, fetch log insertion, and not-found handling.
package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// ── FeedSyncState tests ─────────────────────────────────────────────────────

func TestGetFeedSyncState_NotFound(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	state, err := db.GetFeedSyncState(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetFeedSyncState should return nil error for not found, got: %v", err)
	}
	if state != nil {
		t.Errorf("GetFeedSyncState should return nil for not found, got: %+v", state)
	}
}

func TestUpsertAndGetFeedSyncState(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	cursor := json.RawMessage(`{"window_start":"2025-01-01T00:00:00Z"}`)

	state := store.FeedSyncState{
		FeedName:            "nvd",
		CursorJSON:          cursor,
		LastSuccessAt:       &now,
		LastAttemptAt:       &now,
		ConsecutiveFailures: 0,
		LastError:           "",
	}

	if err := db.UpsertFeedSyncState(ctx, state); err != nil {
		t.Fatalf("UpsertFeedSyncState: %v", err)
	}

	got, err := db.GetFeedSyncState(ctx, "nvd")
	if err != nil {
		t.Fatalf("GetFeedSyncState: %v", err)
	}
	if got == nil {
		t.Fatal("GetFeedSyncState returned nil after upsert")
	}
	if got.FeedName != "nvd" {
		t.Errorf("FeedName = %q, want %q", got.FeedName, "nvd")
	}
	if got.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d, want 0", got.ConsecutiveFailures)
	}
	if got.CursorJSON == nil {
		t.Fatal("CursorJSON should not be nil")
	}
	// Compare parsed JSON — Postgres JSONB normalizes whitespace.
	var gotCursor, wantCursor map[string]any
	if err := json.Unmarshal(got.CursorJSON, &gotCursor); err != nil {
		t.Fatalf("unmarshal got CursorJSON: %v", err)
	}
	if err := json.Unmarshal(cursor, &wantCursor); err != nil {
		t.Fatalf("unmarshal want cursor: %v", err)
	}
	if gotCursor["window_start"] != wantCursor["window_start"] {
		t.Errorf("CursorJSON window_start = %v, want %v", gotCursor["window_start"], wantCursor["window_start"])
	}

	// Update with a failure.
	state.ConsecutiveFailures = 3
	state.LastError = "upstream 503"
	if err := db.UpsertFeedSyncState(ctx, state); err != nil {
		t.Fatalf("UpsertFeedSyncState (update): %v", err)
	}

	got2, err := db.GetFeedSyncState(ctx, "nvd")
	if err != nil {
		t.Fatalf("GetFeedSyncState after update: %v", err)
	}
	if got2.ConsecutiveFailures != 3 {
		t.Errorf("ConsecutiveFailures = %d, want 3", got2.ConsecutiveFailures)
	}
	if got2.LastError != "upstream 503" {
		t.Errorf("LastError = %q, want %q", got2.LastError, "upstream 503")
	}
}

func TestListFeedSyncStates_OrderedByName(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Insert in non-alphabetical order.
	for _, name := range []string{"nvd", "kev", "ghsa"} {
		if err := db.UpsertFeedSyncState(ctx, store.FeedSyncState{FeedName: name}); err != nil {
			t.Fatalf("UpsertFeedSyncState(%q): %v", name, err)
		}
	}

	states, err := db.ListFeedSyncStates(ctx)
	if err != nil {
		t.Fatalf("ListFeedSyncStates: %v", err)
	}
	if len(states) != 3 {
		t.Fatalf("len = %d, want 3", len(states))
	}
	if states[0].FeedName != "ghsa" {
		t.Errorf("states[0].FeedName = %q, want ghsa", states[0].FeedName)
	}
	if states[1].FeedName != "kev" {
		t.Errorf("states[1].FeedName = %q, want kev", states[1].FeedName)
	}
	if states[2].FeedName != "nvd" {
		t.Errorf("states[2].FeedName = %q, want nvd", states[2].FeedName)
	}
}

// ── FeedFetchLog tests ──────────────────────────────────────────────────────

func TestInsertAndListFeedFetchLogs(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	cursor := json.RawMessage(`{"page":1}`)

	t1 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC)

	// Insert two logs for the same feed.
	id1, err := db.InsertFeedFetchLog(ctx, store.FeedFetchLog{
		FeedName:      "kev",
		StartedAt:     t1,
		Status:        "success",
		ItemsFetched:  100,
		ItemsUpserted: 95,
		CursorBefore:  nil,
		CursorAfter:   cursor,
	})
	if err != nil {
		t.Fatalf("InsertFeedFetchLog 1: %v", err)
	}

	id2, err := db.InsertFeedFetchLog(ctx, store.FeedFetchLog{
		FeedName:      "kev",
		StartedAt:     t2,
		Status:        "error",
		ItemsFetched:  50,
		ItemsUpserted: 0,
		ErrorSummary:  "upstream 503",
	})
	if err != nil {
		t.Fatalf("InsertFeedFetchLog 2: %v", err)
	}

	if id1 == id2 {
		t.Error("InsertFeedFetchLog should return distinct UUIDs")
	}

	// List with limit 10 — should return both, newest first.
	logs, err := db.ListRecentFeedFetchLogs(ctx, "kev", 10)
	if err != nil {
		t.Fatalf("ListRecentFeedFetchLogs: %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("len = %d, want 2", len(logs))
	}
	// Newest first.
	if logs[0].ID != id2 {
		t.Errorf("logs[0].ID = %v, want %v (newest first)", logs[0].ID, id2)
	}
	if logs[0].Status != "error" {
		t.Errorf("logs[0].Status = %q, want error", logs[0].Status)
	}
	if logs[0].ErrorSummary != "upstream 503" {
		t.Errorf("logs[0].ErrorSummary = %q, want %q", logs[0].ErrorSummary, "upstream 503")
	}
	if logs[1].ID != id1 {
		t.Errorf("logs[1].ID = %v, want %v", logs[1].ID, id1)
	}
	if logs[1].ItemsFetched != 100 {
		t.Errorf("logs[1].ItemsFetched = %d, want 100", logs[1].ItemsFetched)
	}

	// List with limit 1 — should return only the newest.
	limited, err := db.ListRecentFeedFetchLogs(ctx, "kev", 1)
	if err != nil {
		t.Fatalf("ListRecentFeedFetchLogs(limit=1): %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("len = %d, want 1", len(limited))
	}
	if limited[0].ID != id2 {
		t.Errorf("limited[0].ID = %v, want %v", limited[0].ID, id2)
	}

	// List for a different feed — should return empty.
	other, err := db.ListRecentFeedFetchLogs(ctx, "nvd", 10)
	if err != nil {
		t.Fatalf("ListRecentFeedFetchLogs(nvd): %v", err)
	}
	if len(other) != 0 {
		t.Errorf("len = %d, want 0 for feed with no logs", len(other))
	}
}

func TestInsertFeedFetchLog_PersistsTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	startTime := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	endTime := time.Date(2026, 1, 1, 10, 5, 30, 0, time.UTC)

	id, err := db.InsertFeedFetchLog(ctx, store.FeedFetchLog{
		FeedName:      "nvd",
		StartedAt:     startTime,
		EndedAt:       &endTime,
		Status:        "success",
		ItemsFetched:  100,
		ItemsUpserted: 42,
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if id == (uuid.UUID{}) {
		t.Fatal("expected non-nil ID")
	}

	// Read back the row and verify timestamps are persisted correctly.
	logs, err := db.ListRecentFeedFetchLogs(ctx, "nvd", 1)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}

	log := logs[0]
	// started_at must match what we passed, not "now()"
	if !log.StartedAt.Equal(startTime) {
		t.Errorf("started_at = %v, want %v", log.StartedAt, startTime)
	}
	// ended_at must match what we passed, not "now()"
	if log.EndedAt == nil || !log.EndedAt.Equal(endTime) {
		t.Errorf("ended_at = %v, want %v", log.EndedAt, endTime)
	}
	// Sanity: duration should be ~5.5 minutes, not zero.
	if log.EndedAt != nil {
		duration := log.EndedAt.Sub(log.StartedAt)
		if duration < 5*time.Minute {
			t.Errorf("duration = %v, want >= 5m (started_at and ended_at are probably both now())", duration)
		}
	}
}
