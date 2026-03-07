// ABOUTME: Tests for the EPSS ingest handler — validates cursor persistence, sync state, and error handling.
// ABOUTME: Uses a mock ApplyFunc to isolate handler logic from the real EPSS adapter.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestEPSSHandler_Success(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	newCursor := json.RawMessage(`{"score_date":"2026-03-07T12:00:00Z","model_version":"v2025.03.14"}`)
	applyFn := func(_ context.Context, _ *store.Store, _ json.RawMessage) (json.RawMessage, error) {
		return newCursor, nil
	}

	handler := EPSSHandler(db.Store, applyFn)

	if err := handler(ctx, nil); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	// Verify sync state was persisted.
	state, err := db.GetFeedSyncState(ctx, "epss")
	if err != nil {
		t.Fatalf("GetFeedSyncState: %v", err)
	}
	if state == nil {
		t.Fatal("sync state should not be nil after successful run")
	}
	if state.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d, want 0", state.ConsecutiveFailures)
	}
	if state.LastSuccessAt == nil {
		t.Error("LastSuccessAt should be set after success")
	}
	if state.CursorJSON == nil {
		t.Error("CursorJSON should be set to new cursor")
	}

	// Verify cursor value round-trips correctly.
	var savedCursor map[string]any
	if err := json.Unmarshal(state.CursorJSON, &savedCursor); err != nil {
		t.Fatalf("unmarshal saved cursor: %v", err)
	}
	if savedCursor["score_date"] != "2026-03-07T12:00:00Z" {
		t.Errorf("saved cursor score_date = %v, want 2026-03-07T12:00:00Z", savedCursor["score_date"])
	}

	// Verify fetch log was created.
	logs, err := db.ListRecentFeedFetchLogs(ctx, "epss", 10)
	if err != nil {
		t.Fatalf("ListRecentFeedFetchLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("len(logs) = %d, want 1", len(logs))
	}
	if logs[0].Status != "success" {
		t.Errorf("log status = %q, want success", logs[0].Status)
	}
}

func TestEPSSHandler_Error(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	applyFn := func(_ context.Context, _ *store.Store, _ json.RawMessage) (json.RawMessage, error) {
		return nil, fmt.Errorf("download failed")
	}

	handler := EPSSHandler(db.Store, applyFn)

	err := handler(ctx, nil)
	if err == nil {
		t.Fatal("expected error from handler when Apply fails")
	}

	// Verify failure state was persisted.
	state, err := db.GetFeedSyncState(ctx, "epss")
	if err != nil {
		t.Fatalf("GetFeedSyncState: %v", err)
	}
	if state == nil {
		t.Fatal("sync state should exist after failure")
	}
	if state.ConsecutiveFailures != 1 {
		t.Errorf("ConsecutiveFailures = %d, want 1", state.ConsecutiveFailures)
	}
	if state.LastError != "download failed" {
		t.Errorf("LastError = %q, want %q", state.LastError, "download failed")
	}
	if state.BackoffUntil == nil {
		t.Error("BackoffUntil should be set after failure")
	}

	// Verify error fetch log.
	logs, err := db.ListRecentFeedFetchLogs(ctx, "epss", 10)
	if err != nil {
		t.Fatalf("ListRecentFeedFetchLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("len(logs) = %d, want 1", len(logs))
	}
	if logs[0].Status != "error" {
		t.Errorf("log status = %q, want error", logs[0].Status)
	}
}

func TestEPSSHandler_FailurePreservesLastSuccess(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	var shouldFail bool
	newCursor := json.RawMessage(`{"score_date":"2026-03-07T12:00:00Z"}`)
	applyFn := func(_ context.Context, _ *store.Store, _ json.RawMessage) (json.RawMessage, error) {
		if shouldFail {
			return nil, fmt.Errorf("download failed")
		}
		return newCursor, nil
	}

	handler := EPSSHandler(db.Store, applyFn)

	// First run succeeds.
	if err := handler(ctx, nil); err != nil {
		t.Fatalf("first run: %v", err)
	}

	state, err := db.GetFeedSyncState(ctx, "epss")
	if err != nil {
		t.Fatalf("GetFeedSyncState: %v", err)
	}
	if state.LastSuccessAt == nil {
		t.Fatal("LastSuccessAt should be set after success")
	}
	savedSuccess := *state.LastSuccessAt

	// Second run fails.
	shouldFail = true
	if err := handler(ctx, nil); err == nil {
		t.Fatal("expected error on second run")
	}

	state2, err := db.GetFeedSyncState(ctx, "epss")
	if err != nil {
		t.Fatalf("GetFeedSyncState after failure: %v", err)
	}
	if state2.LastSuccessAt == nil {
		t.Fatal("LastSuccessAt should be preserved after failure")
	}
	if !state2.LastSuccessAt.Equal(savedSuccess) {
		t.Errorf("LastSuccessAt changed from %v to %v (should be preserved)", savedSuccess, *state2.LastSuccessAt)
	}
	if state2.ConsecutiveFailures != 1 {
		t.Errorf("ConsecutiveFailures = %d, want 1", state2.ConsecutiveFailures)
	}
}

func TestEPSSHandler_SyncStateFailOnSuccess_ReturnsError(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	logBuf := captureLogs(t)

	newCursor := json.RawMessage(`{"score_date":"2026-03-07T12:00:00Z"}`)
	applyFn := func(_ context.Context, _ *store.Store, _ json.RawMessage) (json.RawMessage, error) {
		return newCursor, nil
	}

	failStore := &failSyncStateStore{HandlerStore: db.Store}
	handler := epssHandlerWithStore(failStore, db.Store, applyFn)

	err := handler(ctx, nil)

	// Success-path sync state failure must propagate as an error.
	if err == nil {
		t.Fatal("expected error when sync state write fails on success path")
	}
	if !strings.Contains(err.Error(), "persist sync state") {
		t.Errorf("error = %q, want to contain 'persist sync state'", err.Error())
	}
	if !strings.Contains(logBuf.String(), "sync state write failed on success path") {
		t.Errorf("expected log message about sync state failure, got: %s", logBuf.String())
	}
}

func TestEPSSHandler_SyncStateFailOnError_LogsButReturnsOriginal(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	logBuf := captureLogs(t)

	applyFn := func(_ context.Context, _ *store.Store, _ json.RawMessage) (json.RawMessage, error) {
		return nil, fmt.Errorf("download failed")
	}

	failStore := &failSyncStateStore{HandlerStore: db.Store}
	handler := epssHandlerWithStore(failStore, db.Store, applyFn)

	err := handler(ctx, nil)

	// Error-path sync state failure should be logged, but original error returned.
	if err == nil {
		t.Fatal("expected error from handler")
	}
	if !strings.Contains(err.Error(), "download failed") {
		t.Errorf("error = %q, want original error containing 'download failed'", err.Error())
	}
	if !strings.Contains(logBuf.String(), "sync state write failed on error path") {
		t.Errorf("expected log message about sync state failure on error path, got: %s", logBuf.String())
	}
}

func TestEPSSHandler_PassesCursorToApply(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed cursor state.
	seedCursor := json.RawMessage(`{"score_date":"2026-03-06T12:00:00Z"}`)
	now := time.Now().UTC()
	if err := db.UpsertFeedSyncState(ctx, store.FeedSyncState{
		FeedName:      "epss",
		CursorJSON:    seedCursor,
		LastSuccessAt: &now,
		LastAttemptAt: &now,
	}); err != nil {
		t.Fatalf("seed sync state: %v", err)
	}

	var receivedCursor json.RawMessage
	newCursor := json.RawMessage(`{"score_date":"2026-03-07T12:00:00Z"}`)
	applyFn := func(_ context.Context, _ *store.Store, cursor json.RawMessage) (json.RawMessage, error) {
		receivedCursor = cursor
		return newCursor, nil
	}

	handler := EPSSHandler(db.Store, applyFn)
	if err := handler(ctx, nil); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// Verify the cursor passed to Apply matches the seed.
	if receivedCursor == nil {
		t.Fatal("Apply should have received the seed cursor")
	}
	var got map[string]any
	if err := json.Unmarshal(receivedCursor, &got); err != nil {
		t.Fatalf("unmarshal received cursor: %v", err)
	}
	if got["score_date"] != "2026-03-06T12:00:00Z" {
		t.Errorf("received cursor score_date = %v, want 2026-03-06T12:00:00Z", got["score_date"])
	}
}
