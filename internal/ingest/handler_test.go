// ABOUTME: Tests for the feed ingest handler — validates pagination, cursor persistence, and error handling.
// ABOUTME: Uses mock adapters and merge functions to isolate handler logic from external dependencies.
package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// mockAdapter implements feed.Adapter for testing.
type mockAdapter struct {
	mu        sync.Mutex
	callCount int
	fetchFunc func(ctx context.Context, cursor json.RawMessage) (*feed.FetchResult, error)
}

func (m *mockAdapter) Fetch(ctx context.Context, cursor json.RawMessage) (*feed.FetchResult, error) {
	m.mu.Lock()
	m.callCount++
	m.mu.Unlock()
	return m.fetchFunc(ctx, cursor)
}

func (m *mockAdapter) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

// mockMerge records calls to the merge function.
type mockMerge struct {
	mu      sync.Mutex
	calls   []mergeCall
	errFunc func(patch feed.CanonicalPatch) error
}

type mergeCall struct {
	CVEID      string
	SourceName string
}

func (m *mockMerge) fn(_ context.Context, _ *store.Store, patch feed.CanonicalPatch, sourceName string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mergeCall{CVEID: patch.CVEID, SourceName: sourceName})
	m.mu.Unlock()
	if m.errFunc != nil {
		return m.errFunc(patch)
	}
	return nil
}

func (m *mockMerge) Calls() []mergeCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mergeCall(nil), m.calls...)
}

// withMockFactory overrides adapterFactory for the duration of a test and restores it on cleanup.
func withMockFactory(t *testing.T, adapter feed.Adapter) {
	t.Helper()
	origFactory := adapterFactory
	adapterFactory = func(_ string, _ *http.Client) (feed.Adapter, error) {
		return adapter, nil
	}
	t.Cleanup(func() { adapterFactory = origFactory })
}

func TestFeedHandler_Success(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	nextCursor := json.RawMessage(`{"page":2}`)
	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
			return &feed.FetchResult{
				Patches: []feed.CanonicalPatch{
					{CVEID: "CVE-2025-0001", SourceID: "CVE-2025-0001"},
					{CVEID: "CVE-2025-0002", SourceID: "CVE-2025-0002"},
				},
				SourceMeta: feed.SourceMeta{SourceName: "test-feed", FetchedAt: time.Now().UTC()},
				NextCursor: nextCursor,
				LastPage:   true,
			}, nil
		},
	}

	merge := &mockMerge{}
	handler := Handler(db.Store, nil, merge.fn)
	withMockFactory(t, adapter)

	payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
	if err := handler(ctx, payload); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	// Verify merge was called for each patch.
	calls := merge.Calls()
	if len(calls) != 2 {
		t.Fatalf("merge called %d times, want 2", len(calls))
	}
	if calls[0].CVEID != "CVE-2025-0001" {
		t.Errorf("calls[0].CVEID = %q, want CVE-2025-0001", calls[0].CVEID)
	}
	if calls[1].CVEID != "CVE-2025-0002" {
		t.Errorf("calls[1].CVEID = %q, want CVE-2025-0002", calls[1].CVEID)
	}
	for i, c := range calls {
		if c.SourceName != "test-feed" {
			t.Errorf("calls[%d].SourceName = %q, want test-feed", i, c.SourceName)
		}
	}

	// Verify sync state was persisted.
	state, err := db.GetFeedSyncState(ctx, "test-feed")
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
		t.Error("CursorJSON should be set to NextCursor")
	}

	// Verify fetch log was created.
	logs, err := db.ListRecentFeedFetchLogs(ctx, "test-feed", 10)
	if err != nil {
		t.Fatalf("ListRecentFeedFetchLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("len(logs) = %d, want 1", len(logs))
	}
	if logs[0].Status != "success" {
		t.Errorf("log status = %q, want success", logs[0].Status)
	}
	if logs[0].ItemsFetched != 2 {
		t.Errorf("ItemsFetched = %d, want 2", logs[0].ItemsFetched)
	}
}

func TestFeedHandler_LastPageStopsFetching(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
			return &feed.FetchResult{
				Patches: []feed.CanonicalPatch{
					{CVEID: "CVE-2025-0001", SourceID: "CVE-2025-0001"},
				},
				SourceMeta: feed.SourceMeta{SourceName: "test-feed", FetchedAt: time.Now().UTC()},
				NextCursor: json.RawMessage(`{"next":"cursor"}`),
				LastPage:   true,
			}, nil
		},
	}

	merge := &mockMerge{}
	handler := Handler(db.Store, nil, merge.fn)
	withMockFactory(t, adapter)

	payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
	if err := handler(ctx, payload); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// LastPage=true should stop after one call, even though NextCursor is non-nil.
	if adapter.CallCount() != 1 {
		t.Errorf("Fetch called %d times, want 1 (LastPage should stop pagination)", adapter.CallCount())
	}
}

func TestFeedHandler_FetchError(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
			return nil, fmt.Errorf("upstream 503")
		},
	}

	merge := &mockMerge{}
	handler := Handler(db.Store, nil, merge.fn)
	withMockFactory(t, adapter)

	payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
	err := handler(ctx, payload)
	if err == nil {
		t.Fatal("expected error from handler when Fetch fails")
	}

	// Verify failure state was persisted.
	state, err := db.GetFeedSyncState(ctx, "test-feed")
	if err != nil {
		t.Fatalf("GetFeedSyncState: %v", err)
	}
	if state == nil {
		t.Fatal("sync state should exist after failure")
	}
	if state.ConsecutiveFailures != 1 {
		t.Errorf("ConsecutiveFailures = %d, want 1", state.ConsecutiveFailures)
	}
	if state.LastError != "upstream 503" {
		t.Errorf("LastError = %q, want %q", state.LastError, "upstream 503")
	}
	if state.BackoffUntil == nil {
		t.Error("BackoffUntil should be set after failure")
	}

	// Verify error fetch log.
	logs, err := db.ListRecentFeedFetchLogs(ctx, "test-feed", 10)
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

func TestFeedHandler_FailurePreservesLastSuccess(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	var shouldFail bool
	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
			if shouldFail {
				return nil, fmt.Errorf("upstream 503")
			}
			return &feed.FetchResult{
				Patches:    []feed.CanonicalPatch{{CVEID: "CVE-2025-0001", SourceID: "CVE-2025-0001"}},
				SourceMeta: feed.SourceMeta{SourceName: "test-feed", FetchedAt: time.Now().UTC()},
				LastPage:   true,
			}, nil
		},
	}

	merge := &mockMerge{}
	handler := Handler(db.Store, nil, merge.fn)
	withMockFactory(t, adapter)

	// First run succeeds.
	payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
	if err := handler(ctx, payload); err != nil {
		t.Fatalf("first run: %v", err)
	}

	state, err := db.GetFeedSyncState(ctx, "test-feed")
	if err != nil {
		t.Fatalf("GetFeedSyncState: %v", err)
	}
	if state.LastSuccessAt == nil {
		t.Fatal("LastSuccessAt should be set after success")
	}
	savedSuccess := *state.LastSuccessAt

	// Second run fails.
	shouldFail = true
	if err := handler(ctx, payload); err == nil {
		t.Fatal("expected error on second run")
	}

	state2, err := db.GetFeedSyncState(ctx, "test-feed")
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

func TestFeedHandler_MidPaginationError(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	page1Cursor := json.RawMessage(`{"page":2}`)
	var callCount int
	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
			callCount++
			if callCount == 1 {
				return &feed.FetchResult{
					Patches: []feed.CanonicalPatch{
						{CVEID: "CVE-2025-0001", SourceID: "CVE-2025-0001"},
					},
					SourceMeta: feed.SourceMeta{SourceName: "test-feed", FetchedAt: time.Now().UTC()},
					NextCursor: page1Cursor,
					LastPage:   false,
				}, nil
			}
			return nil, fmt.Errorf("page 2 failed")
		},
	}

	merge := &mockMerge{}
	handler := Handler(db.Store, nil, merge.fn)
	withMockFactory(t, adapter)

	payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
	err := handler(ctx, payload)
	if err == nil {
		t.Fatal("expected error from handler on page 2 failure")
	}

	// Verify cursor is saved as page1's NextCursor (last successful page),
	// not the original nil cursor.
	state, err := db.GetFeedSyncState(ctx, "test-feed")
	if err != nil {
		t.Fatalf("GetFeedSyncState: %v", err)
	}
	if state == nil {
		t.Fatal("sync state should exist after mid-pagination failure")
	}

	var savedCursor map[string]any
	if err := json.Unmarshal(state.CursorJSON, &savedCursor); err != nil {
		t.Fatalf("unmarshal saved cursor: %v", err)
	}
	// Should be {"page":2}, not nil/empty.
	if savedCursor["page"] != float64(2) {
		t.Errorf("saved cursor page = %v, want 2 (should save last successful cursor)", savedCursor["page"])
	}

	if state.ConsecutiveFailures != 1 {
		t.Errorf("ConsecutiveFailures = %d, want 1", state.ConsecutiveFailures)
	}

	// Verify fetch log counts items from the successful page.
	logs, err := db.ListRecentFeedFetchLogs(ctx, "test-feed", 10)
	if err != nil {
		t.Fatalf("ListRecentFeedFetchLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("len(logs) = %d, want 1", len(logs))
	}
	if logs[0].ItemsFetched != 1 {
		t.Errorf("ItemsFetched = %d, want 1 (page 1 had 1 item)", logs[0].ItemsFetched)
	}
}

// failSyncStateStore wraps a real store but fails UpsertFeedSyncState.
// This tests error propagation logic — the wrapper is a one-line override, not a full mock.
type failSyncStateStore struct {
	HandlerStore
}

func (f *failSyncStateStore) UpsertFeedSyncState(_ context.Context, _ store.FeedSyncState) error {
	return fmt.Errorf("simulated sync state failure")
}

// captureLogs redirects slog to a buffer for pristine test output, restoring on cleanup.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	origHandler := slog.Default().Handler()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(slog.New(origHandler)) })
	return &buf
}

func TestFeedHandler_SyncStateFailOnSuccess_ReturnsError(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	logBuf := captureLogs(t)

	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
			return &feed.FetchResult{
				Patches:    []feed.CanonicalPatch{{CVEID: "CVE-2025-0001", SourceID: "CVE-2025-0001"}},
				SourceMeta: feed.SourceMeta{SourceName: "test-feed", FetchedAt: time.Now().UTC()},
				LastPage:   true,
			}, nil
		},
	}

	merge := &mockMerge{}
	failStore := &failSyncStateStore{HandlerStore: db.Store}
	handler := handlerWithStore(failStore, db.Store, nil, merge.fn)
	withMockFactory(t, adapter)

	payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
	err := handler(ctx, payload)

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

func TestFeedHandler_SyncStateFailOnError_LogsButReturnsOriginal(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	logBuf := captureLogs(t)

	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
			return nil, fmt.Errorf("upstream 503")
		},
	}

	merge := &mockMerge{}
	failStore := &failSyncStateStore{HandlerStore: db.Store}
	handler := handlerWithStore(failStore, db.Store, nil, merge.fn)
	withMockFactory(t, adapter)

	payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
	err := handler(ctx, payload)

	// Error-path sync state failure should be logged, but original error returned.
	if err == nil {
		t.Fatal("expected error from handler")
	}
	if !strings.Contains(err.Error(), "upstream 503") {
		t.Errorf("error = %q, want original fetch error containing 'upstream 503'", err.Error())
	}
	if !strings.Contains(logBuf.String(), "sync state write failed on error path") {
		t.Errorf("expected log message about sync state failure on error path, got: %s", logBuf.String())
	}
}

func TestFeedHandler_UnknownFeed(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	handler := Handler(db.Store, nil, nil)

	payload, _ := json.Marshal(Payload{FeedName: "bogus"})
	err := handler(ctx, payload)
	if err == nil {
		t.Fatal("expected error for unknown feed")
	}
}

func TestBackoffDuration_NegativeInput(t *testing.T) {
	// Should not panic on negative input (e.g., from DB corruption).
	d := backoffDuration(-1)
	if d < 0 {
		t.Errorf("backoffDuration(-1) = %v, want non-negative", d)
	}
}

func TestBackoffDuration_Zero(t *testing.T) {
	d := backoffDuration(0)
	if d != 30*time.Second {
		t.Errorf("backoffDuration(0) = %v, want 30s", d)
	}
}

func TestBackoffDuration_Capped(t *testing.T) {
	// At failures=10, should be 30s * 1024 = 30720s. Beyond 10 should not increase.
	d10 := backoffDuration(10)
	d20 := backoffDuration(20)
	if d10 != d20 {
		t.Errorf("backoffDuration(20) = %v, want same as backoffDuration(10) = %v", d20, d10)
	}
}
