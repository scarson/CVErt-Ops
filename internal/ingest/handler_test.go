// ABOUTME: Tests for the feed ingest handler — validates pagination, cursor persistence, and error handling.
// ABOUTME: Uses mock adapters and merge functions to isolate handler logic from external dependencies.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

func TestFeedIngestHandler_Success(t *testing.T) {
	t.Parallel()
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
	handler := IngestHandler(db.Store, nil, merge.fn)
	withMockFactory(t, adapter)

	payload, _ := json.Marshal(IngestPayload{FeedName: "test-feed"})
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

func TestFeedIngestHandler_LastPageStopsFetching(t *testing.T) {
	t.Parallel()
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
	handler := IngestHandler(db.Store, nil, merge.fn)
	withMockFactory(t, adapter)

	payload, _ := json.Marshal(IngestPayload{FeedName: "test-feed"})
	if err := handler(ctx, payload); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// LastPage=true should stop after one call, even though NextCursor is non-nil.
	if adapter.CallCount() != 1 {
		t.Errorf("Fetch called %d times, want 1 (LastPage should stop pagination)", adapter.CallCount())
	}
}

func TestFeedIngestHandler_FetchError(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
			return nil, fmt.Errorf("upstream 503")
		},
	}

	merge := &mockMerge{}
	handler := IngestHandler(db.Store, nil, merge.fn)
	withMockFactory(t, adapter)

	payload, _ := json.Marshal(IngestPayload{FeedName: "test-feed"})
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

func TestFeedIngestHandler_MidPaginationError(t *testing.T) {
	t.Parallel()
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
	handler := IngestHandler(db.Store, nil, merge.fn)
	withMockFactory(t, adapter)

	payload, _ := json.Marshal(IngestPayload{FeedName: "test-feed"})
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
}

func TestFeedIngestHandler_UnknownFeed(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	handler := IngestHandler(db.Store, nil, nil)

	payload, _ := json.Marshal(IngestPayload{FeedName: "bogus"})
	err := handler(ctx, payload)
	if err == nil {
		t.Fatal("expected error for unknown feed")
	}
}
