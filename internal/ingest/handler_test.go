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
	"github.com/scarson/cvert-ops/internal/merge"
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

func (m *mockMerge) fn(_ context.Context, _ merge.Store, patch feed.CanonicalPatch, sourceName string) error {
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

// mockFactory returns an AdapterFactory that always returns the given adapter.
func mockFactory(adapter feed.Adapter) AdapterFactory {
	return func(_ string, _ *http.Client) (feed.Adapter, error) {
		return adapter, nil
	}
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
	handler := handlerWithStore(db.Store, db.Store, nil, merge.fn, mockFactory(adapter), nil, nil)

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
	handler := handlerWithStore(db.Store, db.Store, nil, merge.fn, mockFactory(adapter), nil, nil)

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
	handler := handlerWithStore(db.Store, db.Store, nil, merge.fn, mockFactory(adapter), nil, nil)

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
	handler := handlerWithStore(db.Store, db.Store, nil, merge.fn, mockFactory(adapter), nil, nil)

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
	handler := handlerWithStore(db.Store, db.Store, nil, merge.fn, mockFactory(adapter), nil, nil)

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
	handler := handlerWithStore(failStore, db.Store, nil, merge.fn, mockFactory(adapter), nil, nil)

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
	handler := handlerWithStore(failStore, db.Store, nil, merge.fn, mockFactory(adapter), nil, nil)

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

// recordingSyncStore wraps a real store and records UpsertFeedSyncState calls.
type recordingSyncStore struct {
	HandlerStore
	mu     sync.Mutex
	states []store.FeedSyncState
}

func (r *recordingSyncStore) UpsertFeedSyncState(ctx context.Context, state store.FeedSyncState) error {
	r.mu.Lock()
	r.states = append(r.states, state)
	r.mu.Unlock()
	return r.HandlerStore.UpsertFeedSyncState(ctx, state)
}

func (r *recordingSyncStore) States() []store.FeedSyncState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]store.FeedSyncState(nil), r.states...)
}

func TestFeedHandler_MidPageCursorPersist(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	page1Cursor := json.RawMessage(`{"page":2}`)
	page2Cursor := json.RawMessage(`{"page":3}`)
	var callCount int
	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
			callCount++
			switch callCount {
			case 1:
				return &feed.FetchResult{
					Patches:    []feed.CanonicalPatch{{CVEID: "CVE-2025-0001", SourceID: "CVE-2025-0001"}},
					SourceMeta: feed.SourceMeta{SourceName: "test-feed", FetchedAt: time.Now().UTC()},
					NextCursor: page1Cursor,
				}, nil
			case 2:
				return &feed.FetchResult{
					Patches:    []feed.CanonicalPatch{{CVEID: "CVE-2025-0002", SourceID: "CVE-2025-0002"}},
					SourceMeta: feed.SourceMeta{SourceName: "test-feed", FetchedAt: time.Now().UTC()},
					NextCursor: page2Cursor,
					LastPage:   true,
				}, nil
			default:
				t.Fatal("unexpected third Fetch call")
				return nil, nil
			}
		},
	}

	merge := &mockMerge{}
	recStore := &recordingSyncStore{HandlerStore: db.Store}
	handler := handlerWithStore(recStore, db.Store, nil, merge.fn, mockFactory(adapter), nil, nil)

	payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
	if err := handler(ctx, payload); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// Should have at least 3 UpsertFeedSyncState calls:
	// mid-page after page 1, mid-page after page 2, final success.
	states := recStore.States()
	if len(states) < 3 {
		t.Fatalf("expected at least 3 UpsertFeedSyncState calls (mid-page + final), got %d", len(states))
	}

	// The first mid-page persist should have page1's cursor.
	var midPageCursor map[string]any
	if err := json.Unmarshal(states[0].CursorJSON, &midPageCursor); err != nil {
		t.Fatalf("unmarshal mid-page cursor: %v", err)
	}
	if midPageCursor["page"] != float64(2) {
		t.Errorf("mid-page cursor page = %v, want 2", midPageCursor["page"])
	}
	// Mid-page persist should NOT update LastSuccessAt (only final success does).
	if states[0].LastSuccessAt != nil {
		t.Error("mid-page persist should not set LastSuccessAt")
	}

	// Final state should have page2's cursor and LastSuccessAt set.
	finalState := states[len(states)-1]
	var finalCursor map[string]any
	if err := json.Unmarshal(finalState.CursorJSON, &finalCursor); err != nil {
		t.Fatalf("unmarshal final cursor: %v", err)
	}
	if finalCursor["page"] != float64(3) {
		t.Errorf("final cursor page = %v, want 3", finalCursor["page"])
	}
	if finalState.LastSuccessAt == nil {
		t.Error("final state should have LastSuccessAt set")
	}
}

func TestFeedHandler_MidPageCursorPersist_PreservesFailureTracking(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed sync state with existing failure tracking (simulates prior failures).
	now := time.Now().UTC()
	backoff := now.Add(10 * time.Minute)
	if err := db.UpsertFeedSyncState(ctx, store.FeedSyncState{
		FeedName:            "test-feed",
		ConsecutiveFailures: 3,
		LastError:           "previous failure",
		BackoffUntil:        &backoff,
		LastAttemptAt:       &now,
	}); err != nil {
		t.Fatalf("seed sync state: %v", err)
	}

	page1Cursor := json.RawMessage(`{"page":2}`)
	var callCount int
	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
			callCount++
			return &feed.FetchResult{
				Patches:    []feed.CanonicalPatch{{CVEID: "CVE-2025-0001", SourceID: "CVE-2025-0001"}},
				SourceMeta: feed.SourceMeta{SourceName: "test-feed", FetchedAt: time.Now().UTC()},
				NextCursor: page1Cursor,
				LastPage:   true,
			}, nil
		},
	}

	merge := &mockMerge{}
	recStore := &recordingSyncStore{HandlerStore: db.Store}
	handler := handlerWithStore(recStore, db.Store, nil, merge.fn, mockFactory(adapter), nil, nil)

	payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
	if err := handler(ctx, payload); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// Should have at least 2 UpsertFeedSyncState calls: mid-page + final success.
	states := recStore.States()
	if len(states) < 2 {
		t.Fatalf("expected at least 2 UpsertFeedSyncState calls, got %d", len(states))
	}

	// The mid-page persist (first call) must preserve ConsecutiveFailures from the
	// prior state. If a process crash occurs between mid-page and final persist,
	// the failure tracking must not be lost.
	midPage := states[0]
	if midPage.ConsecutiveFailures != 3 {
		t.Errorf("mid-page ConsecutiveFailures = %d, want 3 (preserved from seed)", midPage.ConsecutiveFailures)
	}
	if midPage.BackoffUntil == nil {
		t.Error("mid-page BackoffUntil should be preserved from seed, got nil")
	}
	if midPage.LastError != "previous failure" {
		t.Errorf("mid-page LastError = %q, want %q", midPage.LastError, "previous failure")
	}

	// Final success persist should reset failure tracking.
	finalState := states[len(states)-1]
	if finalState.ConsecutiveFailures != 0 {
		t.Errorf("final ConsecutiveFailures = %d, want 0", finalState.ConsecutiveFailures)
	}
	if finalState.LastError != "" {
		t.Errorf("final LastError = %q, want empty", finalState.LastError)
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

func TestBackoffDuration_One(t *testing.T) {
	d := backoffDuration(1)
	if d != 60*time.Second {
		t.Errorf("backoffDuration(1) = %v, want 1m0s", d)
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

// mockHashReader implements CVEHashReader for testing hash change detection.
type mockHashReader struct {
	mu     sync.Mutex
	hashes map[string]string // cveID -> hash; updated by merge mock to simulate changes
}

func (m *mockHashReader) GetCVEMaterialHash(_ context.Context, cveID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hashes[cveID], nil
}

// mockEvaluator implements RealtimeEvaluator for testing alert evaluation calls.
type mockEvaluator struct {
	mu      sync.Mutex
	calls   []string // CVE IDs passed to EvaluateRealtime
	errFunc func(cveID string) error
}

func (m *mockEvaluator) EvaluateRealtime(_ context.Context, cveID string) error {
	m.mu.Lock()
	m.calls = append(m.calls, cveID)
	m.mu.Unlock()
	if m.errFunc != nil {
		return m.errFunc(cveID)
	}
	return nil
}

func (m *mockEvaluator) Calls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.calls...)
}

func TestFeedHandler_RealtimeEval_CalledOnHashChange(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	hashReader := &mockHashReader{hashes: map[string]string{
		"CVE-2025-0001": "hash-before",
	}}
	eval := &mockEvaluator{}

	// Merge mock simulates a hash change by updating the hash reader.
	mergeFn := func(_ context.Context, _ merge.Store, patch feed.CanonicalPatch, _ string) error {
		hashReader.mu.Lock()
		hashReader.hashes[patch.CVEID] = "hash-after"
		hashReader.mu.Unlock()
		return nil
	}

	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
			return &feed.FetchResult{
				Patches:    []feed.CanonicalPatch{{CVEID: "CVE-2025-0001", SourceID: "CVE-2025-0001"}},
				SourceMeta: feed.SourceMeta{SourceName: "test-feed", FetchedAt: time.Now().UTC()},
				LastPage:   true,
			}, nil
		},
	}

	handler := handlerWithStore(db.Store, db.Store, nil, mergeFn, mockFactory(adapter), eval, hashReader)

	payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
	if err := handler(ctx, payload); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	calls := eval.Calls()
	if len(calls) != 1 {
		t.Fatalf("EvaluateRealtime called %d times, want 1", len(calls))
	}
	if calls[0] != "CVE-2025-0001" {
		t.Errorf("EvaluateRealtime called with %q, want CVE-2025-0001", calls[0])
	}
}

func TestFeedHandler_RealtimeEval_NotCalledWhenHashUnchanged(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	hashReader := &mockHashReader{hashes: map[string]string{
		"CVE-2025-0001": "same-hash",
	}}
	eval := &mockEvaluator{}

	// Merge mock does NOT change the hash.
	mergeFn := func(_ context.Context, _ merge.Store, _ feed.CanonicalPatch, _ string) error {
		return nil
	}

	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
			return &feed.FetchResult{
				Patches:    []feed.CanonicalPatch{{CVEID: "CVE-2025-0001", SourceID: "CVE-2025-0001"}},
				SourceMeta: feed.SourceMeta{SourceName: "test-feed", FetchedAt: time.Now().UTC()},
				LastPage:   true,
			}, nil
		},
	}

	handler := handlerWithStore(db.Store, db.Store, nil, mergeFn, mockFactory(adapter), eval, hashReader)

	payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
	if err := handler(ctx, payload); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	calls := eval.Calls()
	if len(calls) != 0 {
		t.Errorf("EvaluateRealtime called %d times, want 0 (hash unchanged)", len(calls))
	}
}

func TestFeedHandler_RealtimeEval_ErrorDoesNotFailIngest(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	logBuf := captureLogs(t)

	hashReader := &mockHashReader{hashes: map[string]string{
		"CVE-2025-0001": "hash-before",
	}}
	eval := &mockEvaluator{
		errFunc: func(_ string) error {
			return fmt.Errorf("evaluation failed")
		},
	}

	// Merge mock simulates a hash change to trigger evaluation.
	mergeFn := func(_ context.Context, _ merge.Store, patch feed.CanonicalPatch, _ string) error {
		hashReader.mu.Lock()
		hashReader.hashes[patch.CVEID] = "hash-after"
		hashReader.mu.Unlock()
		return nil
	}

	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
			return &feed.FetchResult{
				Patches:    []feed.CanonicalPatch{{CVEID: "CVE-2025-0001", SourceID: "CVE-2025-0001"}},
				SourceMeta: feed.SourceMeta{SourceName: "test-feed", FetchedAt: time.Now().UTC()},
				LastPage:   true,
			}, nil
		},
	}

	handler := handlerWithStore(db.Store, db.Store, nil, mergeFn, mockFactory(adapter), eval, hashReader)

	payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
	err := handler(ctx, payload)

	// Ingestion must succeed even though evaluation failed.
	if err != nil {
		t.Fatalf("handler returned error %v, want nil (eval error should not fail ingest)", err)
	}

	// Evaluation error must be logged (testing-pitfalls §3.2).
	if !strings.Contains(logBuf.String(), "realtime alert evaluation failed") {
		t.Errorf("expected log message about evaluation failure, got: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "evaluation failed") {
		t.Errorf("expected error detail in log, got: %s", logBuf.String())
	}
}
