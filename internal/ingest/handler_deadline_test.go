// ABOUTME: Tests for feed ingest runs that reach the worker's job deadline.
// ABOUTME: Covers recording the outcome on an expired context and ending a long backfill run between pages.
package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// expiringJobContext is a job context whose deadline a test expires explicitly,
// so the test does not race a timer. Deadline reports a distant time, which keeps
// the run from stopping early on its own: the test decides when time runs out.
type expiringJobContext struct {
	context.Context
}

func (expiringJobContext) Deadline() (time.Time, bool) {
	return time.Now().Add(time.Hour), true
}

func (c expiringJobContext) Err() error {
	if c.Context.Err() != nil {
		return context.DeadlineExceeded
	}
	return nil
}

func newExpiringJobContext(t *testing.T) (ctx context.Context, expire func()) {
	t.Helper()
	inner, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return expiringJobContext{inner}, cancel
}

// nearDeadlineContext returns a job context with less than pageReserve left, and
// enough real time left that the run's own writes are not interrupted.
func nearDeadlineContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), pageReserve-time.Second)
	t.Cleanup(cancel)
	return ctx
}

func deadlineTestPage(cursor string, lastPage bool, cveIDs ...string) *feed.FetchResult {
	patches := make([]feed.CanonicalPatch, 0, len(cveIDs))
	for _, id := range cveIDs {
		patches = append(patches, feed.CanonicalPatch{CVEID: id, SourceID: id})
	}
	return &feed.FetchResult{
		Patches:    patches,
		SourceMeta: feed.SourceMeta{SourceName: "test-feed", FetchedAt: time.Now().UTC()},
		NextCursor: json.RawMessage(cursor),
		LastPage:   lastPage,
	}
}

func feedStateAndLatestLog(t *testing.T, db *testutil.TestDB) (*store.FeedSyncState, store.FeedFetchLog) {
	t.Helper()
	ctx := context.Background()
	state, err := db.GetFeedSyncState(ctx, "test-feed")
	if err != nil {
		t.Fatalf("GetFeedSyncState: %v", err)
	}
	if state == nil {
		t.Fatal("feed sync state was not recorded")
	}
	logs, err := db.ListRecentFeedFetchLogs(ctx, "test-feed", 1)
	if err != nil {
		t.Fatalf("ListRecentFeedFetchLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("len(logs) = %d, want 1: the fetch log was not recorded", len(logs))
	}
	return state, logs[0]
}

func cursorPage(t *testing.T, cursor json.RawMessage) float64 {
	t.Helper()
	var decoded struct {
		Page float64 `json:"page"`
	}
	if err := json.Unmarshal(cursor, &decoded); err != nil {
		t.Fatalf("unmarshal cursor %q: %v", cursor, err)
	}
	return decoded.Page
}

// A run that reaches the job deadline before completing a page has made no
// progress. It is a failure, and the failure and backoff must reach the database
// even though the job context has expired.
func TestFeedHandler_DeadlineBeforeFirstPageCompletes_RecordsFailure(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(expire func()) (*mockAdapter, *mockMerge)
		wantText string
	}{
		{
			name: "during fetch",
			setup: func(expire func()) (*mockAdapter, *mockMerge) {
				return &mockAdapter{
					fetchFunc: func(ctx context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
						expire()
						return nil, ctx.Err()
					},
				}, &mockMerge{}
			},
			wantText: "deadline exceeded",
		},
		{
			name: "during merge",
			setup: func(expire func()) (*mockAdapter, *mockMerge) {
				return &mockAdapter{
						fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
							return deadlineTestPage(`{"page":2}`, false, "CVE-2025-0001"), nil
						},
					}, &mockMerge{errFunc: func(feed.CanonicalPatch) error {
						expire()
						return context.DeadlineExceeded
					}}
			},
			wantText: "merge CVE-2025-0001",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := testutil.NewTestDB(t)
			captureLogs(t)
			ctx, expire := newExpiringJobContext(t)
			adapter, mergeMock := tc.setup(expire)
			handler := handlerWithStore(db.Store, db.Store, nil, mergeMock.fn, mockFactory(adapter), nil, nil)

			payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
			err := handler(ctx, payload)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("handler error = %v, want context.DeadlineExceeded", err)
			}

			state, log := feedStateAndLatestLog(t, db)
			if state.ConsecutiveFailures != 1 {
				t.Errorf("ConsecutiveFailures = %d, want 1", state.ConsecutiveFailures)
			}
			if !strings.Contains(state.LastError, tc.wantText) {
				t.Errorf("LastError = %q, want it to contain %q", state.LastError, tc.wantText)
			}
			if state.BackoffUntil == nil {
				t.Error("BackoffUntil should be set after a failed run")
			}
			if log.Status != "error" {
				t.Errorf("log status = %q, want error", log.Status)
			}
		})
	}
}

// A run that finishes its last page as the deadline expires is a complete run.
func TestFeedHandler_FinalPageCompletesAtDeadline_RecordsSuccess(t *testing.T) {
	db := testutil.NewTestDB(t)
	captureLogs(t)
	ctx, expire := newExpiringJobContext(t)

	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
			expire()
			return deadlineTestPage(`{"page":2}`, true, "CVE-2025-0001"), nil
		},
	}
	mergeMock := &mockMerge{}
	handler := handlerWithStore(db.Store, db.Store, nil, mergeMock.fn, mockFactory(adapter), nil, nil)

	payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
	if err := handler(ctx, payload); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	state, log := feedStateAndLatestLog(t, db)
	if state.LastSuccessAt == nil {
		t.Error("LastSuccessAt should be set after a complete run")
	}
	if got := cursorPage(t, state.CursorJSON); got != 2 {
		t.Errorf("cursor page = %v, want 2", got)
	}
	if log.Status != "success" {
		t.Errorf("log status = %q, want success", log.Status)
	}
}

// Near the job deadline, with pages left, a run ends cleanly. The next job
// continues from the saved cursor, and the scheduler starts it on its next tick
// instead of waiting for the feed's interval.
func TestFeedHandler_NearDeadlineWithPagesLeft_StopsAndContinues(t *testing.T) {
	db := testutil.NewTestDB(t)
	bg := context.Background()

	lastSuccess := time.Now().Add(-3 * time.Hour)
	backoff := time.Now().Add(time.Hour)
	if err := db.UpsertFeedSyncState(bg, store.FeedSyncState{
		FeedName:            "test-feed",
		LastSuccessAt:       &lastSuccess,
		ConsecutiveFailures: 2,
		LastError:           "previous failure",
		BackoffUntil:        &backoff,
	}); err != nil {
		t.Fatalf("seed sync state: %v", err)
	}
	seeded, err := db.GetFeedSyncState(bg, "test-feed")
	if err != nil {
		t.Fatalf("GetFeedSyncState: %v", err)
	}

	var cursorsSeen []json.RawMessage
	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, cursor json.RawMessage) (*feed.FetchResult, error) {
			cursorsSeen = append(cursorsSeen, cursor)
			if len(cursorsSeen) == 1 {
				return deadlineTestPage(`{"page":2}`, false, "CVE-2025-0001"), nil
			}
			return deadlineTestPage(`{"page":3}`, true, "CVE-2025-0002"), nil
		},
	}
	mergeMock := &mockMerge{}
	handler := handlerWithStore(db.Store, db.Store, nil, mergeMock.fn, mockFactory(adapter), nil, nil)
	payload, _ := json.Marshal(Payload{FeedName: "test-feed"})

	// First job: stops after one page, without an error, so no attempt is used.
	if err := handler(nearDeadlineContext(t), payload); err != nil {
		t.Fatalf("handler error on the run that stopped early: %v", err)
	}
	if adapter.CallCount() != 1 {
		t.Fatalf("Fetch called %d times, want 1: the run should stop before the next page", adapter.CallCount())
	}

	state, log := feedStateAndLatestLog(t, db)
	if got := cursorPage(t, state.CursorJSON); got != 2 {
		t.Errorf("cursor page = %v, want 2", got)
	}
	if state.LastSuccessAt == nil || !state.LastSuccessAt.Equal(*seeded.LastSuccessAt) {
		t.Errorf("LastSuccessAt = %v, want it unchanged at %v: the feed has not caught up", state.LastSuccessAt, seeded.LastSuccessAt)
	}
	if state.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d, want 0: the run made progress", state.ConsecutiveFailures)
	}
	if state.LastError != "" {
		t.Errorf("LastError = %q, want empty", state.LastError)
	}
	if state.BackoffUntil != nil {
		t.Errorf("BackoffUntil = %v, want nil: a leftover backoff would stall the scheduler", state.BackoffUntil)
	}
	if log.Status != "partial" {
		t.Errorf("log status = %q, want partial", log.Status)
	}
	if log.ItemsUpserted != 1 {
		t.Errorf("ItemsUpserted = %d, want 1", log.ItemsUpserted)
	}

	// The scheduler sees the feed as due even though its 2-hour interval has
	// not passed since the job started.
	sched := NewSchedulerWithRegistry(db.Store, prometheus.NewRegistry())
	sched.maybeEnqueue(bg, FeedScheduleEntry{FeedName: "test-feed", Queue: "feed_ingest", Interval: 2 * time.Hour})
	enqueued, err := db.HasPendingOrRunningJob(bg, "feed:test-feed")
	if err != nil {
		t.Fatalf("HasPendingOrRunningJob: %v", err)
	}
	if !enqueued {
		t.Error("scheduler did not enqueue the next job for a feed with pages left")
	}

	// Second job: continues from the saved cursor and completes.
	if err := handler(bg, payload); err != nil {
		t.Fatalf("handler error on the continuing run: %v", err)
	}
	if got := cursorPage(t, cursorsSeen[1]); got != 2 {
		t.Errorf("continuing run started at cursor page %v, want 2", got)
	}
	state, log = feedStateAndLatestLog(t, db)
	if state.LastSuccessAt == nil || !state.LastSuccessAt.After(*seeded.LastSuccessAt) {
		t.Errorf("LastSuccessAt = %v, want it later than %v after the feed caught up", state.LastSuccessAt, seeded.LastSuccessAt)
	}
	if log.Status != "success" {
		t.Errorf("log status = %q, want success", log.Status)
	}
}

// A page that overruns pageReserve and is interrupted by the deadline, after
// earlier pages completed, ends the run the same way: no failure, cursor at the
// last completed page. The interrupted page is merged again by the next job.
func TestFeedHandler_DeadlineAfterCompletedPage_RecordsPartial(t *testing.T) {
	page1 := deadlineTestPage(`{"page":2}`, false, "CVE-2025-0001")
	page2 := deadlineTestPage(`{"page":3}`, false, "CVE-2025-0002")

	cases := []struct {
		name  string
		setup func(expire func()) (*mockAdapter, *mockMerge)
	}{
		{
			name: "during fetch",
			setup: func(expire func()) (*mockAdapter, *mockMerge) {
				calls := 0
				return &mockAdapter{
					fetchFunc: func(ctx context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
						calls++
						if calls == 1 {
							return page1, nil
						}
						expire()
						return nil, ctx.Err()
					},
				}, &mockMerge{}
			},
		},
		{
			name: "during merge",
			setup: func(expire func()) (*mockAdapter, *mockMerge) {
				calls := 0
				return &mockAdapter{
						fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
							calls++
							if calls == 1 {
								return page1, nil
							}
							return page2, nil
						},
					}, &mockMerge{errFunc: func(patch feed.CanonicalPatch) error {
						if patch.CVEID == "CVE-2025-0002" {
							expire()
							return context.DeadlineExceeded
						}
						return nil
					}}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := testutil.NewTestDB(t)
			captureLogs(t)
			ctx, expire := newExpiringJobContext(t)
			adapter, mergeMock := tc.setup(expire)
			handler := handlerWithStore(db.Store, db.Store, nil, mergeMock.fn, mockFactory(adapter), nil, nil)

			payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
			if err := handler(ctx, payload); err != nil {
				t.Fatalf("handler error = %v, want nil: the backfill made progress", err)
			}

			state, log := feedStateAndLatestLog(t, db)
			if got := cursorPage(t, state.CursorJSON); got != 2 {
				t.Errorf("cursor page = %v, want 2 (the last completed page)", got)
			}
			if state.ConsecutiveFailures != 0 {
				t.Errorf("ConsecutiveFailures = %d, want 0", state.ConsecutiveFailures)
			}
			if state.LastSuccessAt != nil {
				t.Errorf("LastSuccessAt = %v, want nil: the feed has not caught up", state.LastSuccessAt)
			}
			if log.Status != "partial" {
				t.Errorf("log status = %q, want partial", log.Status)
			}
		})
	}
}

// Stopping near the deadline applies only while pages remain. A run that has
// reached its end is complete, including when the empty-page stop ended it: the
// generic adapter's offset pagination with no page_size relies on that stop.
func TestFeedHandler_RunEndsNearDeadline_RecordsSuccess(t *testing.T) {
	cases := []struct {
		name string
		page *feed.FetchResult
	}{
		{name: "last page", page: deadlineTestPage(`{"page":2}`, true, "CVE-2025-0001")},
		{name: "nil next cursor", page: &feed.FetchResult{
			Patches:    []feed.CanonicalPatch{{CVEID: "CVE-2025-0001", SourceID: "CVE-2025-0001"}},
			SourceMeta: feed.SourceMeta{SourceName: "test-feed", FetchedAt: time.Now().UTC()},
		}},
		{name: "empty page", page: deadlineTestPage(`{"page":2}`, false)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := testutil.NewTestDB(t)
			adapter := &mockAdapter{
				fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
					return tc.page, nil
				},
			}
			mergeMock := &mockMerge{}
			handler := handlerWithStore(db.Store, db.Store, nil, mergeMock.fn, mockFactory(adapter), nil, nil)

			payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
			if err := handler(nearDeadlineContext(t), payload); err != nil {
				t.Fatalf("handler error: %v", err)
			}

			if adapter.CallCount() != 1 {
				t.Errorf("Fetch called %d times, want 1", adapter.CallCount())
			}
			state, log := feedStateAndLatestLog(t, db)
			if state.LastSuccessAt == nil {
				t.Error("LastSuccessAt should be set after a complete run")
			}
			if log.Status != "success" {
				t.Errorf("log status = %q, want success", log.Status)
			}
		})
	}
}

// An empty page ends a run with no deadline in play as well.
func TestFeedHandler_EmptyPageWithChangingCursor_EndsRun(t *testing.T) {
	db := testutil.NewTestDB(t)
	page := 1
	adapter := &mockAdapter{
		fetchFunc: func(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
			page++
			cursor, _ := json.Marshal(map[string]int{"page": page})
			return deadlineTestPage(string(cursor), false), nil
		},
	}
	mergeMock := &mockMerge{}
	handler := handlerWithStore(db.Store, db.Store, nil, mergeMock.fn, mockFactory(adapter), nil, nil)

	payload, _ := json.Marshal(Payload{FeedName: "test-feed"})
	if err := handler(context.Background(), payload); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if adapter.CallCount() != 1 {
		t.Errorf("Fetch called %d times, want 1: an empty page must end the run", adapter.CallCount())
	}
}
