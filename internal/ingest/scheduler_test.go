// ABOUTME: Tests for the feed scheduler — validates job enqueueing logic based on sync state timing.
// ABOUTME: Uses a mock SchedulerStore to unit test scheduling decisions without a real database.
package ingest

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
)

// mockSchedulerStore implements SchedulerStore for testing.
type mockSchedulerStore struct {
	mu         sync.Mutex
	syncStates map[string]*store.FeedSyncState
	pending    map[string]bool
	enqueued   []enqueuedJob
}

type enqueuedJob struct {
	Queue    string
	LockKey  string
	Payload  json.RawMessage
}

func newMockSchedulerStore() *mockSchedulerStore {
	return &mockSchedulerStore{
		syncStates: make(map[string]*store.FeedSyncState),
		pending:    make(map[string]bool),
	}
}

func (m *mockSchedulerStore) GetFeedSyncState(_ context.Context, feedName string) (*store.FeedSyncState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncStates[feedName], nil
}

func (m *mockSchedulerStore) HasPendingOrRunningJob(_ context.Context, lockKey string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pending[lockKey], nil
}

func (m *mockSchedulerStore) EnqueueJob(_ context.Context, queue string, _ int32, payload json.RawMessage, lockKey *string, _ int32, _ *time.Time) (uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	lk := ""
	if lockKey != nil {
		lk = *lockKey
	}
	m.enqueued = append(m.enqueued, enqueuedJob{Queue: queue, LockKey: lk, Payload: payload})
	return uuid.New(), nil
}

func (m *mockSchedulerStore) Enqueued() []enqueuedJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]enqueuedJob(nil), m.enqueued...)
}

func TestScheduler_EnqueuesNeverSyncedFeeds(t *testing.T) {
	ms := newMockSchedulerStore()
	// No sync states set — all feeds are "never synced"
	s := NewScheduler(ms)

	s.tick(context.Background())

	enqueued := ms.Enqueued()
	if len(enqueued) != len(defaultSchedule) {
		t.Fatalf("enqueued %d jobs, want %d (all feeds never synced)", len(enqueued), len(defaultSchedule))
	}

	// Verify EPSS uses epss_ingest queue.
	for _, job := range enqueued {
		var p Payload
		if err := json.Unmarshal(job.Payload, &p); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if p.FeedName == "epss" {
			if job.Queue != "epss_ingest" {
				t.Errorf("EPSS job queue = %q, want epss_ingest", job.Queue)
			}
		} else {
			if job.Queue != "feed_ingest" {
				t.Errorf("%s job queue = %q, want feed_ingest", p.FeedName, job.Queue)
			}
		}
		if job.LockKey != "feed:"+p.FeedName {
			t.Errorf("lock key = %q, want %q", job.LockKey, "feed:"+p.FeedName)
		}
	}
}

func TestScheduler_SkipsNotYetDueFeeds(t *testing.T) {
	ms := newMockSchedulerStore()
	recent := time.Now().UTC().Add(-30 * time.Minute) // synced 30 min ago
	ms.syncStates["nvd"] = &store.FeedSyncState{
		FeedName:      "nvd",
		LastSuccessAt: &recent,
	}
	// NVD interval is 2h, so 30 min ago is not due yet.

	s := NewScheduler(ms)
	s.tick(context.Background())

	enqueued := ms.Enqueued()
	for _, job := range enqueued {
		var p Payload
		_ = json.Unmarshal(job.Payload, &p)
		if p.FeedName == "nvd" {
			t.Error("nvd should not be enqueued — last synced 30 min ago, interval is 2h")
		}
	}
	// All others should be enqueued (never synced).
	if len(enqueued) != len(defaultSchedule)-1 {
		t.Errorf("enqueued %d jobs, want %d", len(enqueued), len(defaultSchedule)-1)
	}
}

func TestScheduler_EnqueuesDueFeeds(t *testing.T) {
	ms := newMockSchedulerStore()
	old := time.Now().UTC().Add(-3 * time.Hour) // synced 3h ago
	ms.syncStates["nvd"] = &store.FeedSyncState{
		FeedName:      "nvd",
		LastSuccessAt: &old,
	}
	// NVD interval is 2h, 3h ago is overdue.

	s := NewScheduler(ms)
	s.tick(context.Background())

	enqueued := ms.Enqueued()
	var foundNVD bool
	for _, job := range enqueued {
		var p Payload
		_ = json.Unmarshal(job.Payload, &p)
		if p.FeedName == "nvd" {
			foundNVD = true
		}
	}
	if !foundNVD {
		t.Error("nvd should be enqueued — last synced 3h ago, interval is 2h")
	}
}

func TestScheduler_SkipsAlreadyPendingFeeds(t *testing.T) {
	ms := newMockSchedulerStore()
	// No sync states — all feeds are "never synced" and due
	// But mark NVD as already having a pending job.
	ms.pending["feed:nvd"] = true

	s := NewScheduler(ms)
	s.tick(context.Background())

	enqueued := ms.Enqueued()
	for _, job := range enqueued {
		var p Payload
		_ = json.Unmarshal(job.Payload, &p)
		if p.FeedName == "nvd" {
			t.Error("nvd should not be enqueued — already has a pending job")
		}
	}
	if len(enqueued) != len(defaultSchedule)-1 {
		t.Errorf("enqueued %d jobs, want %d", len(enqueued), len(defaultSchedule)-1)
	}
}

func TestScheduler_SkipsFeedsInBackoff(t *testing.T) {
	ms := newMockSchedulerStore()
	backoff := time.Now().UTC().Add(10 * time.Minute) // backoff until 10 min from now
	old := time.Now().UTC().Add(-3 * time.Hour)
	ms.syncStates["nvd"] = &store.FeedSyncState{
		FeedName:      "nvd",
		LastSuccessAt: &old,
		BackoffUntil:  &backoff,
	}

	s := NewScheduler(ms)
	s.tick(context.Background())

	enqueued := ms.Enqueued()
	for _, job := range enqueued {
		var p Payload
		_ = json.Unmarshal(job.Payload, &p)
		if p.FeedName == "nvd" {
			t.Error("nvd should not be enqueued — currently in backoff")
		}
	}
}
