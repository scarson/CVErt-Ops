// ABOUTME: Periodically enqueues feed ingestion jobs based on configured intervals.
// ABOUTME: Checks sync state timing and deduplicates to avoid double-scheduling.
package ingest

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
)

// SchedulerStore is the subset of store.Store the scheduler needs.
type SchedulerStore interface {
	GetFeedSyncState(ctx context.Context, feedName string) (*store.FeedSyncState, error)
	EnqueueJob(ctx context.Context, queue string, priority int32, payload json.RawMessage, lockKey *string, maxAttempts int32, runAfter *time.Time) (uuid.UUID, error)
	HasPendingOrRunningJob(ctx context.Context, lockKey string) (bool, error)
}

type feedScheduleEntry struct {
	FeedName string
	Queue    string
	Interval time.Duration
}

var defaultSchedule = []feedScheduleEntry{
	{FeedName: "nvd", Queue: "feed_ingest", Interval: 2 * time.Hour},
	{FeedName: "mitre", Queue: "feed_ingest", Interval: 24 * time.Hour},
	{FeedName: "kev", Queue: "feed_ingest", Interval: 24 * time.Hour},
	{FeedName: "ghsa", Queue: "feed_ingest", Interval: 6 * time.Hour},
	{FeedName: "osv", Queue: "feed_ingest", Interval: 24 * time.Hour},
	{FeedName: "msrc", Queue: "feed_ingest", Interval: 24 * time.Hour},
	{FeedName: "redhat", Queue: "feed_ingest", Interval: 12 * time.Hour},
	{FeedName: "epss", Queue: "epss_ingest", Interval: 24 * time.Hour},
}

// Scheduler periodically enqueues feed ingestion jobs.
type Scheduler struct {
	store    SchedulerStore
	schedule []feedScheduleEntry
}

// NewScheduler creates a scheduler that uses the default feed schedule.
func NewScheduler(st SchedulerStore) *Scheduler {
	return &Scheduler{
		store:    st,
		schedule: defaultSchedule,
	}
}

// Start runs the scheduler loop, ticking every minute. It runs the first tick
// immediately so feeds start fetching on first boot. Blocks until ctx is cancelled.
func (s *Scheduler) Start(ctx context.Context) {
	slog.Info("feed scheduler started", "feeds", len(s.schedule))
	s.tick(ctx)

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

// tick checks each feed and enqueues jobs for feeds that are due.
func (s *Scheduler) tick(ctx context.Context) {
	for _, entry := range s.schedule {
		s.maybeEnqueue(ctx, entry)
	}
}

func (s *Scheduler) maybeEnqueue(ctx context.Context, entry feedScheduleEntry) {
	state, err := s.store.GetFeedSyncState(ctx, entry.FeedName)
	if err != nil {
		slog.Error("scheduler error", "feed", entry.FeedName, "error", err)
		return
	}

	if state != nil {
		// Skip if in backoff.
		if state.BackoffUntil != nil && state.BackoffUntil.After(time.Now()) {
			slog.Debug("feed in backoff", "feed", entry.FeedName, "until", *state.BackoffUntil)
			return
		}

		// Skip if not yet due.
		if state.LastSuccessAt != nil && state.LastSuccessAt.Add(entry.Interval).After(time.Now()) {
			slog.Debug("feed not yet due", "feed", entry.FeedName,
				"next_due", state.LastSuccessAt.Add(entry.Interval))
			return
		}
	}

	lockKey := "feed:" + entry.FeedName
	has, err := s.store.HasPendingOrRunningJob(ctx, lockKey)
	if err != nil {
		slog.Error("scheduler error", "feed", entry.FeedName, "error", err)
		return
	}
	if has {
		slog.Debug("feed job already pending", "feed", entry.FeedName)
		return
	}

	payload, _ := json.Marshal(Payload{FeedName: entry.FeedName})
	if _, err := s.store.EnqueueJob(ctx, entry.Queue, 0, payload, &lockKey, 3, nil); err != nil {
		slog.Error("scheduler error", "feed", entry.FeedName, "error", err)
		return
	}
	slog.Info("feed job enqueued", "feed", entry.FeedName, "queue", entry.Queue)
}
