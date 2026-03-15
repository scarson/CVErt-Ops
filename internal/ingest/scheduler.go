// ABOUTME: Periodically enqueues feed ingestion jobs based on configured intervals.
// ABOUTME: Checks sync state timing and deduplicates to avoid double-scheduling.
package ingest

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/scarson/cvert-ops/internal/store"
)

// defaultJobsEnqueued and defaultJobsSkipped are registered with the default
// Prometheus registry. Used by NewScheduler; NewSchedulerWithRegistry creates
// isolated counters per Scheduler instance for test-safe metrics.
var defaultJobsEnqueued = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "cvert_feed_jobs_enqueued_total",
	Help: "Total feed ingestion jobs enqueued by the scheduler.",
}, []string{"feed"})

var defaultJobsSkipped = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "cvert_feed_jobs_skipped_total",
	Help: "Total feed ingestion jobs skipped by the scheduler.",
}, []string{"feed", "reason"})

// SchedulerStore is the subset of store.Store the scheduler needs.
type SchedulerStore interface {
	GetFeedSyncState(ctx context.Context, feedName string) (*store.FeedSyncState, error)
	EnqueueJob(ctx context.Context, queue string, priority int32, payload json.RawMessage, lockKey *string, maxAttempts int32, runAfter *time.Time) (uuid.UUID, error)
}

// FeedScheduleEntry defines a single feed's scheduling parameters.
// Exported so that main.go can build entries from generic feed configs.
type FeedScheduleEntry struct {
	FeedName string
	Queue    string
	Interval time.Duration
}

var defaultSchedule = []FeedScheduleEntry{
	{FeedName: "nvd", Queue: "feed_ingest", Interval: 2 * time.Hour},
	{FeedName: "mitre", Queue: "feed_ingest", Interval: 24 * time.Hour},
	{FeedName: "kev", Queue: "feed_ingest", Interval: 24 * time.Hour},
	{FeedName: "ghsa", Queue: "feed_ingest", Interval: 6 * time.Hour},
	{FeedName: "osv", Queue: "feed_ingest", Interval: 24 * time.Hour},
	{FeedName: "msrc", Queue: "feed_ingest", Interval: 24 * time.Hour},
	{FeedName: "redhat", Queue: "feed_ingest", Interval: 12 * time.Hour},
	{FeedName: "epss", Queue: "epss_ingest", Interval: 24 * time.Hour},
	{FeedName: "alert:batch", Queue: "alert_batch", Interval: 2 * time.Minute},
	{FeedName: "alert:epss", Queue: "alert_epss", Interval: 24 * time.Hour},
	{FeedName: "alert:zombie_sweep", Queue: "alert_zombie_sweep", Interval: 5 * time.Minute},
}

// Scheduler periodically enqueues feed ingestion jobs.
type Scheduler struct {
	store        SchedulerStore
	schedule     []FeedScheduleEntry
	jobsEnqueued *prometheus.CounterVec
	jobsSkipped  *prometheus.CounterVec
}

// NewScheduler creates a scheduler that uses the default feed schedule
// and the default Prometheus registry.
func NewScheduler(st SchedulerStore) *Scheduler {
	return &Scheduler{
		store:        st,
		schedule:     defaultSchedule,
		jobsEnqueued: defaultJobsEnqueued,
		jobsSkipped:  defaultJobsSkipped,
	}
}

// NewSchedulerWithRegistry creates a scheduler with metrics registered in the
// given Prometheus registry. Useful for testing with isolated registries.
func NewSchedulerWithRegistry(st SchedulerStore, reg prometheus.Registerer) *Scheduler {
	return &Scheduler{
		store:    st,
		schedule: defaultSchedule,
		jobsEnqueued: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "cvert_feed_jobs_enqueued_total",
			Help: "Total feed ingestion jobs enqueued by the scheduler.",
		}, []string{"feed"}),
		jobsSkipped: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "cvert_feed_jobs_skipped_total",
			Help: "Total feed ingestion jobs skipped by the scheduler.",
		}, []string{"feed", "reason"}),
	}
}

// AddEntries appends additional schedule entries (e.g., from generic feed configs).
// Must be called before Start.
func (s *Scheduler) AddEntries(entries []FeedScheduleEntry) {
	s.schedule = append(s.schedule, entries...)
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

func (s *Scheduler) maybeEnqueue(ctx context.Context, entry FeedScheduleEntry) {
	state, err := s.store.GetFeedSyncState(ctx, entry.FeedName)
	if err != nil {
		slog.Error("scheduler error", "feed", entry.FeedName, "error", err)
		return
	}

	if state != nil {
		// Skip if in backoff.
		if state.BackoffUntil != nil && state.BackoffUntil.After(time.Now()) {
			s.jobsSkipped.WithLabelValues(entry.FeedName, "backoff").Inc()
			slog.Debug("feed in backoff", "feed", entry.FeedName, "until", *state.BackoffUntil)
			return
		}

		// Skip if not yet due.
		if state.LastSuccessAt != nil && state.LastSuccessAt.Add(entry.Interval).After(time.Now()) {
			s.jobsSkipped.WithLabelValues(entry.FeedName, "not_due").Inc()
			slog.Debug("feed not yet due", "feed", entry.FeedName,
				"next_due", state.LastSuccessAt.Add(entry.Interval))
			return
		}
	}

	lockKey := "feed:" + entry.FeedName
	payload, _ := json.Marshal(Payload{FeedName: entry.FeedName})
	id, err := s.store.EnqueueJob(ctx, entry.Queue, 0, payload, &lockKey, 3, nil)
	if err != nil {
		slog.Error("scheduler error", "feed", entry.FeedName, "error", err)
		return
	}
	if id == uuid.Nil {
		s.jobsSkipped.WithLabelValues(entry.FeedName, "already_pending").Inc()
		slog.Debug("feed job already pending", "feed", entry.FeedName)
		return
	}
	s.jobsEnqueued.WithLabelValues(entry.FeedName).Inc()
	slog.Info("feed job enqueued", "feed", entry.FeedName, "queue", entry.Queue)
}
