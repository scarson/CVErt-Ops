package worker

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
)

const (
	// pollInterval is how often each queue goroutine checks for new jobs.
	pollInterval = 2 * time.Second

	// staleCheckInterval is how often the recovery goroutine runs.
	staleCheckInterval = 1 * time.Minute

	// staleThreshold is the age at which a 'running' job is considered stuck.
	staleThreshold = 5 * time.Minute
)

// Pool manages a set of goroutine workers that claim and execute jobs from
// the job_queue table. One polling goroutine runs per registered queue; a
// shared stale-lock recovery goroutine resets stuck jobs.
type Pool struct {
	store    *store.Store
	workerID string
	mu       sync.RWMutex
	handlers map[string]Handler
}

// New creates a Pool backed by s. A random workerID is generated at construction
// time to distinguish this process in the locked_by column.
func New(s *store.Store) *Pool {
	return &Pool{
		store:    s,
		workerID: uuid.New().String(),
		handlers: make(map[string]Handler),
	}
}

// Register associates h with the named queue. Must be called before Start.
func (p *Pool) Register(queue string, h Handler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handlers[queue] = h
}

// Start launches one polling goroutine per registered queue plus the stale-lock
// recovery goroutine, then blocks until ctx is cancelled. When ctx is cancelled,
// all goroutines stop accepting new jobs, any in-flight job completes, and Start
// returns after all goroutines have exited.
func (p *Pool) Start(ctx context.Context) {
	p.mu.RLock()
	queues := make([]string, 0, len(p.handlers))
	for q := range p.handlers {
		queues = append(queues, q)
	}
	p.mu.RUnlock()

	var wg sync.WaitGroup

	for _, q := range queues {
		wg.Add(1)
		go func(queue string) {
			defer wg.Done()
			p.runQueue(ctx, queue)
		}(q)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		p.runStaleRecovery(ctx)
	}()

	wg.Wait()
	slog.Info("worker pool stopped", "worker_id", p.workerID)
}

// runQueue polls queue for jobs until ctx is cancelled. Uses time.NewTicker
// (not time.After) to avoid timer leaks.
func (p *Pool) runQueue(ctx context.Context, queue string) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	slog.Info("worker queue started", "queue", queue, "worker_id", p.workerID)

	for {
		select {
		case <-ctx.Done():
			slog.Info("worker queue stopping", "queue", queue)
			return
		case <-ticker.C:
			p.processOne(ctx, queue)
		}
	}
}

// processOne claims one job from queue and executes it. Errors are logged but
// do not stop the polling loop — the goroutine continues to the next tick.
func (p *Pool) processOne(ctx context.Context, queue string) {
	job, err := p.store.ClaimJob(ctx, queue, p.workerID)
	if err != nil {
		slog.Error("claim job error", "queue", queue, "error", err)
		return
	}
	if job == nil {
		return // no job available; normal case
	}

	p.mu.RLock()
	h := p.handlers[queue]
	p.mu.RUnlock()

	if h == nil {
		slog.Error("no handler registered for queue",
			"queue", queue, "job_id", job.ID)
		return
	}

	slog.Info("executing job",
		"queue", queue, "job_id", job.ID, "attempts", job.Attempts)

	if err := h(ctx, job.Payload); err != nil {
		slog.Error("job handler failed",
			"queue", queue, "job_id", job.ID, "error", err)
		if failErr := p.store.FailJob(ctx, job.ID, err.Error()); failErr != nil {
			slog.Error("fail job error", "job_id", job.ID, "error", failErr)
		}
		return
	}

	if err := p.store.CompleteJob(ctx, job.ID); err != nil {
		slog.Error("complete job error", "job_id", job.ID, "error", err)
		return
	}
	slog.Info("job completed", "queue", queue, "job_id", job.ID)
}

// runStaleRecovery periodically resets jobs stuck in 'running' state. Uses
// time.NewTicker (not time.After) to avoid timer leaks.
func (p *Pool) runStaleRecovery(ctx context.Context) {
	ticker := time.NewTicker(staleCheckInterval)
	defer ticker.Stop()

	slog.Info("stale recovery started", "worker_id", p.workerID,
		"threshold", staleThreshold, "check_interval", staleCheckInterval)

	for {
		select {
		case <-ctx.Done():
			slog.Info("stale recovery stopping")
			return
		case <-ticker.C:
			n, err := p.store.RecoverStaleJobs(ctx, staleThreshold)
			if err != nil {
				slog.Error("stale job recovery error", "error", err)
				continue
			}
			if n > 0 {
				slog.Info("reclaimed stale jobs", "count", n)
			}
		}
	}
}
