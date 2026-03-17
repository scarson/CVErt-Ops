// ABOUTME: Worker pool that claims and executes jobs from the job_queue table.
// ABOUTME: Per-queue concurrency semaphores, panic recovery, and stale-job reclamation.
package worker

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/metrics"
	"github.com/scarson/cvert-ops/internal/store"
)

// JobStore is the subset of store.Store that the worker pool needs to claim,
// complete, fail, and recover jobs.
type JobStore interface {
	ClaimJob(ctx context.Context, queue, workerID string) (*store.Job, error)
	CompleteJob(ctx context.Context, id uuid.UUID) error
	FailJob(ctx context.Context, id uuid.UUID, errMsg string) error
	RecoverStaleJobs(ctx context.Context, staleAfter time.Duration) (int, error)
}

const (
	// pollInterval is how often each queue goroutine checks for new jobs.
	pollInterval = 2 * time.Second

	// staleCheckInterval is how often the recovery goroutine runs.
	staleCheckInterval = 1 * time.Minute

	// staleThreshold is the age at which a 'running' job is considered stuck.
	staleThreshold = 5 * time.Minute

	// maxJobDuration caps how long a single job can run. Prevents unbounded
	// shutdown hangs when in-flight jobs use context.WithoutCancel.
	maxJobDuration = 10 * time.Minute
)

// PeriodicTask runs on a fixed interval alongside the job queue polling.
type PeriodicTask struct {
	Name     string
	Interval time.Duration
	Fn       func(ctx context.Context) error
}

// Pool manages a set of goroutine workers that claim and execute jobs from
// the job_queue table. One polling goroutine runs per registered queue; a
// shared stale-lock recovery goroutine resets stuck jobs. Per-queue concurrency
// limits control how many jobs execute simultaneously within each queue.
type Pool struct {
	store       JobStore
	workerID    string
	mu          sync.RWMutex
	handlers    map[string]Handler
	concurrency map[string]int
	periodic    []PeriodicTask
}

// New creates a Pool backed by s. A random workerID is generated at construction
// time to distinguish this process in the locked_by column.
func New(s JobStore) *Pool {
	return &Pool{
		store:       s,
		workerID:    uuid.New().String(),
		handlers:    make(map[string]Handler),
		concurrency: make(map[string]int),
	}
}

// Register associates h with the named queue with concurrency 1 (sequential).
// Must be called before Start.
func (p *Pool) Register(queue string, h Handler) {
	p.RegisterWithConcurrency(queue, h, 1)
}

// RegisterPeriodic adds a periodic task that runs alongside the job queues.
// Must be called before Start.
func (p *Pool) RegisterPeriodic(task PeriodicTask) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.periodic = append(p.periodic, task)
}

// RegisterWithConcurrency associates h with the named queue and allows up to
// concurrency jobs to execute simultaneously. Must be called before Start.
func (p *Pool) RegisterWithConcurrency(queue string, h Handler, concurrency int) {
	if concurrency < 1 {
		concurrency = 1
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handlers[queue] = h
	p.concurrency[queue] = concurrency
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
		wg.Go(func() {
			p.runQueue(ctx, q)
		})
	}

	wg.Go(func() {
		p.runStaleRecovery(ctx)
	})

	p.mu.RLock()
	tasks := make([]PeriodicTask, len(p.periodic))
	copy(tasks, p.periodic)
	p.mu.RUnlock()
	for _, task := range tasks {
		wg.Go(func() {
			p.runPeriodic(ctx, task)
		})
	}

	wg.Wait()
	slog.Info("worker pool stopped", "worker_id", p.workerID)
}

// runQueue polls queue for jobs until ctx is cancelled. A per-queue semaphore
// limits how many jobs execute concurrently. Uses time.NewTicker (not
// time.After) to avoid timer leaks.
func (p *Pool) runQueue(ctx context.Context, queue string) {
	p.mu.RLock()
	maxConc := p.concurrency[queue]
	p.mu.RUnlock()
	if maxConc < 1 {
		maxConc = 1
	}

	sem := make(chan struct{}, maxConc)
	var inflight sync.WaitGroup

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	slog.Info("worker queue started", "queue", queue, "worker_id", p.workerID, "concurrency", maxConc)

	for {
		select {
		case <-ctx.Done():
			slog.Info("worker queue stopping", "queue", queue)
			inflight.Wait()
			return
		case <-ticker.C:
			select {
			case sem <- struct{}{}:
				inflight.Go(func() {
					defer func() { <-sem }()
					// Detach from parent shutdown signal so in-flight DB writes
				// complete, but cap each job to prevent unbounded shutdown hangs.
				jobCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), maxJobDuration)
				defer cancel()
				p.processOne(jobCtx, queue)
				})
			default:
				// all concurrency slots occupied, skip this tick
			}
		}
	}
}

// processOne claims one job from queue and executes it. Errors are logged but
// do not stop the polling loop — the goroutine continues to the next tick.
// Panics in handlers are recovered and the job is marked as failed.
func (p *Pool) processOne(ctx context.Context, queue string) {
	job, err := p.store.ClaimJob(ctx, queue, p.workerID)
	if err != nil {
		slog.Error("claim job error", "queue", queue, "error", err)
		return
	}
	if job == nil {
		return // no job available; normal case
	}

	metrics.WorkerJobsClaimedTotal.WithLabelValues(queue).Inc()
	start := time.Now()

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

	if err := p.safeExecute(ctx, h, job.Payload); err != nil {
		slog.Error("job handler failed",
			"queue", queue, "job_id", job.ID, "error", err)
		if failErr := p.store.FailJob(ctx, job.ID, err.Error()); failErr != nil {
			slog.Error("fail job error", "job_id", job.ID, "error", failErr)
		}
		metrics.WorkerJobsCompletedTotal.WithLabelValues(queue, "failure").Inc()
		metrics.WorkerJobDuration.WithLabelValues(queue).Observe(time.Since(start).Seconds())
		return
	}

	if err := p.store.CompleteJob(ctx, job.ID); err != nil {
		slog.Error("complete job error", "job_id", job.ID, "error", err)
		return
	}
	metrics.WorkerJobsCompletedTotal.WithLabelValues(queue, "success").Inc()
	metrics.WorkerJobDuration.WithLabelValues(queue).Observe(time.Since(start).Seconds())
	slog.Info("job completed", "queue", queue, "job_id", job.ID)
}

// safeExecute runs a handler with panic recovery. If the handler panics,
// the panic is caught and returned as an error with a stack trace.
func (p *Pool) safeExecute(ctx context.Context, h Handler, payload []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("worker panic recovered",
				"error", r, "stack", string(debug.Stack()))
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return h(ctx, payload)
}

// runPeriodic runs a single PeriodicTask on its configured interval until ctx
// is cancelled. Errors are logged, never returned.
func (p *Pool) runPeriodic(ctx context.Context, task PeriodicTask) {
	ticker := time.NewTicker(task.Interval)
	defer ticker.Stop()

	slog.Info("periodic task started", "task", task.Name, "interval", task.Interval)

	for {
		select {
		case <-ctx.Done():
			slog.Info("periodic task stopping", "task", task.Name)
			return
		case <-ticker.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						slog.Error("periodic task panic", "task", task.Name,
							"error", r, "stack", string(debug.Stack()))
					}
				}()
				if err := task.Fn(ctx); err != nil {
					slog.Error("periodic task error", "task", task.Name, "error", err)
				}
			}()
		}
	}
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
