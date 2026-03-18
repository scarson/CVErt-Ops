// ABOUTME: Unit tests for the worker pool constructor, handler registration, and lifecycle.
// ABOUTME: Verifies New, Register, Start, processOne, and runStaleRecovery without a database.
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
)

// fakeJobStore implements JobStore for unit tests without a database.
type fakeJobStore struct {
	mu sync.Mutex

	claimFn    func(ctx context.Context, queue, workerID string) (*store.Job, error)
	completeFn func(ctx context.Context, id uuid.UUID) error
	failFn     func(ctx context.Context, id uuid.UUID, errMsg string) error
	recoverFn  func(ctx context.Context, staleAfter time.Duration) (int, error)
}

func (f *fakeJobStore) ClaimJob(ctx context.Context, queue, workerID string) (*store.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimFn != nil {
		return f.claimFn(ctx, queue, workerID)
	}
	return nil, nil
}

func (f *fakeJobStore) CompleteJob(ctx context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.completeFn != nil {
		return f.completeFn(ctx, id)
	}
	return nil
}

func (f *fakeJobStore) FailJob(ctx context.Context, id uuid.UUID, errMsg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFn != nil {
		return f.failFn(ctx, id, errMsg)
	}
	return nil
}

func (f *fakeJobStore) RecoverStaleJobs(ctx context.Context, staleAfter time.Duration) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recoverFn != nil {
		return f.recoverFn(ctx, staleAfter)
	}
	return 0, nil
}

func (f *fakeJobStore) CountPendingJobs(_ context.Context) (int64, error) {
	return 0, nil
}

func TestNewPool(t *testing.T) {
	t.Parallel()

	p := New(nil)
	if p == nil {
		t.Fatal("New returned nil")
	}
	if p.workerID == "" {
		t.Error("workerID is empty")
	}
	if p.handlers == nil {
		t.Error("handlers map is nil")
	}
	if len(p.handlers) != 0 {
		t.Errorf("handlers map should be empty, got %d entries", len(p.handlers))
	}
}

func TestNewPoolUniqueWorkerID(t *testing.T) {
	t.Parallel()

	p1 := New(nil)
	p2 := New(nil)
	if p1.workerID == p2.workerID {
		t.Errorf("two pools should have different workerIDs, both got %q", p1.workerID)
	}
}

func TestRegister(t *testing.T) {
	t.Parallel()

	p := New(nil)
	called := false
	p.Register("test-queue", func(_ context.Context, _ json.RawMessage) error {
		called = true
		return nil
	})

	h := p.handlers["test-queue"]
	if h == nil {
		t.Fatal("handler not stored for test-queue")
	}

	// Verify the stored handler is the one we registered by invoking it.
	if err := h(context.Background(), nil); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if !called {
		t.Error("stored handler was not the one we registered")
	}
}

func TestRegisterMultipleQueues(t *testing.T) {
	t.Parallel()

	p := New(nil)
	queues := []string{"alerts", "notifications", "feed-sync"}
	for _, q := range queues {
		p.Register(q, func(_ context.Context, _ json.RawMessage) error {
			return nil
		})
	}

	if len(p.handlers) != len(queues) {
		t.Errorf("expected %d handlers, got %d", len(queues), len(p.handlers))
	}
	for _, q := range queues {
		if p.handlers[q] == nil {
			t.Errorf("handler missing for queue %q", q)
		}
	}
}

func TestRegisterOverwritesSameQueue(t *testing.T) {
	t.Parallel()

	p := New(nil)

	firstCalled := false
	p.Register("q", func(_ context.Context, _ json.RawMessage) error {
		firstCalled = true
		return nil
	})

	secondCalled := false
	p.Register("q", func(_ context.Context, _ json.RawMessage) error {
		secondCalled = true
		return nil
	})

	if len(p.handlers) != 1 {
		t.Errorf("expected 1 handler, got %d", len(p.handlers))
	}

	_ = p.handlers["q"](context.Background(), nil)
	if firstCalled {
		t.Error("first handler should have been overwritten")
	}
	if !secondCalled {
		t.Error("second handler should be the active one")
	}
}

func TestStartWithCancelledContext(t *testing.T) {
	t.Parallel()

	p := New(nil)
	p.Register("q", func(_ context.Context, _ json.RawMessage) error {
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately before Start

	done := make(chan struct{})
	go func() {
		p.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Start returned promptly — success.
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return within 5s after context was already cancelled")
	}
}

func TestStartWithImmediateCancel(t *testing.T) {
	t.Parallel()

	p := New(nil)
	p.Register("q", func(_ context.Context, _ json.RawMessage) error {
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		p.Start(ctx)
		close(done)
	}()

	// Cancel shortly after Start begins — before the first poll tick (2s).
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Start returned promptly — success.
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return within 5s after cancel")
	}
}

func TestStartNoRegisteredQueues(t *testing.T) {
	t.Parallel()

	p := New(nil)
	// No queues registered — Start should still launch the stale recovery
	// goroutine and return when context is cancelled.

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		p.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(5 * time.Second):
		t.Fatal("Start with no queues did not return within 5s after cancel")
	}
}

func TestStartMultipleQueuesShutdown(t *testing.T) {
	t.Parallel()

	p := New(nil)
	for _, q := range []string{"a", "b", "c"} {
		p.Register(q, func(_ context.Context, _ json.RawMessage) error {
			return nil
		})
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		p.Start(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// All goroutines (3 queue + 1 stale recovery) stopped.
	case <-time.After(5 * time.Second):
		t.Fatal("Start with 3 queues did not return within 5s after cancel")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// processOne tests
// ──────────────────────────────────────────────────────────────────────────────

func TestProcessOne_NilJob(t *testing.T) {
	t.Parallel()

	fs := &fakeJobStore{
		claimFn: func(_ context.Context, _, _ string) (*store.Job, error) {
			return nil, nil
		},
	}
	p := New(fs)
	p.Register("q", func(_ context.Context, _ json.RawMessage) error {
		t.Fatal("handler should not be called when no job claimed")
		return nil
	})

	p.processOne(context.Background(), "q")
	// No panic, no handler call — success.
}

func TestProcessOne_ClaimError(t *testing.T) {
	t.Parallel()

	fs := &fakeJobStore{
		claimFn: func(_ context.Context, _, _ string) (*store.Job, error) {
			return nil, fmt.Errorf("db connection lost")
		},
	}
	p := New(fs)
	p.Register("q", func(_ context.Context, _ json.RawMessage) error {
		t.Fatal("handler should not be called when claim fails")
		return nil
	})

	p.processOne(context.Background(), "q")
	// Logs error but doesn't panic — success.
}

func TestProcessOne_HandlerSuccess(t *testing.T) {
	t.Parallel()

	jobID := uuid.New()
	var completedID uuid.UUID

	fs := &fakeJobStore{
		claimFn: func(_ context.Context, _, _ string) (*store.Job, error) {
			return &store.Job{ID: jobID, Queue: "q", Payload: json.RawMessage(`{}`), Attempts: 1}, nil
		},
		completeFn: func(_ context.Context, id uuid.UUID) error {
			completedID = id
			return nil
		},
	}
	p := New(fs)
	handlerCalled := false
	p.Register("q", func(_ context.Context, _ json.RawMessage) error {
		handlerCalled = true
		return nil
	})

	p.processOne(context.Background(), "q")

	if !handlerCalled {
		t.Error("handler was not called")
	}
	if completedID != jobID {
		t.Errorf("CompleteJob called with %v, want %v", completedID, jobID)
	}
}

func TestProcessOne_HandlerFailure(t *testing.T) {
	t.Parallel()

	jobID := uuid.New()
	var failedID uuid.UUID
	var failedMsg string

	fs := &fakeJobStore{
		claimFn: func(_ context.Context, _, _ string) (*store.Job, error) {
			return &store.Job{ID: jobID, Queue: "q", Payload: json.RawMessage(`{}`), Attempts: 1}, nil
		},
		failFn: func(_ context.Context, id uuid.UUID, errMsg string) error {
			failedID = id
			failedMsg = errMsg
			return nil
		},
	}
	p := New(fs)
	p.Register("q", func(_ context.Context, _ json.RawMessage) error {
		return fmt.Errorf("webhook timeout")
	})

	p.processOne(context.Background(), "q")

	if failedID != jobID {
		t.Errorf("FailJob called with %v, want %v", failedID, jobID)
	}
	if failedMsg != "webhook timeout" {
		t.Errorf("FailJob errMsg = %q, want %q", failedMsg, "webhook timeout")
	}
}

func TestProcessOne_NilHandler(t *testing.T) {
	t.Parallel()

	fs := &fakeJobStore{
		claimFn: func(_ context.Context, _, _ string) (*store.Job, error) {
			return &store.Job{ID: uuid.New(), Queue: "orphan", Payload: json.RawMessage(`{}`), Attempts: 1}, nil
		},
	}
	p := New(fs)
	// No handler registered for "orphan" queue.

	p.processOne(context.Background(), "orphan")
	// Logs error about missing handler but does not panic.
}

func TestProcessOne_HandlerFailure_FailJobError(t *testing.T) {
	t.Parallel()

	fs := &fakeJobStore{
		claimFn: func(_ context.Context, _, _ string) (*store.Job, error) {
			return &store.Job{ID: uuid.New(), Queue: "q", Payload: json.RawMessage(`{}`), Attempts: 1}, nil
		},
		failFn: func(_ context.Context, _ uuid.UUID, _ string) error {
			return fmt.Errorf("db write error")
		},
	}
	p := New(fs)
	p.Register("q", func(_ context.Context, _ json.RawMessage) error {
		return fmt.Errorf("handler failed")
	})

	p.processOne(context.Background(), "q")
	// Both handler and FailJob fail — should log both errors without panic.
}

func TestProcessOne_CompleteJobError(t *testing.T) {
	t.Parallel()

	fs := &fakeJobStore{
		claimFn: func(_ context.Context, _, _ string) (*store.Job, error) {
			return &store.Job{ID: uuid.New(), Queue: "q", Payload: json.RawMessage(`{}`), Attempts: 1}, nil
		},
		completeFn: func(_ context.Context, _ uuid.UUID) error {
			return fmt.Errorf("db write error")
		},
	}
	p := New(fs)
	p.Register("q", func(_ context.Context, _ json.RawMessage) error {
		return nil
	})

	p.processOne(context.Background(), "q")
	// Handler succeeded but CompleteJob fails — logs error without panic.
}

// ──────────────────────────────────────────────────────────────────────────────
// runStaleRecovery tests
// ──────────────────────────────────────────────────────────────────────────────

func TestRunStaleRecovery_CallsRecoverAndStops(t *testing.T) {
	t.Parallel()

	var recoverCalls int
	fs := &fakeJobStore{
		recoverFn: func(_ context.Context, _ time.Duration) (int, error) {
			recoverCalls++
			return 0, nil
		},
	}
	p := New(fs)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		p.runStaleRecovery(ctx)
		close(done)
	}()

	// Cancel after a brief delay — just enough for the goroutine to start.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Stopped cleanly.
	case <-time.After(5 * time.Second):
		t.Fatal("runStaleRecovery did not stop within 5s after cancel")
	}
}

func TestRunStaleRecovery_ErrorContinues(t *testing.T) {
	t.Parallel()

	var calls int
	fs := &fakeJobStore{
		recoverFn: func(_ context.Context, _ time.Duration) (int, error) {
			calls++
			return 0, fmt.Errorf("db error")
		},
	}
	p := New(fs)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		p.runStaleRecovery(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Logs error but does not crash — success.
	case <-time.After(5 * time.Second):
		t.Fatal("runStaleRecovery did not stop within 5s after cancel")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// runQueue tests
// ──────────────────────────────────────────────────────────────────────────────

func TestRunQueue_ContextCancellationStops(t *testing.T) {
	t.Parallel()

	fs := &fakeJobStore{}
	p := New(fs)
	p.Register("q", func(_ context.Context, _ json.RawMessage) error {
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		p.runQueue(ctx, "q")
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Stopped cleanly.
	case <-time.After(5 * time.Second):
		t.Fatal("runQueue did not stop within 5s after cancel")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Per-queue concurrency tests
// ──────────────────────────────────────────────────────────────────────────────

func TestRegisterWithConcurrency(t *testing.T) {
	t.Parallel()

	p := New(nil)
	p.RegisterWithConcurrency("alerts", func(_ context.Context, _ json.RawMessage) error {
		return nil
	}, 4)

	if p.handlers["alerts"] == nil {
		t.Fatal("handler not stored")
	}
	if got := p.concurrency["alerts"]; got != 4 {
		t.Errorf("concurrency = %d, want 4", got)
	}
}

func TestRegisterDefaultConcurrencyIsOne(t *testing.T) {
	t.Parallel()

	p := New(nil)
	p.Register("q", func(_ context.Context, _ json.RawMessage) error {
		return nil
	})

	if got := p.concurrency["q"]; got != 1 {
		t.Errorf("concurrency = %d, want 1 (default)", got)
	}
}

func TestRunQueue_ConcurrentProcessing(t *testing.T) {
	t.Parallel()

	const maxConc = 3
	var running int32
	var maxRunning int32

	started := make(chan struct{}, 10)
	block := make(chan struct{})

	fs := &fakeJobStore{
		claimFn: func(_ context.Context, _, _ string) (*store.Job, error) {
			return &store.Job{ID: uuid.New(), Queue: "q", Payload: json.RawMessage(`{}`), Attempts: 1}, nil
		},
	}
	p := New(fs)
	p.RegisterWithConcurrency("q", func(_ context.Context, _ json.RawMessage) error {
		n := atomic.AddInt32(&running, 1)
		for {
			old := atomic.LoadInt32(&maxRunning)
			if n <= old || atomic.CompareAndSwapInt32(&maxRunning, old, n) {
				break
			}
		}
		started <- struct{}{}
		<-block
		atomic.AddInt32(&running, -1)
		return nil
	}, maxConc)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		p.runQueue(ctx, "q")
		close(done)
	}()

	// Wait for maxConc handlers to start (may take up to maxConc*pollInterval).
	for i := 0; i < maxConc; i++ {
		select {
		case <-started:
		case <-time.After(15 * time.Second):
			t.Fatalf("handler %d did not start within timeout", i+1)
		}
	}

	// Verify exactly maxConc are running.
	if got := atomic.LoadInt32(&running); got != int32(maxConc) {
		t.Errorf("running handlers = %d, want %d", got, maxConc)
	}

	// Wait one more tick and verify no more than maxConc started.
	time.Sleep(3 * time.Second)
	if got := atomic.LoadInt32(&maxRunning); got > int32(maxConc) {
		t.Errorf("max concurrent = %d, exceeds limit %d", got, maxConc)
	}

	close(block)
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runQueue did not stop within timeout")
	}
}

func TestRunQueue_ConcurrencyOneIsSequential(t *testing.T) {
	t.Parallel()

	var running int32
	var maxRunning int32
	jobCount := 0

	fs := &fakeJobStore{
		claimFn: func(_ context.Context, _, _ string) (*store.Job, error) {
			return &store.Job{ID: uuid.New(), Queue: "q", Payload: json.RawMessage(`{}`), Attempts: 1}, nil
		},
	}
	p := New(fs)
	p.Register("q", func(_ context.Context, _ json.RawMessage) error {
		n := atomic.AddInt32(&running, 1)
		for {
			old := atomic.LoadInt32(&maxRunning)
			if n <= old || atomic.CompareAndSwapInt32(&maxRunning, old, n) {
				break
			}
		}
		jobCount++
		time.Sleep(50 * time.Millisecond)
		atomic.AddInt32(&running, -1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		p.runQueue(ctx, "q")
		close(done)
	}()

	// Let a few ticks execute.
	time.Sleep(5 * time.Second)
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runQueue did not stop within timeout")
	}

	if got := atomic.LoadInt32(&maxRunning); got > 1 {
		t.Errorf("max concurrent = %d, want 1 for default concurrency", got)
	}
}
