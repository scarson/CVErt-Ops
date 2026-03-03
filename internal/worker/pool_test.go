// ABOUTME: Unit tests for the worker pool constructor, handler registration, and lifecycle.
// ABOUTME: Verifies New, Register, and Start shutdown behavior without requiring a database.
package worker

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

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
