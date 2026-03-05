// ABOUTME: Regression test for worker pool panic recovery bug.
// ABOUTME: Validates that a panicking handler is caught and job is marked as failed.
package worker

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
)

func TestProcessOne_HandlerPanic(t *testing.T) {
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
		panic("something went terribly wrong")
	})

	// processOne must recover from the panic and mark the job as failed.
	p.processOne(context.Background(), "q")

	if failedID != jobID {
		t.Errorf("FailJob called with %v, want %v", failedID, jobID)
	}
	if failedMsg == "" {
		t.Error("FailJob errMsg is empty; should contain panic info")
	}
}
