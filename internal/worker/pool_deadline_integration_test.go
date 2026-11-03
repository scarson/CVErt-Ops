// ABOUTME: Integration tests for recording a job's outcome after its deadline has passed.
// ABOUTME: A job that runs to maxJobDuration must still be marked dead or succeeded, not left running.
package worker

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// runPastDeadline enqueues one job on queue "q", runs it through processOne
// with a short deadline using handler h, and returns the job's final status.
func runPastDeadline(t *testing.T, h Handler) string {
	t.Helper()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	jobID, err := tdb.EnqueueJob(ctx, "q", 0, json.RawMessage(`{}`), nil, 1, nil)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}
	if jobID == uuid.Nil {
		t.Fatal("EnqueueJob returned no job ID")
	}

	p := New(tdb.Store)
	p.Register("q", h)
	jobCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	p.processOne(jobCtx, "q")

	var status string
	if err := tdb.DB().QueryRowContext(ctx,
		"SELECT status FROM job_queue WHERE id = $1", jobID,
	).Scan(&status); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	return status
}

func TestProcessOne_HandlerTimesOut_JobRecordedDead(t *testing.T) {
	t.Parallel()
	status := runPastDeadline(t, func(ctx context.Context, _ json.RawMessage) error {
		<-ctx.Done()
		return ctx.Err()
	})
	// max_attempts is 1, so the failure exhausts the job.
	if status != "dead" {
		t.Errorf("job status after handler deadline = %q, want dead", status)
	}
}

func TestProcessOne_HandlerSucceedsAtDeadline_JobRecordedSucceeded(t *testing.T) {
	t.Parallel()
	status := runPastDeadline(t, func(ctx context.Context, _ json.RawMessage) error {
		<-ctx.Done()
		return nil
	})
	if status != "succeeded" {
		t.Errorf("job status after handler finished at its deadline = %q, want succeeded", status)
	}
}
