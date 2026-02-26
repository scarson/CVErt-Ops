// Package worker provides a goroutine pool that claims and executes jobs
// from the job_queue table using FOR UPDATE SKIP LOCKED.
//
// Handlers are registered per queue name before calling Pool.Start.
// Each queue gets a dedicated polling goroutine; a shared recovery goroutine
// resets any jobs stuck in 'running' state.
package worker

import (
	"context"
	"encoding/json"
)

// Handler is the function executed for each claimed job.
// A non-nil return value triggers retry logic (exponential backoff up to
// max_attempts, then dead status). A nil return marks the job succeeded.
type Handler func(ctx context.Context, payload json.RawMessage) error
