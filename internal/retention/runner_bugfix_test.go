// ABOUTME: Bug fix tests for retention Runner.Run error propagation.
// ABOUTME: Verifies Run returns context.Canceled when context is cancelled.
package retention_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/scarson/cvert-ops/internal/retention"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestRunnerRun_ReturnsCancelledContextError(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	cfg := defaultConfig()
	runner := retention.NewRunner(db.Store, cfg, slog.Default())
	err := runner.Run(ctx)
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}
