// ABOUTME: Tests for worker job metrics registration.
// ABOUTME: Verifies counter and histogram descriptors for job lifecycle tracking.
package metrics_test

import (
	"testing"

	"github.com/scarson/cvert-ops/internal/metrics"
)

func TestWorkerMetricsRegistered(t *testing.T) {
	metrics.WorkerJobsClaimedTotal.WithLabelValues("feed_sync").Inc()
	metrics.WorkerJobsCompletedTotal.WithLabelValues("feed_sync", "success").Inc()
	metrics.WorkerJobsCompletedTotal.WithLabelValues("alert_eval", "failure").Inc()
	metrics.WorkerJobDuration.WithLabelValues("feed_sync").Observe(12.5)
}
