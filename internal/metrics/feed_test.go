// ABOUTME: Tests for feed ingestion metrics registration.
// ABOUTME: Verifies all six feed metric descriptors are registered without panics.
package metrics_test

import (
	"testing"

	"github.com/scarson/cvert-ops/internal/metrics"
)

func TestFeedMetricsRegistered(_ *testing.T) {
	metrics.FeedItemsFetchedTotal.WithLabelValues("nvd").Inc()
	metrics.FeedItemsMergedTotal.WithLabelValues("nvd").Inc()
	metrics.FeedFetchDuration.WithLabelValues("nvd").Observe(5.0)
	metrics.FeedErrorsTotal.WithLabelValues("nvd").Inc()
	metrics.FeedLastSuccessTimestamp.WithLabelValues("nvd").SetToCurrentTime()
	metrics.FeedConsecutiveFailures.WithLabelValues("nvd").Set(0)
}
