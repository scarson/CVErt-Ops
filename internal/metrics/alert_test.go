// ABOUTME: Tests for alert evaluation metrics registration.
// ABOUTME: Verifies counter and histogram descriptors for all evaluation paths.
package metrics_test

import (
	"testing"

	"github.com/scarson/cvert-ops/internal/metrics"
)

func TestAlertMetricsRegistered(_ *testing.T) {
	metrics.AlertRulesEvaluatedTotal.WithLabelValues("realtime").Inc()
	metrics.AlertMatchesTotal.WithLabelValues("batch").Inc()
	metrics.AlertEvaluationDuration.WithLabelValues("epss").Observe(0.05)
}
