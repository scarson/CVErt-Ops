// ABOUTME: Tests for HTTP request metrics registration.
// ABOUTME: Verifies counter and histogram descriptors are registered without panics.
package metrics_test

import (
	"testing"

	"github.com/scarson/cvert-ops/internal/metrics"
)

func TestHTTPMetricsRegistered(_ *testing.T) {
	metrics.HTTPRequestsTotal.WithLabelValues("GET", "/api/v1/healthz", "200").Inc()
	metrics.HTTPRequestDuration.WithLabelValues("GET", "/api/v1/healthz").Observe(0.01)
}
