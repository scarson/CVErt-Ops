// ABOUTME: Tests for security event metrics registration.
// ABOUTME: Verifies security event metric descriptors are registered without panics.
package metrics_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/scarson/cvert-ops/internal/metrics"
)

func TestSecurityMetricsRegistered(t *testing.T) {
	metrics.SecurityEventsTotal.WithLabelValues("auth.login_failed", "info").Inc()
	metrics.SecurityEventsDropped.Inc()
}

func TestSecurityEventsTotal_Increments(t *testing.T) {
	before := testutil.ToFloat64(metrics.SecurityEventsTotal.WithLabelValues("test.event", "test"))
	metrics.SecurityEventsTotal.WithLabelValues("test.event", "test").Inc()
	after := testutil.ToFloat64(metrics.SecurityEventsTotal.WithLabelValues("test.event", "test"))
	if after != before+1 {
		t.Errorf("SecurityEventsTotal: got %f, want %f", after, before+1)
	}
}

func TestSecurityEventsDropped_Increments(t *testing.T) {
	before := testutil.ToFloat64(metrics.SecurityEventsDropped)
	metrics.SecurityEventsDropped.Inc()
	after := testutil.ToFloat64(metrics.SecurityEventsDropped)
	if after != before+1 {
		t.Errorf("SecurityEventsDropped: got %f, want %f", after, before+1)
	}
}
