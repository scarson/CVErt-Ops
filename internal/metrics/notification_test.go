// ABOUTME: Tests for notification delivery metrics registration.
// ABOUTME: Verifies counter and histogram descriptors for delivery tracking.
package metrics_test

import (
	"testing"

	"github.com/scarson/cvert-ops/internal/metrics"
)

func TestNotificationMetricsRegistered(_ *testing.T) {
	metrics.NotificationDeliveriesTotal.WithLabelValues("webhook", "success").Inc()
	metrics.NotificationDeliveriesTotal.WithLabelValues("email", "failure").Inc()
	metrics.NotificationDeliveriesTotal.WithLabelValues("webhook", "exhausted").Inc()
	metrics.NotificationDeliveryDuration.WithLabelValues("webhook").Observe(1.5)
	metrics.NotificationDeliveryDuration.WithLabelValues("email").Observe(0.3)
}
