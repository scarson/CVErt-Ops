// ABOUTME: Prometheus metrics for notification delivery tracking.
// ABOUTME: Instrumented by the notification worker after each delivery attempt.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var NotificationDeliveriesTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_notification_deliveries_total",
		Help: "Total notification deliveries by channel type and status.",
	},
	[]string{"channel_type", "status"},
)

var NotificationDeliveryDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "cvertops_notification_delivery_duration_seconds",
		Help:    "Notification delivery duration by channel type.",
		Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30},
	},
	[]string{"channel_type"},
)
