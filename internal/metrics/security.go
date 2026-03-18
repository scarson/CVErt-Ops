// ABOUTME: Prometheus metrics for the security event pipeline.
// ABOUTME: Tracks event counts by type/severity and rate-limiter drops.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// SecurityEventsTotal counts security events recorded to the database.
var SecurityEventsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_security_events_total",
		Help: "Total security events recorded.",
	},
	[]string{"event_type", "severity"},
)

// SecurityEventsDropped counts security events dropped by the rate limiter.
var SecurityEventsDropped = promauto.NewCounter(prometheus.CounterOpts{
	Name: "cvertops_security_events_dropped_total",
	Help: "Security events dropped by rate limiter.",
})

// SecurityEventsWriteFailed counts security events that failed to write to the database.
var SecurityEventsWriteFailed = promauto.NewCounter(prometheus.CounterOpts{
	Name: "cvertops_security_events_write_failed_total",
	Help: "Security events that failed to write to the database.",
})
