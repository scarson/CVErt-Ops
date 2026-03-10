// ABOUTME: Prometheus metrics for HTTP request counting and latency.
// ABOUTME: Instrumented by the metrics middleware on the API sub-router.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var HTTPRequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_http_requests_total",
		Help: "Total HTTP requests by method, route pattern, and status code.",
	},
	[]string{"method", "route", "status_code"},
)

var HTTPRequestDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "cvertops_http_request_duration_seconds",
		Help:    "HTTP request duration by method and route pattern.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
	},
	[]string{"method", "route"},
)
