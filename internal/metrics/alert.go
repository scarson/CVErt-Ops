// ABOUTME: Prometheus metrics for alert rule evaluation throughput and latency.
// ABOUTME: Instrumented by the alert evaluator across realtime, batch, and EPSS paths.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var AlertRulesEvaluatedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_alert_rules_evaluated_total",
		Help: "Total alert rules evaluated by evaluation path.",
	},
	[]string{"path"},
)

var AlertMatchesTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_alert_matches_total",
		Help: "Total alert matches produced by evaluation path.",
	},
	[]string{"path"},
)

var AlertEvaluationDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "cvertops_alert_evaluation_duration_seconds",
		Help:    "Alert evaluation duration by evaluation path.",
		Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 15},
	},
	[]string{"path"},
)
