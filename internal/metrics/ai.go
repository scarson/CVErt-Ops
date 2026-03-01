// ABOUTME: Prometheus metrics for AI features (NL search, summarization).
// ABOUTME: Registered globally; instrumented from API handlers and the AI package.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// AIRequestsTotal counts AI requests, labeled by feature and status.
var AIRequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_ai_requests_total",
		Help: "Total AI requests by feature and status.",
	},
	[]string{"feature", "status"},
)

// AIRequestDuration observes AI request latency, labeled by feature.
var AIRequestDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "cvertops_ai_request_duration_seconds",
		Help:    "AI request latency by feature.",
		Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30},
	},
	[]string{"feature"},
)

// AICacheHitsTotal counts AI cache hits, labeled by feature.
var AICacheHitsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_ai_cache_hits_total",
		Help: "AI cache hits by feature.",
	},
	[]string{"feature"},
)

// AICacheMissesTotal counts AI cache misses, labeled by feature.
var AICacheMissesTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_ai_cache_misses_total",
		Help: "AI cache misses by feature.",
	},
	[]string{"feature"},
)

// AIQuotaDenialsTotal counts AI quota denials, labeled by feature.
var AIQuotaDenialsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_ai_quota_denials_total",
		Help: "AI quota denials by feature.",
	},
	[]string{"feature"},
)

// AITokensTotal counts AI tokens consumed, labeled by feature and direction.
var AITokensTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_ai_tokens_total",
		Help: "Total AI tokens consumed by feature and direction.",
	},
	[]string{"feature", "direction"},
)
