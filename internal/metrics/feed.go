// ABOUTME: Prometheus metrics for feed ingestion health and throughput.
// ABOUTME: Instrumented by the ingest handler after each fetch-merge cycle.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// FeedItemsFetchedTotal counts items fetched from feed sources.
var FeedItemsFetchedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_feed_items_fetched_total",
		Help: "Total items fetched from feed sources.",
	},
	[]string{"feed"},
)

// FeedItemsMergedTotal counts items successfully merged into the CVE corpus.
var FeedItemsMergedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_feed_items_merged_total",
		Help: "Total items successfully merged into the CVE corpus.",
	},
	[]string{"feed"},
)

// FeedFetchDuration observes feed fetch operation latency.
var FeedFetchDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "cvertops_feed_fetch_duration_seconds",
		Help:    "Duration of feed fetch operations.",
		Buckets: []float64{1, 5, 15, 30, 60, 120, 300},
	},
	[]string{"feed"},
)

// FeedErrorsTotal counts feed fetch errors.
var FeedErrorsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_feed_errors_total",
		Help: "Total feed fetch errors.",
	},
	[]string{"feed"},
)

// FeedLastSuccessTimestamp records the last successful fetch time per feed.
var FeedLastSuccessTimestamp = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cvertops_feed_last_success_timestamp",
		Help: "Unix timestamp of the last successful feed fetch.",
	},
	[]string{"feed"},
)

// FeedConsecutiveFailures tracks the current streak of fetch failures per feed.
var FeedConsecutiveFailures = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cvertops_feed_consecutive_failures",
		Help: "Current count of consecutive fetch failures per feed.",
	},
	[]string{"feed"},
)

// FeedCircuitBreakerState tracks the circuit breaker state per feed.
// 0=closed (healthy), 1=half-open (probing), 2=open (blocking).
var FeedCircuitBreakerState = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cvertops_feed_circuit_breaker_state",
		Help: "Circuit breaker state per feed: 0=closed, 1=half-open, 2=open.",
	},
	[]string{"feed"},
)
