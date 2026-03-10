// ABOUTME: Prometheus metrics for feed ingestion health and throughput.
// ABOUTME: Instrumented by the ingest handler after each fetch-merge cycle.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var FeedItemsFetchedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_feed_items_fetched_total",
		Help: "Total items fetched from feed sources.",
	},
	[]string{"feed"},
)

var FeedItemsMergedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_feed_items_merged_total",
		Help: "Total items successfully merged into the CVE corpus.",
	},
	[]string{"feed"},
)

var FeedFetchDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "cvertops_feed_fetch_duration_seconds",
		Help:    "Duration of feed fetch operations.",
		Buckets: []float64{1, 5, 15, 30, 60, 120, 300},
	},
	[]string{"feed"},
)

var FeedErrorsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_feed_errors_total",
		Help: "Total feed fetch errors.",
	},
	[]string{"feed"},
)

var FeedLastSuccessTimestamp = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cvertops_feed_last_success_timestamp",
		Help: "Unix timestamp of the last successful feed fetch.",
	},
	[]string{"feed"},
)

var FeedConsecutiveFailures = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cvertops_feed_consecutive_failures",
		Help: "Current count of consecutive fetch failures per feed.",
	},
	[]string{"feed"},
)
