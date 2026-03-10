// ABOUTME: Prometheus metrics for background worker job lifecycle.
// ABOUTME: Instrumented by the worker pool after job claim and completion.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var WorkerJobsClaimedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_worker_jobs_claimed_total",
		Help: "Total jobs claimed by the worker pool.",
	},
	[]string{"job_type"},
)

var WorkerJobsCompletedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_worker_jobs_completed_total",
		Help: "Total jobs completed by the worker pool.",
	},
	[]string{"job_type", "status"},
)

var WorkerJobDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "cvertops_worker_job_duration_seconds",
		Help:    "Worker job duration by job type.",
		Buckets: []float64{0.01, 0.1, 0.5, 1, 5, 15, 60, 300},
	},
	[]string{"job_type"},
)
