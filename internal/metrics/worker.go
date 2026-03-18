// ABOUTME: Prometheus metrics for background worker job lifecycle.
// ABOUTME: Instrumented by the worker pool after job claim and completion.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// WorkerJobsClaimedTotal counts jobs claimed by the worker pool.
var WorkerJobsClaimedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_worker_jobs_claimed_total",
		Help: "Total jobs claimed by the worker pool.",
	},
	[]string{"job_type"},
)

// WorkerJobsCompletedTotal counts completed jobs, labeled by type and status.
var WorkerJobsCompletedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cvertops_worker_jobs_completed_total",
		Help: "Total jobs completed by the worker pool.",
	},
	[]string{"job_type", "status"},
)

// WorkerJobsPending is the current number of pending jobs in the queue.
var WorkerJobsPending = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "cvertops_worker_jobs_pending",
	Help: "Number of pending jobs in the queue.",
})

// WorkerJobDuration observes job execution latency, labeled by job type.
var WorkerJobDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "cvertops_worker_job_duration_seconds",
		Help:    "Worker job duration by job type.",
		Buckets: []float64{0.01, 0.1, 0.5, 1, 5, 15, 60, 300},
	},
	[]string{"job_type"},
)
