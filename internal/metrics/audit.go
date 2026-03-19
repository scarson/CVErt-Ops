// ABOUTME: Prometheus metrics for the audit logging pipeline.
// ABOUTME: Tracks audit log write failures for NIST AU-5 compliance alerting.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// AuditWriteFailures counts audit log entries that failed to write to the database.
var AuditWriteFailures = promauto.NewCounter(prometheus.CounterOpts{
	Name: "cvertops_audit_write_failures_total",
	Help: "Audit log entries that failed to write to the database.",
})
