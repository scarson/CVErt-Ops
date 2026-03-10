// ABOUTME: Prometheus collector for pgxpool connection stats.
// ABOUTME: Reports pool utilization as gauges on each scrape — no polling goroutine.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// PoolStats holds the connection pool statistics reported by the collector.
type PoolStats struct {
	AcquiredConns int32
	IdleConns     int32
	MaxConns      int32
	TotalConns    int32
}

// PoolStatter provides a snapshot of connection pool statistics.
type PoolStatter interface {
	PoolStats() PoolStats
}

// DBPoolCollector implements prometheus.Collector for connection pool stats.
type DBPoolCollector struct {
	pool         PoolStatter
	acquiredDesc *prometheus.Desc
	idleDesc     *prometheus.Desc
	maxDesc      *prometheus.Desc
	totalDesc    *prometheus.Desc
}

// NewDBPoolCollector creates a collector that reports pool stats on each scrape.
func NewDBPoolCollector(pool PoolStatter) *DBPoolCollector {
	return &DBPoolCollector{
		pool: pool,
		acquiredDesc: prometheus.NewDesc(
			"cvertops_db_pool_acquired_conns",
			"Number of currently acquired connections in the pool.",
			nil, nil,
		),
		idleDesc: prometheus.NewDesc(
			"cvertops_db_pool_idle_conns",
			"Number of currently idle connections in the pool.",
			nil, nil,
		),
		maxDesc: prometheus.NewDesc(
			"cvertops_db_pool_max_conns",
			"Maximum number of connections allowed in the pool.",
			nil, nil,
		),
		totalDesc: prometheus.NewDesc(
			"cvertops_db_pool_total_conns",
			"Total number of connections in the pool.",
			nil, nil,
		),
	}
}

// Describe sends the descriptor for each metric to the channel.
func (c *DBPoolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.acquiredDesc
	ch <- c.idleDesc
	ch <- c.maxDesc
	ch <- c.totalDesc
}

// Collect reads current pool stats and sends gauge values.
func (c *DBPoolCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.pool.PoolStats()
	ch <- prometheus.MustNewConstMetric(c.acquiredDesc, prometheus.GaugeValue, float64(s.AcquiredConns))
	ch <- prometheus.MustNewConstMetric(c.idleDesc, prometheus.GaugeValue, float64(s.IdleConns))
	ch <- prometheus.MustNewConstMetric(c.maxDesc, prometheus.GaugeValue, float64(s.MaxConns))
	ch <- prometheus.MustNewConstMetric(c.totalDesc, prometheus.GaugeValue, float64(s.TotalConns))
}
