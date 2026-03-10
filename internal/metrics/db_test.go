// ABOUTME: Tests for DB pool Prometheus collector with isolated registry.
// ABOUTME: Verifies all four pool gauge metrics are reported on each scrape.
package metrics_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/scarson/cvert-ops/internal/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakePoolStatter struct {
	stats metrics.PoolStats
}

func (f *fakePoolStatter) PoolStats() metrics.PoolStats {
	return f.stats
}

func TestDBPoolCollector(t *testing.T) {
	reg := prometheus.NewRegistry()
	collector := metrics.NewDBPoolCollector(&fakePoolStatter{
		stats: metrics.PoolStats{
			AcquiredConns: 3,
			IdleConns:     7,
			MaxConns:      10,
			TotalConns:    10,
		},
	})
	reg.MustRegister(collector)

	mfs, err := reg.Gather()
	require.NoError(t, err)

	values := make(map[string]float64)
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			values[mf.GetName()] = m.GetGauge().GetValue()
		}
	}

	assert.Equal(t, float64(3), values["cvertops_db_pool_acquired_conns"], "acquired_conns")
	assert.Equal(t, float64(7), values["cvertops_db_pool_idle_conns"], "idle_conns")
	assert.Equal(t, float64(10), values["cvertops_db_pool_max_conns"], "max_conns")
	assert.Equal(t, float64(10), values["cvertops_db_pool_total_conns"], "total_conns")
}
