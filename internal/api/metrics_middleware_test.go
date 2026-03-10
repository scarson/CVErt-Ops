// ABOUTME: Tests for the HTTP metrics middleware — verifies route pattern labels and status code capture.
// ABOUTME: Ensures cardinality safety by asserting route patterns contain placeholders, not real UUIDs.
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsMiddleware_UsesRoutePattern(t *testing.T) {
	// Isolated registry to avoid polluting the global one.
	reg := prometheus.NewRegistry()
	reqTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_http_requests_total",
			Help: "test",
		},
		[]string{"method", "route", "status_code"},
	)
	reqDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "test_http_request_duration_seconds",
			Help:    "test",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "route"},
	)
	reg.MustRegister(reqTotal, reqDuration)

	mw := httpMetricsMiddleware(reqTotal, reqDuration)

	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(mw)
		r.Get("/orgs/{org_id}/cves/{cve_id}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/550e8400-e29b-41d4-a716-446655440000/cves/CVE-2024-1234", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Gather metrics and verify route label uses the pattern, not the actual URL.
	mfs, err := reg.Gather()
	require.NoError(t, err)

	var foundCounter bool
	for _, mf := range mfs {
		if mf.GetName() == "test_http_requests_total" {
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "route" {
						assert.Equal(t, "/api/v1/orgs/{org_id}/cves/{cve_id}", lp.GetValue(),
							"route label must use chi route pattern, not actual URL")
						foundCounter = true
					}
					if lp.GetName() == "status_code" {
						assert.Equal(t, "200", lp.GetValue())
					}
				}
			}
		}
	}
	assert.True(t, foundCounter, "expected test_http_requests_total metric to be recorded")
}

func TestMetricsMiddleware_404Route(t *testing.T) {
	reg := prometheus.NewRegistry()
	reqTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_404_requests_total",
			Help: "test",
		},
		[]string{"method", "route", "status_code"},
	)
	reqDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "test_404_request_duration_seconds",
			Help:    "test",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "route"},
	)
	reg.MustRegister(reqTotal, reqDuration)

	mw := httpMetricsMiddleware(reqTotal, reqDuration)

	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(mw)
		r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	// Hit a route that doesn't exist
	req := httptest.NewRequest(http.MethodGet, "/api/v1/nonexistent", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	mfs, err := reg.Gather()
	require.NoError(t, err)

	// For unmatched routes, the route label should be empty or a safe fallback.
	for _, mf := range mfs {
		if mf.GetName() == "test_404_requests_total" {
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "route" {
						// Unmatched routes should NOT contain the actual path
						assert.NotEqual(t, "/api/v1/nonexistent", lp.GetValue(),
							"unmatched route should not use actual path")
					}
				}
			}
		}
	}
}
