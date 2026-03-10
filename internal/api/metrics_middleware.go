// ABOUTME: HTTP metrics middleware that records request count and duration per route pattern.
// ABOUTME: Uses chi's RoutePattern() for cardinality-safe route labels (no UUIDs in labels).
package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
)

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

// httpMetricsMiddleware returns middleware that records request count and
// duration using the provided metric vectors. It MUST be registered on a
// sub-router (after chi route matching) so that RoutePattern() returns
// the parameterized pattern, not an empty string.
func httpMetricsMiddleware(reqTotal *prometheus.CounterVec, reqDuration *prometheus.HistogramVec) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}

			next.ServeHTTP(sw, r)

			route := chi.RouteContext(r.Context()).RoutePattern()
			if route == "" {
				route = "unmatched"
			}

			reqTotal.WithLabelValues(r.Method, route, strconv.Itoa(sw.code)).Inc()
			reqDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
		})
	}
}
