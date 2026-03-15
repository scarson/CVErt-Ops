// ABOUTME: Tests that /metrics is not served on the main API router.
// ABOUTME: The metrics endpoint lives on a separate port (Task 9).
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler_MetricsNotOnMainRouter(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:       "test-secret-that-is-long-enough-for-validation",
		JWTAlgorithm:    "HS256",
		AppEnv:          "development",
		ExternalURL:     "http://localhost:8080",
		FrontendURL:     "/",
		ListenAddr:      ":8080",
		MetricsPort:     "9090",
		DBMaxConns:      5,
		LockoutDuration: 15 * 60_000_000_000, // 15m in ns
	}
	srv, err := NewServer(nil, cfg, ServerDeps{})
	require.NoError(t, err)
	defer srv.Close()

	handler := srv.Handler()

	// /metrics should NOT be handled by the main router — it should NOT
	// return Prometheus exposition format content.
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	assert.False(t, strings.Contains(body, "# HELP"),
		"/metrics on main router should not contain Prometheus metrics")
	assert.False(t, strings.Contains(body, "# TYPE"),
		"/metrics on main router should not contain Prometheus metrics")
}
