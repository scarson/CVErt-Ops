// Package api wires up the chi router, huma OpenAPI instance, middleware
// chain, and HTTP handlers for CVErt Ops.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewRouter builds the full chi router with middleware, /healthz, /metrics,
// and the huma OpenAPI sub-router at /api/v1.
//
// db may be nil only in tests that don't need a DB (healthz will return degraded).
func NewRouter(db *pgxpool.Pool) http.Handler {
	r := chi.NewRouter()

	// ── Security headers (PLAN.md §18.3) ─────────────────────────────────────
	// Must be first so they appear on every response including errors.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			next.ServeHTTP(w, r)
		})
	})

	// ── Standard chi middleware ───────────────────────────────────────────────
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	// 1 MB global body limit — protect against OOM from large request bodies
	// (PLAN.md §18.3 "HTTP request body size limit").
	r.Use(middleware.RequestSize(1 << 20))
	r.Use(middleware.Recoverer)

	// ── Infrastructure endpoints ──────────────────────────────────────────────
	r.Get("/healthz", healthzHandler(db))
	r.Handle("/metrics", promhttp.Handler())

	// ── API v1 sub-router with huma (OpenAPI 3.1) ────────────────────────────
	apiRouter := chi.NewRouter()
	humaConfig := huma.DefaultConfig("CVErt Ops API", "0.1.0")
	humaConfig.Info.Description = "Vulnerability intelligence and alerting API"
	api := humachi.New(apiRouter, humaConfig)
	_ = api // used in future phases when routes are registered

	r.Mount("/api/v1", apiRouter)

	return r
}

// healthResponse is the JSON body for /healthz.
type healthResponse struct {
	Status string `json:"status"`
	DB     string `json:"db,omitempty"`
}

// healthzHandler returns 200 {"status":"ok"} when the DB is reachable,
// or 503 {"status":"degraded","db":"unavailable"} when it is not.
func healthzHandler(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := healthResponse{Status: "ok"}
		statusCode := http.StatusOK

		if db == nil {
			resp.Status = "degraded"
			resp.DB = "unavailable"
			statusCode = http.StatusServiceUnavailable
		} else if err := db.Ping(r.Context()); err != nil {
			slog.WarnContext(r.Context(), "healthz: db ping failed", "error", err)
			resp.Status = "degraded"
			resp.DB = "unavailable"
			statusCode = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.ErrorContext(r.Context(), "healthz: failed to encode response", "error", err)
		}
	}
}
