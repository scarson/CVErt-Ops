// ABOUTME: HTTP server struct, constructor, and handler wiring for CVErt Ops.
// ABOUTME: Holds auth dependencies (store, config, argon2 semaphore) used by handlers.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/store"
)

// Server holds the dependencies for the HTTP layer.
type Server struct {
	store       *store.Store
	cfg         *config.Config
	argon2Sem   chan struct{}
	rateLimiter *ipRateLimiter
}

// NewServer creates a Server. Returns an error if Google OIDC initialization fails.
// If cfg.GoogleClientID is empty, Google OIDC is skipped.
func NewServer(s *store.Store, cfg *config.Config) (*Server, error) {
	sem := make(chan struct{}, cfg.Argon2MaxConcurrent)
	evictTTL := cfg.RateLimitEvictTTL
	if evictTTL == 0 {
		evictTTL = 15 * time.Minute
	}
	// 10 requests per minute, burst of 10.
	rl := newIPRateLimiter(rate.Limit(10.0/60), 10, evictTTL)
	return &Server{store: s, cfg: cfg, argon2Sem: sem, rateLimiter: rl}, nil
}

// Handler builds and returns the http.Handler.
func (srv *Server) Handler() http.Handler {
	var db *pgxpool.Pool
	if srv.store != nil {
		db = srv.store.Pool()
	}
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
	registerAuthRoutes(api, srv)
	registerCVERoutes(api, srv.store)

	// ── Org management routes (chi, not huma, for per-group RBAC middleware) ──
	apiRouter.Route("/orgs", func(r chi.Router) {
		r.Use(srv.RequireAuthenticated())
		r.Post("/", srv.createOrgHandler)

		r.Route("/{org_id}", func(r chi.Router) {
			r.Use(srv.RequireOrgRole(RoleViewer))
			r.Get("/", srv.getOrgHandler)
			r.With(srv.RequireOrgRole(RoleAdmin)).Patch("/", srv.updateOrgHandler)

			// Member management
			r.Route("/members", func(r chi.Router) {
				r.Get("/", srv.listMembersHandler)
				r.With(srv.RequireOrgRole(RoleAdmin)).Patch("/{user_id}", srv.updateMemberRoleHandler)
				r.With(srv.RequireOrgRole(RoleAdmin)).Delete("/{user_id}", srv.removeMemberHandler)
			})
		})
	})

	r.Mount("/api/v1", apiRouter)

	return r
}

// acquireArgon2 tries to acquire the argon2 semaphore. Returns false if all
// slots are in use — the caller should return 503 immediately (do NOT block).
func (srv *Server) acquireArgon2() bool {
	select {
	case srv.argon2Sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (srv *Server) releaseArgon2() { <-srv.argon2Sem }

// NewRouter builds the full chi router with middleware, /healthz, /metrics,
// and the huma OpenAPI sub-router at /api/v1.
//
// s may be nil only in tests that don't need a DB (healthz will return degraded).
func NewRouter(s *store.Store) http.Handler {
	cfg := &config.Config{Argon2MaxConcurrent: 5} //nolint:exhaustruct // legacy wrapper; only argon2 sem size matters here
	srv, _ := NewServer(s, cfg)
	return srv.Handler()
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
