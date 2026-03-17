// ABOUTME: HTTP server struct, constructor, and handler wiring for CVErt Ops.
// ABOUTME: Holds auth dependencies (store, config, argon2 semaphore) used by handlers.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/ai"
	"github.com/scarson/cvert-ops/internal/alert"
	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/metrics"
	"github.com/scarson/cvert-ops/internal/secure"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/web"
)

// ServerDeps holds optional dependencies injected at construction time.
// All fields are optional (nil/zero means "not configured").
type ServerDeps struct {
	AlertCache            *alert.RuleCache
	AlertEvaluator        *alert.Evaluator
	LLM                   ai.LLMClient
	AuditWriter           *audit.Writer
	EventWriter           *secure.EventWriter
	ConfigHolder          *config.Holder
	ExpectedSchemaVersion int
	VersionInfo           VersionInfo
}

// Server holds the dependencies for the HTTP layer.
type Server struct {
	store                 *store.Store
	cfg                   *config.Config
	argon2Sem             chan struct{}
	rateLimiter           *ipRateLimiter
	ghOAuth               *oauth2.Config   // nil when GitHub OAuth is not configured
	ghAPIBaseURL          string           // GitHub REST API base URL; overridable in tests
	googleOIDC            *oidc.Provider   // nil when Google OIDC is not configured
	googleOAuth           *oauth2.Config   // nil when Google OIDC is not configured
	orgRL                 *orgRateLimiter  // per-org API rate limiter
	tierCache             *tierCache       // short-lived cache for org tier + overrides
	oidcProviders         sync.Map         // issuer URL → *oidc.Provider; lazy-loaded per SSO connection
	alertCache            *alert.RuleCache // nil when alert evaluation is not configured
	alertEvaluator        *alert.Evaluator // nil when alert evaluation is not configured
	llm                   ai.LLMClient     // nil when AI features are not configured
	auditWriter           *audit.Writer    // nil when audit logging is not configured
	eventWriter           *secure.EventWriter // async security event recording
	lockout               *lockoutManager  // brute-force login protection
	configHolder          *config.Holder   // hot-reloadable config for admin reload endpoint
	bootstrapMu           sync.Mutex       // serializes first-user bootstrap in invite-only mode
	expectedSchemaVersion int              // migration version for /readyz check
	versionInfo           VersionInfo      // build metadata for /admin/version
	healthChecks          []func() bool    // extra readiness checks (e.g., delivery worker)
	humaAPI               huma.API         // production huma API instance for spec merging
}

// NewServer creates a Server. Returns an error if Google OIDC initialization fails.
// If cfg.GoogleClientID is empty, Google OIDC is skipped.
func NewServer(s *store.Store, cfg *config.Config, deps ServerDeps) (*Server, error) {
	sem := make(chan struct{}, cfg.Argon2MaxConcurrent)
	evictTTL := cfg.RateLimitEvictTTL
	if evictTTL == 0 {
		evictTTL = 15 * time.Minute
	}
	// 10 requests per minute, burst of 10.
	rl := newIPRateLimiter(rate.Limit(10.0/60), 10, evictTTL)
	orgRL := newOrgRateLimiter(time.Now, evictTTL)
	tc := newTierCache(time.Now, 30*time.Second, 5*time.Minute)
	lockoutThreshold := cfg.LockoutThreshold
	if lockoutThreshold == 0 {
		lockoutThreshold = 5
	}
	lockoutDuration := cfg.LockoutDuration
	if lockoutDuration == 0 {
		lockoutDuration = 15 * time.Minute
	}
	srv := &Server{
		store:                 s,
		cfg:                   cfg,
		argon2Sem:             sem,
		rateLimiter:           rl,
		orgRL:                 orgRL,
		tierCache:             tc,
		ghAPIBaseURL:          "https://api.github.com",
		eventWriter:           deps.EventWriter,
		lockout:               newLockoutManager(s, lockoutThreshold, lockoutDuration),
		alertCache:            deps.AlertCache,
		alertEvaluator:        deps.AlertEvaluator,
		llm:                   deps.LLM,
		auditWriter:           deps.AuditWriter,
		configHolder:          deps.ConfigHolder,
		expectedSchemaVersion: deps.ExpectedSchemaVersion,
		versionInfo:           deps.VersionInfo,
	}

	// ── GitHub OAuth (optional) ───────────────────────────────────────────────
	if cfg.GitHubClientID != "" {
		srv.ghOAuth = &oauth2.Config{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			RedirectURL:  cfg.ExternalURL + "/api/v1/auth/oauth/github/callback",
			Endpoint:     github.Endpoint,
			Scopes:       []string{"user:email"}, // REQUIRED per PLAN.md §7.2
		}
	}

	// ── Google OIDC (optional) ────────────────────────────────────────────────
	if cfg.GoogleClientID != "" {
		ctx := context.Background()
		var (
			googleProvider *oidc.Provider
			googleErr      error
		)
		for attempt := 1; attempt <= 5; attempt++ {
			googleProvider, googleErr = oidc.NewProvider(ctx, "https://accounts.google.com")
			if googleErr == nil {
				break
			}
			slog.Warn("google oidc: provider init failed, retrying", "attempt", attempt, "err", googleErr)
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		if googleErr != nil {
			return nil, fmt.Errorf("google oidc provider: %w", googleErr)
		}
		srv.googleOIDC = googleProvider
		srv.googleOAuth = &oauth2.Config{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURL:  cfg.ExternalURL + "/api/v1/auth/oauth/google/callback",
			Endpoint:     googleProvider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		}
	}

	return srv, nil
}

// Close releases resources held by the server (e.g., the rate limiter cleanup goroutine).
func (srv *Server) Close() {
	if srv.rateLimiter != nil {
		srv.rateLimiter.Stop()
	}
	if srv.orgRL != nil {
		srv.orgRL.Stop()
	}
	if srv.tierCache != nil {
		srv.tierCache.Stop()
	}
	if srv.eventWriter != nil {
		srv.eventWriter.Stop()
	}
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

	// ── CORS (after security headers, before other middleware) ──────────────
	if corsHandler := srv.corsMiddleware(); corsHandler != nil {
		r.Use(corsHandler)
	}

	// ── Standard chi middleware ───────────────────────────────────────────────
	r.Use(middleware.RequestID)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if reqID := middleware.GetReqID(r.Context()); reqID != "" {
				w.Header().Set(middleware.RequestIDHeader, reqID)
			}
			next.ServeHTTP(w, r)
		})
	})
	r.Use(middleware.RealIP)
	r.Use(clientIPMiddleware)
	r.Use(contextLoggerMiddleware)
	// 1 MB global body limit — protect against OOM from large request bodies
	// (PLAN.md §18.3 "HTTP request body size limit").
	r.Use(middleware.RequestSize(1 << 20))
	r.Use(middleware.Recoverer)

	// ── Infrastructure endpoints ──────────────────────────────────────────────
	r.Get("/healthz", healthzHandler())
	r.Get("/readyz", readyzHandler(db, srv.expectedSchemaVersion, srv.healthChecks...))

	// ── API v1 sub-router with huma (OpenAPI 3.1) ────────────────────────────
	apiRouter := chi.NewRouter()
	// HTTP metrics middleware on the sub-router so RoutePattern() is populated.
	apiRouter.Use(httpMetricsMiddleware(metrics.HTTPRequestsTotal, metrics.HTTPRequestDuration))
	// CSRF protection: cookie-authenticated state-changing requests must include
	// X-Requested-By: CVErt-Ops. Bearer-token requests and safe methods are exempt.
	apiRouter.Use(csrfProtect)
	humaConfig := huma.DefaultConfig("CVErt Ops API", "0.1.0")
	humaConfig.Info.Description = "Vulnerability intelligence and alerting API"
	api := humachi.New(apiRouter, humaConfig)
	srv.humaAPI = api
	registerAuthRoutes(api, srv)
	registerMFARoutes(api, srv)
	registerCVERoutes(api, srv.store)

	// ── SSO discovery (public, no auth, rate limited by IP) ─────────────────────
	apiRouter.With(srv.authRateLimit()).Post("/auth/discover", srv.discoverHandler)

	// ── OAuth routes (chi, not huma — these are redirects, not JSON API calls) ─
	apiRouter.With(srv.authRateLimit()).Get("/auth/oauth/github", srv.githubInitHandler)
	apiRouter.With(srv.authRateLimit()).Get("/auth/oauth/github/callback", srv.githubCallbackHandler)
	apiRouter.With(srv.authRateLimit()).Get("/auth/oauth/google", srv.googleInitHandler)
	apiRouter.With(srv.authRateLimit()).Get("/auth/oauth/google/callback", srv.googleCallbackHandler)

	// ── Generic OIDC SSO routes ─────────────────────────────────────────────
	apiRouter.With(srv.authRateLimit()).Get("/auth/oidc/{connection_id}/login", srv.oidcLoginHandler)
	apiRouter.With(srv.authRateLimit()).Get("/auth/oidc/callback", srv.oidcCallbackHandler)
	apiRouter.With(srv.authRateLimit()).Get("/auth/oidc/link-callback", srv.oidcLinkCallbackHandler)

	// ── Admin routes (authenticated + site admin, not org-scoped) ───────────
	apiRouter.Route("/admin", func(r chi.Router) {
		r.Use(srv.RequireAuthenticated())
		r.Use(srv.RequireSiteAdmin())
		r.Get("/feeds", srv.listFeedsHandler)
		r.Post("/feeds/{feed}/run", srv.triggerFeedHandler)
		r.Post("/feeds/{feed}/pause", srv.pauseFeedHandler)
		r.Post("/feeds/{feed}/resume", srv.resumeFeedHandler)
		r.Get("/feeds/{feed}/logs", srv.feedLogsHandler)
		r.Get("/version", srv.versionHandler)
		r.Get("/doctor", srv.doctorHandler)

		// Org management.
		r.Get("/orgs", srv.adminListOrgsHandler)
		r.Patch("/orgs/{org_id}", srv.adminPatchOrgHandler)
		r.Get("/orgs/{org_id}/usage", srv.adminOrgUsageHandler)

		// User management.
		r.Get("/users", srv.adminListUsersHandler)
		r.Post("/users/{user_id}/disable", srv.adminDisableUserHandler)
		r.Post("/users/{user_id}/enable", srv.adminEnableUserHandler)
		r.Post("/users/{user_id}/unlock", srv.adminUnlockUserHandler)
		r.Post("/users/{user_id}/reset-password", srv.adminResetPasswordHandler)

		// Delivery management.
		r.Get("/deliveries", srv.adminListDeliveriesHandler)
		r.Post("/deliveries/{id}/retry", srv.adminRetryDeliveryHandler)
		r.Post("/deliveries/retry-failed", srv.adminBulkRetryDeliveriesHandler)

		// System management.
		r.Post("/reindex", srv.adminReindexHandler)
		r.Post("/reload-config", srv.adminReloadConfigHandler)
		r.Get("/config", srv.adminConfigHandler)
		r.Get("/audit-log", srv.adminAuditLogHandler)
		r.Get("/security-events", srv.adminSecurityEventsHandler)
	})

	// ── Org management routes (chi, not huma, for per-group RBAC middleware) ──
	apiRouter.Route("/orgs", func(r chi.Router) {
		r.Use(srv.RequireAuthenticated())
		r.Post("/", srv.createOrgHandler)

		r.Route("/{org_id}", func(r chi.Router) {
			r.Use(srv.RequireOrgRole(RoleViewer))
			r.Use(srv.tierMiddleware)
			r.Use(srv.orgRateLimitMiddleware)
			r.Get("/", srv.getOrgHandler)
			r.Get("/tier", srv.getOrgTierHandler)
			r.With(srv.RequireOrgRole(RoleAdmin)).Patch("/", srv.updateOrgHandler)
			r.With(srv.RequireOrgRole(RoleOwner)).Patch("/mfa-settings", srv.adminUpdateOrgMFASettingsHandler)

			// Member management
			r.Route("/members", func(r chi.Router) {
				r.Get("/", srv.listMembersHandler)
				r.With(srv.RequireOrgRole(RoleAdmin)).Patch("/{user_id}", srv.updateMemberRoleHandler)
				r.With(srv.RequireOrgRole(RoleAdmin)).Delete("/{user_id}", srv.removeMemberHandler)
				r.With(srv.RequireOrgRole(RoleAdmin)).Post("/{user_id}/reset-mfa", srv.adminResetMFAHandler)
				r.With(srv.RequireOrgRole(RoleAdmin)).Post("/{user_id}/force-password-reset", srv.adminForcePasswordResetHandler)
				r.With(srv.RequireOrgRole(RoleAdmin)).Post("/{user_id}/require-mfa", srv.adminRequireMFAHandler)
				r.With(srv.RequireOrgRole(RoleAdmin)).Delete("/{user_id}/require-mfa", srv.adminUnrequireMFAHandler)
			})

			// Invitation management
			r.Route("/invitations", func(r chi.Router) {
				r.With(srv.RequireOrgRole(RoleAdmin)).Post("/", srv.createInvitationHandler)
				r.With(srv.RequireOrgRole(RoleAdmin)).Get("/", srv.listInvitationsHandler)
				r.With(srv.RequireOrgRole(RoleAdmin)).Delete("/{id}", srv.cancelInvitationHandler)
				r.With(srv.RequireOrgRole(RoleAdmin)).Post("/{id}/resend", srv.resendInvitationHandler)
			})

			// API key management
			r.Route("/api-keys", func(r chi.Router) {
				r.With(srv.RequireOrgRole(RoleMember)).Post("/", srv.createAPIKeyHandler)
				r.Get("/", srv.listAPIKeysHandler)
				r.Delete("/{id}", srv.revokeAPIKeyHandler)
			})

			// Watchlist management
			r.Route("/watchlists", func(r chi.Router) {
				r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.listWatchlistsHandler)
				r.With(srv.RequireOrgRole(RoleMember)).Post("/", srv.createWatchlistHandler)
				r.Route("/{id}", func(r chi.Router) {
					r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.getWatchlistHandler)
					r.With(srv.RequireOrgRole(RoleMember)).Patch("/", srv.updateWatchlistHandler)
					r.With(srv.RequireOrgRole(RoleMember)).Delete("/", srv.deleteWatchlistHandler)
					r.Route("/items", func(r chi.Router) {
						r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.listWatchlistItemsHandler)
						r.With(srv.RequireOrgRole(RoleMember)).Post("/", srv.createWatchlistItemHandler)
						r.With(srv.RequireOrgRole(RoleMember)).Delete("/{item_id}", srv.deleteWatchlistItemHandler)
					})
				})
			})

			// Notification channel management
			r.Route("/channels", func(r chi.Router) {
				r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.listChannelsHandler)
				r.With(srv.RequireOrgRole(RoleAdmin)).Post("/", srv.createChannelHandler)
				r.Route("/{id}", func(r chi.Router) {
					r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.getChannelHandler)
					r.With(srv.RequireOrgRole(RoleAdmin)).Patch("/", srv.patchChannelHandler)
					r.With(srv.RequireOrgRole(RoleAdmin)).Delete("/", srv.deleteChannelHandler)
					r.With(srv.RequireOrgRole(RoleAdmin)).Post("/rotate-secret", srv.rotateSecretHandler)
					r.With(srv.RequireOrgRole(RoleAdmin)).Post("/clear-secondary", srv.clearSecondarySecretHandler)
					r.With(srv.RequireOrgRole(RoleAdmin)).Post("/test", srv.testChannelHandler)
				})
			})

			// Alert event listing
			r.With(srv.RequireOrgRole(RoleViewer)).Get("/alert-events", srv.listAlertEventsHandler)

			// SSO connection management (enterprise only, owner only)
			r.Route("/sso", func(r chi.Router) {
				r.With(srv.RequireOrgRole(RoleOwner)).Post("/", srv.createSSOHandler)
				r.With(srv.RequireOrgRole(RoleOwner)).Get("/", srv.getSSOHandler)
				r.With(srv.RequireOrgRole(RoleOwner)).Patch("/", srv.patchSSOHandler)
				r.With(srv.RequireOrgRole(RoleOwner)).Delete("/", srv.deleteSSOHandler)
				r.With(srv.RequireOrgRole(RoleOwner)).Put("/domains", srv.putSSODomainsHandler)
				r.With(srv.RequireOrgRole(RoleMember)).Get("/link", srv.oidcLinkInitHandler)
			})

			// Audit log (enterprise only, admin+)
			r.With(srv.RequireOrgRole(RoleAdmin)).Get("/audit-log", srv.listAuditLogHandler)

			// Delivery history
			r.Route("/deliveries", func(r chi.Router) {
				r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.listDeliveriesHandler)
				r.Route("/{id}", func(r chi.Router) {
					r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.getDeliveryHandler)
					r.With(srv.RequireOrgRole(RoleAdmin)).Post("/replay", srv.replayDeliveryHandler)
				})
			})

			// Alert rule management
			r.Route("/alert-rules", func(r chi.Router) {
				r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.listAlertRulesHandler)
				r.With(srv.RequireOrgRole(RoleMember)).Post("/", srv.createAlertRuleHandler)
				r.With(srv.RequireOrgRole(RoleViewer)).Post("/validate", srv.validateAlertRuleHandler)
				r.Route("/{id}", func(r chi.Router) {
					r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.getAlertRuleHandler)
					r.With(srv.RequireOrgRole(RoleMember)).Patch("/", srv.updateAlertRuleHandler)
					r.With(srv.RequireOrgRole(RoleMember)).Delete("/", srv.deleteAlertRuleHandler)
					r.With(srv.RequireOrgRole(RoleViewer)).Post("/dry-run", srv.dryRunHandler)
					r.With(srv.RequireOrgRole(RoleViewer)).Get("/channels", srv.listRuleChannelsHandler)
					r.With(srv.RequireOrgRole(RoleMember)).Put("/channels/{channel_id}", srv.bindRuleChannelHandler)
					r.With(srv.RequireOrgRole(RoleMember)).Delete("/channels/{channel_id}", srv.unbindRuleChannelHandler)
				})
			})

			// Scheduled digest reports
			r.Route("/reports", func(r chi.Router) {
				r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.listReportsHandler)
				r.With(srv.RequireOrgRole(RoleMember)).Post("/", srv.createReportHandler)
				r.Route("/{id}", func(r chi.Router) {
					r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.getReportHandler)
					r.With(srv.RequireOrgRole(RoleMember)).Patch("/", srv.patchReportHandler)
					r.With(srv.RequireOrgRole(RoleMember)).Delete("/", srv.deleteReportHandler)
					r.Route("/channels", func(r chi.Router) {
						r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.listReportChannelsHandler)
						r.With(srv.RequireOrgRole(RoleMember)).Put("/{channel_id}", srv.bindChannelToReportHandler)
						r.With(srv.RequireOrgRole(RoleMember)).Delete("/{channel_id}", srv.unbindChannelFromReportHandler)
					})
				})
			})

			// Inbound webhook for custom feed data ingestion (member+)
			r.With(srv.RequireOrgRole(RoleMember)).Post("/ingest", srv.ingestHandler)

			// AI-powered search and summarization (viewer+ per PLAN.md §7.3)
			r.Route("/ai", func(r chi.Router) {
				r.With(srv.RequireOrgRole(RoleViewer)).Post("/nl-search", srv.nlSearchHandler)
				r.With(srv.RequireOrgRole(RoleViewer)).Post("/summarize/{cve_id}", srv.summarizeHandler)
			})

			// Saved searches (viewer can list/get/execute; member+ to create/patch/delete)
			r.Route("/saved-searches", func(r chi.Router) {
				r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.listSavedSearchesHandler)
				r.With(srv.RequireOrgRole(RoleMember)).Post("/", srv.createSavedSearchHandler)
				r.Route("/{id}", func(r chi.Router) {
					r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.getSavedSearchHandler)
					r.With(srv.RequireOrgRole(RoleMember)).Patch("/", srv.patchSavedSearchHandler)
					r.With(srv.RequireOrgRole(RoleMember)).Delete("/", srv.deleteSavedSearchHandler)
					r.With(srv.RequireOrgRole(RoleViewer)).Post("/execute", srv.executeSavedSearchHandler)
				})
			})

			// Group management
			r.Route("/groups", func(r chi.Router) {
				r.Get("/", srv.listGroupsHandler)
				r.With(srv.RequireOrgRole(RoleAdmin)).Post("/", srv.createGroupHandler)
				r.Route("/{group_id}", func(r chi.Router) {
					r.Get("/", srv.getGroupHandler)
					r.With(srv.RequireOrgRole(RoleAdmin)).Patch("/", srv.updateGroupHandler)
					r.With(srv.RequireOrgRole(RoleAdmin)).Delete("/", srv.deleteGroupHandler)
					r.Route("/members", func(r chi.Router) {
						r.Get("/", srv.listGroupMembersHandler)
						r.With(srv.RequireOrgRole(RoleAdmin)).Post("/", srv.addGroupMemberHandler)
						r.With(srv.RequireOrgRole(RoleAdmin)).Delete("/{user_id}", srv.removeGroupMemberHandler)
					})
				})
			})
		})
	})

	r.Mount("/api/v1", apiRouter)

	// ── SPA fallback (serves embedded frontend) ─────────────────────────────
	if frontendFS, err := web.Assets(); err == nil {
		r.Handle("/*", newSPAHandler(frontendFS))
	}

	return r
}


// AddHealthCheck registers an extra readiness check for the /readyz endpoint.
// Must be called before Handler() — not safe for concurrent use.
func (srv *Server) AddHealthCheck(check func() bool) {
	srv.healthChecks = append(srv.healthChecks, check)
}

// auditLog records an audit entry if the audit writer is configured.
// Extracts actor context from the request. Nil-safe: no-op if writer is nil.
func (srv *Server) auditLog(r *http.Request, entry audit.Entry) {
	if srv.auditWriter == nil {
		return
	}
	if entry.ActorID == nil {
		if uid, ok := r.Context().Value(ctxUserID).(uuid.UUID); ok {
			entry.ActorID = &uid
		}
	}
	srv.auditWriter.Log(r.Context(), entry)
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

// healthzHandler returns a liveness probe handler. No external dependencies
// are checked — if the process can respond, it's alive. Kubernetes uses this
// to decide whether to restart the pod.
func healthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "alive"}); err != nil {
			slog.ErrorContext(r.Context(), "healthz: failed to encode response", "error", err)
		}
	}
}
