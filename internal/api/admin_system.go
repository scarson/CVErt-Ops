// ABOUTME: Site admin system management API handlers.
// ABOUTME: Search reindex trigger, runtime config view, cross-org audit log.
package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/store"
)

// adminReindexHandler handles POST /api/v1/admin/reindex.
// Enqueues an async search index rebuild job, returns 202 Accepted.
func (srv *Server) adminReindexHandler(w http.ResponseWriter, r *http.Request) {
	lockKey := "system:reindex"
	jobID, err := srv.store.EnqueueJob(r.Context(), "system_reindex", 0, nil, &lockKey, 1, nil)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin reindex: enqueue", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if jobID == uuid.Nil {
		writeProblem(w, http.StatusConflict, "reindex job already pending")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID.String()})
}

// adminConfigHandler handles GET /api/v1/admin/config.
// Returns runtime configuration with secrets redacted.
func (srv *Server) adminConfigHandler(w http.ResponseWriter, _ *http.Request) {
	// Build a safe representation of config — secrets masked.
	cfg := srv.cfg
	redacted := map[string]any{
		"listen_addr":       cfg.ListenAddr,
		"app_env":           cfg.AppEnv,
		"external_url":      cfg.ExternalURL,
		"frontend_url":      cfg.FrontendURL,
		"registration_mode": cfg.RegistrationMode,
		"cookie_secure":     cfg.CookieSecure,

		// Auth.
		"jwt_algorithm":        cfg.JWTAlgorithm,
		"lockout_threshold":    cfg.LockoutThreshold,
		"lockout_duration":     cfg.LockoutDuration.String(),
		"argon2_max_concurrent": cfg.Argon2MaxConcurrent,

		// Database.
		"db_max_conns":            cfg.DBMaxConns,
		"db_max_conn_idle_time":   cfg.DBMaxConnIdleTime.String(),
		"db_statement_timeout_ms": cfg.DBStatementTimeoutMS,
		"db_query_exec_mode":      cfg.DBQueryExecMode,

		// Feed scheduler.
		"feed_scheduler_enabled": cfg.FeedSchedulerEnabled,

		// Notifications.
		"notify_max_concurrent_per_org": cfg.NotifyMaxConcurrentPerOrg,
		"notify_debounce_seconds":       cfg.NotifyDebounceSeconds,
		"notify_claim_batch_size":       cfg.NotifyClaimBatchSize,
		"notify_max_attempts":           cfg.NotifyMaxAttempts,
		"notify_backoff_base_seconds":   cfg.NotifyBackoffBaseSeconds,

		// Data retention.
		"retention_cleanup_enabled":    cfg.RetentionCleanupEnabled,
		"retention_cleanup_batch_size": cfg.RetentionCleanupBatchSize,
		"retention_raw_payload_days":   cfg.RetentionRawPayloadDays,
		"retention_feed_fetch_log_days": cfg.RetentionFeedFetchLogDays,
		"retention_alert_events_days":  cfg.RetentionAlertEventsDays,
		"retention_notif_deliveries_days": cfg.RetentionNotifDeliveriesDays,
		"retention_audit_log_days":     cfg.RetentionAuditLogDays,
		"retention_job_queue_hours":    cfg.RetentionJobQueueHours,

		// AI.
		"ai_quota_enabled": cfg.AIQuotaEnabled,
		"gemini_model":     cfg.GeminiModel,
		"gemini_timeout":   cfg.GeminiTimeout.String(),
		"gemini_mock":      cfg.GeminiMock,

		// Logging.
		"log_level":  cfg.LogLevel,
		"log_format": cfg.LogFormat,

		// Secrets — redacted.
		"jwt_secret":           redactSecret(cfg.JWTSecret),
		"database_url":         redactSecret(cfg.DatabaseURL),
		"database_url_migrate": redactSecret(cfg.DatabaseURLMigrate),
		"nvd_api_key":          redactSecret(cfg.NVDAPIKey),
		"gemini_api_key":       redactSecret(cfg.GeminiAPIKey),
		"github_client_secret": redactSecret(cfg.GitHubClientSecret),
		"google_client_secret": redactSecret(cfg.GoogleClientSecret),
		"smtp_password":        redactSecret(cfg.SMTPPassword),
		"sso_encryption_key":   redactSecret(cfg.SSOEncryptionKey),
	}

	writeJSON(w, http.StatusOK, redacted)
}

// adminAuditCursor is the opaque cursor for admin audit log pagination.
type adminAuditCursor struct {
	T  time.Time `json:"t"`
	ID string    `json:"id"`
}

// adminAuditLogHandler handles GET /api/v1/admin/audit-log.
// Cross-org audit log listing with optional filters and opaque cursor pagination.
func (srv *Server) adminAuditLogHandler(w http.ResponseWriter, r *http.Request) {
	limit, ok := parseLimitParam(w, r, 50, 200)
	if !ok {
		return
	}

	var afterTime *time.Time
	var afterID *uuid.UUID
	if c := r.URL.Query().Get("cursor"); c != "" {
		var cur adminAuditCursor
		if err := decodePageCursor(c, &cur); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		afterTime = &cur.T
		id, err := uuid.Parse(cur.ID)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		afterID = &id
	}

	q := r.URL.Query()
	params := store.AdminAuditListParams{
		EntityType:      q.Get("entity_type"),
		Action:          q.Get("action"),
		CursorCreatedAt: afterTime,
		CursorID:        afterID,
		PageSize:        limit + 1,
	}

	if orgIDStr := q.Get("org_id"); orgIDStr != "" {
		id, err := uuid.Parse(orgIDStr)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid org_id")
			return
		}
		params.OrgID = &id
	}

	if actorIDStr := q.Get("actor_id"); actorIDStr != "" {
		id, err := uuid.Parse(actorIDStr)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid actor_id")
			return
		}
		params.ActorID = &id
	}

	entries, err := srv.store.AdminListAuditEntries(r.Context(), params)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin audit log", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	var nextCursor string
	if len(entries) > limit {
		entries = entries[:limit]
		last := entries[len(entries)-1]
		nextCursor = encodePageCursor(adminAuditCursor{T: last.CreatedAt, ID: last.ID.String()})
	}

	writeList(w, entries, nextCursor)
}

// redactSecret returns "***" for non-empty secrets, empty string otherwise.
func redactSecret(s string) string {
	if s == "" {
		return ""
	}
	return "***"
}

