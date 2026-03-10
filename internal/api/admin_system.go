// ABOUTME: Site admin system management API handlers.
// ABOUTME: Search reindex trigger, runtime config view, cross-org audit log.
package api

import (
	"log/slog"
	"net/http"
	"strconv"
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
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if jobID == uuid.Nil {
		http.Error(w, "reindex job already pending", http.StatusConflict)
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
		"nvd_api_key":          redactSecret(cfg.NVDAPIKey),
		"gemini_api_key":       redactSecret(cfg.GeminiAPIKey),
		"github_client_secret": redactSecret(cfg.GitHubClientSecret),
		"google_client_secret": redactSecret(cfg.GoogleClientSecret),
		"smtp_password":        redactSecret(cfg.SMTPPassword),
		"sso_encryption_key":   redactSecret(cfg.SSOEncryptionKey),
	}

	writeJSON(w, http.StatusOK, redacted)
}

// adminAuditLogHandler handles GET /api/v1/admin/audit-log.
// Cross-org audit log listing with optional filters and keyset pagination.
func (srv *Server) adminAuditLogHandler(w http.ResponseWriter, r *http.Request) {
	limit := 50
	q := r.URL.Query()

	if l := q.Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed < 1 || parsed > 200 {
			http.Error(w, "invalid limit (1-200)", http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	params := store.AdminAuditListParams{
		EntityType: q.Get("entity_type"),
		Action:     q.Get("action"),
		PageSize:   limit + 1,
	}

	if orgIDStr := q.Get("org_id"); orgIDStr != "" {
		id, err := uuid.Parse(orgIDStr)
		if err != nil {
			http.Error(w, "invalid org_id", http.StatusBadRequest)
			return
		}
		params.OrgID = &id
	}

	if actorIDStr := q.Get("actor_id"); actorIDStr != "" {
		id, err := uuid.Parse(actorIDStr)
		if err != nil {
			http.Error(w, "invalid actor_id", http.StatusBadRequest)
			return
		}
		params.ActorID = &id
	}

	if cursor := q.Get("after_time"); cursor != "" {
		t, err := time.Parse(time.RFC3339Nano, cursor)
		if err != nil {
			http.Error(w, "invalid after_time (RFC3339)", http.StatusBadRequest)
			return
		}
		params.CursorCreatedAt = &t
	}
	if cursor := q.Get("after_id"); cursor != "" {
		id, err := uuid.Parse(cursor)
		if err != nil {
			http.Error(w, "invalid after_id (UUID)", http.StatusBadRequest)
			return
		}
		params.CursorID = &id
	}
	if (params.CursorCreatedAt == nil) != (params.CursorID == nil) {
		http.Error(w, "after_time and after_id must both be provided or both omitted", http.StatusBadRequest)
		return
	}

	entries, err := srv.store.AdminListAuditEntries(r.Context(), params)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin audit log", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	hasMore := len(entries) > limit
	if hasMore {
		entries = entries[:limit]
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":    entries,
		"has_more": hasMore,
	})
}

// redactSecret returns "***" for non-empty secrets, empty string otherwise.
func redactSecret(s string) string {
	if s == "" {
		return ""
	}
	return "***"
}

