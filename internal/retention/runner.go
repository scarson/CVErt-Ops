// ABOUTME: Scheduled retention cleanup job that deletes old data per §21.
// ABOUTME: Runs as a job_queue entry with bounded-batch deletes per table.
package retention

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/tier"
)

// Config holds retention runner parameters.
type Config struct {
	Enabled           bool
	BatchSize         int
	MaxRuntimeSeconds int
	// Per-table retention windows (global tables).
	RawPayloadDays   int
	FeedFetchLogDays int
	JobQueueHours    int
	AILogDays        int
	SecurityEventsDays int
	// Per-table retention windows (tier-gated tables — fallback defaults).
	AlertEventsDays  int
	NotifDelivDays   int
	AuditLogDays     int
}

// Runner executes bounded-batch retention cleanup across all tables.
type Runner struct {
	store *store.Store
	cfg   Config
	log   *slog.Logger
	now   func() time.Time
}

// NewRunner creates a retention runner.
func NewRunner(s *store.Store, cfg Config, log *slog.Logger) *Runner {
	return &Runner{
		store: s,
		cfg:   cfg,
		log:   log,
		now:   time.Now,
	}
}

// Run executes retention cleanup across all tables. Errors per table are logged
// but don't stop the run. Returns nil unless the context is cancelled.
func (r *Runner) Run(ctx context.Context) error {
	if !r.cfg.Enabled {
		r.log.Info("retention cleanup disabled, skipping")
		return nil
	}

	start := r.now()
	deadline := start.Add(time.Duration(r.cfg.MaxRuntimeSeconds) * time.Second)
	r.log.Info("retention cleanup started", "batch_size", r.cfg.BatchSize, "max_runtime_seconds", r.cfg.MaxRuntimeSeconds)

	// Global tables (no org filtering).
	r.cleanupTable(ctx, "cve_raw_payloads", deadline, func(ctx context.Context, cutoff time.Time, batch int) (int64, error) {
		return r.store.CleanupCveRawPayloads(ctx, cutoff, batch)
	}, start.AddDate(0, 0, -r.cfg.RawPayloadDays))

	r.cleanupTable(ctx, "feed_fetch_log", deadline, func(ctx context.Context, cutoff time.Time, batch int) (int64, error) {
		return r.store.CleanupFeedFetchLog(ctx, cutoff, batch)
	}, start.AddDate(0, 0, -r.cfg.FeedFetchLogDays))

	r.cleanupTable(ctx, "job_queue", deadline, func(ctx context.Context, cutoff time.Time, batch int) (int64, error) {
		return r.store.CleanupJobQueue(ctx, cutoff, batch)
	}, start.Add(-time.Duration(r.cfg.JobQueueHours)*time.Hour))

	r.cleanupTable(ctx, "refresh_tokens", deadline, func(ctx context.Context, cutoff time.Time, batch int) (int64, error) {
		return r.store.CleanupRefreshTokens(ctx, cutoff, batch)
	}, start.Add(-60*time.Second)) // 60s grace window

	r.cleanupTable(ctx, "ai_request_log", deadline, func(ctx context.Context, cutoff time.Time, batch int) (int64, error) {
		return r.store.CleanupAIRequestLogBatch(ctx, cutoff, batch)
	}, start.AddDate(0, 0, -r.cfg.AILogDays))

	r.cleanupTable(ctx, "ai_cache", deadline, func(ctx context.Context, cutoff time.Time, batch int) (int64, error) {
		return r.store.CleanupAICacheBatch(ctx, cutoff, batch)
	}, start) // TTL-based — delete anything expired before now

	r.cleanupTable(ctx, "ai_usage_counters", deadline, func(ctx context.Context, cutoff time.Time, batch int) (int64, error) {
		return r.store.CleanupAIUsageCounters(ctx, cutoff, batch)
	}, start.AddDate(0, 0, -r.cfg.AILogDays))

	r.cleanupTable(ctx, "security_events", deadline, func(ctx context.Context, cutoff time.Time, batch int) (int64, error) {
		return r.store.CleanupSecurityEvents(ctx, cutoff, batch)
	}, start.AddDate(0, 0, -r.cfg.SecurityEventsDays))

	// Check for context cancellation between global and tier-gated phases.
	if err := ctx.Err(); err != nil {
		return err
	}

	// Tier-gated tables: group orgs by retention window, run per-group cleanup.
	if err := r.cleanupTierGated(ctx, deadline, start); err != nil {
		r.log.Error("tier-gated retention cleanup", "error", err)
		return fmt.Errorf("tier-gated cleanup: %w", err)
	}

	elapsed := r.now().Sub(start)
	r.log.Info("retention cleanup finished", "elapsed", elapsed)
	return ctx.Err()
}

// cleanupTierGated handles org-scoped tables with tier-configurable retention windows.
func (r *Runner) cleanupTierGated(ctx context.Context, deadline, start time.Time) error {
	orgs, err := r.store.ListAllOrgs(ctx)
	if err != nil {
		return err
	}

	// Group orgs by alert_events retention window.
	alertGroups := groupByRetentionDays(orgs, "retention_alert_events_days", r.cfg.AlertEventsDays)
	for days, orgIDs := range alertGroups {
		cutoff := start.AddDate(0, 0, -days)
		r.cleanupTable(ctx, "alert_events", deadline, func(ctx context.Context, _ time.Time, batch int) (int64, error) {
			return r.store.CleanupAlertEvents(ctx, orgIDs, cutoff, batch)
		}, cutoff)
	}

	// Group orgs by notification_deliveries retention window.
	notifGroups := groupByRetentionDays(orgs, "retention_notification_deliveries_days", r.cfg.NotifDelivDays)
	for days, orgIDs := range notifGroups {
		cutoff := start.AddDate(0, 0, -days)
		r.cleanupTable(ctx, "notification_deliveries", deadline, func(ctx context.Context, _ time.Time, batch int) (int64, error) {
			return r.store.CleanupNotificationDeliveries(ctx, orgIDs, cutoff, batch)
		}, cutoff)
	}

	// Group orgs by audit_log retention window.
	auditGroups := groupByRetentionDays(orgs, "retention_audit_log_days", r.cfg.AuditLogDays)
	for days, orgIDs := range auditGroups {
		cutoff := start.AddDate(0, 0, -days)
		r.cleanupTable(ctx, "audit_log", deadline, func(ctx context.Context, _ time.Time, batch int) (int64, error) {
			return r.store.CleanupAuditLog(ctx, orgIDs, cutoff, batch)
		}, cutoff)
	}

	return nil
}

// groupByRetentionDays groups orgs by their effective retention window (days).
// The overrideName is checked in each org's tier_overrides; if absent, the tier
// resolver falls back to defaultDays for all tiers.
func groupByRetentionDays(orgs []store.OrgTierRow, overrideName string, defaultDays int) map[int][]uuid.UUID {
	groups := make(map[int][]uuid.UUID)
	for _, org := range orgs {
		resolver := &tier.Resolver{Tier: org.Tier, Overrides: org.Overrides}
		days := resolver.IntLimit(overrideName, defaultDays, defaultDays, defaultDays)
		if days < 0 {
			continue // unlimited retention — skip this org
		}
		groups[days] = append(groups[days], org.ID)
	}
	return groups
}

type cleanupFunc func(ctx context.Context, cutoff time.Time, batchSize int) (int64, error)

// cleanupTable runs bounded-batch deletes in a loop until 0 rows deleted or
// deadline exceeded. The cutoff parameter is passed through to fn.
func (r *Runner) cleanupTable(ctx context.Context, table string, deadline time.Time, fn cleanupFunc, cutoff time.Time) {
	var totalDeleted int64
	tableStart := r.now()

	for {
		if r.now().After(deadline) {
			r.log.Warn("retention max runtime reached, stopping", "table", table, "deleted_so_far", totalDeleted)
			return
		}

		if err := ctx.Err(); err != nil {
			r.log.Warn("retention context cancelled", "table", table, "deleted_so_far", totalDeleted)
			return
		}

		n, err := fn(ctx, cutoff, r.cfg.BatchSize)
		if err != nil {
			r.log.Error("retention cleanup error", "table", table, "error", err, "deleted_so_far", totalDeleted)
			return
		}

		totalDeleted += n
		if n == 0 {
			break
		}
	}

	if totalDeleted > 0 {
		elapsed := r.now().Sub(tableStart)
		r.log.Info("retention cleanup completed", "table", table, "deleted", totalDeleted, "elapsed", elapsed)
	}
}
