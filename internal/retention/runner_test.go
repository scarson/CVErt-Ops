// ABOUTME: Integration tests for the retention runner.
// ABOUTME: Verifies bounded-batch cleanup, max runtime, disabled gate, and per-org tier grouping.
package retention_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/retention"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func defaultConfig() retention.Config {
	return retention.Config{
		Enabled:           true,
		BatchSize:         1000,
		MaxRuntimeSeconds: 60,
		RawPayloadDays:    90,
		FeedFetchLogDays:  90,
		JobQueueHours:     24,
		AILogDays:          90,
		SecurityEventsDays: 90,
		AlertEventsDays:   365,
		NotifDelivDays:    90,
		AuditLogDays:      365,
	}
}

func TestRunner_AllTables(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	old := now.Add(-100 * 24 * time.Hour)
	recent := now.Add(-10 * 24 * time.Hour)
	org, _ := db.CreateOrg(ctx, "RetAllOrg")

	// Seed cve_raw_payloads.
	for _, ts := range []time.Time{old, recent} {
		if _, err := db.Pool().Exec(ctx,
			`INSERT INTO cve_raw_payloads (cve_id, source_name, payload, ingested_at)
			 VALUES ('CVE-2024-ALL', 'nvd', '{}', $1)`, ts,
		); err != nil {
			t.Fatalf("seed raw payloads: %v", err)
		}
	}

	// Seed feed_fetch_log.
	for _, ts := range []time.Time{old, recent} {
		if _, err := db.Pool().Exec(ctx,
			`INSERT INTO feed_fetch_log (feed_name, started_at, status) VALUES ('nvd', $1, 'success')`, ts,
		); err != nil {
			t.Fatalf("seed feed log: %v", err)
		}
	}

	// Seed job_queue (succeeded, old finished_at).
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO job_queue (queue, priority, payload, status, finished_at)
		 VALUES ('test', 0, '{}', 'succeeded', $1)`, old,
	); err != nil {
		t.Fatalf("seed job: %v", err)
	}

	// Seed refresh_tokens (expired long ago).
	var userID uuid.UUID
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO users (email, display_name, password_hash)
		 VALUES ('retall@example.com', 'RetAll', 'hash') RETURNING id`,
	).Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO refresh_tokens (jti, user_id, token_version, expires_at)
		 VALUES ($1, $2, 1, $3)`, uuid.New(), userID, old,
	); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	// Seed ai_request_log.
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO ai_request_log (org_id, user_id, feature, input_hash, prompt_version, model, cache_hit, latency_ms, status, created_at)
		 VALUES ($1, $1, 'nl_search', 'old', 'v1', 'mock', false, 100, 'success', $2)`,
		org.ID, old,
	); err != nil {
		t.Fatalf("seed ai log: %v", err)
	}

	// Seed ai_cache (expired).
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO ai_cache (org_id, feature, prompt_version, input_hash, response, expires_at)
		 VALUES ($1, 'nl_search', 'v1', 'expired', '"x"', $2)`,
		org.ID, now.Add(-1*time.Hour),
	); err != nil {
		t.Fatalf("seed ai cache: %v", err)
	}

	// Seed ai_usage_counters (old daily).
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO ai_usage_counters (org_id, feature, date, count) VALUES ($1, 'nl_search', $2, 5)`,
		org.ID, old.Format("2006-01-02"),
	); err != nil {
		t.Fatalf("seed ai usage: %v", err)
	}

	// Seed security_events (old + recent).
	for _, ts := range []time.Time{old, recent} {
		if _, err := db.Pool().Exec(ctx,
			`INSERT INTO security_events (event_type, severity, created_at)
			 VALUES ('auth.login_failed', 'info', $1)`, ts,
		); err != nil {
			t.Fatalf("seed security_events: %v", err)
		}
	}

	// Seed alert_events (old).
	var ruleID uuid.UUID
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO alert_rules (org_id, name, logic, conditions, status)
		 VALUES ($1, 'retRule', 'and', '[]'::jsonb, 'active') RETURNING id`, org.ID,
	).Scan(&ruleID); err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash, first_fired_at)
		 VALUES ($1, $2, 'CVE-2024-ALL', 'hash', $3)`, org.ID, ruleID, old,
	); err != nil {
		t.Fatalf("seed alert event: %v", err)
	}

	// Seed notification_deliveries (old).
	var chanID uuid.UUID
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO notification_channels (org_id, name, type, config)
		 VALUES ($1, 'retChan', 'webhook', '{"url":"http://example.com"}') RETURNING id`, org.ID,
	).Scan(&chanID); err != nil {
		t.Fatalf("create channel: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO notification_deliveries (org_id, rule_id, channel_id, payload, created_at, kind)
		 VALUES ($1, $2, $3, '[]', $4, 'alert')`, org.ID, ruleID, chanID, old,
	); err != nil {
		t.Fatalf("seed delivery: %v", err)
	}

	// Seed audit_log (old).
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO audit_log (org_id, actor_email, action, entity_type, entity_id, success, created_at)
		 VALUES ($1, 'test@example.com', 'create', 'alert_rule', 'ent-1', true, $2)`, org.ID, old,
	); err != nil {
		t.Fatalf("seed audit log: %v", err)
	}

	cfg := defaultConfig()
	cfg.AlertEventsDays = 90 // match other tables so 100-day-old data gets cleaned
	cfg.AuditLogDays = 90    // match other tables so 100-day-old data gets cleaned
	runner := retention.NewRunner(db.Store, cfg, slog.Default())
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Verify old rows deleted.
	counts := map[string]int{
		"cve_raw_payloads":        0,
		"feed_fetch_log":          0,
		"refresh_tokens":          0,
		"ai_request_log":          0,
		"ai_cache":                0,
		"ai_usage_counters":       0,
		"security_events":         0,
		"alert_events":            0,
		"notification_deliveries": 0,
		"audit_log":               0,
	}
	for table := range counts {
		var n int
		if err := db.DB().QueryRowContext(ctx,
			"SELECT COUNT(*) FROM "+table, //nolint:gosec // table name is hardcoded
		).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		counts[table] = n
	}

	// cve_raw_payloads: old deleted, recent kept → 1
	if counts["cve_raw_payloads"] != 1 {
		t.Errorf("cve_raw_payloads remaining = %d, want 1", counts["cve_raw_payloads"])
	}
	// feed_fetch_log: old deleted, recent kept → 1
	if counts["feed_fetch_log"] != 1 {
		t.Errorf("feed_fetch_log remaining = %d, want 1", counts["feed_fetch_log"])
	}
	// refresh_tokens: expired long ago, cleaned → 0
	if counts["refresh_tokens"] != 0 {
		t.Errorf("refresh_tokens remaining = %d, want 0", counts["refresh_tokens"])
	}
	// AI tables: all old/expired → 0
	if counts["ai_request_log"] != 0 {
		t.Errorf("ai_request_log remaining = %d, want 0", counts["ai_request_log"])
	}
	if counts["ai_cache"] != 0 {
		t.Errorf("ai_cache remaining = %d, want 0", counts["ai_cache"])
	}
	if counts["ai_usage_counters"] != 0 {
		t.Errorf("ai_usage_counters remaining = %d, want 0", counts["ai_usage_counters"])
	}
	// security_events: old deleted, recent kept → 1
	if counts["security_events"] != 1 {
		t.Errorf("security_events remaining = %d, want 1", counts["security_events"])
	}
	// Org-scoped: all old → 0
	if counts["alert_events"] != 0 {
		t.Errorf("alert_events remaining = %d, want 0", counts["alert_events"])
	}
	if counts["notification_deliveries"] != 0 {
		t.Errorf("notification_deliveries remaining = %d, want 0", counts["notification_deliveries"])
	}
	if counts["audit_log"] != 0 {
		t.Errorf("audit_log remaining = %d, want 0", counts["audit_log"])
	}

	// Job queue: succeeded old → 0 for test queue
	var jqRemaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM job_queue WHERE queue = 'test'",
	).Scan(&jqRemaining); err != nil {
		t.Fatalf("count job_queue: %v", err)
	}
	if jqRemaining != 0 {
		t.Errorf("job_queue remaining = %d, want 0", jqRemaining)
	}
}

func TestRunner_MaxRuntime(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	old := now.Add(-100 * 24 * time.Hour)

	// Seed many old rows.
	for i := 0; i < 50; i++ {
		if _, err := db.Pool().Exec(ctx,
			`INSERT INTO cve_raw_payloads (cve_id, source_name, payload, ingested_at)
			 VALUES ($1, 'nvd', '{}', $2)`,
			"CVE-2024-RUNTIME", old.Add(time.Duration(i)*time.Second),
		); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	cfg := defaultConfig()
	cfg.MaxRuntimeSeconds = 0 // immediate deadline — should stop after first table
	cfg.BatchSize = 5

	runner := retention.NewRunner(db.Store, cfg, slog.Default())
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Some rows may have been deleted, but the test is that the runner didn't panic
	// and respected the deadline. It should have stopped early.
	var remaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM cve_raw_payloads WHERE cve_id = 'CVE-2024-RUNTIME'",
	).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	// With MaxRuntimeSeconds=0, the first check should catch it after at most one batch.
	if remaining < 1 {
		t.Errorf("expected some rows remaining with immediate deadline, got %d", remaining)
	}
}

func TestRunner_Disabled(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	old := now.Add(-100 * 24 * time.Hour)

	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO cve_raw_payloads (cve_id, source_name, payload, ingested_at)
		 VALUES ('CVE-2024-DISABLED', 'nvd', '{}', $1)`, old,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cfg := defaultConfig()
	cfg.Enabled = false

	runner := retention.NewRunner(db.Store, cfg, slog.Default())
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Row should still exist.
	var remaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM cve_raw_payloads WHERE cve_id = 'CVE-2024-DISABLED'",
	).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 1 {
		t.Errorf("remaining = %d, want 1 (disabled should not delete)", remaining)
	}
}

func TestRunner_PerOrgGroup(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	// 200 days old: within enterprise 365d window, outside free 90d window.
	boundary := now.Add(-200 * 24 * time.Hour)

	orgFree, _ := db.CreateOrg(ctx, "RetFreeOrg")
	orgEnt, _ := db.CreateOrg(ctx, "RetEntOrg")

	// Set enterprise tier + retention override on orgEnt.
	// Tier differentiation comes from tier_overrides, not the tier name itself
	// (groupByRetentionDays uses the same defaultDays for all tiers).
	if err := db.UpdateOrgTier(ctx, orgEnt.ID, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`UPDATE organizations SET tier_overrides = '{"retention_alert_events_days": 365}' WHERE id = $1`, orgEnt.ID,
	); err != nil {
		t.Fatalf("set tier overrides: %v", err)
	}

	// Create alert rules.
	var ruleIDFree, ruleIDEnt uuid.UUID
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO alert_rules (org_id, name, logic, conditions, status)
		 VALUES ($1, 'rule', 'and', '[]'::jsonb, 'active') RETURNING id`, orgFree.ID,
	).Scan(&ruleIDFree); err != nil {
		t.Fatalf("create rule free: %v", err)
	}
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO alert_rules (org_id, name, logic, conditions, status)
		 VALUES ($1, 'rule', 'and', '[]'::jsonb, 'active') RETURNING id`, orgEnt.ID,
	).Scan(&ruleIDEnt); err != nil {
		t.Fatalf("create rule ent: %v", err)
	}

	// Seed alert events at boundary timestamp for both orgs.
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash, first_fired_at)
		 VALUES ($1, $2, 'CVE-2024-ORG1', 'hash', $3)`, orgFree.ID, ruleIDFree, boundary,
	); err != nil {
		t.Fatalf("seed free event: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash, first_fired_at)
		 VALUES ($1, $2, 'CVE-2024-ORG2', 'hash', $3)`, orgEnt.ID, ruleIDEnt, boundary,
	); err != nil {
		t.Fatalf("seed ent event: %v", err)
	}

	cfg := defaultConfig()
	// Free: 90 days → boundary (200d old) should be deleted.
	// Enterprise: 365 days → boundary (200d old) should be retained.
	cfg.AlertEventsDays = 90 // free default

	runner := retention.NewRunner(db.Store, cfg, slog.Default())
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Free org's event should be deleted (200d > 90d retention).
	var freeRemaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM alert_events WHERE org_id = $1", orgFree.ID,
	).Scan(&freeRemaining); err != nil {
		t.Fatalf("count free: %v", err)
	}
	if freeRemaining != 0 {
		t.Errorf("free org remaining = %d, want 0 (200d old, 90d retention)", freeRemaining)
	}

	// Enterprise org's event should survive (200d < 365d retention).
	var entRemaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM alert_events WHERE org_id = $1", orgEnt.ID,
	).Scan(&entRemaining); err != nil {
		t.Fatalf("count ent: %v", err)
	}
	if entRemaining != 1 {
		t.Errorf("enterprise org remaining = %d, want 1 (200d old, 365d retention)", entRemaining)
	}
}

func TestRunner_AuditLogRetention(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	// 200 days old: within enterprise 365d window, outside free 90d window.
	boundary := now.Add(-200 * 24 * time.Hour)

	orgFree, _ := db.CreateOrg(ctx, "AuditFreeOrg")
	orgEnt, _ := db.CreateOrg(ctx, "AuditEntOrg")

	// Set enterprise tier + retention override on orgEnt.
	if err := db.UpdateOrgTier(ctx, orgEnt.ID, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`UPDATE organizations SET tier_overrides = '{"retention_audit_log_days": 365}' WHERE id = $1`, orgEnt.ID,
	); err != nil {
		t.Fatalf("set tier overrides: %v", err)
	}

	// Seed audit_log entries at boundary timestamp for both orgs.
	for _, p := range []struct {
		orgID uuid.UUID
		email string
	}{
		{orgFree.ID, "free@example.com"},
		{orgEnt.ID, "ent@example.com"},
	} {
		if _, err := db.Pool().Exec(ctx,
			`INSERT INTO audit_log (org_id, actor_email, action, entity_type, entity_id, success, created_at)
			 VALUES ($1, $2, 'create', 'alert_rule', 'ent-1', true, $3)`,
			p.orgID, p.email, boundary,
		); err != nil {
			t.Fatalf("seed audit_log %s: %v", p.email, err)
		}
	}

	cfg := defaultConfig()
	// Free: 90 days → boundary (200d old) should be deleted.
	// Enterprise: 365 days override → boundary (200d old) should be retained.
	cfg.AuditLogDays = 90

	runner := retention.NewRunner(db.Store, cfg, slog.Default())
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Free org's entry should be deleted (200d > 90d retention).
	var freeRemaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM audit_log WHERE org_id = $1", orgFree.ID,
	).Scan(&freeRemaining); err != nil {
		t.Fatalf("count free: %v", err)
	}
	if freeRemaining != 0 {
		t.Errorf("free org remaining = %d, want 0 (200d old, 90d retention)", freeRemaining)
	}

	// Enterprise org's entry should survive (200d < 365d retention).
	var entRemaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM audit_log WHERE org_id = $1", orgEnt.ID,
	).Scan(&entRemaining); err != nil {
		t.Fatalf("count ent: %v", err)
	}
	if entRemaining != 1 {
		t.Errorf("enterprise org remaining = %d, want 1 (200d old, 365d retention)", entRemaining)
	}
}

func TestRunner_AuditLogBatchSize(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	old := now.Add(-200 * 24 * time.Hour)
	org, _ := db.CreateOrg(ctx, "AuditBatchOrg")

	// Insert 15 old audit_log entries.
	for i := 0; i < 15; i++ {
		if _, err := db.Pool().Exec(ctx,
			`INSERT INTO audit_log (org_id, actor_email, action, entity_type, entity_id, success, created_at)
			 VALUES ($1, 'batch@example.com', 'create', 'alert_rule', $2, true, $3)`,
			org.ID, uuid.New().String(), old.Add(time.Duration(i)*time.Second),
		); err != nil {
			t.Fatalf("seed audit_log %d: %v", i, err)
		}
	}

	cfg := defaultConfig()
	cfg.AuditLogDays = 90
	cfg.BatchSize = 5 // should loop: 5 + 5 + 5

	runner := retention.NewRunner(db.Store, cfg, slog.Default())
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// All 15 should be deleted (runner loops batches of 5).
	var remaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM audit_log WHERE org_id = $1", org.ID,
	).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 0 {
		t.Errorf("remaining = %d, want 0 (all 15 should be deleted via batch loop)", remaining)
	}
}

func TestRunner_UnlimitedRetentionSkipsOrg(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	old := now.Add(-500 * 24 * time.Hour) // 500 days old

	org, _ := db.CreateOrg(ctx, "UnlimitedRetOrg")
	if err := db.UpdateOrgTier(ctx, org.ID, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	// Set retention override to -1 (unlimited) for alert events.
	if _, err := db.Pool().Exec(ctx,
		`UPDATE organizations SET tier_overrides = '{"retention_alert_events_days": -1}' WHERE id = $1`, org.ID,
	); err != nil {
		t.Fatalf("set tier overrides: %v", err)
	}

	// Create an alert rule and a very old alert event.
	var ruleID uuid.UUID
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO alert_rules (org_id, name, logic, conditions, status)
		 VALUES ($1, 'rule', 'and', '[]'::jsonb, 'active') RETURNING id`, org.ID,
	).Scan(&ruleID); err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash, first_fired_at)
		 VALUES ($1, $2, 'CVE-2024-UNLIM', 'hash', $3)`, org.ID, ruleID, old,
	); err != nil {
		t.Fatalf("seed alert event: %v", err)
	}

	cfg := defaultConfig()
	cfg.AlertEventsDays = 90 // default would delete 500-day-old data

	runner := retention.NewRunner(db.Store, cfg, slog.Default())
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Org with unlimited retention (-1 override) should keep its old data.
	var remaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM alert_events WHERE org_id = $1", org.ID,
	).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 1 {
		t.Errorf("remaining = %d, want 1 (unlimited retention should skip org)", remaining)
	}
}

func TestRunner_AICleanup(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	old := now.Add(-100 * 24 * time.Hour)
	org, _ := db.CreateOrg(ctx, "AICleanupOrg")

	// Seed ai_request_log, ai_cache, ai_usage_counters.
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO ai_request_log (org_id, user_id, feature, input_hash, prompt_version, model, cache_hit, latency_ms, status, created_at)
		 VALUES ($1, $1, 'nl_search', 'old', 'v1', 'mock', false, 100, 'success', $2)`,
		org.ID, old,
	); err != nil {
		t.Fatalf("seed ai log: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO ai_cache (org_id, feature, prompt_version, input_hash, response, expires_at)
		 VALUES ($1, 'nl_search', 'v1', 'expired', '"x"', $2)`,
		org.ID, now.Add(-1*time.Hour),
	); err != nil {
		t.Fatalf("seed ai cache: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO ai_usage_counters (org_id, feature, date, count) VALUES ($1, 'nl_search', $2, 5)`,
		org.ID, old.Format("2006-01-02"),
	); err != nil {
		t.Fatalf("seed ai usage: %v", err)
	}

	runner := retention.NewRunner(db.Store, defaultConfig(), slog.Default())
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, table := range []string{"ai_request_log", "ai_cache", "ai_usage_counters"} {
		var remaining int
		if err := db.DB().QueryRowContext(ctx,
			"SELECT COUNT(*) FROM "+table+" WHERE org_id = $1", org.ID, //nolint:gosec // table name is hardcoded
		).Scan(&remaining); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if remaining != 0 {
			t.Errorf("%s remaining = %d, want 0", table, remaining)
		}
	}
}

func TestRunner_BatchLoop(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	old := now.Add(-100 * 24 * time.Hour)

	// Insert 25 old rows.
	for i := 0; i < 25; i++ {
		if _, err := db.Pool().Exec(ctx,
			`INSERT INTO cve_raw_payloads (cve_id, source_name, payload, ingested_at)
			 VALUES ($1, 'nvd', '{}', $2)`,
			"CVE-2024-BATCH", old.Add(time.Duration(i)*time.Second),
		); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	cfg := defaultConfig()
	cfg.BatchSize = 10 // should loop: 10 + 10 + 5

	runner := retention.NewRunner(db.Store, cfg, slog.Default())
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// All 25 should be deleted (runner loops until 0 returned).
	var remaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM cve_raw_payloads WHERE cve_id = 'CVE-2024-BATCH'",
	).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 0 {
		t.Errorf("remaining = %d, want 0 (all 25 should be deleted via batch loop)", remaining)
	}
}

func TestRunner_ErrorIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	old := now.Add(-100 * 24 * time.Hour)

	// Seed data in cve_raw_payloads and feed_fetch_log.
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO cve_raw_payloads (cve_id, source_name, payload, ingested_at)
		 VALUES ('CVE-2024-ERR', 'nvd', '{}', $1)`, old,
	); err != nil {
		t.Fatalf("seed raw: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO feed_fetch_log (feed_name, started_at, status) VALUES ('nvd', $1, 'success')`, old,
	); err != nil {
		t.Fatalf("seed fetch log: %v", err)
	}

	// Break cve_raw_payloads so its cleanup query fails (rename the column
	// referenced in the DELETE). feed_fetch_log should still be cleaned.
	if _, err := db.Pool().Exec(ctx,
		`ALTER TABLE cve_raw_payloads RENAME COLUMN ingested_at TO ingested_at_broken`,
	); err != nil {
		t.Fatalf("break table: %v", err)
	}

	cfg := defaultConfig()
	runner := retention.NewRunner(db.Store, cfg, slog.Default())
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Run returned error: %v (should be nil even with per-table errors)", err)
	}

	// feed_fetch_log should be cleaned despite the cve_raw_payloads error.
	var feedRemaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM feed_fetch_log WHERE feed_name = 'nvd'",
	).Scan(&feedRemaining); err != nil {
		t.Fatalf("count feed: %v", err)
	}
	if feedRemaining != 0 {
		t.Errorf("feed_fetch_log remaining = %d, want 0 (error in earlier table should not block)", feedRemaining)
	}
}
