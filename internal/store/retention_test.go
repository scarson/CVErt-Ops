// ABOUTME: Integration tests for bounded-batch retention cleanup queries.
// ABOUTME: Verifies each table's cleanup respects cutoff, batch size, and filters.
package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestCleanupCveRawPayloads(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	oldTime := now.Add(-100 * 24 * time.Hour)
	recentTime := now.Add(-10 * 24 * time.Hour)

	// Insert old and recent rows.
	for _, ts := range []time.Time{oldTime, oldTime, recentTime} {
		if _, err := db.Pool().Exec(ctx,
			`INSERT INTO cve_raw_payloads (cve_id, source_name, payload, ingested_at)
			 VALUES ($1, $2, $3, $4)`,
			"CVE-2024-0001", "nvd", `{}`, ts,
		); err != nil {
			t.Fatalf("seed cve_raw_payloads: %v", err)
		}
	}

	cutoff := now.Add(-50 * 24 * time.Hour)
	n, err := db.CleanupCveRawPayloads(ctx, cutoff, 100)
	if err != nil {
		t.Fatalf("CleanupCveRawPayloads: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2", n)
	}

	// Recent row should survive.
	var remaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM cve_raw_payloads",
	).Scan(&remaining); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining != 1 {
		t.Errorf("remaining = %d, want 1", remaining)
	}
}

func TestCleanupFeedFetchLog(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	oldTime := now.Add(-100 * 24 * time.Hour)
	recentTime := now.Add(-10 * 24 * time.Hour)

	for _, ts := range []time.Time{oldTime, recentTime} {
		if _, err := db.Pool().Exec(ctx,
			`INSERT INTO feed_fetch_log (feed_name, started_at, status, items_fetched, items_upserted)
			 VALUES ($1, $2, $3, $4, $5)`,
			"nvd", ts, "success", 10, 5,
		); err != nil {
			t.Fatalf("seed feed_fetch_log: %v", err)
		}
	}

	cutoff := now.Add(-50 * 24 * time.Hour)
	n, err := db.CleanupFeedFetchLog(ctx, cutoff, 100)
	if err != nil {
		t.Fatalf("CleanupFeedFetchLog: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted = %d, want 1", n)
	}
}

func TestCleanupAlertEvents_OrgFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	oldTime := now.Add(-400 * 24 * time.Hour)

	// Create two orgs with alert rules.
	org1, _ := db.CreateOrg(ctx, "RetentionOrg1")
	org2, _ := db.CreateOrg(ctx, "RetentionOrg2")

	// Create alert rules (FK requirement).
	var ruleID1, ruleID2 uuid.UUID
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO alert_rules (org_id, name, logic, conditions, status)
		 VALUES ($1, 'rule1', 'and', '[]'::jsonb, 'active') RETURNING id`,
		org1.ID,
	).Scan(&ruleID1); err != nil {
		t.Fatalf("create rule1: %v", err)
	}
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO alert_rules (org_id, name, logic, conditions, status)
		 VALUES ($1, 'rule2', 'and', '[]'::jsonb, 'active') RETURNING id`,
		org2.ID,
	).Scan(&ruleID2); err != nil {
		t.Fatalf("create rule2: %v", err)
	}

	// Insert old events for both orgs.
	for _, p := range []struct {
		orgID  uuid.UUID
		ruleID uuid.UUID
		cveID  string
	}{
		{org1.ID, ruleID1, "CVE-2024-0001"},
		{org2.ID, ruleID2, "CVE-2024-0002"},
	} {
		if _, err := db.Pool().Exec(ctx,
			`INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash, first_fired_at)
			 VALUES ($1, $2, $3, $4, $5)`,
			p.orgID, p.ruleID, p.cveID, "hash1", oldTime,
		); err != nil {
			t.Fatalf("seed alert_events: %v", err)
		}
	}

	// Cleanup only org1.
	cutoff := now.Add(-365 * 24 * time.Hour)
	n, err := db.CleanupAlertEvents(ctx, []uuid.UUID{org1.ID}, cutoff, 100)
	if err != nil {
		t.Fatalf("CleanupAlertEvents: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted = %d, want 1 (only org1)", n)
	}

	// org2's event should survive.
	var remaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM alert_events WHERE org_id = $1", org2.ID,
	).Scan(&remaining); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining != 1 {
		t.Errorf("org2 remaining = %d, want 1", remaining)
	}
}

func TestCleanupNotificationDeliveries_OrgFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	oldTime := now.Add(-100 * 24 * time.Hour)

	org1, _ := db.CreateOrg(ctx, "NotifRetOrg1")
	org2, _ := db.CreateOrg(ctx, "NotifRetOrg2")

	// Create alert rules and channels (FK requirements).
	var ruleID1, ruleID2 uuid.UUID
	var chanID1, chanID2 uuid.UUID
	for _, p := range []struct {
		orgID  uuid.UUID
		ruleID *uuid.UUID
		chanID *uuid.UUID
	}{
		{org1.ID, &ruleID1, &chanID1},
		{org2.ID, &ruleID2, &chanID2},
	} {
		if err := db.Pool().QueryRow(ctx,
			`INSERT INTO alert_rules (org_id, name, logic, conditions, status)
			 VALUES ($1, 'rule', 'and', '[]'::jsonb, 'active') RETURNING id`,
			p.orgID,
		).Scan(p.ruleID); err != nil {
			t.Fatalf("create rule: %v", err)
		}
		if err := db.Pool().QueryRow(ctx,
			`INSERT INTO notification_channels (org_id, name, type, config)
			 VALUES ($1, 'chan', 'webhook', '{"url":"http://example.com"}') RETURNING id`,
			p.orgID,
		).Scan(p.chanID); err != nil {
			t.Fatalf("create channel: %v", err)
		}
	}

	// Insert old deliveries for both orgs.
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO notification_deliveries (org_id, rule_id, channel_id, payload, created_at, kind)
		 VALUES ($1, $2, $3, '[]', $4, 'alert')`,
		org1.ID, ruleID1, chanID1, oldTime,
	); err != nil {
		t.Fatalf("seed delivery org1: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO notification_deliveries (org_id, rule_id, channel_id, payload, created_at, kind)
		 VALUES ($1, $2, $3, '[]', $4, 'alert')`,
		org2.ID, ruleID2, chanID2, oldTime,
	); err != nil {
		t.Fatalf("seed delivery org2: %v", err)
	}

	// Cleanup only org1.
	cutoff := now.Add(-50 * 24 * time.Hour)
	n, err := db.CleanupNotificationDeliveries(ctx, []uuid.UUID{org1.ID}, cutoff, 100)
	if err != nil {
		t.Fatalf("CleanupNotificationDeliveries: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted = %d, want 1 (only org1)", n)
	}

	// org2's delivery should survive.
	var remaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM notification_deliveries WHERE org_id = $1", org2.ID,
	).Scan(&remaining); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining != 1 {
		t.Errorf("org2 remaining = %d, want 1", remaining)
	}
}

func TestCleanupJobQueue_StatusFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	oldTime := now.Add(-48 * time.Hour)

	// Insert jobs with various statuses and old finished_at.
	for _, status := range []string{"succeeded", "dead", "pending", "running"} {
		finishedAt := interface{}(nil)
		if status == "succeeded" || status == "dead" {
			finishedAt = oldTime
		}
		if _, err := db.Pool().Exec(ctx,
			`INSERT INTO job_queue (queue, priority, payload, status, finished_at)
			 VALUES ($1, $2, $3, $4, $5)`,
			"test_queue", 0, `{}`, status, finishedAt,
		); err != nil {
			t.Fatalf("seed job %s: %v", status, err)
		}
	}

	cutoff := now.Add(-24 * time.Hour)
	n, err := db.CleanupJobQueue(ctx, cutoff, 100)
	if err != nil {
		t.Fatalf("CleanupJobQueue: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2 (succeeded + dead)", n)
	}

	// pending and running should survive.
	var remaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM job_queue WHERE queue = 'test_queue'",
	).Scan(&remaining); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining != 2 {
		t.Errorf("remaining = %d, want 2 (pending + running)", remaining)
	}
}

func TestCleanupRefreshTokens_GraceWindow(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()

	// Create a user (FK requirement).
	var userID uuid.UUID
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO users (email, display_name, password_hash)
		 VALUES ($1, $2, $3) RETURNING id`,
		"retention-test@example.com", "RetTest", "not-real-hash",
	).Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Insert tokens: expired 30s ago (within grace), expired 90s ago (past grace).
	jti30s := uuid.New()
	jti90s := uuid.New()
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO refresh_tokens (jti, user_id, token_version, expires_at)
		 VALUES ($1, $2, 1, $3)`,
		jti30s, userID, now.Add(-30*time.Second),
	); err != nil {
		t.Fatalf("seed token 30s: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO refresh_tokens (jti, user_id, token_version, expires_at)
		 VALUES ($1, $2, 1, $3)`,
		jti90s, userID, now.Add(-90*time.Second),
	); err != nil {
		t.Fatalf("seed token 90s: %v", err)
	}

	// Grace window = 60s, so cutoff = now - 60s.
	cutoff := now.Add(-60 * time.Second)
	n, err := db.CleanupRefreshTokens(ctx, cutoff, 100)
	if err != nil {
		t.Fatalf("CleanupRefreshTokens: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted = %d, want 1 (only token expired 90s ago)", n)
	}

	// Token expired 30s ago should survive (within grace).
	var remaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1", userID,
	).Scan(&remaining); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining != 1 {
		t.Errorf("remaining = %d, want 1", remaining)
	}
}

func TestCleanupAIRequestLog(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	org, _ := db.CreateOrg(ctx, "AILogRetOrg")

	// Insert old and recent request log entries.
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO ai_request_log (org_id, user_id, feature, input_hash, prompt_version, model, cache_hit, latency_ms, status, created_at)
		 VALUES ($1, $1, 'nl_search', 'old', 'v1', 'mock', false, 100, 'success', $2)`,
		org.ID, now.Add(-100*24*time.Hour),
	); err != nil {
		t.Fatalf("seed old log: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO ai_request_log (org_id, user_id, feature, input_hash, prompt_version, model, cache_hit, latency_ms, status, created_at)
		 VALUES ($1, $1, 'nl_search', 'recent', 'v1', 'mock', false, 100, 'success', $2)`,
		org.ID, now.Add(-10*24*time.Hour),
	); err != nil {
		t.Fatalf("seed recent log: %v", err)
	}

	cutoff := now.Add(-90 * 24 * time.Hour)
	n, err := db.CleanupAIRequestLogBatch(ctx, cutoff, 100)
	if err != nil {
		t.Fatalf("CleanupAIRequestLogBatch: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted = %d, want 1", n)
	}
}

func TestCleanupAICache_TTL(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	org, _ := db.CreateOrg(ctx, "AICacheRetOrg")

	// Insert expired and non-expired cache entries.
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO ai_cache (org_id, feature, prompt_version, input_hash, response, expires_at)
		 VALUES ($1, 'nl_search', 'v1', 'expired', '"cached"', $2)`,
		org.ID, now.Add(-1*time.Hour),
	); err != nil {
		t.Fatalf("seed expired cache: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO ai_cache (org_id, feature, prompt_version, input_hash, response, expires_at)
		 VALUES ($1, 'nl_search', 'v1', 'valid', '"cached"', $2)`,
		org.ID, now.Add(1*time.Hour),
	); err != nil {
		t.Fatalf("seed valid cache: %v", err)
	}

	n, err := db.CleanupAICacheBatch(ctx, now, 100)
	if err != nil {
		t.Fatalf("CleanupAICacheBatch: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted = %d, want 1 (only expired)", n)
	}
}

func TestCleanupAIUsageCounters_DailyOnly(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	org, _ := db.CreateOrg(ctx, "AIUsageRetOrg")

	oldDate := now.AddDate(0, 0, -100)
	recentDate := now.AddDate(0, 0, -10)

	// Insert old and recent daily rows.
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO ai_usage_counters (org_id, feature, date, count)
		 VALUES ($1, 'nl_search', $2, 5)`,
		org.ID, oldDate.Format("2006-01-02"),
	); err != nil {
		t.Fatalf("seed old usage: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO ai_usage_counters (org_id, feature, date, count)
		 VALUES ($1, 'nl_search', $2, 3)`,
		org.ID, recentDate.Format("2006-01-02"),
	); err != nil {
		t.Fatalf("seed recent usage: %v", err)
	}

	cutoff := now.AddDate(0, 0, -90)
	n, err := db.CleanupAIUsageCounters(ctx, cutoff, 100)
	if err != nil {
		t.Fatalf("CleanupAIUsageCounters: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted = %d, want 1 (only old daily row)", n)
	}

	// Recent row should survive.
	var remaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM ai_usage_counters WHERE org_id = $1", org.ID,
	).Scan(&remaining); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining != 1 {
		t.Errorf("remaining = %d, want 1", remaining)
	}
}

func TestCleanup_BatchSizeLimit(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	oldTime := now.Add(-100 * 24 * time.Hour)

	// Insert 20 old rows.
	for i := 0; i < 20; i++ {
		if _, err := db.Pool().Exec(ctx,
			`INSERT INTO cve_raw_payloads (cve_id, source_name, payload, ingested_at)
			 VALUES ($1, $2, $3, $4)`,
			"CVE-2024-BATCH", "nvd", `{}`, oldTime.Add(time.Duration(i)*time.Second),
		); err != nil {
			t.Fatalf("seed batch row %d: %v", i, err)
		}
	}

	cutoff := now.Add(-50 * 24 * time.Hour)

	// First call: batch_size=5, should delete exactly 5.
	n, err := db.CleanupCveRawPayloads(ctx, cutoff, 5)
	if err != nil {
		t.Fatalf("batch 1: %v", err)
	}
	if n != 5 {
		t.Errorf("batch 1 deleted = %d, want 5", n)
	}

	// Second call: should delete another 5.
	n, err = db.CleanupCveRawPayloads(ctx, cutoff, 5)
	if err != nil {
		t.Fatalf("batch 2: %v", err)
	}
	if n != 5 {
		t.Errorf("batch 2 deleted = %d, want 5", n)
	}

	// Verify 10 remain.
	var remaining int
	if err := db.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM cve_raw_payloads WHERE cve_id = 'CVE-2024-BATCH'",
	).Scan(&remaining); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining != 10 {
		t.Errorf("remaining = %d, want 10", remaining)
	}
}

func TestHasPendingOrRunningJob(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	lockKey := "cleanup:retention"

	// No job — should return false.
	has, err := db.HasPendingOrRunningJob(ctx, lockKey)
	if err != nil {
		t.Fatalf("HasPendingOrRunningJob: %v", err)
	}
	if has {
		t.Error("expected false with no jobs")
	}

	// Insert a pending job with the lock key.
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO job_queue (queue, priority, payload, lock_key, status)
		 VALUES ('retention_cleanup', 0, '{}', $1, 'pending')`,
		lockKey,
	); err != nil {
		t.Fatalf("seed pending job: %v", err)
	}

	has, err = db.HasPendingOrRunningJob(ctx, lockKey)
	if err != nil {
		t.Fatalf("HasPendingOrRunningJob: %v", err)
	}
	if !has {
		t.Error("expected true with pending job")
	}
}
