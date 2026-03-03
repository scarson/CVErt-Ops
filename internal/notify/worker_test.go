// ABOUTME: Integration tests for the delivery worker: claim, retry, exhaustion, per-org semaphore.
// ABOUTME: Uses testutil.NewTestDB; each test runs against a real Postgres testcontainer.
package notify_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/notify"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// plainHTTPClient returns a plain http.Client suitable for tests.
// safeurl blocks 127.0.0.1 used by httptest servers.
func plainHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// newTestWorker creates a Worker with default test SmtpConfig and empty externalURL.
func newTestWorker(s *testutil.TestDB, client *http.Client, cfg notify.WorkerConfig) *notify.Worker {
	return notify.NewWorker(s.Store, client, cfg, notify.SmtpConfig{}, "")
}

func TestWorker_ClaimsAndDeliversPendingRow(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Set up a test HTTP server that records calls and returns 200.
	var called atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	org, _ := s.CreateOrg(ctx, "WorkerDeliverOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "WorkerDeliverRule")

	// Create a channel pointing at the test server.
	cfg, _ := json.Marshal(map[string]string{"url": srv.URL})
	chanRow, _, err := s.CreateNotificationChannel(ctx, org.ID, "WorkerDeliverChan", "webhook", json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	chanID := chanRow.ID

	// Bind channel to rule and create a pending delivery with debounce=0 (immediately claimable).
	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}
	payload, _ := json.Marshal(map[string]string{"cve_id": "CVE-2025-9001"})
	if err := s.UpsertDelivery(ctx, org.ID, rule.ID, chanID, payload, 0); err != nil {
		t.Fatalf("UpsertDelivery: %v", err)
	}

	w := newTestWorker(s, plainHTTPClient(), notify.WorkerConfig{
		ClaimBatchSize:      10,
		MaxAttempts:         3,
		BackoffBaseSeconds:  1,
		MaxConcurrentPerOrg: 4,
	})
	w.RunOnce(ctx)

	// The test server must have received exactly one call.
	if n := called.Load(); n != 1 {
		t.Errorf("webhook calls = %d, want 1", n)
	}

	// The delivery row must be marked succeeded.
	var status string
	var attemptCount int32
	if err := s.DB().QueryRowContext(ctx,
		"SELECT status, attempt_count FROM notification_deliveries WHERE channel_id=$1",
		chanID).Scan(&status, &attemptCount); err != nil {
		t.Fatalf("scan delivery row: %v", err)
	}
	if status != "succeeded" {
		t.Errorf("delivery status = %q, want %q", status, "succeeded")
	}
}

func TestWorker_RetryOnNon2xx(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Server always returns 500.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	org, _ := s.CreateOrg(ctx, "WorkerRetryOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "WorkerRetryRule")

	cfg, _ := json.Marshal(map[string]string{"url": srv.URL})
	chanRow, _, err := s.CreateNotificationChannel(ctx, org.ID, "WorkerRetryChan", "webhook", json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	chanID := chanRow.ID

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}
	payload, _ := json.Marshal(map[string]string{"cve_id": "CVE-2025-9002"})
	if err := s.UpsertDelivery(ctx, org.ID, rule.ID, chanID, payload, 0); err != nil {
		t.Fatalf("UpsertDelivery: %v", err)
	}

	w := newTestWorker(s, plainHTTPClient(), notify.WorkerConfig{
		ClaimBatchSize:      10,
		MaxAttempts:         3,
		BackoffBaseSeconds:  1,
		MaxConcurrentPerOrg: 4,
	})
	w.RunOnce(ctx)

	// After one failed attempt the row should be requeued (pending) with attempt_count=1.
	var status string
	var attemptCount int32
	if err := s.DB().QueryRowContext(ctx,
		"SELECT status, attempt_count FROM notification_deliveries WHERE channel_id=$1",
		chanID).Scan(&status, &attemptCount); err != nil {
		t.Fatalf("scan delivery row: %v", err)
	}
	if status != "pending" {
		t.Errorf("delivery status = %q, want %q", status, "pending")
	}
	if attemptCount != 1 {
		t.Errorf("attempt_count = %d, want 1", attemptCount)
	}
}

func TestWorker_ExhaustsAfterMaxAttempts(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Server always returns 502.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	org, _ := s.CreateOrg(ctx, "WorkerExhaustOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "WorkerExhaustRule")

	cfg, _ := json.Marshal(map[string]string{"url": srv.URL})
	chanRow, _, err := s.CreateNotificationChannel(ctx, org.ID, "WorkerExhaustChan", "webhook", json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	chanID := chanRow.ID

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}
	payload, _ := json.Marshal(map[string]string{"cve_id": "CVE-2025-9003"})
	if err := s.UpsertDelivery(ctx, org.ID, rule.ID, chanID, payload, 0); err != nil {
		t.Fatalf("UpsertDelivery: %v", err)
	}

	// Pre-seed attempt_count=3 so the next failure hits the MaxAttempts=4 limit.
	if _, err := s.DB().ExecContext(ctx,
		"UPDATE notification_deliveries SET attempt_count=3 WHERE channel_id=$1",
		chanID); err != nil {
		t.Fatalf("pre-seed attempt_count: %v", err)
	}

	w := newTestWorker(s, plainHTTPClient(), notify.WorkerConfig{
		ClaimBatchSize:      10,
		MaxAttempts:         4,
		BackoffBaseSeconds:  1,
		MaxConcurrentPerOrg: 4,
	})
	w.RunOnce(ctx)

	// With attempt_count starting at 3, nextAttempt=4 >= MaxAttempts=4, so must be exhausted.
	var status string
	if err := s.DB().QueryRowContext(ctx,
		"SELECT status FROM notification_deliveries WHERE channel_id=$1",
		chanID).Scan(&status); err != nil {
		t.Fatalf("scan delivery row: %v", err)
	}
	if status != "failed" {
		t.Errorf("delivery status = %q, want %q", status, "failed")
	}
}

func TestWorker_ExhaustsIfChannelDeleted(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WorkerDeletedChanOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "WorkerDeletedChanRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "WorkerDeletedChanCh")

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}
	payload, _ := json.Marshal(map[string]string{"cve_id": "CVE-2025-9004"})
	if err := s.UpsertDelivery(ctx, org.ID, rule.ID, chanID, payload, 0); err != nil {
		t.Fatalf("UpsertDelivery: %v", err)
	}
	// Soft-delete the channel so GetNotificationChannelForDelivery returns nil.
	if err := s.SoftDeleteNotificationChannel(ctx, org.ID, chanID); err != nil {
		t.Fatalf("SoftDeleteNotificationChannel: %v", err)
	}

	w := newTestWorker(s, plainHTTPClient(), notify.WorkerConfig{
		ClaimBatchSize:      10,
		MaxAttempts:         4,
		BackoffBaseSeconds:  1,
		MaxConcurrentPerOrg: 5,
	})
	w.RunOnce(ctx)

	var status string
	if err := s.DB().QueryRowContext(ctx,
		"SELECT status FROM notification_deliveries WHERE channel_id=$1",
		chanID).Scan(&status); err != nil {
		t.Fatalf("scan delivery row: %v", err)
	}
	if status != "failed" {
		t.Errorf("deleted-channel delivery status = %q, want %q", status, "failed")
	}
}

func TestWorker_ExhaustsUnknownChannelType(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WorkerUnknownTypeOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "WorkerUnknownTypeRule")

	// Create a valid channel, then change the type to an unsupported value via raw SQL
	// (the DB CHECK constraint rejects unknown types at insert time).
	cfg, _ := json.Marshal(map[string]string{"url": "https://example.com"})
	chanRow, _, err := s.CreateNotificationChannel(ctx, org.ID, "WorkerUnknownChan", "webhook", json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	chanID := chanRow.ID
	if _, err := s.DB().ExecContext(ctx,
		"ALTER TABLE notification_channels DROP CONSTRAINT IF EXISTS notification_channels_type_check"); err != nil {
		t.Fatalf("drop type check: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx,
		"UPDATE notification_channels SET type = 'sms' WHERE id = $1", chanID); err != nil {
		t.Fatalf("update type to sms: %v", err)
	}

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}
	payload, _ := json.Marshal(map[string]string{"cve_id": "CVE-2025-9005"})
	if err := s.UpsertDelivery(ctx, org.ID, rule.ID, chanID, payload, 0); err != nil {
		t.Fatalf("UpsertDelivery: %v", err)
	}

	w := newTestWorker(s, plainHTTPClient(), notify.WorkerConfig{
		ClaimBatchSize:      10,
		MaxAttempts:         4,
		BackoffBaseSeconds:  1,
		MaxConcurrentPerOrg: 4,
	})
	w.RunOnce(ctx)

	// Unknown channel type should be exhausted immediately.
	var status string
	var lastError *string
	if err := s.DB().QueryRowContext(ctx,
		"SELECT status, last_error FROM notification_deliveries WHERE channel_id=$1",
		chanID).Scan(&status, &lastError); err != nil {
		t.Fatalf("scan delivery row: %v", err)
	}
	if status != "failed" {
		t.Errorf("unknown-type delivery status = %q, want %q", status, "failed")
	}
	if lastError == nil || *lastError == "" {
		t.Error("expected last_error to contain unsupported channel type message")
	}
}

func TestWorker_EmailChannel_InvalidSMTP(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WorkerEmailOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "WorkerEmailRule")

	// Create an email channel with recipients.
	emailCfg, _ := json.Marshal(map[string]any{
		"recipients": []string{"test@example.com"},
	})
	chanRow, _, err := s.CreateNotificationChannel(ctx, org.ID, "WorkerEmailChan", "email", json.RawMessage(emailCfg))
	if err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	chanID := chanRow.ID

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}

	// UpsertDelivery wraps the payload in jsonb_build_array, so pass a single snapshot object.
	payload, _ := json.Marshal(map[string]any{
		"cve_id":              "CVE-2025-9010",
		"severity":            "HIGH",
		"cvss_v3_score":       8.1,
		"description_primary": "Test vulnerability",
		"exploit_available":   false,
		"in_cisa_kev":         false,
	})
	if err := s.UpsertDelivery(ctx, org.ID, rule.ID, chanID, payload, 0); err != nil {
		t.Fatalf("UpsertDelivery: %v", err)
	}

	// Use an unreachable SMTP server — delivery should retry (not exhaust).
	w := notify.NewWorker(s.Store, plainHTTPClient(), notify.WorkerConfig{
		ClaimBatchSize:      10,
		MaxAttempts:         3,
		BackoffBaseSeconds:  1,
		MaxConcurrentPerOrg: 4,
	}, notify.SmtpConfig{
		Host: "192.0.2.1", // TEST-NET, unreachable
		Port: 25,
		From: "test@example.com",
	}, "https://cvert.example.com")
	w.RunOnce(ctx)

	// Connection failure is transient — should be retried (pending with attempt_count=1).
	var status string
	var attemptCount int32
	if err := s.DB().QueryRowContext(ctx,
		"SELECT status, attempt_count FROM notification_deliveries WHERE channel_id=$1",
		chanID).Scan(&status, &attemptCount); err != nil {
		t.Fatalf("scan delivery row: %v", err)
	}
	if status != "pending" {
		t.Errorf("email delivery status = %q, want %q (retry on SMTP failure)", status, "pending")
	}
	if attemptCount != 1 {
		t.Errorf("attempt_count = %d, want 1", attemptCount)
	}
}

// TestWorker_RetentionSchedule verifies that scheduleRetention enqueues a
// retention_cleanup job when none is pending, and skips when one already exists.
func TestWorker_RetentionSchedule(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// With RetentionEnabled=false, no job should be enqueued.
	wDisabled := newTestWorker(s, plainHTTPClient(), notify.WorkerConfig{
		ClaimBatchSize:      10,
		MaxAttempts:         3,
		BackoffBaseSeconds:  1,
		MaxConcurrentPerOrg: 4,
		RetentionEnabled:    false,
	})
	wDisabled.RunRetentionScheduleOnce(ctx)

	var count int
	if err := s.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM job_queue WHERE queue = 'retention_cleanup'",
	).Scan(&count); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if count != 0 {
		t.Errorf("RetentionEnabled=false: job count = %d, want 0", count)
	}

	// With RetentionEnabled=true, a job should be enqueued.
	wEnabled := newTestWorker(s, plainHTTPClient(), notify.WorkerConfig{
		ClaimBatchSize:      10,
		MaxAttempts:         3,
		BackoffBaseSeconds:  1,
		MaxConcurrentPerOrg: 4,
		RetentionEnabled:    true,
	})
	wEnabled.RunRetentionScheduleOnce(ctx)

	if err := s.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM job_queue WHERE queue = 'retention_cleanup'",
	).Scan(&count); err != nil {
		t.Fatalf("count jobs after schedule: %v", err)
	}
	if count != 1 {
		t.Errorf("first schedule: job count = %d, want 1", count)
	}

	// Second call should NOT enqueue a duplicate (pending job exists).
	wEnabled.RunRetentionScheduleOnce(ctx)

	if err := s.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM job_queue WHERE queue = 'retention_cleanup'",
	).Scan(&count); err != nil {
		t.Fatalf("count jobs after second schedule: %v", err)
	}
	if count != 1 {
		t.Errorf("second schedule: job count = %d, want 1 (no duplicate)", count)
	}
}

func TestWorker_BackoffSeconds_ReflectedInSendAfter(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Server always returns 500 → triggers retry with backoff.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	org, _ := s.CreateOrg(ctx, "WorkerBackoffOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "WorkerBackoffRule")

	cfg, _ := json.Marshal(map[string]string{"url": srv.URL})
	chanRow, _, err := s.CreateNotificationChannel(ctx, org.ID, "WorkerBackoffChan", "webhook", json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	chanID := chanRow.ID

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}
	payload, _ := json.Marshal(map[string]string{"cve_id": "CVE-2025-BACKOFF"})
	if err := s.UpsertDelivery(ctx, org.ID, rule.ID, chanID, payload, 0); err != nil {
		t.Fatalf("UpsertDelivery: %v", err)
	}

	beforeRetry := time.Now()
	w := newTestWorker(s, plainHTTPClient(), notify.WorkerConfig{
		ClaimBatchSize:      10,
		MaxAttempts:         5,
		BackoffBaseSeconds:  10,
		MaxConcurrentPerOrg: 4,
	})
	w.RunOnce(ctx)

	// After first failure (attempt=1), backoff = 10 * 2^0 * [0.5,1.5) = [5,15) seconds.
	var sendAfter time.Time
	if err := s.DB().QueryRowContext(ctx,
		"SELECT send_after FROM notification_deliveries WHERE channel_id=$1",
		chanID).Scan(&sendAfter); err != nil {
		t.Fatalf("scan send_after: %v", err)
	}

	minExpected := beforeRetry.Add(5 * time.Second)
	maxExpected := beforeRetry.Add(16 * time.Second) // 15s + 1s tolerance
	if sendAfter.Before(minExpected) {
		t.Errorf("send_after %v is before minimum expected %v", sendAfter, minExpected)
	}
	if sendAfter.After(maxExpected) {
		t.Errorf("send_after %v is after maximum expected %v", sendAfter, maxExpected)
	}
}

func TestWorker_StuckReset(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WorkerStuckOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "WorkerStuckRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "WorkerStuckChan")

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}
	payload, _ := json.Marshal(map[string]string{"cve_id": "CVE-2025-STUCK"})
	if err := s.UpsertDelivery(ctx, org.ID, rule.ID, chanID, payload, 0); err != nil {
		t.Fatalf("UpsertDelivery: %v", err)
	}

	// Manually set the delivery to "processing" with an old updated_at.
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE notification_deliveries SET status='processing', updated_at=NOW() - INTERVAL '10 minutes' WHERE channel_id=$1`,
		chanID); err != nil {
		t.Fatalf("set stuck state: %v", err)
	}

	w := newTestWorker(s, plainHTTPClient(), notify.WorkerConfig{
		ClaimBatchSize:      10,
		MaxAttempts:         3,
		BackoffBaseSeconds:  1,
		MaxConcurrentPerOrg: 4,
		StuckThreshold:      2 * time.Minute,
	})
	w.RunStuckResetOnce(ctx)

	// The stuck delivery should be reset to "pending".
	var status string
	if err := s.DB().QueryRowContext(ctx,
		"SELECT status FROM notification_deliveries WHERE channel_id=$1",
		chanID).Scan(&status); err != nil {
		t.Fatalf("scan status: %v", err)
	}
	if status != "pending" {
		t.Errorf("stuck delivery status = %q, want %q", status, "pending")
	}
}

func TestWorker_Recovery_OrphanedEvents(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WorkerRecoveryOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "WorkerRecoveryRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "WorkerRecoveryChan")

	// Activate the rule so it's eligible.
	if err := s.SetAlertRuleStatus(ctx, org.ID, rule.ID, "active"); err != nil {
		t.Fatalf("SetAlertRuleStatus: %v", err)
	}
	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}

	// Create an orphaned alert event: fired > 1 minute ago, no delivery exists.
	if _, err := s.DB().ExecContext(ctx, `
		INSERT INTO alert_events (id, org_id, rule_id, cve_id, material_hash, first_fired_at, last_match_state, suppress_delivery)
		VALUES ($1, $2, $3, $4, $5, NOW() - INTERVAL '5 minutes', true, false)`,
		uuid.New(), org.ID, rule.ID, "CVE-2025-ORPHAN", uuid.New()); err != nil {
		t.Fatalf("insert orphaned alert event: %v", err)
	}

	dispatcher := notify.NewDispatcher(s.Store, 0)
	w := newTestWorker(s, plainHTTPClient(), notify.WorkerConfig{
		ClaimBatchSize:      10,
		MaxAttempts:         3,
		BackoffBaseSeconds:  1,
		MaxConcurrentPerOrg: 4,
	})
	w.SetDispatcher(dispatcher)
	w.RunRecoveryOnce(ctx)

	// Recovery should have called Fanout, creating a delivery row.
	var count int
	if err := s.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM notification_deliveries WHERE rule_id=$1 AND channel_id=$2",
		rule.ID, chanID).Scan(&count); err != nil {
		t.Fatalf("count deliveries: %v", err)
	}
	if count != 1 {
		t.Errorf("recovery delivery rows = %d, want 1", count)
	}
}

func TestWorker_Recovery_NilDispatcher_NoOp(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// With nil dispatcher, runRecovery should return immediately (no panic).
	w := newTestWorker(s, plainHTTPClient(), notify.WorkerConfig{
		ClaimBatchSize:      10,
		MaxAttempts:         3,
		BackoffBaseSeconds:  1,
		MaxConcurrentPerOrg: 4,
	})
	// SetDispatcher NOT called — dispatcher is nil.
	w.RunRecoveryOnce(ctx) // Should not panic.
}

func TestWorker_GracefulShutdown(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)

	w := newTestWorker(s, plainHTTPClient(), notify.WorkerConfig{
		ClaimBatchSize:      10,
		MaxAttempts:         3,
		BackoffBaseSeconds:  1,
		MaxConcurrentPerOrg: 4,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Start(ctx)
		close(done)
	}()

	// Cancel immediately — Start should return promptly.
	cancel()
	select {
	case <-done:
		// Success: Start returned after context cancellation.
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return within 5s after context cancellation")
	}
}

func TestWorker_EmailDigestBranch(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WorkerDigestOrg")

	// Create an email channel.
	emailCfg, _ := json.Marshal(map[string]any{
		"recipients": []string{"digest@example.com"},
	})
	chanRow, _, err := s.CreateNotificationChannel(ctx, org.ID, "WorkerDigestChan", "email", json.RawMessage(emailCfg))
	if err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	chanID := chanRow.ID

	// Create a scheduled report.
	report, err := s.CreateScheduledReport(ctx, org.ID, store.CreateScheduledReportParams{
		Name:          "WorkerDigestReport",
		ScheduledTime: "08:00:00",
		Timezone:      "UTC",
		NextRunAt:     time.Now().Add(24 * time.Hour),
		SendOnEmpty:   true,
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("CreateScheduledReport: %v", err)
	}

	// Insert a digest delivery (simulates what executeDigestReport does).
	payload, _ := json.Marshal([]map[string]any{{
		"cve_id":              "CVE-2025-9020",
		"severity":            "CRITICAL",
		"cvss_v3_score":       9.8,
		"description_primary": "Test digest vulnerability",
		"exploit_available":   true,
		"in_cisa_kev":         false,
	}})
	if err := s.InsertDigestDelivery(ctx, org.ID, report.ID, chanID, payload); err != nil {
		t.Fatalf("InsertDigestDelivery: %v", err)
	}

	// Use unreachable SMTP — delivery should retry (not crash on digest template).
	w := notify.NewWorker(s.Store, plainHTTPClient(), notify.WorkerConfig{
		ClaimBatchSize:      10,
		MaxAttempts:         3,
		BackoffBaseSeconds:  1,
		MaxConcurrentPerOrg: 4,
	}, notify.SmtpConfig{
		Host: "192.0.2.1",
		Port: 25,
		From: "test@example.com",
	}, "https://cvert.example.com")
	w.RunOnce(ctx)

	// Digest delivery should retry on SMTP failure (pending with attempt_count=1).
	var status string
	var attemptCount int32
	if err := s.DB().QueryRowContext(ctx,
		"SELECT status, attempt_count FROM notification_deliveries WHERE channel_id=$1 AND report_id=$2",
		chanID, report.ID).Scan(&status, &attemptCount); err != nil {
		t.Fatalf("scan digest delivery row: %v", err)
	}
	if status != "pending" {
		t.Errorf("digest delivery status = %q, want %q (retry on SMTP failure)", status, "pending")
	}
	if attemptCount != 1 {
		t.Errorf("attempt_count = %d, want 1", attemptCount)
	}
}
