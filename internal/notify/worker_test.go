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
