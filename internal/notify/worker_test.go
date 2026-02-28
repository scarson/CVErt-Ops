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

	w := notify.NewWorker(s.Store, plainHTTPClient(), notify.WorkerConfig{
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

	w := notify.NewWorker(s.Store, plainHTTPClient(), notify.WorkerConfig{
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

	w := notify.NewWorker(s.Store, plainHTTPClient(), notify.WorkerConfig{
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
