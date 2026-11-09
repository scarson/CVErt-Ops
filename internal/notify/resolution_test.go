// ABOUTME: Integration tests for resolution notifications: reasons, delivery rows, webhook and email sends.
// ABOUTME: CVEs are written through the real merge pipeline; deliveries run against a real Postgres.
package notify_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/notify"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// ingestCVE writes a CVE with the given status and CVSS v3 score through the merge pipeline.
func ingestCVE(t *testing.T, s *testutil.TestDB, ctx context.Context, cveID, status string, score float64, retracted bool) {
	t.Helper()
	if err := merge.Ingest(ctx, s.Store, feed.CanonicalPatch{
		CVEID:       cveID,
		Status:      status,
		CVSSv3Score: &score,
		IsWithdrawn: retracted,
	}, "nvd"); err != nil {
		t.Fatalf("merge.Ingest(%s): %v", cveID, err)
	}
}

// resolutionItem is one CVE in a resolution delivery's payload.
type resolutionItem struct {
	CVEID       string   `json:"cve_id"`
	Reason      string   `json:"reason"`
	CVSSV3Score *float64 `json:"cvss_v3_score"`
}

// pendingResolutionItems returns the payload of the channel's one pending resolution delivery.
func pendingResolutionItems(t *testing.T, s *testutil.TestDB, ctx context.Context, ruleID, chanID uuid.UUID) []resolutionItem {
	t.Helper()
	var raw []byte
	if err := s.DB().QueryRowContext(ctx,
		`SELECT payload FROM notification_deliveries
		 WHERE rule_id = $1 AND channel_id = $2 AND kind = 'resolution' AND status = 'pending'`,
		ruleID, chanID).Scan(&raw); err != nil {
		t.Fatalf("scan resolution delivery: %v", err)
	}
	var items []resolutionItem
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("unmarshal resolution payload: %v", err)
	}
	return items
}

func TestFanoutResolution_ReasonFollowsCVEStatus(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "ResolutionReasonOrg")

	const (
		rejected  = "CVE was rejected by its source"
		withdrawn = "CVE was withdrawn by its source"
		noMatch   = "CVE no longer matches this rule's conditions"
	)
	tests := []struct {
		name       string
		cveID      string
		status     string
		retracted  bool
		wantReason string
	}{
		{name: "rejected by NVD", cveID: "CVE-2025-7001", status: "Rejected", retracted: true, wantReason: rejected},
		{name: "rejected by MITRE", cveID: "CVE-2025-7002", status: "REJECTED", retracted: true, wantReason: rejected},
		{name: "withdrawn advisory", cveID: "CVE-2025-7003", status: "withdrawn", retracted: true, wantReason: withdrawn},
		{name: "still published", cveID: "CVE-2025-7004", status: "Analyzed", wantReason: noMatch},
		{name: "no status", cveID: "CVE-2025-7005", wantReason: noMatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := mustCreateAlertRule(t, s, ctx, org.ID, "ResolutionReason "+tc.name)
			chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "ResolutionReason "+tc.name)
			if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
				t.Fatalf("BindChannelToRule: %v", err)
			}
			ingestCVE(t, s, ctx, tc.cveID, tc.status, 4.3, tc.retracted)

			if err := notify.NewDispatcher(s.Store, 300).FanoutResolution(ctx, org.ID, rule.ID, tc.cveID); err != nil {
				t.Fatalf("FanoutResolution: %v", err)
			}

			items := pendingResolutionItems(t, s, ctx, rule.ID, chanID)
			if len(items) != 1 {
				t.Fatalf("payload items = %d, want 1", len(items))
			}
			if items[0].CVEID != tc.cveID {
				t.Errorf("cve_id = %q, want %q", items[0].CVEID, tc.cveID)
			}
			if items[0].Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", items[0].Reason, tc.wantReason)
			}
		})
	}
}

func TestFanoutResolution_CarriesCurrentScore(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "ResolutionScoreOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "ResolutionScoreRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "ResolutionScoreChan")
	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}
	const cveID = "CVE-2025-7010"
	ingestCVE(t, s, ctx, cveID, "Analyzed", 4.3, false)

	if err := notify.NewDispatcher(s.Store, 300).FanoutResolution(ctx, org.ID, rule.ID, cveID); err != nil {
		t.Fatalf("FanoutResolution: %v", err)
	}

	items := pendingResolutionItems(t, s, ctx, rule.ID, chanID)
	if len(items) != 1 || items[0].CVSSV3Score == nil || *items[0].CVSSV3Score != 4.3 {
		t.Errorf("payload = %+v, want one item with cvss_v3_score 4.3", items)
	}
}

func TestFanoutResolution_EveryBoundChannelGetsOneDelivery(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "ResolutionChannelsOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "ResolutionChannelsRule")
	const cveID = "CVE-2025-7011"
	ingestCVE(t, s, ctx, cveID, "Analyzed", 4.3, false)

	channels := make([]uuid.UUID, 2)
	for i, name := range []string{"ResolutionChanA", "ResolutionChanB"} {
		chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, name)
		if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
			t.Fatalf("BindChannelToRule: %v", err)
		}
		channels[i] = chanID
	}

	if err := notify.NewDispatcher(s.Store, 300).FanoutResolution(ctx, org.ID, rule.ID, cveID); err != nil {
		t.Fatalf("FanoutResolution: %v", err)
	}

	for _, chanID := range channels {
		if items := pendingResolutionItems(t, s, ctx, rule.ID, chanID); len(items) != 1 {
			t.Errorf("channel %s payload items = %d, want 1", chanID, len(items))
		}
	}
}

// resolutionWorkerConfig delivers once per claim with a short retry backoff.
var resolutionWorkerConfig = notify.WorkerConfig{
	ClaimBatchSize:      10,
	MaxAttempts:         3,
	BackoffBaseSeconds:  1,
	MaxConcurrentPerOrg: 4,
}

// webhookBodyAfterDelivery runs enqueue against a webhook channel bound to a new rule,
// delivers it, and returns the request body the receiver got.
func webhookBodyAfterDelivery(t *testing.T, s *testutil.TestDB, ctx context.Context, name string, enqueue func(orgID, ruleID uuid.UUID)) []byte {
	t.Helper()
	bodies := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read webhook body: %v", err)
		}
		bodies <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	org := s.MustCreateOrg(t, ctx, name)
	rule := mustCreateAlertRule(t, s, ctx, org.ID, name)
	cfg, _ := json.Marshal(map[string]string{"url": srv.URL})
	chanRow, _, err := s.CreateNotificationChannel(ctx, org.ID, name, "webhook", json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	if err := s.BindChannelToRule(ctx, rule.ID, chanRow.ID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}
	enqueue(org.ID, rule.ID)

	runClaimUntilAttempted(t, s, ctx, newTestWorker(s, plainHTTPClient(), resolutionWorkerConfig))

	select {
	case body := <-bodies:
		return body
	default:
		t.Fatal("webhook receiver got no request")
		return nil
	}
}

func TestWorker_ResolutionWebhookBodyNamesEventType(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	const cveID = "CVE-2025-7020"
	ingestCVE(t, s, ctx, cveID, "Rejected", 4.3, true)

	body := webhookBodyAfterDelivery(t, s, ctx, "ResolutionWebhook", func(orgID, ruleID uuid.UUID) {
		if err := notify.NewDispatcher(s.Store, 0).FanoutResolution(ctx, orgID, ruleID, cveID); err != nil {
			t.Fatalf("FanoutResolution: %v", err)
		}
	})

	var got struct {
		EventType string           `json:"event_type"`
		CVEs      []resolutionItem `json:"cves"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("webhook body %s is not a resolution object: %v", body, err)
	}
	if got.EventType != "resolution" {
		t.Errorf("event_type = %q, want resolution", got.EventType)
	}
	if len(got.CVEs) != 1 || got.CVEs[0].CVEID != cveID || got.CVEs[0].Reason != "CVE was rejected by its source" {
		t.Errorf("cves = %+v, want %s with its rejection reason", got.CVEs, cveID)
	}
}

func TestWorker_AlertWebhookBodyStaysAnArray(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	const cveID = "CVE-2025-7021"
	ingestCVE(t, s, ctx, cveID, "Analyzed", 9.8, false)

	body := webhookBodyAfterDelivery(t, s, ctx, "AlertWebhookShape", func(orgID, ruleID uuid.UUID) {
		if err := notify.NewDispatcher(s.Store, 0).Fanout(ctx, orgID, ruleID, cveID); err != nil {
			t.Fatalf("Fanout: %v", err)
		}
	})

	var got []map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("webhook body %s is not an array: %v", body, err)
	}
	if len(got) != 1 || got[0]["cve_id"] != cveID {
		t.Errorf("body = %v, want one snapshot of %s", got, cveID)
	}
}

// TestWorker_ResolutionEmailReachesSMTP uses an unreachable SMTP server: a kind the
// email path cannot render fails permanently, while a rendered email retries.
func TestWorker_ResolutionEmailReachesSMTP(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ResolutionEmailOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "ResolutionEmailRule")
	cfg, _ := json.Marshal(map[string]any{"recipients": []string{"test@example.com"}})
	chanRow, _, err := s.CreateNotificationChannel(ctx, org.ID, "ResolutionEmailChan", "email", json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	if err := s.BindChannelToRule(ctx, rule.ID, chanRow.ID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}
	const cveID = "CVE-2025-7022"
	ingestCVE(t, s, ctx, cveID, "Analyzed", 4.3, false)
	if err := notify.NewDispatcher(s.Store, 0).FanoutResolution(ctx, org.ID, rule.ID, cveID); err != nil {
		t.Fatalf("FanoutResolution: %v", err)
	}

	w := notify.NewWorker(s.Store, plainHTTPClient(), resolutionWorkerConfig, notify.SmtpConfig{
		Host: "192.0.2.1", // TEST-NET, unreachable
		Port: 25,
		From: "test@example.com",
	}, "https://cvert.example.com")
	runClaimUntilAttempted(t, s, ctx, w)

	var status string
	var attempts int32
	if err := s.DB().QueryRowContext(ctx,
		"SELECT status, attempt_count FROM notification_deliveries WHERE channel_id = $1",
		chanRow.ID).Scan(&status, &attempts); err != nil {
		t.Fatalf("scan delivery row: %v", err)
	}
	if status != "pending" || attempts != 1 {
		t.Errorf("status = %q, attempts = %d, want pending after one SMTP attempt", status, attempts)
	}
}
