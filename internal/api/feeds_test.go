// ABOUTME: Integration tests for admin feed status and manual trigger endpoints.
// ABOUTME: Uses real Postgres via testutil.NewTestDB and the full srv.Handler() stack.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/ingest"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// ── HTTP helpers ──────────────────────────────────────────────────────────────

func doGetFeeds(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/admin/feeds", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("get feeds: %v", err)
	}
	return resp
}

func doTriggerFeed(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, feedName string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/admin/feeds/"+feedName+"/run", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("trigger feed: %v", err)
	}
	return resp
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestAdminFeeds_ListWithSeededData(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, ts := newRegisterServer(t, db, "open")
	ctx := context.Background()

	// Register + login to get an access token.
	doRegister(t, ctx, ts, "feeds@test.com", "TestPassword1234!")
	loginResp := doLogin(t, ctx, ts, "feeds@test.com", "TestPassword1234!")
	defer loginResp.Body.Close() //nolint:errcheck
	accessToken := cookieValue(loginResp, "access_token")
	if accessToken == "" {
		t.Fatal("no access_token cookie after login")
	}

	// Seed feed sync states.
	now := time.Now().UTC()
	oneHourAgo := now.Add(-1 * time.Hour)
	if err := db.UpsertFeedSyncState(ctx, store.FeedSyncState{
		FeedName:      "nvd",
		LastSuccessAt: &oneHourAgo,
		LastAttemptAt: &oneHourAgo,
	}); err != nil {
		t.Fatalf("seed nvd sync state: %v", err)
	}

	twoHoursAgo := now.Add(-2 * time.Hour)
	backoff := now.Add(30 * time.Minute)
	if err := db.UpsertFeedSyncState(ctx, store.FeedSyncState{
		FeedName:            "kev",
		LastSuccessAt:       &twoHoursAgo,
		LastAttemptAt:       &oneHourAgo,
		ConsecutiveFailures: 2,
		LastError:           "connection refused",
		BackoffUntil:        &backoff,
	}); err != nil {
		t.Fatalf("seed kev sync state: %v", err)
	}

	// Seed a fetch log for nvd.
	endedAt := oneHourAgo.Add(30 * time.Second)
	if _, err := db.InsertFeedFetchLog(ctx, store.FeedFetchLog{
		FeedName:      "nvd",
		StartedAt:     oneHourAgo,
		EndedAt:       &endedAt,
		Status:        "success",
		ItemsFetched:  100,
		ItemsUpserted: 42,
	}); err != nil {
		t.Fatalf("seed nvd fetch log: %v", err)
	}

	// Call the endpoint.
	resp := doGetFeeds(t, ctx, ts, accessToken)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/feeds: got %d, want 200", resp.StatusCode)
	}

	var body struct {
		Feeds []struct {
			FeedName            string `json:"feed_name"`
			ConsecutiveFailures int32  `json:"consecutive_failures"`
			LastError           string `json:"last_error,omitempty"`
			RecentLogs          []struct {
				Status string `json:"status"`
			} `json:"recent_logs"`
		} `json:"feeds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(body.Feeds) < 2 {
		t.Fatalf("expected at least 2 feeds, got %d", len(body.Feeds))
	}

	// Find nvd and kev entries.
	var foundNVD, foundKEV bool
	for _, f := range body.Feeds {
		switch f.FeedName {
		case "nvd":
			foundNVD = true
			if len(f.RecentLogs) != 1 {
				t.Errorf("nvd: expected 1 recent log, got %d", len(f.RecentLogs))
			}
			if len(f.RecentLogs) > 0 && f.RecentLogs[0].Status != "success" {
				t.Errorf("nvd log status = %q, want success", f.RecentLogs[0].Status)
			}
		case "kev":
			foundKEV = true
			if f.ConsecutiveFailures != 2 {
				t.Errorf("kev consecutive_failures = %d, want 2", f.ConsecutiveFailures)
			}
			if f.LastError != "connection refused" {
				t.Errorf("kev last_error = %q, want %q", f.LastError, "connection refused")
			}
		}
	}
	if !foundNVD {
		t.Error("nvd not found in feeds response")
	}
	if !foundKEV {
		t.Error("kev not found in feeds response")
	}
}

func TestAdminFeeds_ListEmptyDB(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, ts := newRegisterServer(t, db, "open")
	ctx := context.Background()

	doRegister(t, ctx, ts, "empty@test.com", "TestPassword1234!")
	loginResp := doLogin(t, ctx, ts, "empty@test.com", "TestPassword1234!")
	defer loginResp.Body.Close() //nolint:errcheck
	accessToken := cookieValue(loginResp, "access_token")

	resp := doGetFeeds(t, ctx, ts, accessToken)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/feeds: got %d, want 200", resp.StatusCode)
	}

	var body struct {
		Feeds []struct {
			FeedName string `json:"feed_name"`
		} `json:"feeds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// All known feeds should appear even with no sync state rows.
	if len(body.Feeds) != len(ingest.KnownFeeds) {
		t.Fatalf("expected %d feeds, got %d", len(ingest.KnownFeeds), len(body.Feeds))
	}

	feedSet := make(map[string]bool)
	for _, f := range body.Feeds {
		feedSet[f.FeedName] = true
	}
	for _, name := range ingest.KnownFeeds {
		if !feedSet[name] {
			t.Errorf("missing feed %q in response", name)
		}
	}
}

func TestAdminFeeds_TriggerFeed(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, ts := newRegisterServer(t, db, "open")
	ctx := context.Background()

	doRegister(t, ctx, ts, "trigger@test.com", "TestPassword1234!")
	loginResp := doLogin(t, ctx, ts, "trigger@test.com", "TestPassword1234!")
	defer loginResp.Body.Close() //nolint:errcheck
	accessToken := cookieValue(loginResp, "access_token")

	// Trigger NVD feed.
	resp := doTriggerFeed(t, ctx, ts, accessToken, "nvd")
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /admin/feeds/nvd/run: got %d, want 202", resp.StatusCode)
	}

	var triggerBody struct {
		JobID string `json:"job_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&triggerBody); err != nil {
		t.Fatalf("decode trigger response: %v", err)
	}
	if triggerBody.JobID == "" {
		t.Error("expected non-empty job_id")
	}
}

func TestAdminFeeds_TriggerEPSS(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, ts := newRegisterServer(t, db, "open")
	ctx := context.Background()

	doRegister(t, ctx, ts, "epss@test.com", "TestPassword1234!")
	loginResp := doLogin(t, ctx, ts, "epss@test.com", "TestPassword1234!")
	defer loginResp.Body.Close() //nolint:errcheck
	accessToken := cookieValue(loginResp, "access_token")

	resp := doTriggerFeed(t, ctx, ts, accessToken, "epss")
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /admin/feeds/epss/run: got %d, want 202", resp.StatusCode)
	}
}

func TestAdminFeeds_TriggerUnknownFeed(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, ts := newRegisterServer(t, db, "open")
	ctx := context.Background()

	doRegister(t, ctx, ts, "unknown@test.com", "TestPassword1234!")
	loginResp := doLogin(t, ctx, ts, "unknown@test.com", "TestPassword1234!")
	defer loginResp.Body.Close() //nolint:errcheck
	accessToken := cookieValue(loginResp, "access_token")

	resp := doTriggerFeed(t, ctx, ts, accessToken, "bogus")
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /admin/feeds/bogus/run: got %d, want 400", resp.StatusCode)
	}
}

func TestAdminFeeds_TriggerAlreadyPending(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, ts := newRegisterServer(t, db, "open")
	ctx := context.Background()

	doRegister(t, ctx, ts, "pending@test.com", "TestPassword1234!")
	loginResp := doLogin(t, ctx, ts, "pending@test.com", "TestPassword1234!")
	defer loginResp.Body.Close() //nolint:errcheck
	accessToken := cookieValue(loginResp, "access_token")

	// Trigger once — should succeed.
	resp1 := doTriggerFeed(t, ctx, ts, accessToken, "nvd")
	defer resp1.Body.Close() //nolint:errcheck
	if resp1.StatusCode != http.StatusAccepted {
		t.Fatalf("first trigger: got %d, want 202", resp1.StatusCode)
	}

	// Trigger again — should get 409 Conflict.
	resp2 := doTriggerFeed(t, ctx, ts, accessToken, "nvd")
	defer resp2.Body.Close() //nolint:errcheck
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("second trigger: got %d, want 409", resp2.StatusCode)
	}
}

func TestAdminFeeds_RequiresAuth(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, ts := newRegisterServer(t, db, "open")
	ctx := context.Background()

	// GET without auth.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/admin/feeds", nil)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /admin/feeds without auth: got %d, want 401", resp.StatusCode)
	}
}

func TestAdminFeeds_NonSiteAdmin_403(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, ts := newRegisterServer(t, db, "open")
	ctx := context.Background()

	// First user becomes site admin automatically.
	doRegister(t, ctx, ts, "admin@test.com", "TestPassword1234!")

	// Second user is NOT site admin.
	doRegister(t, ctx, ts, "regular@test.com", "TestPassword1234!")
	loginResp := doLogin(t, ctx, ts, "regular@test.com", "TestPassword1234!")
	defer loginResp.Body.Close() //nolint:errcheck
	accessToken := cookieValue(loginResp, "access_token")
	if accessToken == "" {
		t.Fatal("no access_token cookie after login")
	}

	// GET /admin/feeds as non-admin → 403.
	resp := doGetFeeds(t, ctx, ts, accessToken)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /admin/feeds as non-admin: got %d, want 403", resp.StatusCode)
	}

	// POST /admin/feeds/nvd/run as non-admin → 403.
	resp2 := doTriggerFeed(t, ctx, ts, accessToken, "nvd")
	defer resp2.Body.Close() //nolint:errcheck
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /admin/feeds/nvd/run as non-admin: got %d, want 403", resp2.StatusCode)
	}
}
