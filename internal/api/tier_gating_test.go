// ABOUTME: Integration tests for tier-based resource and channel type gating on create handlers.
// ABOUTME: Verifies alert rules, watchlists, members, and channel types respect tier limits.
package api

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestTierGating_AlertRules_FreeLimit(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")
	reg := doRegister(t, ctx, ts, "tiergate1@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "tiergate1@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec // test

	orgID, _ := uuid.Parse(reg.OrgID)

	// Ensure org is on free tier (default).
	tier, _, _ := db.GetOrgTier(ctx, orgID)
	if tier != "free" {
		t.Fatalf("expected free tier, got %q", tier)
	}

	// Create 5 alert rules (free tier limit).
	for i := 0; i < 5; i++ {
		body := fmt.Sprintf(`{"name":"Rule %d","logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}],"enabled":false}`, i)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			fmt.Sprintf("%s/api/v1/orgs/%s/alert-rules", ts.URL, orgID),
			bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cookie", "access_token="+token)
		req.Header.Set("X-Requested-By", "CVErt-Ops")
		resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
		if err != nil {
			t.Fatalf("create rule %d: %v", i, err)
		}
		resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create rule %d: got %d, want 201", i, resp.StatusCode)
		}
	}

	// 6th should fail with 403.
	body := `{"name":"Rule 5","logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}],"enabled":false}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v1/orgs/%s/alert-rules", ts.URL, orgID),
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create rule 6: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("6th rule: got %d, want 403", resp.StatusCode)
	}
}

func TestTierGating_Watchlists_FreeLimit(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")
	reg := doRegister(t, ctx, ts, "tiergate2@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "tiergate2@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec // test

	orgID, _ := uuid.Parse(reg.OrgID)

	// Create 3 watchlists (free tier limit).
	for i := 0; i < 3; i++ {
		body := fmt.Sprintf(`{"name":"WL %d"}`, i)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			fmt.Sprintf("%s/api/v1/orgs/%s/watchlists", ts.URL, orgID),
			bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cookie", "access_token="+token)
		req.Header.Set("X-Requested-By", "CVErt-Ops")
		resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
		if err != nil {
			t.Fatalf("create watchlist %d: %v", i, err)
		}
		resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create watchlist %d: got %d, want 201", i, resp.StatusCode)
		}
	}

	// 4th should fail with 403.
	body := `{"name":"WL 3"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v1/orgs/%s/watchlists", ts.URL, orgID),
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create watchlist 4: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("4th watchlist: got %d, want 403", resp.StatusCode)
	}
}

func TestTierGating_Channels_FreeBlocksEmail(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")
	reg := doRegister(t, ctx, ts, "tiergate4@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "tiergate4@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec // test

	orgID, _ := uuid.Parse(reg.OrgID)

	// Webhook should succeed on free tier.
	webhookBody := `{"name":"WH","type":"webhook","config":{"url":"https://example.com/hook"}}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v1/orgs/%s/channels", ts.URL, orgID),
		bytes.NewBufferString(webhookBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create webhook: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("webhook on free: got %d, want 201", resp.StatusCode)
	}

	// Email should fail with 403 on free tier.
	emailBody := `{"name":"EM","type":"email","config":{"recipients":["ops@example.com"]}}`
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v1/orgs/%s/channels", ts.URL, orgID),
		bytes.NewBufferString(emailBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err = ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create email: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("email on free: got %d, want 403", resp.StatusCode)
	}
}

func TestTierGating_Channels_ProAllowsEmail(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")
	reg := doRegister(t, ctx, ts, "tiergate5@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "tiergate5@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec // test

	orgID, _ := uuid.Parse(reg.OrgID)

	// Upgrade to pro tier.
	if err := db.UpdateOrgTier(ctx, orgID, "pro"); err != nil {
		t.Fatalf("set pro tier: %v", err)
	}

	// Email should succeed on pro tier.
	emailBody := `{"name":"EM Pro","type":"email","config":{"recipients":["ops@example.com"]}}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v1/orgs/%s/channels", ts.URL, orgID),
		bytes.NewBufferString(emailBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create email: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("email on pro: got %d, want 201", resp.StatusCode)
	}
}

func TestTierGating_Channels_OverrideAllowsEmail(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")
	reg := doRegister(t, ctx, ts, "tiergate6@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "tiergate6@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec // test

	orgID, _ := uuid.Parse(reg.OrgID)

	// Free tier with override allowing email channels.
	_, err := db.Pool().Exec(ctx,
		`UPDATE organizations SET tier_overrides = $1 WHERE id = $2`,
		`{"channels_email": true}`, orgID)
	if err != nil {
		t.Fatalf("set tier_overrides: %v", err)
	}

	// Email should succeed with override.
	emailBody := `{"name":"EM Override","type":"email","config":{"recipients":["ops@example.com"]}}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v1/orgs/%s/channels", ts.URL, orgID),
		bytes.NewBufferString(emailBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create email: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("email with override: got %d, want 201", resp.StatusCode)
	}
}

func TestTierGating_AlertRules_OverrideExpandsLimit(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")
	reg := doRegister(t, ctx, ts, "tiergate3@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "tiergate3@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec // test

	orgID, _ := uuid.Parse(reg.OrgID)

	// Set override to allow 10 alert rules on free tier.
	_, err := db.Pool().Exec(ctx,
		`UPDATE organizations SET tier_overrides = $1 WHERE id = $2`,
		`{"max_alert_rules": 10}`, orgID)
	if err != nil {
		t.Fatalf("set tier_overrides: %v", err)
	}

	// Create 6 rules (above default free=5, but within override=10).
	for i := 0; i < 6; i++ {
		body := fmt.Sprintf(`{"name":"OvRule %d","logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}],"enabled":false}`, i)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			fmt.Sprintf("%s/api/v1/orgs/%s/alert-rules", ts.URL, orgID),
			bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cookie", "access_token="+token)
		req.Header.Set("X-Requested-By", "CVErt-Ops")
		resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
		if err != nil {
			t.Fatalf("create rule %d: %v", i, err)
		}
		resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("create rule %d with override: got %d, want 201", i, resp.StatusCode)
		}
	}
}

func TestTierGating_Members_FreeLimit(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")
	reg := doRegister(t, ctx, ts, "tiergate8@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "tiergate8@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec // test

	orgID, _ := uuid.Parse(reg.OrgID)

	// Org starts with 1 member (the owner). Add 4 more via DB to reach free limit of 5.
	for i := 0; i < 4; i++ {
		userID := uuid.New()
		_, err := db.Pool().Exec(ctx,
			`INSERT INTO users (id, email, display_name, password_hash) VALUES ($1, $2, $3, $4)`,
			userID, fmt.Sprintf("filler%d@example.com", i), fmt.Sprintf("Filler %d", i), "not-a-real-hash")
		if err != nil {
			t.Fatalf("create filler user %d: %v", i, err)
		}
		_, err = db.Pool().Exec(ctx,
			`INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, 'member')`,
			orgID, userID)
		if err != nil {
			t.Fatalf("create filler member %d: %v", i, err)
		}
	}

	// Creating an invitation should fail with 403 (5 members = free limit).
	body := `{"email":"new-member@example.com","role":"member"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v1/orgs/%s/invitations", ts.URL, orgID),
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("invitation at limit: got %d, want 403", resp.StatusCode)
	}
}

func TestTierGating_Members_PendingInvitationsConsumeSlots(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")
	reg := doRegister(t, ctx, ts, "tiergate9@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "tiergate9@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec // test

	orgID, _ := uuid.Parse(reg.OrgID)

	// Org starts with 1 member (the owner). Add 3 more via DB to get to 4 members.
	for i := 0; i < 3; i++ {
		userID := uuid.New()
		_, err := db.Pool().Exec(ctx,
			`INSERT INTO users (id, email, display_name, password_hash) VALUES ($1, $2, $3, $4)`,
			userID, fmt.Sprintf("slotfill%d@example.com", i), fmt.Sprintf("SlotFill %d", i), "not-a-real-hash")
		if err != nil {
			t.Fatalf("create filler user %d: %v", i, err)
		}
		_, err = db.Pool().Exec(ctx,
			`INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, 'member')`,
			orgID, userID)
		if err != nil {
			t.Fatalf("create filler member %d: %v", i, err)
		}
	}

	// Create 1 invitation via API (4 members + 1 pending = 5 slots consumed).
	body := `{"email":"pending1@example.com","role":"member"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v1/orgs/%s/invitations", ts.URL, orgID),
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create invitation 1: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("invitation 1: got %d, want 202", resp.StatusCode)
	}

	// 2nd invitation should fail — pending invitation consumed the 5th slot.
	body = `{"email":"pending2@example.com","role":"member"}`
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v1/orgs/%s/invitations", ts.URL, orgID),
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err = ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create invitation 2: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("invitation 2 at limit: got %d, want 403", resp.StatusCode)
	}
}

func TestTierGating_OrgRateLimit(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")
	reg := doRegister(t, ctx, ts, "tiergate7@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "tiergate7@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec // test

	orgID, _ := uuid.Parse(reg.OrgID)

	// Set a very low rate limit override (2 req/min, burst=2) to trigger 429 quickly.
	_, err := db.Pool().Exec(ctx,
		`UPDATE organizations SET tier_overrides = $1 WHERE id = $2`,
		`{"api_rate_limit": 2}`, orgID)
	if err != nil {
		t.Fatalf("set tier_overrides: %v", err)
	}

	// Send requests until we get a 429.
	got429 := false
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("%s/api/v1/orgs/%s", ts.URL, orgID), nil)
		req.Header.Set("Cookie", "access_token="+token)
		resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Error("expected at least one 429 response with rate limit of 2/min, but none received")
	}
}
