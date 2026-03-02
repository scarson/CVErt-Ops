// ABOUTME: Integration tests for tier-based resource gating on create handlers.
// ABOUTME: Verifies alert rules, watchlists, and member invitations respect tier limits.
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
