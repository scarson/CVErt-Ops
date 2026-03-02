// ABOUTME: Integration tests for GET /api/v1/orgs/{org_id}/tier endpoint.
// ABOUTME: Verifies tier info response includes resolved limits and usage counts.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestGetOrgTier_FreeTier(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")
	reg := doRegister(t, ctx, ts, "orgtier1@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "orgtier1@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec // test

	orgID, _ := uuid.Parse(reg.OrgID)

	// Create 2 alert rules to test usage count.
	for i := 0; i < 2; i++ {
		body := fmt.Sprintf(`{"name":"TR %d","logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}],"enabled":false}`, i)
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
	}

	// GET /tier endpoint.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/api/v1/orgs/%s/tier", ts.URL, orgID), nil)
	req.Header.Set("Cookie", "access_token="+token)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("get tier: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get tier: got %d, want 200", resp.StatusCode)
	}

	var result struct {
		Tier   string `json:"tier"`
		Limits map[string]struct {
			Limit   *int  `json:"limit,omitempty"`
			Used    *int  `json:"used,omitempty"`
			Allowed *bool `json:"allowed,omitempty"`
		} `json:"limits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode tier response: %v", err)
	}

	if result.Tier != "free" {
		t.Errorf("tier = %q, want free", result.Tier)
	}

	// Check alert rules limit.
	ar, ok := result.Limits["max_alert_rules"]
	if !ok {
		t.Fatal("missing max_alert_rules in limits")
	}
	if ar.Limit == nil || *ar.Limit != 5 {
		t.Errorf("max_alert_rules.limit = %v, want 5", ar.Limit)
	}
	if ar.Used == nil || *ar.Used != 2 {
		t.Errorf("max_alert_rules.used = %v, want 2", ar.Used)
	}

	// Check watchlists limit.
	wl, ok := result.Limits["max_watchlists"]
	if !ok {
		t.Fatal("missing max_watchlists in limits")
	}
	if wl.Limit == nil || *wl.Limit != 3 {
		t.Errorf("max_watchlists.limit = %v, want 3", wl.Limit)
	}

	// Check email channel flag.
	ce, ok := result.Limits["channels_email"]
	if !ok {
		t.Fatal("missing channels_email in limits")
	}
	if ce.Allowed == nil || *ce.Allowed != false {
		t.Errorf("channels_email.allowed = %v, want false", ce.Allowed)
	}

	// Check webhook channel flag.
	cw, ok := result.Limits["channels_webhook"]
	if !ok {
		t.Fatal("missing channels_webhook in limits")
	}
	if cw.Allowed == nil || *cw.Allowed != true {
		t.Errorf("channels_webhook.allowed = %v, want true", cw.Allowed)
	}
}
