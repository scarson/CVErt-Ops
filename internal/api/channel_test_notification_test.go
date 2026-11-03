// ABOUTME: Integration tests for the POST /channels/{id}/test endpoint.
// ABOUTME: Verifies test notification responses, error handling, and auth requirements.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/notify"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func doTestChannel(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, channelID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/channels/"+channelID+"/test", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("test channel: %v", err)
	}
	return resp
}

func TestChannelTest_Webhook_Unreachable(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")
	reg := doRegister(t, ctx, ts, "admin@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "admin@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Create a webhook channel pointing to a host that won't respond.
	channelBody := `{"name":"bad-hook","type":"webhook","config":{"url":"https://unreachable.invalid:9999/hook"}}`
	createResp := doCreateChannel(t, ctx, ts, token, reg.OrgID, channelBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec
	if createResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create channel: got %d, body: %s", createResp.StatusCode, body)
	}
	var ch struct {
		ID string `json:"id"`
	}
	json.NewDecoder(createResp.Body).Decode(&ch) //nolint:errcheck,gosec

	// Test the channel — should return 502 with success=false when delivery fails.
	resp := doTestChannel(t, ctx, ts, token, reg.OrgID, ch.ID)
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusBadGateway {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("test channel: got %d, body: %s, want 502", resp.StatusCode, body)
	}

	var result struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&result) //nolint:errcheck,gosec
	if result.Success {
		t.Error("expected success=false for unreachable host")
	}
	if result.Error == "" {
		t.Error("expected non-empty error message")
	}
}

// newPrivateDestServer starts a server whose webhook client allows the given
// private destinations, so a test can reach or be refused by a loopback receiver.
func newPrivateDestServer(t *testing.T, db *testutil.TestDB, hosts, cidrs, ports string) *httptest.Server {
	t.Helper()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:           "regtestsecret",
		RegistrationMode:    "open",
		Argon2MaxConcurrent: 5,
		MFAPendingTokenTTL:  5 * time.Minute,
		WebhookPrivateHosts: hosts,
		WebhookPrivateCIDRs: cidrs,
		WebhookPrivatePorts: ports,
	}
	srv, err := NewServer(db.Store, cfg, ServerDeps{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.Close)
	return ts
}

// testLoopbackChannel registers a webhook channel at a loopback receiver that
// answers with status, tests it, and returns the response status and body.
func testLoopbackChannel(t *testing.T, cidrs string, status int) (int, testChannelResponse) {
	t.Helper()
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(receiver.Close)
	u, err := url.Parse(receiver.URL)
	if err != nil {
		t.Fatalf("parse receiver URL: %v", err)
	}

	db := testutil.NewTestDB(t)
	ctx := context.Background()
	ts := newPrivateDestServer(t, db, "127.0.0.1", cidrs, u.Port())
	reg := doRegister(t, ctx, ts, "admin@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "admin@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	channelBody := `{"name":"lan-hook","type":"webhook","config":{"url":"` + receiver.URL + `/hook"}}`
	createResp := doCreateChannel(t, ctx, ts, token, reg.OrgID, channelBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec
	if createResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create channel: got %d, body: %s", createResp.StatusCode, body)
	}
	var ch struct {
		ID string `json:"id"`
	}
	json.NewDecoder(createResp.Body).Decode(&ch) //nolint:errcheck,gosec

	resp := doTestChannel(t, ctx, ts, token, reg.OrgID, ch.ID)
	defer resp.Body.Close() //nolint:errcheck,gosec
	var result testChannelResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode test channel response: %v", err)
	}
	return resp.StatusCode, result
}

// TestChannelTest_Webhook_RefusedDestinationHidesAddress verifies that a refused
// dial does not return the resolved address, which would let an org admin map
// internal DNS by registering host names and testing them.
func TestChannelTest_Webhook_RefusedDestinationHidesAddress(t *testing.T) {
	t.Parallel()
	// 127.0.0.1 is listed, but its network is not, so the dial is refused with
	// "ip: 127.0.0.1 not found in allowlist".
	status, result := testLoopbackChannel(t, "10.0.0.0/8", http.StatusOK)
	if status != http.StatusBadGateway {
		t.Fatalf("test channel: got %d, want 502", status)
	}
	if result.Success {
		t.Fatal("expected success=false for a refused destination")
	}
	if result.Error != notify.ErrCauseWithheld.Error() {
		t.Errorf("error = %q, want %q", result.Error, notify.ErrCauseWithheld.Error())
	}
	if strings.Contains(result.Error, "127.0.0.1") {
		t.Errorf("error %q reveals the resolved address", result.Error)
	}
}

// TestChannelTest_Webhook_ReportsReceiverStatus verifies that a status from a
// receiver the request reached is still reported to the caller.
func TestChannelTest_Webhook_ReportsReceiverStatus(t *testing.T) {
	t.Parallel()
	status, result := testLoopbackChannel(t, "127.0.0.0/8", http.StatusInternalServerError)
	if status != http.StatusBadGateway {
		t.Fatalf("test channel: got %d, want 502", status)
	}
	if !strings.Contains(result.Error, "unexpected status 500") {
		t.Errorf("error = %q, want it to report the receiver's status 500", result.Error)
	}
}

func TestChannelTest_Email(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")
	reg := doRegister(t, ctx, ts, "admin@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "admin@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Enable email channels via tier override.
	_, err := db.Pool().Exec(ctx,
		`UPDATE organizations SET tier_overrides = $1 WHERE id = $2`,
		`{"channels_email": true}`, reg.OrgID)
	if err != nil {
		t.Fatalf("set tier_overrides: %v", err)
	}

	// Create an email channel.
	channelBody := `{"name":"test-email","type":"email","config":{"recipients":["test@example.com"]}}`
	createResp := doCreateChannel(t, ctx, ts, token, reg.OrgID, channelBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec
	if createResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create email channel: got %d, body: %s", createResp.StatusCode, body)
	}
	var ch struct {
		ID string `json:"id"`
	}
	json.NewDecoder(createResp.Body).Decode(&ch) //nolint:errcheck,gosec

	// Test the email channel — will fail because SMTP is not configured in tests,
	// should return 502 with success=false (not 500).
	resp := doTestChannel(t, ctx, ts, token, reg.OrgID, ch.ID)
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusBadGateway {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("test email channel: got %d, body: %s, want 502", resp.StatusCode, body)
	}

	var result struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&result) //nolint:errcheck,gosec
	// SMTP is not configured in tests, so delivery fails — verify the endpoint
	// reports failure gracefully rather than returning 500.
	if result.Success {
		t.Error("expected success=false when SMTP is not configured")
	}
	if result.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestChannelTest_NotFound(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")
	reg := doRegister(t, ctx, ts, "admin@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "admin@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	fakeID := "00000000-0000-0000-0000-000000000001"
	resp := doTestChannel(t, ctx, ts, token, reg.OrgID, fakeID)
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("test channel not found: got %d, want 404", resp.StatusCode)
	}
}

func TestChannelTest_RequiresAdmin(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")
	reg := doRegister(t, ctx, ts, "owner@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "owner@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	ownerToken := cookieValue(loginResp, "access_token")

	// Create a channel as owner (owner >= admin).
	channelBody := `{"name":"test-hook","type":"webhook","config":{"url":"https://example.com/hook"}}`
	createResp := doCreateChannel(t, ctx, ts, ownerToken, reg.OrgID, channelBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec
	var ch struct {
		ID string `json:"id"`
	}
	json.NewDecoder(createResp.Body).Decode(&ch) //nolint:errcheck,gosec

	// Create a viewer user.
	doRegister(t, ctx, ts, "viewer@example.com", "test-password-1234")
	viewerLoginResp := doLogin(t, ctx, ts, "viewer@example.com", "test-password-1234")
	defer viewerLoginResp.Body.Close() //nolint:errcheck,gosec
	viewerToken := cookieValue(viewerLoginResp, "access_token")

	// Invite viewer to the org as viewer role.
	inviteBody := `{"email":"viewer@example.com","role":"viewer"}`
	invReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+reg.OrgID+"/invitations", bytes.NewBufferString(inviteBody))
	invReq.Header.Set("Content-Type", "application/json")
	invReq.Header.Set("Cookie", "access_token="+ownerToken)
	invReq.Header.Set("X-Requested-By", "CVErt-Ops")
	invResp, _ := ts.Client().Do(invReq) //nolint:gosec,errcheck
	if invResp != nil {
		invResp.Body.Close() //nolint:errcheck,gosec
	}

	// Accept invitation as viewer.
	invitations, _ := db.ListOrgInvitations(ctx, mustParseUUID(t, reg.OrgID))
	if len(invitations) > 0 {
		acceptReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			ts.URL+"/api/v1/auth/invitations/"+invitations[0].Token+"/accept", nil)
		acceptReq.Header.Set("Cookie", "access_token="+viewerToken)
		acceptReq.Header.Set("X-Requested-By", "CVErt-Ops")
		acceptResp, _ := ts.Client().Do(acceptReq) //nolint:gosec,errcheck
		if acceptResp != nil {
			acceptResp.Body.Close() //nolint:errcheck,gosec
		}
	}

	// Viewer tries to test the channel — should be 403.
	resp := doTestChannel(t, ctx, ts, viewerToken, reg.OrgID, ch.ID)
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer test channel: got %d, want 403", resp.StatusCode)
	}
}
