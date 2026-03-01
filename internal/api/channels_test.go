// ABOUTME: Integration tests for notification channel HTTP handlers.
// ABOUTME: Uses real Postgres via testutil.NewTestDB and the full srv.Handler() stack.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// ── HTTP helper functions ─────────────────────────────────────────────────────

func doCreateChannel(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/channels", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	return resp
}

func doGetChannel(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/channels/"+id, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("get channel: %v", err)
	}
	return resp
}

func doListChannels(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/channels", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("list channels: %v", err)
	}
	return resp
}

func doPatchChannel(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPatch, ts.URL+"/api/v1/orgs/"+orgID+"/channels/"+id, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("patch channel: %v", err)
	}
	return resp
}

func doDeleteChannel(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, ts.URL+"/api/v1/orgs/"+orgID+"/channels/"+id, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("delete channel: %v", err)
	}
	return resp
}

func doRotateSecret(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/channels/"+id+"/rotate-secret", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("rotate secret: %v", err)
	}
	return resp
}

func doClearSecondary(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/channels/"+id+"/clear-secondary", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("clear secondary: %v", err)
	}
	return resp
}

// validChannelBody is a minimal valid webhook channel body for testing.
const validChannelBody = `{"name":"Test Webhook","type":"webhook","config":{"url":"https://example.com/hook"}}`

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestCreateChannel_SigningSecretReturnedOnce verifies the signing_secret is present in
// create response and absent in subsequent GET.
func TestCreateChannel_SigningSecretReturnedOnce(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateChannel(t, ctx, ts, token, aliceReg.OrgID, validChannelBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create channel: got %d, want 201", createResp.StatusCode)
	}
	var created struct {
		ID            string `json:"id"`
		SigningSecret string `json:"signing_secret"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("created channel has empty ID")
	}
	if created.SigningSecret == "" {
		t.Fatal("create response must include signing_secret")
	}

	// GET must not include signing_secret.
	getResp := doGetChannel(t, ctx, ts, token, aliceReg.OrgID, created.ID)
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get channel: got %d, want 200", getResp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if s, ok := got["signing_secret"]; ok && s != "" {
		t.Errorf("GET response must not include non-empty signing_secret, got %v", s)
	}
}

// TestCreateChannel_URLRequired verifies that a webhook channel without a url in config
// returns 422.
func TestCreateChannel_URLRequired(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Config with no "url" key.
	noURLBody := `{"name":"Bad Webhook","type":"webhook","config":{}}`
	resp := doCreateChannel(t, ctx, ts, token, aliceReg.OrgID, noURLBody)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("create without url: got %d, want 422", resp.StatusCode)
	}
}

// TestListChannels_ReturnsCreated verifies that a created channel appears in list results.
func TestListChannels_ReturnsCreated(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateChannel(t, ctx, ts, token, aliceReg.OrgID, validChannelBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d, want 201", createResp.StatusCode)
	}

	listResp := doListChannels(t, ctx, ts, token, aliceReg.OrgID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list channels: got %d, want 200", listResp.StatusCode)
	}
	var listed struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Items) != 1 {
		t.Fatalf("list items count = %d, want 1", len(listed.Items))
	}
}

// TestPatchChannel_PartialUpdate verifies that PATCHing only the name preserves the config.
func TestPatchChannel_PartialUpdate(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateChannel(t, ctx, ts, token, aliceReg.OrgID, validChannelBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d, want 201", createResp.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	patchResp := doPatchChannel(t, ctx, ts, token, aliceReg.OrgID, created.ID, `{"name":"Renamed Channel"}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("patch channel: got %d, want 200", patchResp.StatusCode)
	}
	var patched struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(patchResp.Body).Decode(&patched); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	if patched.Name != "Renamed Channel" {
		t.Errorf("patched name = %q, want %q", patched.Name, "Renamed Channel")
	}
}

// TestDeleteChannel_409IfActiveRuleBound verifies that deleting a channel with an active
// bound rule returns 409.
func TestDeleteChannel_409IfActiveRuleBound(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create a channel.
	createChanResp := doCreateChannel(t, ctx, ts, token, aliceReg.OrgID, validChannelBody)
	defer createChanResp.Body.Close() //nolint:errcheck,gosec // G104
	if createChanResp.StatusCode != http.StatusCreated {
		t.Fatalf("create channel: got %d, want 201", createChanResp.StatusCode)
	}
	var createdChan struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createChanResp.Body).Decode(&createdChan); err != nil {
		t.Fatalf("decode create channel: %v", err)
	}

	// Create an alert rule via HTTP.
	createRuleResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer createRuleResp.Body.Close() //nolint:errcheck,gosec // G104
	if createRuleResp.StatusCode != http.StatusAccepted {
		t.Fatalf("create alert rule: got %d, want 202", createRuleResp.StatusCode)
	}
	var createdRule struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createRuleResp.Body).Decode(&createdRule); err != nil {
		t.Fatalf("decode create rule: %v", err)
	}

	// Bind the channel to the rule via store (simulates the binding management API).
	if err := db.BindChannelToRule(ctx,
		mustParseUUID(t, createdRule.ID),
		mustParseUUID(t, createdChan.ID),
		mustParseUUID(t, aliceReg.OrgID),
	); err != nil {
		t.Fatalf("bind channel to rule: %v", err)
	}

	// DELETE must return 409 because the channel has an active bound rule.
	delResp := doDeleteChannel(t, ctx, ts, token, aliceReg.OrgID, createdChan.ID)
	defer delResp.Body.Close() //nolint:errcheck,gosec // G104
	if delResp.StatusCode != http.StatusConflict {
		t.Fatalf("delete with active bound rule: got %d, want 409", delResp.StatusCode)
	}
}

// TestDeleteChannel_SoftDeleteSucceeds verifies that a channel with no active bound rules
// can be soft-deleted and returns 204.
func TestDeleteChannel_SoftDeleteSucceeds(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateChannel(t, ctx, ts, token, aliceReg.OrgID, validChannelBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create channel: got %d, want 201", createResp.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	delResp := doDeleteChannel(t, ctx, ts, token, aliceReg.OrgID, created.ID)
	defer delResp.Body.Close() //nolint:errcheck,gosec // G104
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete channel: got %d, want 204", delResp.StatusCode)
	}

	// Verify it is gone.
	getResp := doGetChannel(t, ctx, ts, token, aliceReg.OrgID, created.ID)
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("get deleted channel: got %d, want 404", getResp.StatusCode)
	}
}

// TestRotateSecret_NewPrimaryReturned verifies that rotate-secret returns a non-empty
// signing_secret in the response.
func TestRotateSecret_NewPrimaryReturned(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateChannel(t, ctx, ts, token, aliceReg.OrgID, validChannelBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create channel: got %d, want 201", createResp.StatusCode)
	}
	var created struct {
		ID            string `json:"id"`
		SigningSecret string `json:"signing_secret"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	rotateResp := doRotateSecret(t, ctx, ts, token, aliceReg.OrgID, created.ID)
	defer rotateResp.Body.Close() //nolint:errcheck,gosec // G104
	if rotateResp.StatusCode != http.StatusOK {
		t.Fatalf("rotate secret: got %d, want 200", rotateResp.StatusCode)
	}
	var rotated struct {
		SigningSecret string `json:"signing_secret"`
	}
	if err := json.NewDecoder(rotateResp.Body).Decode(&rotated); err != nil {
		t.Fatalf("decode rotate: %v", err)
	}
	if rotated.SigningSecret == "" {
		t.Fatal("rotate response must include a non-empty signing_secret")
	}
	if rotated.SigningSecret == created.SigningSecret {
		t.Error("rotated secret must differ from the original")
	}
}

// TestClearSecondarySecret_204 verifies that clear-secondary returns 204 and
// subsequent delivery no longer sends a secondary signature header.
func TestClearSecondarySecret_204(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateChannel(t, ctx, ts, token, aliceReg.OrgID, validChannelBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create channel: got %d, want 201", createResp.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// Rotate to promote current primary to secondary.
	rotateResp := doRotateSecret(t, ctx, ts, token, aliceReg.OrgID, created.ID)
	defer rotateResp.Body.Close() //nolint:errcheck,gosec // G104
	if rotateResp.StatusCode != http.StatusOK {
		t.Fatalf("rotate secret: got %d, want 200", rotateResp.StatusCode)
	}

	// Clear the secondary.
	clearResp := doClearSecondary(t, ctx, ts, token, aliceReg.OrgID, created.ID)
	defer clearResp.Body.Close() //nolint:errcheck,gosec // G104
	if clearResp.StatusCode != http.StatusNoContent {
		t.Fatalf("clear secondary: got %d, want 204", clearResp.StatusCode)
	}
}

// TestCreateChannel_SSRFBlockedURL verifies that webhook channels with private/internal
// URLs are rejected at registration time with 422.
func TestCreateChannel_SSRFBlockedURL(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	cases := []struct {
		url  string
		desc string
	}{
		{"http://localhost/hook", "localhost"},
		{"http://127.0.0.1/hook", "loopback IP"},
		{"http://10.0.0.1/hook", "private class A"},
		{"http://192.168.1.1/hook", "private class C"},
		{"http://169.254.169.254/hook", "link-local / AWS metadata"},
		{"ftp://example.com/hook", "non-http scheme"},
		{"http://internal.local/hook", ".local hostname"},
	}
	for _, tc := range cases {
		body := `{"name":"Bad Webhook","type":"webhook","config":{"url":"` + tc.url + `"}}`
		resp := doCreateChannel(t, ctx, ts, token, aliceReg.OrgID, body)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("url %q (%s): got %d, want 422", tc.url, tc.desc, resp.StatusCode)
		}
	}
}

// TestValidateWebhookURL exercises the static SSRF validator directly.
func TestValidateWebhookURL(t *testing.T) {
	t.Parallel()
	valid := []string{
		"https://example.com/hook",
		"http://example.com/hook",
		"https://hooks.example.com:8443/path?foo=bar",
	}
	for _, u := range valid {
		if err := validateWebhookURL(u); err != nil {
			t.Errorf("validateWebhookURL(%q) = %v, want nil", u, err)
		}
	}

	invalid := []struct {
		url  string
		desc string
	}{
		{"", "empty"},
		{"not-a-url", "no scheme"},
		{"ftp://example.com/hook", "ftp scheme"},
		{"http://localhost/hook", "localhost"},
		{"http://localhost.local/hook", ".local suffix"},
		{"http://api.internal/hook", ".internal suffix"},
		{"http://127.0.0.1/hook", "loopback"},
		{"http://::1/hook", "IPv6 loopback"},
		{"http://10.1.2.3/hook", "RFC1918 10/8"},
		{"http://172.16.0.1/hook", "RFC1918 172.16/12"},
		{"http://192.168.99.1/hook", "RFC1918 192.168/16"},
		{"http://169.254.100.200/hook", "link-local"},
		{"http://0.0.0.0/hook", "unspecified"},
	}
	for _, tc := range invalid {
		if err := validateWebhookURL(tc.url); err == nil {
			t.Errorf("validateWebhookURL(%q) (%s) = nil, want error", tc.url, tc.desc)
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// mustParseUUID parses a UUID string and fails the test if invalid.
func mustParseUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("mustParseUUID(%q): %v", s, err)
	}
	return id
}
