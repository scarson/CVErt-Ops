// ABOUTME: Integration tests proving channel credentials never leave the API after creation.
// ABOUTME: Covers every route that returns channel config and the admin edit round trip.
package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/notify"
	"github.com/scarson/cvert-ops/internal/testutil"
)

const (
	storedHeaderCredential = "Bearer stored-header-credential"
	storedWebhookURL       = "https://hook-user:url-password@hooks.example.com/services/url-path-secret?token=url-query-secret" //nolint:gosec // G101: test fixture, not a real credential
	maskedWebhookURL       = "https://hooks.example.com/***"
)

// credentialFragments are the stored values no response may contain.
var credentialFragments = []string{"stored-header-credential", "hook-user", "url-password", "url-path-secret", "url-query-secret"}

const credentialChannelBody = `{"name":"Credentialed Hook","type":"webhook","config":{` +
	`"url":"` + storedWebhookURL + `",` +
	`"custom_headers":{"Authorization":"` + storedHeaderCredential + `","X-Team":"secops"}}}`

type channelRedactionFixture struct {
	db         *testutil.TestDB
	ts         *httptest.Server
	orgID      string
	ownerToken string
	viewerKey  string
	channelID  string
	ruleID     string
	reportID   string
}

// newChannelRedactionFixture registers an owner, stores a credentialed webhook
// channel bound to one alert rule and one report, and issues a viewer API key.
func newChannelRedactionFixture(t *testing.T) *channelRedactionFixture {
	t.Helper()
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "owner@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "owner@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	f := &channelRedactionFixture{db: db, ts: ts, orgID: reg.OrgID, ownerToken: token}

	var channel, rule, report struct {
		ID string `json:"id"`
	}
	channelResp := doCreateChannel(t, ctx, ts, token, reg.OrgID, credentialChannelBody)
	defer channelResp.Body.Close() //nolint:errcheck,gosec // G104
	decodeCreated(t, channelResp, &channel)
	ruleResp := doCreateAlertRule(t, ctx, ts, token, reg.OrgID, validRuleDSL)
	defer ruleResp.Body.Close() //nolint:errcheck,gosec // G104
	decodeCreated(t, ruleResp, &rule)
	reportResp := doCreateReport(t, ctx, ts, token, reg.OrgID, validReportBody)
	defer reportResp.Body.Close() //nolint:errcheck,gosec // G104
	decodeCreated(t, reportResp, &report)
	f.channelID, f.ruleID, f.reportID = channel.ID, rule.ID, report.ID

	bindRule := doBindChannel(t, ctx, ts, token, reg.OrgID, rule.ID, channel.ID)
	defer bindRule.Body.Close() //nolint:errcheck,gosec // G104
	bindReport := doBindReportChannel(t, ctx, ts, token, reg.OrgID, report.ID, channel.ID)
	defer bindReport.Body.Close() //nolint:errcheck,gosec // G104
	if bindRule.StatusCode != http.StatusNoContent || bindReport.StatusCode != http.StatusNoContent {
		t.Fatalf("bind channel: rule %d, report %d, want 204", bindRule.StatusCode, bindReport.StatusCode)
	}

	keyResp := doCreateAPIKey(t, ctx, ts, token, reg.OrgID, "Agent Key", "viewer")
	defer keyResp.Body.Close() //nolint:errcheck,gosec // G104
	var key createAPIKeyResponse
	decodeCreated(t, keyResp, &key)
	f.viewerKey = key.RawKey
	return f
}

func decodeCreated(t *testing.T, resp *http.Response, into any) {
	t.Helper()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d: %s", resp.StatusCode, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
}

func (f *channelRedactionFixture) getWithViewerKey(t *testing.T, path string) string {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, f.ts.URL+"/api/v1/orgs/"+f.orgID+path, nil)
	req.Header.Set("Authorization", "Bearer "+f.viewerKey)
	resp, err := f.ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: got %d: %s", path, resp.StatusCode, body)
	}
	return string(body)
}

func (f *channelRedactionFixture) patch(t *testing.T, body string) (int, string) {
	t.Helper()
	resp := doPatchChannel(t, context.Background(), f.ts, f.ownerToken, f.orgID, f.channelID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	got, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(got)
}

// deliveredConfig reads the channel the way the delivery worker does.
func (f *channelRedactionFixture) deliveredConfig(t *testing.T) notify.WebhookConfig {
	t.Helper()
	row, err := f.db.GetNotificationChannelForDelivery(context.Background(), uuid.MustParse(f.channelID))
	if err != nil || row == nil {
		t.Fatalf("load channel for delivery: row=%v err=%v", row, err)
	}
	return notify.ChannelWebhookConfig(row)
}

func assertStoredCredentialIntact(t *testing.T, cfg notify.WebhookConfig) {
	t.Helper()
	if cfg.URL != storedWebhookURL {
		t.Errorf("stored url = %q, want %q", cfg.URL, storedWebhookURL)
	}
	if cfg.CustomHeaders["Authorization"] != storedHeaderCredential {
		t.Errorf("stored Authorization = %q, want %q", cfg.CustomHeaders["Authorization"], storedHeaderCredential)
	}
}

func assertNoCredential(t *testing.T, label, body string) {
	t.Helper()
	for _, fragment := range credentialFragments {
		if strings.Contains(body, fragment) {
			t.Errorf("%s: response exposes %q: %s", label, fragment, body)
		}
	}
}

// TestChannelRoutes_ViewerKeyCannotReadCredentials reads every route that
// returns channel config with a read-only API key.
func TestChannelRoutes_ViewerKeyCannotReadCredentials(t *testing.T) {
	t.Parallel()
	f := newChannelRedactionFixture(t)

	routes := []struct {
		name string
		path string
	}{
		{"get channel", "/channels/" + f.channelID},
		{"list channels", "/channels"},
		{"rule channels", "/alert-rules/" + f.ruleID + "/channels"},
		{"report channels", "/reports/" + f.reportID + "/channels"},
	}
	for _, route := range routes {
		body := f.getWithViewerKey(t, route.path)
		assertNoCredential(t, route.name, body)
		if !strings.Contains(body, `"Authorization":"[REDACTED]"`) {
			t.Errorf("%s: header name must stay visible with a masked value: %s", route.name, body)
		}
		if !strings.Contains(body, `"X-Team":"[REDACTED]"`) {
			t.Errorf("%s: every header value must be masked: %s", route.name, body)
		}
		if !strings.Contains(body, `"url":"`+maskedWebhookURL+`"`) {
			t.Errorf("%s: url must be reduced to scheme and host: %s", route.name, body)
		}
	}
}

// TestChannelWriteResponses_DoNotEchoCredentials checks the create and patch
// responses returned to an owner.
func TestChannelWriteResponses_DoNotEchoCredentials(t *testing.T) {
	t.Parallel()
	f := newChannelRedactionFixture(t)
	ctx := context.Background()

	second := strings.Replace(credentialChannelBody, "Credentialed Hook", "Second Hook", 1)
	createResp := doCreateChannel(t, ctx, f.ts, f.ownerToken, f.orgID, second)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	created, _ := io.ReadAll(createResp.Body)
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d: %s", createResp.StatusCode, created)
	}
	assertNoCredential(t, "create response", string(created))

	status, patched := f.patch(t, `{"name":"Renamed Hook"}`)
	if status != http.StatusOK {
		t.Fatalf("patch: got %d: %s", status, patched)
	}
	assertNoCredential(t, "patch response", patched)
}

// TestPatchChannel_EditRoundTripKeepsStoredCredential sends the masked config
// an owner reads back through PATCH and checks what delivery will use.
func TestPatchChannel_EditRoundTripKeepsStoredCredential(t *testing.T) {
	t.Parallel()
	f := newChannelRedactionFixture(t)
	ctx := context.Background()

	getResp := doGetChannel(t, ctx, f.ts, f.ownerToken, f.orgID, f.channelID)
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	var read ChannelEntry
	if err := json.NewDecoder(getResp.Body).Decode(&read); err != nil {
		t.Fatalf("decode get: %v", err)
	}

	status, body := f.patch(t, `{"name":"Edited Hook","config":`+string(read.Config)+`}`)
	if status != http.StatusOK {
		t.Fatalf("round trip patch: got %d: %s", status, body)
	}
	assertNoCredential(t, "round trip patch response", body)

	got := f.deliveredConfig(t)
	assertStoredCredentialIntact(t, got)
	if got.CustomHeaders["X-Team"] != "secops" {
		t.Errorf("stored X-Team = %q, want secops", got.CustomHeaders["X-Team"])
	}
}

// TestPatchChannel_ReplacesOnlyWhatTheClientChanged keeps a masked header while
// rotating another value in the same request.
func TestPatchChannel_ReplacesOnlyWhatTheClientChanged(t *testing.T) {
	t.Parallel()
	f := newChannelRedactionFixture(t)

	status, body := f.patch(t, `{"config":{"url":"`+maskedWebhookURL+`","custom_headers":{`+
		`"Authorization":"[REDACTED]","X-Team":"blue","X-Added":"added-value"}}}`)
	if status != http.StatusOK {
		t.Fatalf("patch: got %d: %s", status, body)
	}

	got := f.deliveredConfig(t)
	assertStoredCredentialIntact(t, got)
	if got.CustomHeaders["X-Team"] != "blue" {
		t.Errorf("stored X-Team = %q, want blue", got.CustomHeaders["X-Team"])
	}
	if got.CustomHeaders["X-Added"] != "added-value" {
		t.Errorf("stored X-Added = %q, want added-value", got.CustomHeaders["X-Added"])
	}
}

// TestPatchChannel_NewDestinationNeedsCredentialReentered blocks repointing a
// channel while keeping its masked credential, which would send the stored
// credential to a host the caller chose.
func TestPatchChannel_NewDestinationNeedsCredentialReentered(t *testing.T) {
	t.Parallel()
	maskedHeaders := `"custom_headers":{"Authorization":"[REDACTED]"}`
	cases := []struct {
		name string
		url  string
	}{
		{"different host", "https://collector.example.net/capture"},
		{"https downgraded to http", "http://hooks.example.com/services/plain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newChannelRedactionFixture(t)

			status, body := f.patch(t, `{"config":{"url":"`+tc.url+`",`+maskedHeaders+`}}`)
			if status != http.StatusUnprocessableEntity {
				t.Fatalf("patch: got %d, want 422: %s", status, body)
			}
			assertStoredCredentialIntact(t, f.deliveredConfig(t))
		})
	}
}

// TestPatchChannel_NewDestinationWithFreshCredential accepts a move when the
// caller supplies the header value again.
func TestPatchChannel_NewDestinationWithFreshCredential(t *testing.T) {
	t.Parallel()
	f := newChannelRedactionFixture(t)

	status, body := f.patch(t, `{"config":{"url":"https://other.example.net/hook",`+
		`"custom_headers":{"Authorization":"Bearer replacement"}}}`)
	if status != http.StatusOK {
		t.Fatalf("patch: got %d: %s", status, body)
	}
	got := f.deliveredConfig(t)
	if got.URL != "https://other.example.net/hook" {
		t.Errorf("stored url = %q", got.URL)
	}
	if got.CustomHeaders["Authorization"] != "Bearer replacement" {
		t.Errorf("stored Authorization = %q", got.CustomHeaders["Authorization"])
	}
}

// TestChannelWrites_RejectUnresolvablePlaceholders keeps placeholder text out of
// storage when no stored value exists for it.
func TestChannelWrites_RejectUnresolvablePlaceholders(t *testing.T) {
	t.Parallel()
	f := newChannelRedactionFixture(t)
	ctx := context.Background()

	patches := []struct {
		name string
		body string
	}{
		{"masked value for an unknown header", `{"config":{"url":"` + maskedWebhookURL + `","custom_headers":{"X-Unknown":"[REDACTED]"}}}`},
		{"masked path on another host", `{"config":{"url":"https://other.example.net/***"}}`},
	}
	for _, tc := range patches {
		status, body := f.patch(t, tc.body)
		if status != http.StatusUnprocessableEntity {
			t.Errorf("%s: got %d, want 422: %s", tc.name, status, body)
		}
	}
	assertStoredCredentialIntact(t, f.deliveredConfig(t))

	creates := []struct {
		name string
		body string
	}{
		{"masked header", `{"name":"Copy A","type":"webhook","config":{"url":"https://example.com/hook","custom_headers":{"Authorization":"[REDACTED]"}}}`},
		{"masked url", `{"name":"Copy B","type":"webhook","config":{"url":"https://example.com/***"}}`},
	}
	for _, tc := range creates {
		resp := doCreateChannel(t, ctx, f.ts, f.ownerToken, f.orgID, tc.body)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("create with %s: got %d, want 422", tc.name, resp.StatusCode)
		}
	}
}

// TestChannelAudit_HeaderValuesRedacted confirms the audit log applies the same
// masking as the API.
func TestChannelAudit_HeaderValuesRedacted(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts, aw := newAuditServer(t, db)

	reg := doRegister(t, ctx, ts, "audit-channel@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "audit-channel@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doCreateChannel(t, ctx, ts, token, reg.OrgID, credentialChannelBody)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d", resp.StatusCode)
	}
	aw.Flush()

	entry := findAuditEntry(t, db, uuid.MustParse(reg.OrgID), "channel", "create")
	if entry == nil {
		t.Fatal("no audit entry for channel create")
	}
	assertNoCredential(t, "audit new_state", string(entry.NewState))
}

// TestChannelResponseConfig_MalformedStoredConfigFailsClosed covers stored rows
// the write path can no longer produce.
func TestChannelResponseConfig_MalformedStoredConfigFailsClosed(t *testing.T) {
	t.Parallel()
	for _, stored := range []string{`"https://user:pw@example.com/x"`, `["secret"]`, `not json`} {
		if got := string(channelResponseConfig(json.RawMessage(stored))); got != `{}` {
			t.Errorf("channelResponseConfig(%s) = %s, want {}", stored, got)
		}
	}
}
