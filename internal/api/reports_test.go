// ABOUTME: Integration tests for scheduled digest report HTTP handlers.
// ABOUTME: Uses real Postgres via testutil.NewTestDB and the full srv.Handler() stack.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// ── HTTP helper functions ─────────────────────────────────────────────────────

func doCreateReport(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/reports", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create report: %v", err)
	}
	return resp
}

func doGetReport(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/reports/"+id, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("get report: %v", err)
	}
	return resp
}

func doListReports(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/reports", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("list reports: %v", err)
	}
	return resp
}

func doPatchReport(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPatch, ts.URL+"/api/v1/orgs/"+orgID+"/reports/"+id, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("patch report: %v", err)
	}
	return resp
}

func doDeleteReport(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, ts.URL+"/api/v1/orgs/"+orgID+"/reports/"+id, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("delete report: %v", err)
	}
	return resp
}

func doBindReportChannel(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, reportID, channelID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut,
		ts.URL+"/api/v1/orgs/"+orgID+"/reports/"+reportID+"/channels/"+channelID, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("bind report channel: %v", err)
	}
	return resp
}

func doUnbindReportChannel(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, reportID, channelID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete,
		ts.URL+"/api/v1/orgs/"+orgID+"/reports/"+reportID+"/channels/"+channelID, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("unbind report channel: %v", err)
	}
	return resp
}

func doListReportChannels(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, reportID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		ts.URL+"/api/v1/orgs/"+orgID+"/reports/"+reportID+"/channels", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("list report channels: %v", err)
	}
	return resp
}

// validReportBody is a minimal valid report body for testing.
const validReportBody = `{"name":"Daily Digest","scheduled_time":"09:00","timezone":"America/New_York"}`

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestCreateReport_Valid(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doCreateReport(t, ctx, ts, token, reg.OrgID, validReportBody)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create report: got %d, want 201", resp.StatusCode)
	}
	var created reportEntry
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("created report has empty ID")
	}
	if created.NextRunAt == "" {
		t.Fatal("created report missing next_run_at")
	}
	if created.Status != "active" {
		t.Errorf("status = %q, want %q", created.Status, "active")
	}
	if created.ScheduledTime != "09:00:00" {
		t.Errorf("scheduled_time = %q, want %q", created.ScheduledTime, "09:00:00")
	}
}

func TestCreateReport_InvalidTimezone(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doCreateReport(t, ctx, ts, token, reg.OrgID,
		`{"name":"Bad TZ","scheduled_time":"09:00","timezone":"Invalid/Zone"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("create with bad timezone: got %d, want 422", resp.StatusCode)
	}
}

func TestCreateReport_MissingName(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doCreateReport(t, ctx, ts, token, reg.OrgID,
		`{"scheduled_time":"09:00","timezone":"UTC"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("create with no name: got %d, want 422", resp.StatusCode)
	}
}

func TestCreateReport_InvalidSeverityThreshold(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doCreateReport(t, ctx, ts, token, reg.OrgID,
		`{"name":"Bad Sev","scheduled_time":"09:00","timezone":"UTC","severity_threshold":"extreme"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("create with bad severity: got %d, want 422", resp.StatusCode)
	}
}

func TestGetReport_NotFound(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doGetReport(t, ctx, ts, token, reg.OrgID, "00000000-0000-0000-0000-000000000099")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("get nonexistent report: got %d, want 404", resp.StatusCode)
	}
}

func TestListReports(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create two reports.
	resp1 := doCreateReport(t, ctx, ts, token, reg.OrgID, validReportBody)
	defer resp1.Body.Close() //nolint:errcheck,gosec // G104
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("create report 1: got %d", resp1.StatusCode)
	}
	resp2 := doCreateReport(t, ctx, ts, token, reg.OrgID,
		`{"name":"Weekly High","scheduled_time":"14:00","timezone":"UTC","severity_threshold":"high"}`)
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("create report 2: got %d", resp2.StatusCode)
	}

	listResp := doListReports(t, ctx, ts, token, reg.OrgID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list reports: got %d, want 200", listResp.StatusCode)
	}
	var list reportListResponse
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Items) != 2 {
		t.Errorf("list items = %d, want 2", len(list.Items))
	}
}

func TestPatchReport_UpdateSchedule(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateReport(t, ctx, ts, token, reg.OrgID, validReportBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created reportEntry
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	origNextRun := created.NextRunAt

	// Patch to a different time.
	patchResp := doPatchReport(t, ctx, ts, token, reg.OrgID, created.ID,
		`{"scheduled_time":"18:30:00"}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("patch report: got %d, want 200", patchResp.StatusCode)
	}
	var patched reportEntry
	if err := json.NewDecoder(patchResp.Body).Decode(&patched); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	if patched.ScheduledTime != "18:30:00" {
		t.Errorf("scheduled_time = %q, want %q", patched.ScheduledTime, "18:30:00")
	}
	if patched.NextRunAt == origNextRun {
		t.Error("next_run_at should have been recalculated after scheduled_time change")
	}
}

func TestPatchReport_Unpause(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateReport(t, ctx, ts, token, reg.OrgID, validReportBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created reportEntry
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// Pause the report.
	pauseResp := doPatchReport(t, ctx, ts, token, reg.OrgID, created.ID, `{"status":"paused"}`)
	defer pauseResp.Body.Close() //nolint:errcheck,gosec // G104
	if pauseResp.StatusCode != http.StatusOK {
		t.Fatalf("pause: got %d, want 200", pauseResp.StatusCode)
	}
	var paused reportEntry
	if err := json.NewDecoder(pauseResp.Body).Decode(&paused); err != nil {
		t.Fatalf("decode pause: %v", err)
	}
	if paused.Status != "paused" {
		t.Fatalf("status after pause = %q, want paused", paused.Status)
	}
	pausedNextRun := paused.NextRunAt

	// Un-pause with a different scheduled_time so next_run_at must change.
	unpauseResp := doPatchReport(t, ctx, ts, token, reg.OrgID, created.ID,
		`{"status":"active","scheduled_time":"23:00"}`)
	defer unpauseResp.Body.Close() //nolint:errcheck,gosec // G104
	if unpauseResp.StatusCode != http.StatusOK {
		t.Fatalf("unpause: got %d, want 200", unpauseResp.StatusCode)
	}
	var unpaused reportEntry
	if err := json.NewDecoder(unpauseResp.Body).Decode(&unpaused); err != nil {
		t.Fatalf("decode unpause: %v", err)
	}
	if unpaused.Status != "active" {
		t.Errorf("status after unpause = %q, want active", unpaused.Status)
	}
	if unpaused.NextRunAt == pausedNextRun {
		t.Error("next_run_at should have been recalculated on unpause")
	}
}

func TestDeleteReport(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateReport(t, ctx, ts, token, reg.OrgID, validReportBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created reportEntry
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	delResp := doDeleteReport(t, ctx, ts, token, reg.OrgID, created.ID)
	defer delResp.Body.Close() //nolint:errcheck,gosec // G104
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: got %d, want 204", delResp.StatusCode)
	}

	// Verify no longer in list.
	listResp := doListReports(t, ctx, ts, token, reg.OrgID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	var list reportListResponse
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("list items after delete = %d, want 0", len(list.Items))
	}
}

func TestBindChannelToReport(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create a report.
	createResp := doCreateReport(t, ctx, ts, token, reg.OrgID, validReportBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created reportEntry
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Create a channel.
	chanResp := doCreateChannel(t, ctx, ts, token, reg.OrgID, validChannelBody)
	defer chanResp.Body.Close() //nolint:errcheck,gosec // G104
	var ch struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(chanResp.Body).Decode(&ch); err != nil {
		t.Fatalf("decode channel: %v", err)
	}

	// Bind channel to report.
	bindResp := doBindReportChannel(t, ctx, ts, token, reg.OrgID, created.ID, ch.ID)
	defer bindResp.Body.Close() //nolint:errcheck,gosec // G104
	if bindResp.StatusCode != http.StatusNoContent {
		t.Fatalf("bind: got %d, want 204", bindResp.StatusCode)
	}

	// Idempotent bind.
	bind2 := doBindReportChannel(t, ctx, ts, token, reg.OrgID, created.ID, ch.ID)
	defer bind2.Body.Close() //nolint:errcheck,gosec // G104
	if bind2.StatusCode != http.StatusNoContent {
		t.Errorf("idempotent bind: got %d, want 204", bind2.StatusCode)
	}

	// List channels should show 1.
	listResp := doListReportChannels(t, ctx, ts, token, reg.OrgID, created.ID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	var list channelListResponse
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Errorf("bound channels = %d, want 1", len(list.Items))
	}
}

func TestUnbindChannelFromReport(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create report + channel + bind.
	createResp := doCreateReport(t, ctx, ts, token, reg.OrgID, validReportBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created reportEntry
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	chanResp := doCreateChannel(t, ctx, ts, token, reg.OrgID, validChannelBody)
	defer chanResp.Body.Close() //nolint:errcheck,gosec // G104
	var ch struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(chanResp.Body).Decode(&ch); err != nil {
		t.Fatalf("decode channel: %v", err)
	}

	bindResp := doBindReportChannel(t, ctx, ts, token, reg.OrgID, created.ID, ch.ID)
	defer bindResp.Body.Close() //nolint:errcheck,gosec // G104

	// Unbind.
	unbindResp := doUnbindReportChannel(t, ctx, ts, token, reg.OrgID, created.ID, ch.ID)
	defer unbindResp.Body.Close() //nolint:errcheck,gosec // G104
	if unbindResp.StatusCode != http.StatusNoContent {
		t.Fatalf("unbind: got %d, want 204", unbindResp.StatusCode)
	}

	// List channels should show 0.
	listResp := doListReportChannels(t, ctx, ts, token, reg.OrgID, created.ID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	var list channelListResponse
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("bound channels after unbind = %d, want 0", len(list.Items))
	}
}
