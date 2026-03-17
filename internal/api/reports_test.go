// ABOUTME: Integration tests for scheduled digest report HTTP handlers.
// ABOUTME: Uses real Postgres via testutil.NewTestDB and the full srv.Handler() stack.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

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
	var list listResponse[reportEntry]
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
	var list listResponse[reportEntry]
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
	var list listResponse[channelEntry]
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Errorf("bound channels = %d, want 1", len(list.Items))
	}
}

// TestPatchReport_IndividualFields verifies that patching individual fields works
// independently: name, severity_threshold, send_on_empty, ai_summary.
func TestPatchReport_IndividualFields(t *testing.T) {
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

	// Patch name only.
	resp1 := doPatchReport(t, ctx, ts, token, reg.OrgID, created.ID, `{"name":"Renamed Report"}`)
	defer resp1.Body.Close() //nolint:errcheck,gosec // G104
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("patch name: got %d, want 200", resp1.StatusCode)
	}
	var p1 reportEntry
	if err := json.NewDecoder(resp1.Body).Decode(&p1); err != nil {
		t.Fatalf("decode patch name: %v", err)
	}
	if p1.Name != "Renamed Report" {
		t.Errorf("name = %q, want %q", p1.Name, "Renamed Report")
	}

	// Patch severity_threshold.
	resp2 := doPatchReport(t, ctx, ts, token, reg.OrgID, created.ID, `{"severity_threshold":"high"}`)
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("patch severity: got %d, want 200", resp2.StatusCode)
	}
	var p2 reportEntry
	if err := json.NewDecoder(resp2.Body).Decode(&p2); err != nil {
		t.Fatalf("decode patch severity: %v", err)
	}
	if p2.SeverityThreshold == nil || *p2.SeverityThreshold != "high" {
		t.Errorf("severity_threshold = %v, want high", p2.SeverityThreshold)
	}

	// Patch send_on_empty to false.
	resp3 := doPatchReport(t, ctx, ts, token, reg.OrgID, created.ID, `{"send_on_empty":false}`)
	defer resp3.Body.Close() //nolint:errcheck,gosec // G104
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("patch send_on_empty: got %d, want 200", resp3.StatusCode)
	}
	var p3 reportEntry
	if err := json.NewDecoder(resp3.Body).Decode(&p3); err != nil {
		t.Fatalf("decode patch send_on_empty: %v", err)
	}
	if p3.SendOnEmpty {
		t.Error("send_on_empty should be false after PATCH")
	}

	// Patch ai_summary to true.
	resp4 := doPatchReport(t, ctx, ts, token, reg.OrgID, created.ID, `{"ai_summary":true}`)
	defer resp4.Body.Close() //nolint:errcheck,gosec // G104
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("patch ai_summary: got %d, want 200", resp4.StatusCode)
	}
	var p4 reportEntry
	if err := json.NewDecoder(resp4.Body).Decode(&p4); err != nil {
		t.Fatalf("decode patch ai_summary: %v", err)
	}
	if !p4.AISummary {
		t.Error("ai_summary should be true after PATCH")
	}
}

// TestPatchReport_ClearSeverityThreshold verifies that PATCH with empty string
// severity_threshold clears it to null (no severity filter).
func TestPatchReport_ClearSeverityThreshold(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create report with severity_threshold = "high".
	createResp := doCreateReport(t, ctx, ts, token, reg.OrgID,
		`{"name":"Sev Test","scheduled_time":"09:00","timezone":"UTC","severity_threshold":"high"}`)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d, want 201", createResp.StatusCode)
	}
	var created reportEntry
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.SeverityThreshold == nil || *created.SeverityThreshold != "high" {
		t.Fatalf("created severity_threshold = %v, want high", created.SeverityThreshold)
	}

	// PATCH with empty string to clear severity_threshold.
	patchResp := doPatchReport(t, ctx, ts, token, reg.OrgID, created.ID,
		`{"severity_threshold":""}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("patch clear severity: got %d, want 200", patchResp.StatusCode)
	}
	var patched reportEntry
	if err := json.NewDecoder(patchResp.Body).Decode(&patched); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	if patched.SeverityThreshold != nil {
		t.Errorf("severity_threshold after clear = %v, want nil", *patched.SeverityThreshold)
	}

	// Verify via GET too.
	getResp := doGetReport(t, ctx, ts, token, reg.OrgID, created.ID)
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	var fetched reportEntry
	if err := json.NewDecoder(getResp.Body).Decode(&fetched); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if fetched.SeverityThreshold != nil {
		t.Errorf("severity_threshold after GET = %v, want nil", *fetched.SeverityThreshold)
	}
}

// TestPatchReport_InvalidStatus verifies that invalid status values are rejected.
func TestPatchReport_InvalidStatus(t *testing.T) {
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

	resp := doPatchReport(t, ctx, ts, token, reg.OrgID, created.ID, `{"status":"deleted"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("invalid status: got %d, want 422", resp.StatusCode)
	}
}

// TestPatchReport_InvalidTimezone verifies that an invalid timezone via PATCH returns 422.
func TestPatchReport_InvalidTimezone(t *testing.T) {
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

	resp := doPatchReport(t, ctx, ts, token, reg.OrgID, created.ID, `{"timezone":"Invalid/Zone"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("invalid timezone via PATCH: got %d, want 422", resp.StatusCode)
	}
}

// TestCreateReport_SendOnEmptyDefault verifies that omitting send_on_empty
// defaults to true (matching DB DEFAULT TRUE).
func TestCreateReport_SendOnEmptyDefault(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create without send_on_empty.
	resp := doCreateReport(t, ctx, ts, token, reg.OrgID, validReportBody)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d, want 201", resp.StatusCode)
	}
	var created reportEntry
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !created.SendOnEmpty {
		t.Error("send_on_empty should default to true when omitted")
	}

	// Create with explicit false.
	resp2 := doCreateReport(t, ctx, ts, token, reg.OrgID,
		`{"name":"No Empty","scheduled_time":"10:00","timezone":"UTC","send_on_empty":false}`)
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("create with false: got %d, want 201", resp2.StatusCode)
	}
	var created2 reportEntry
	if err := json.NewDecoder(resp2.Body).Decode(&created2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created2.SendOnEmpty {
		t.Error("send_on_empty should be false when explicitly set")
	}
}

// TestReports_CrossOrgIsolation verifies that org B cannot see or modify org A's reports.
// In "open" registration mode, only the first user gets an auto-created org;
// Bob must create his org explicitly.
func TestReports_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Alice is the first user — she gets an auto-org.
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceLogin := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer aliceLogin.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLogin, "access_token")

	// Bob is the second user — no auto-org, so create one explicitly.
	doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobLogin := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
	defer bobLogin.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLogin, "access_token")

	createOrgReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/orgs", bytes.NewBufferString(`{"name":"Bob Org"}`))
	createOrgReq.Header.Set("Content-Type", "application/json")
	createOrgReq.Header.Set("Cookie", "access_token="+bobToken)
	createOrgReq.Header.Set("X-Requested-By", "CVErt-Ops")
	createOrgResp, err := ts.Client().Do(createOrgReq) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create bob org: %v", err)
	}
	defer createOrgResp.Body.Close() //nolint:errcheck,gosec // G104
	if createOrgResp.StatusCode != http.StatusCreated {
		t.Fatalf("create bob org: got %d, want 201", createOrgResp.StatusCode)
	}
	var bobOrg struct {
		OrgID string `json:"org_id"`
	}
	if err := json.NewDecoder(createOrgResp.Body).Decode(&bobOrg); err != nil {
		t.Fatalf("decode bob org: %v", err)
	}

	// Alice creates a report in her org.
	createResp := doCreateReport(t, ctx, ts, aliceToken, aliceReg.OrgID, validReportBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("alice create: got %d", createResp.StatusCode)
	}
	var created reportEntry
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Bob cannot see Alice's report via GET on his own org.
	getResp := doGetReport(t, ctx, ts, bobToken, bobOrg.OrgID, created.ID)
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("bob get alice's report in bob's org: got %d, want 404", getResp.StatusCode)
	}

	// Bob's list should be empty.
	listResp := doListReports(t, ctx, ts, bobToken, bobOrg.OrgID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	var list listResponse[reportEntry]
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("bob's list should be empty, got %d items", len(list.Items))
	}

	// Bob cannot access Alice's org at all — should get 403.
	crossOrgResp := doGetReport(t, ctx, ts, bobToken, aliceReg.OrgID, created.ID)
	defer crossOrgResp.Body.Close() //nolint:errcheck,gosec // G104
	if crossOrgResp.StatusCode != http.StatusForbidden {
		t.Errorf("bob accessing alice's org: got %d, want 403", crossOrgResp.StatusCode)
	}

	// Alice's report should still exist.
	aliceGet := doGetReport(t, ctx, ts, aliceToken, aliceReg.OrgID, created.ID)
	defer aliceGet.Body.Close() //nolint:errcheck,gosec // G104
	if aliceGet.StatusCode != http.StatusOK {
		t.Errorf("alice's report should still exist: got %d, want 200", aliceGet.StatusCode)
	}
}

// TestCreateReport_DuplicateName verifies that creating two reports with the same
// name in the same org is rejected by the unique constraint.
func TestCreateReport_DuplicateName(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp1 := doCreateReport(t, ctx, ts, token, reg.OrgID, validReportBody)
	defer resp1.Body.Close() //nolint:errcheck,gosec // G104
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("create 1: got %d, want 201", resp1.StatusCode)
	}

	resp2 := doCreateReport(t, ctx, ts, token, reg.OrgID, validReportBody)
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	// DB partial unique index `scheduled_reports_name_uq` prevents duplicate names
	// within the same org. Handler returns 500 (unique violation not caught as 409).
	if resp2.StatusCode == http.StatusCreated {
		t.Error("create duplicate name: should be rejected (unique constraint)")
	}
}

// TestReports_RBAC_ViewerCannotWrite verifies that a viewer-role user can read
// reports but cannot create, update, delete, or manage channel bindings.
func TestReports_RBAC_ViewerCannotWrite(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Alice is the org owner.
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceOrgID, _ := uuid.Parse(aliceReg.OrgID)
	aliceLogin := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer aliceLogin.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLogin, "access_token")

	// Bob is a viewer in Alice's org.
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, aliceOrgID, bobUserID, "viewer"); err != nil {
		t.Fatalf("add Bob as viewer: %v", err)
	}
	bobLogin := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
	defer bobLogin.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLogin, "access_token")

	// Alice creates a report and a channel for bind tests.
	createResp := doCreateReport(t, ctx, ts, aliceToken, aliceReg.OrgID, validReportBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("alice create report: got %d", createResp.StatusCode)
	}
	var report reportEntry
	if err := json.NewDecoder(createResp.Body).Decode(&report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	chanResp := doCreateChannel(t, ctx, ts, aliceToken, aliceReg.OrgID, validChannelBody)
	defer chanResp.Body.Close() //nolint:errcheck,gosec // G104
	var ch struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(chanResp.Body).Decode(&ch); err != nil {
		t.Fatalf("decode channel: %v", err)
	}

	// Viewer CAN read.
	t.Run("GET /reports", func(t *testing.T) {
		resp := doListReports(t, ctx, ts, bobToken, aliceReg.OrgID)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusOK {
			t.Errorf("viewer list reports: got %d, want 200", resp.StatusCode)
		}
	})
	t.Run("GET /reports/{id}", func(t *testing.T) {
		resp := doGetReport(t, ctx, ts, bobToken, aliceReg.OrgID, report.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusOK {
			t.Errorf("viewer get report: got %d, want 200", resp.StatusCode)
		}
	})
	t.Run("GET /reports/{id}/channels", func(t *testing.T) {
		resp := doListReportChannels(t, ctx, ts, bobToken, aliceReg.OrgID, report.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusOK {
			t.Errorf("viewer list report channels: got %d, want 200", resp.StatusCode)
		}
	})

	// Viewer CANNOT write.
	t.Run("POST /reports", func(t *testing.T) {
		resp := doCreateReport(t, ctx, ts, bobToken, aliceReg.OrgID,
			`{"name":"Sneaky Report","scheduled_time":"10:00","timezone":"UTC"}`)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("viewer create report: got %d, want 403", resp.StatusCode)
		}
	})
	t.Run("PATCH /reports/{id}", func(t *testing.T) {
		resp := doPatchReport(t, ctx, ts, bobToken, aliceReg.OrgID, report.ID, `{"name":"Hacked"}`)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("viewer patch report: got %d, want 403", resp.StatusCode)
		}
	})
	t.Run("DELETE /reports/{id}", func(t *testing.T) {
		resp := doDeleteReport(t, ctx, ts, bobToken, aliceReg.OrgID, report.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("viewer delete report: got %d, want 403", resp.StatusCode)
		}
	})
	t.Run("PUT /reports/{id}/channels/{channel_id}", func(t *testing.T) {
		resp := doBindReportChannel(t, ctx, ts, bobToken, aliceReg.OrgID, report.ID, ch.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("viewer bind channel: got %d, want 403", resp.StatusCode)
		}
	})
	t.Run("DELETE /reports/{id}/channels/{channel_id}", func(t *testing.T) {
		resp := doUnbindReportChannel(t, ctx, ts, bobToken, aliceReg.OrgID, report.ID, ch.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("viewer unbind channel: got %d, want 403", resp.StatusCode)
		}
	})
}

// TestBindChannelToReport_CrossOrgChannelRejected verifies that binding
// org B's channel to org A's report is rejected (channel not found in org A).
func TestBindChannelToReport_CrossOrgChannelRejected(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Alice owns org A.
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceLogin := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer aliceLogin.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLogin, "access_token")

	// Bob owns org B.
	doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobLogin := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
	defer bobLogin.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLogin, "access_token")
	bobOrgReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/orgs", bytes.NewBufferString(`{"name":"Bob Org"}`))
	bobOrgReq.Header.Set("Content-Type", "application/json")
	bobOrgReq.Header.Set("Cookie", "access_token="+bobToken)
	bobOrgReq.Header.Set("X-Requested-By", "CVErt-Ops")
	bobOrgResp, err := ts.Client().Do(bobOrgReq) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create bob org: %v", err)
	}
	defer bobOrgResp.Body.Close() //nolint:errcheck,gosec // G104
	var bobOrg struct {
		OrgID string `json:"org_id"`
	}
	if err := json.NewDecoder(bobOrgResp.Body).Decode(&bobOrg); err != nil {
		t.Fatalf("decode bob org: %v", err)
	}

	// Bob creates a channel in his org.
	bobChanResp := doCreateChannel(t, ctx, ts, bobToken, bobOrg.OrgID, validChannelBody)
	defer bobChanResp.Body.Close() //nolint:errcheck,gosec // G104
	if bobChanResp.StatusCode != http.StatusCreated {
		t.Fatalf("bob create channel: got %d", bobChanResp.StatusCode)
	}
	var bobChan struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(bobChanResp.Body).Decode(&bobChan); err != nil {
		t.Fatalf("decode bob channel: %v", err)
	}

	// Alice creates a report in her org.
	createResp := doCreateReport(t, ctx, ts, aliceToken, aliceReg.OrgID, validReportBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var report reportEntry
	if err := json.NewDecoder(createResp.Body).Decode(&report); err != nil {
		t.Fatalf("decode report: %v", err)
	}

	// Alice tries to bind Bob's channel to her report — should fail with 404
	// (channel not found in Alice's org).
	bindResp := doBindReportChannel(t, ctx, ts, aliceToken, aliceReg.OrgID, report.ID, bobChan.ID)
	defer bindResp.Body.Close() //nolint:errcheck,gosec // G104
	if bindResp.StatusCode != http.StatusNotFound {
		t.Errorf("bind cross-org channel: got %d, want 404", bindResp.StatusCode)
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
	var list listResponse[channelEntry]
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("bound channels after unbind = %d, want 0", len(list.Items))
	}
}

// ── Contract tests ────────────────────────────────────────────────────────────

func TestCreateReport_MalformedJSON(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doCreateReport(t, ctx, ts, token, reg.OrgID, `{bad`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed JSON: got %d, want 400", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var problem struct {
		Status int `json:"status"`
		Errors []struct {
			Location string `json:"location"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if len(problem.Errors) == 0 {
		t.Fatal("expected at least one error detail")
	}
	if problem.Errors[0].Location != "body" {
		t.Errorf("errors[0].location = %q, want %q", problem.Errors[0].Location, "body")
	}
}

func TestCreateReport_LocationHeader(t *testing.T) {
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
		t.Fatalf("create: got %d, want 201", resp.StatusCode)
	}
	var created reportEntry
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("Location header is empty")
	}
	if !strings.Contains(loc, created.ID) {
		t.Errorf("Location %q does not contain report ID %q", loc, created.ID)
	}
}

func TestListReports_Envelope(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	listResp := doListReports(t, ctx, ts, token, reg.OrgID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list: got %d, want 200", listResp.StatusCode)
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(listResp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := raw["items"]; !ok {
		t.Fatal("response missing 'items' key")
	}
}

func TestCreateReport_ValidationErrorFormat(t *testing.T) {
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
		t.Fatalf("bad timezone: got %d, want 422", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var problem struct {
		Status int `json:"status"`
		Errors []struct {
			Location string `json:"location"`
			Message  string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Status != http.StatusUnprocessableEntity {
		t.Errorf("problem.status = %d, want 422", problem.Status)
	}
	if len(problem.Errors) == 0 {
		t.Fatal("expected at least one error detail")
	}
	if problem.Errors[0].Location != "body.timezone" {
		t.Errorf("errors[0].location = %q, want %q", problem.Errors[0].Location, "body.timezone")
	}
}
