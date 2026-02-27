// ABOUTME: Integration tests for org management API: create, read, update.
// ABOUTME: Uses real Postgres via testutil.NewTestDB and the full srv.Handler() stack.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// doCreateOrg calls POST /api/v1/orgs with the given access token and org name.
// Returns the response (caller must close Body).
func doCreateOrg(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, name string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q}`, name)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server
	if err != nil {
		t.Fatalf("create org request: %v", err)
	}
	return resp
}

// doGetOrg calls GET /api/v1/orgs/{orgID} with the given access token.
// Returns the response (caller must close Body).
func doGetOrg(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server
	if err != nil {
		t.Fatalf("get org request: %v", err)
	}
	return resp
}

// doUpdateOrg calls PATCH /api/v1/orgs/{orgID} with the given access token and name.
// Returns the response (caller must close Body).
func doUpdateOrg(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, name string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q}`, name)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPatch, ts.URL+"/api/v1/orgs/"+orgID, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server
	if err != nil {
		t.Fatalf("update org request: %v", err)
	}
	return resp
}

// TestCreateOrg_Success verifies that POST /api/v1/orgs creates an org and
// returns 201 with the org_id and name, and that the creator is set as owner.
func TestCreateOrg_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	aliceUserID, err := uuid.Parse(aliceReg.UserID)
	if err != nil {
		t.Fatalf("parse alice user ID: %v", err)
	}

	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d, want 200", loginResp.StatusCode)
	}
	accessToken := cookieValue(loginResp, "access_token")

	resp := doCreateOrg(t, ctx, ts, accessToken, "Acme Corp")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create org: got %d, want 201", resp.StatusCode)
	}

	var out struct {
		OrgID string `json:"org_id"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.OrgID == "" {
		t.Fatal("org_id is empty")
	}
	if out.Name != "Acme Corp" {
		t.Errorf("name = %q, want %q", out.Name, "Acme Corp")
	}

	// Verify the creator is the owner of the new org.
	orgID, err := uuid.Parse(out.OrgID)
	if err != nil {
		t.Fatalf("parse org ID: %v", err)
	}
	role, err := db.GetOrgMemberRole(ctx, orgID, aliceUserID)
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if role == nil || *role != "owner" {
		t.Errorf("creator role = %v, want owner", role)
	}
}

// TestCreateOrg_Unauthenticated verifies that POST /api/v1/orgs without
// authentication returns 401.
func TestCreateOrg_Unauthenticated(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	body := `{"name":"Test Org"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", resp.StatusCode)
	}
}

// TestGetOrg_Success verifies that GET /api/v1/orgs/{org_id} returns 200 with
// org details for a member.
func TestGetOrg_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	resp := doGetOrg(t, ctx, ts, accessToken, aliceReg.OrgID)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get org: got %d, want 200", resp.StatusCode)
	}

	var out struct {
		OrgID     string `json:"org_id"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.OrgID != aliceReg.OrgID {
		t.Errorf("org_id = %q, want %q", out.OrgID, aliceReg.OrgID)
	}
	if out.Name == "" {
		t.Error("name is empty")
	}
	if out.CreatedAt == "" {
		t.Error("created_at is empty")
	}
}

// TestGetOrg_NotMember verifies that GET /api/v1/orgs/{org_id} returns 403
// when the authenticated user is not a member of the org.
func TestGetOrg_NotMember(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	doRegister(t, ctx, ts, "bob@example.com", "password123")

	loginResp := doLogin(t, ctx, ts, "bob@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(loginResp, "access_token")

	resp := doGetOrg(t, ctx, ts, bobToken, aliceReg.OrgID)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got %d, want 403", resp.StatusCode)
	}
}

// TestUpdateOrg_AsOwner verifies that PATCH /api/v1/orgs/{org_id} returns 200
// and updates the org name when the caller is an owner.
func TestUpdateOrg_AsOwner(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	resp := doUpdateOrg(t, ctx, ts, accessToken, aliceReg.OrgID, "Renamed Org")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update org: got %d, want 200", resp.StatusCode)
	}

	var out struct {
		OrgID string `json:"org_id"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Name != "Renamed Org" {
		t.Errorf("name = %q, want %q", out.Name, "Renamed Org")
	}
}

// TestUpdateOrg_AsViewer verifies that PATCH /api/v1/orgs/{org_id} returns 403
// when the caller only has the viewer role.
func TestUpdateOrg_AsViewer(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "password123")

	// Insert bob as viewer in alice's org via the superuser store.
	orgID, _ := uuid.Parse(aliceReg.OrgID)
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, orgID, bobUserID, "viewer"); err != nil {
		t.Fatalf("add bob as viewer: %v", err)
	}

	loginResp := doLogin(t, ctx, ts, "bob@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(loginResp, "access_token")

	resp := doUpdateOrg(t, ctx, ts, bobToken, aliceReg.OrgID, "Hacked")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got %d, want 403", resp.StatusCode)
	}
}
