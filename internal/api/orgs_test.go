// ABOUTME: Integration tests for org management API: create, read, update, members, invitations.
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

// ── Member management tests ───────────────────────────────────────────────────

// doListMembers calls GET /api/v1/orgs/{orgID}/members.
func doListMembers(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/members", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server
	if err != nil {
		t.Fatalf("list members request: %v", err)
	}
	return resp
}

// doUpdateMemberRole calls PATCH /api/v1/orgs/{orgID}/members/{userID}.
func doUpdateMemberRole(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, userID, role string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"role":%q}`, role)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPatch, ts.URL+"/api/v1/orgs/"+orgID+"/members/"+userID, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server
	if err != nil {
		t.Fatalf("update member role request: %v", err)
	}
	return resp
}

// doRemoveMember calls DELETE /api/v1/orgs/{orgID}/members/{userID}.
func doRemoveMember(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, userID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, ts.URL+"/api/v1/orgs/"+orgID+"/members/"+userID, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server
	if err != nil {
		t.Fatalf("remove member request: %v", err)
	}
	return resp
}

// TestListMembers_Success verifies that GET /members returns 200 with a member list.
func TestListMembers_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	resp := doListMembers(t, ctx, ts, accessToken, aliceReg.OrgID)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list members: got %d, want 200", resp.StatusCode)
	}

	var members []struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
		Email  string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&members); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("len(members) = %d, want 1", len(members))
	}
	if members[0].UserID != aliceReg.UserID {
		t.Errorf("user_id = %q, want %q", members[0].UserID, aliceReg.UserID)
	}
	if members[0].Role != "owner" {
		t.Errorf("role = %q, want owner", members[0].Role)
	}
}

// TestListMembers_NotMember verifies that GET /members returns 403 for non-members.
func TestListMembers_NotMember(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	doRegister(t, ctx, ts, "bob@example.com", "password123")

	loginResp := doLogin(t, ctx, ts, "bob@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(loginResp, "access_token")

	resp := doListMembers(t, ctx, ts, bobToken, aliceReg.OrgID)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got %d, want 403", resp.StatusCode)
	}
}

// TestUpdateMemberRole_Success verifies that PATCH /members/{user_id} updates
// the role and returns 200.
func TestUpdateMemberRole_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "password123")
	orgID, _ := uuid.Parse(aliceReg.OrgID)
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, orgID, bobUserID, "viewer"); err != nil {
		t.Fatalf("add bob: %v", err)
	}

	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(loginResp, "access_token")

	resp := doUpdateMemberRole(t, ctx, ts, aliceToken, aliceReg.OrgID, bobReg.UserID, "member")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update role: got %d, want 200", resp.StatusCode)
	}

	// Verify role was updated in DB.
	role, err := db.GetOrgMemberRole(ctx, orgID, bobUserID)
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if role == nil || *role != "member" {
		t.Errorf("role = %v, want member", role)
	}
}

// TestUpdateMemberRole_CannotAssignOwner verifies that PATCH cannot assign the
// "owner" role (ownership transfer uses a separate endpoint).
func TestUpdateMemberRole_CannotAssignOwner(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "password123")
	orgID, _ := uuid.Parse(aliceReg.OrgID)
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, orgID, bobUserID, "viewer"); err != nil {
		t.Fatalf("add bob: %v", err)
	}

	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(loginResp, "access_token")

	resp := doUpdateMemberRole(t, ctx, ts, aliceToken, aliceReg.OrgID, bobReg.UserID, "owner")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("got %d, want 400", resp.StatusCode)
	}
}

// TestUpdateMemberRole_CannotChangeExistingOwner verifies that PATCH on a
// member who is already an owner returns 403.
func TestUpdateMemberRole_CannotChangeExistingOwner(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// alice is auto-bootstrapped as owner; she tries to demote herself.
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")

	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(loginResp, "access_token")

	resp := doUpdateMemberRole(t, ctx, ts, aliceToken, aliceReg.OrgID, aliceReg.UserID, "member")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got %d, want 403", resp.StatusCode)
	}
}

// TestUpdateMemberRole_CannotExceedCallerRole verifies that a caller cannot
// assign a role higher than their own effective role.
func TestUpdateMemberRole_CannotExceedCallerRole(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "password123")
	carolReg := doRegister(t, ctx, ts, "carol@example.com", "password123")
	orgID, _ := uuid.Parse(aliceReg.OrgID)
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	carolUserID, _ := uuid.Parse(carolReg.UserID)
	// bob is admin, carol is viewer
	if err := db.CreateOrgMember(ctx, orgID, bobUserID, "admin"); err != nil {
		t.Fatalf("add bob: %v", err)
	}
	if err := db.CreateOrgMember(ctx, orgID, carolUserID, "viewer"); err != nil {
		t.Fatalf("add carol: %v", err)
	}

	// Login as bob (admin); try to promote carol to "admin" (equal — OK), then "owner" (blocked)
	loginResp := doLogin(t, ctx, ts, "bob@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(loginResp, "access_token")

	// Admin can promote to member (≤ admin).
	resp := doUpdateMemberRole(t, ctx, ts, bobToken, aliceReg.OrgID, carolReg.UserID, "member")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("promote to member: got %d, want 200", resp.StatusCode)
	}

	// Admin cannot promote to owner (> admin) — "owner" is rejected at the bad-role check.
	resp2 := doUpdateMemberRole(t, ctx, ts, bobToken, aliceReg.OrgID, carolReg.UserID, "owner")
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("promote to owner: got %d, want 400", resp2.StatusCode)
	}
}

// TestRemoveMember_Success verifies that DELETE /members/{user_id} removes the
// member and returns 204.
func TestRemoveMember_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "password123")
	orgID, _ := uuid.Parse(aliceReg.OrgID)
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, orgID, bobUserID, "viewer"); err != nil {
		t.Fatalf("add bob: %v", err)
	}

	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(loginResp, "access_token")

	resp := doRemoveMember(t, ctx, ts, aliceToken, aliceReg.OrgID, bobReg.UserID)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("remove member: got %d, want 204", resp.StatusCode)
	}

	// Verify bob is no longer a member.
	role, err := db.GetOrgMemberRole(ctx, orgID, bobUserID)
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if role != nil {
		t.Errorf("bob still has role %q, want not a member", *role)
	}
}

// TestRemoveMember_SoleOwner verifies that DELETE /members/{user_id} returns 403
// when the target is the sole owner.
func TestRemoveMember_SoleOwner(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")

	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(loginResp, "access_token")

	// Alice tries to remove herself (sole owner).
	resp := doRemoveMember(t, ctx, ts, aliceToken, aliceReg.OrgID, aliceReg.UserID)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got %d, want 403", resp.StatusCode)
	}
}

// ── Invitation tests ──────────────────────────────────────────────────────────

// doCreateInvitation calls POST /api/v1/orgs/{orgID}/invitations.
func doCreateInvitation(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, email, role string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"email":%q,"role":%q}`, email, role)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/invitations", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server
	if err != nil {
		t.Fatalf("create invitation request: %v", err)
	}
	return resp
}

// doListInvitations calls GET /api/v1/orgs/{orgID}/invitations.
func doListInvitations(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/invitations", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server
	if err != nil {
		t.Fatalf("list invitations request: %v", err)
	}
	return resp
}

// doCancelInvitation calls DELETE /api/v1/orgs/{orgID}/invitations/{id}.
func doCancelInvitation(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, invID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, ts.URL+"/api/v1/orgs/"+orgID+"/invitations/"+invID, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server
	if err != nil {
		t.Fatalf("cancel invitation request: %v", err)
	}
	return resp
}

// doGetInvitation calls GET /api/v1/auth/invitations/{token} (public).
func doGetInvitation(t *testing.T, ctx context.Context, ts *httptest.Server, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/auth/invitations/"+token, nil)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server
	if err != nil {
		t.Fatalf("get invitation request: %v", err)
	}
	return resp
}

// doAcceptInvitation calls POST /api/v1/auth/invitations/{token}/accept.
func doAcceptInvitation(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/invitations/"+token+"/accept", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server
	if err != nil {
		t.Fatalf("accept invitation request: %v", err)
	}
	return resp
}

// TestCreateInvitation_Success verifies that POST /invitations returns 202.
func TestCreateInvitation_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(loginResp, "access_token")

	resp := doCreateInvitation(t, ctx, ts, aliceToken, aliceReg.OrgID, "bob@example.com", "member")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create invitation: got %d, want 202", resp.StatusCode)
	}

	var body struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Email != "bob@example.com" {
		t.Errorf("email = %q, want bob@example.com", body.Email)
	}
	if body.Role != "member" {
		t.Errorf("role = %q, want member", body.Role)
	}
	if body.ID == "" {
		t.Error("id is empty")
	}
}

// TestCreateInvitation_AsViewer verifies that a viewer cannot create invitations.
func TestCreateInvitation_AsViewer(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "password123")
	orgID, _ := uuid.Parse(aliceReg.OrgID)
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, orgID, bobUserID, "viewer"); err != nil {
		t.Fatalf("add bob: %v", err)
	}

	loginResp := doLogin(t, ctx, ts, "bob@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(loginResp, "access_token")

	resp := doCreateInvitation(t, ctx, ts, bobToken, aliceReg.OrgID, "carol@example.com", "member")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got %d, want 403", resp.StatusCode)
	}
}

// TestListInvitations_Success verifies that GET /invitations returns pending invitations.
func TestListInvitations_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(loginResp, "access_token")

	// Create an invitation.
	createResp := doCreateInvitation(t, ctx, ts, aliceToken, aliceReg.OrgID, "bob@example.com", "member")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusAccepted {
		t.Fatalf("create invitation: got %d, want 202", createResp.StatusCode)
	}

	resp := doListInvitations(t, ctx, ts, aliceToken, aliceReg.OrgID)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list invitations: got %d, want 200", resp.StatusCode)
	}

	var items []struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("len = %d, want 1", len(items))
	}
	if items[0].Email != "bob@example.com" {
		t.Errorf("email = %q, want bob@example.com", items[0].Email)
	}
}

// TestCancelInvitation_Success verifies that DELETE /invitations/{id} cancels and returns 204.
func TestCancelInvitation_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(loginResp, "access_token")

	// Create an invitation.
	createResp := doCreateInvitation(t, ctx, ts, aliceToken, aliceReg.OrgID, "bob@example.com", "member")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var inv struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&inv); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	resp := doCancelInvitation(t, ctx, ts, aliceToken, aliceReg.OrgID, inv.ID)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("cancel invitation: got %d, want 204", resp.StatusCode)
	}

	// Verify invitation is gone from the list.
	listResp := doListInvitations(t, ctx, ts, aliceToken, aliceReg.OrgID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	var items []struct{ ID string }
	if err := json.NewDecoder(listResp.Body).Decode(&items); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("len = %d, want 0 after cancel", len(items))
	}
}

// TestGetInvitation_Success verifies that GET /auth/invitations/{token} returns org name + role.
func TestGetInvitation_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(loginResp, "access_token")

	// Create invitation and get the token from the DB.
	createResp := doCreateInvitation(t, ctx, ts, aliceToken, aliceReg.OrgID, "bob@example.com", "viewer")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusAccepted {
		t.Fatalf("create invitation: got %d, want 202", createResp.StatusCode)
	}

	orgID, _ := uuid.Parse(aliceReg.OrgID)
	invitations, err := db.ListOrgInvitations(ctx, orgID)
	if err != nil || len(invitations) != 1 {
		t.Fatalf("list invitations from DB: err=%v, len=%d", err, len(invitations))
	}
	token := invitations[0].Token

	resp := doGetInvitation(t, ctx, ts, token)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get invitation: got %d, want 200", resp.StatusCode)
	}

	var body struct {
		OrgName   string `json:"org_name"`
		Role      string `json:"role"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Role != "viewer" {
		t.Errorf("role = %q, want viewer", body.Role)
	}
	if body.OrgName == "" {
		t.Error("org_name is empty")
	}
	if body.ExpiresAt == "" {
		t.Error("expires_at is empty")
	}
}

// TestGetInvitation_NotFound verifies GET /auth/invitations/{token} returns 404 for unknown tokens.
func TestGetInvitation_NotFound(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	resp := doGetInvitation(t, ctx, ts, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want 404", resp.StatusCode)
	}
}

// TestAcceptInvitation_Success verifies POST /auth/invitations/{token}/accept joins the org.
func TestAcceptInvitation_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "password123")

	// Alice creates an invitation for bob.
	aliceLoginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer aliceLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLoginResp, "access_token")

	createResp := doCreateInvitation(t, ctx, ts, aliceToken, aliceReg.OrgID, "bob@example.com", "member")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusAccepted {
		t.Fatalf("create invitation: got %d, want 202", createResp.StatusCode)
	}

	// Get the token from DB.
	orgID, _ := uuid.Parse(aliceReg.OrgID)
	invitations, err := db.ListOrgInvitations(ctx, orgID)
	if err != nil || len(invitations) != 1 {
		t.Fatalf("list invitations from DB: err=%v, len=%d", err, len(invitations))
	}
	invToken := invitations[0].Token

	// Bob accepts.
	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "password123")
	defer bobLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLoginResp, "access_token")

	resp := doAcceptInvitation(t, ctx, ts, bobToken, invToken)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("accept invitation: got %d, want 200", resp.StatusCode)
	}

	// Verify bob is now in Alice's org.
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	role, err := db.GetOrgMemberRole(ctx, orgID, bobUserID)
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if role == nil || *role != "member" {
		t.Errorf("role = %v, want member", role)
	}
}

// TestAcceptInvitation_Idempotent verifies that accepting an already-joined invitation is a no-op.
func TestAcceptInvitation_Idempotent(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "password123")

	aliceLoginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer aliceLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLoginResp, "access_token")

	createResp := doCreateInvitation(t, ctx, ts, aliceToken, aliceReg.OrgID, "bob@example.com", "member")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104

	orgID, _ := uuid.Parse(aliceReg.OrgID)
	invitations, err := db.ListOrgInvitations(ctx, orgID)
	if err != nil || len(invitations) != 1 {
		t.Fatalf("list invitations from DB: err=%v, len=%d", err, len(invitations))
	}
	invToken := invitations[0].Token

	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "password123")
	defer bobLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLoginResp, "access_token")

	// First accept.
	resp1 := doAcceptInvitation(t, ctx, ts, bobToken, invToken)
	defer resp1.Body.Close() //nolint:errcheck,gosec // G104
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first accept: got %d, want 200", resp1.StatusCode)
	}

	// Second accept — bob is already a member, should still return 200.
	resp2 := doAcceptInvitation(t, ctx, ts, bobToken, invToken)
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("second accept: got %d, want 200 (idempotent)", resp2.StatusCode)
	}

	// Verify bob is still in Alice's org with the correct role.
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	role, err := db.GetOrgMemberRole(ctx, orgID, bobUserID)
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if role == nil || *role != "member" {
		t.Errorf("role = %v, want member", role)
	}
}
