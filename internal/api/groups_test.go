// ABOUTME: Integration tests for group management API: create, read, update, delete, members.
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

// doCreateGroup calls POST /api/v1/orgs/{orgID}/groups.
func doCreateGroup(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, name, description string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q,"description":%q}`, name, description)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/groups", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	return resp
}

// doListGroups calls GET /api/v1/orgs/{orgID}/groups.
func doListGroups(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/groups", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	return resp
}

// doGetGroup calls GET /api/v1/orgs/{orgID}/groups/{groupID}.
func doGetGroup(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, groupID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/groups/"+groupID, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("get group: %v", err)
	}
	return resp
}

// doUpdateGroup calls PATCH /api/v1/orgs/{orgID}/groups/{groupID}.
func doUpdateGroup(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, groupID, name, description string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q,"description":%q}`, name, description)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPatch, ts.URL+"/api/v1/orgs/"+orgID+"/groups/"+groupID, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("update group: %v", err)
	}
	return resp
}

// doUpdateGroupRaw calls PATCH /api/v1/orgs/{orgID}/groups/{groupID} with a raw JSON body.
// Allows sending partial payloads for pointer DTO testing.
func doUpdateGroupRaw(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, groupID, rawJSON string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPatch, ts.URL+"/api/v1/orgs/"+orgID+"/groups/"+groupID, bytes.NewBufferString(rawJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("update group raw: %v", err)
	}
	return resp
}

// doDeleteGroup calls DELETE /api/v1/orgs/{orgID}/groups/{groupID}.
func doDeleteGroup(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, groupID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, ts.URL+"/api/v1/orgs/"+orgID+"/groups/"+groupID, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("delete group: %v", err)
	}
	return resp
}

// doAddGroupMember calls POST /api/v1/orgs/{orgID}/groups/{groupID}/members.
func doAddGroupMember(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, groupID, userID string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"user_id":%q}`, userID)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/groups/"+groupID+"/members", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("add group member: %v", err)
	}
	return resp
}

// doListGroupMembers calls GET /api/v1/orgs/{orgID}/groups/{groupID}/members.
func doListGroupMembers(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, groupID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/groups/"+groupID+"/members", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("list group members: %v", err)
	}
	return resp
}

// doRemoveGroupMember calls DELETE /api/v1/orgs/{orgID}/groups/{groupID}/members/{userID}.
func doRemoveGroupMember(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, groupID, userID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, ts.URL+"/api/v1/orgs/"+orgID+"/groups/"+groupID+"/members/"+userID, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("remove group member: %v", err)
	}
	return resp
}

// TestCreateGroup_Success verifies that an admin can create a group.
func TestCreateGroup_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	resp := doCreateGroup(t, ctx, ts, accessToken, aliceReg.OrgID, "Engineering", "Engineering team")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create group: got %d, want 201", resp.StatusCode)
	}

	var out struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		CreatedAt   string `json:"created_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.ID == "" {
		t.Error("id is empty")
	}
	if out.Name != "Engineering" {
		t.Errorf("name = %q, want %q", out.Name, "Engineering")
	}
	if out.Description != "Engineering team" {
		t.Errorf("description = %q, want %q", out.Description, "Engineering team")
	}
	if out.CreatedAt == "" {
		t.Error("created_at is empty")
	}
}

// TestCreateGroup_AsViewer verifies that a viewer cannot create a group.
func TestCreateGroup_AsViewer(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceOrgID, _ := uuid.Parse(aliceReg.OrgID)

	bobReg := doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, aliceOrgID, bobUserID, "viewer"); err != nil {
		t.Fatalf("add Bob as viewer: %v", err)
	}

	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
	defer bobLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLoginResp, "access_token")

	resp := doCreateGroup(t, ctx, ts, bobToken, aliceReg.OrgID, "Secret", "")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer create group: got %d, want 403", resp.StatusCode)
	}
}

// TestListGroups_Success verifies that GET /groups returns all non-deleted groups.
func TestListGroups_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	r1 := doCreateGroup(t, ctx, ts, accessToken, aliceReg.OrgID, "Eng", "Engineering")
	defer r1.Body.Close() //nolint:errcheck,gosec // G104
	r2 := doCreateGroup(t, ctx, ts, accessToken, aliceReg.OrgID, "QA", "Quality Assurance")
	defer r2.Body.Close() //nolint:errcheck,gosec // G104
	if r1.StatusCode != http.StatusCreated || r2.StatusCode != http.StatusCreated {
		t.Fatal("create groups failed")
	}

	listResp := doListGroups(t, ctx, ts, accessToken, aliceReg.OrgID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list groups: got %d, want 200", listResp.StatusCode)
	}

	var envelope struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(envelope.Items) != 2 {
		t.Errorf("got %d groups, want 2", len(envelope.Items))
	}
}

// TestGetGroup_Success verifies that GET /groups/{id} returns a single group.
func TestGetGroup_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	createResp := doCreateGroup(t, ctx, ts, accessToken, aliceReg.OrgID, "Eng", "")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	getResp := doGetGroup(t, ctx, ts, accessToken, aliceReg.OrgID, created.ID)
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get group: got %d, want 200", getResp.StatusCode)
	}

	var out struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(getResp.Body).Decode(&out); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if out.ID != created.ID {
		t.Errorf("id = %q, want %q", out.ID, created.ID)
	}
	if out.Name != "Eng" {
		t.Errorf("name = %q, want %q", out.Name, "Eng")
	}
}

// TestUpdateGroup_Success verifies that PATCH /groups/{id} updates the group.
func TestUpdateGroup_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	createResp := doCreateGroup(t, ctx, ts, accessToken, aliceReg.OrgID, "Eng", "")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	updateResp := doUpdateGroup(t, ctx, ts, accessToken, aliceReg.OrgID, created.ID, "Engineering", "All engineers")
	defer updateResp.Body.Close() //nolint:errcheck,gosec // G104
	if updateResp.StatusCode != http.StatusOK {
		t.Fatalf("update group: got %d, want 200", updateResp.StatusCode)
	}

	var out struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(updateResp.Body).Decode(&out); err != nil {
		t.Fatalf("decode update: %v", err)
	}
	if out.Name != "Engineering" {
		t.Errorf("name = %q, want %q", out.Name, "Engineering")
	}
	if out.Description != "All engineers" {
		t.Errorf("description = %q, want %q", out.Description, "All engineers")
	}
}

// TestDeleteGroup_SoftDelete verifies that DELETE /groups/{id} soft-deletes the group
// and it is no longer returned by the list endpoint.
func TestDeleteGroup_SoftDelete(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	createResp := doCreateGroup(t, ctx, ts, accessToken, aliceReg.OrgID, "Temp", "Temporary group")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	deleteResp := doDeleteGroup(t, ctx, ts, accessToken, aliceReg.OrgID, created.ID)
	defer deleteResp.Body.Close() //nolint:errcheck,gosec // G104
	if deleteResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete group: got %d, want 204", deleteResp.StatusCode)
	}

	// Group should no longer appear in list.
	listResp := doListGroups(t, ctx, ts, accessToken, aliceReg.OrgID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	var listEnvelope struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listEnvelope); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listEnvelope.Items) != 0 {
		t.Errorf("after soft-delete, got %d groups, want 0", len(listEnvelope.Items))
	}

	// GET should return 404.
	getResp := doGetGroup(t, ctx, ts, accessToken, aliceReg.OrgID, created.ID)
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("get deleted group: got %d, want 404", getResp.StatusCode)
	}
}

// TestGroupMembers_AddListRemove verifies add → list → remove flow for group members.
func TestGroupMembers_AddListRemove(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Alice is org owner.
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceOrgID, _ := uuid.Parse(aliceReg.OrgID)
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	// Bob is a member of Alice's org.
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, aliceOrgID, bobUserID, "member"); err != nil {
		t.Fatalf("add Bob: %v", err)
	}

	// Create a group.
	createResp := doCreateGroup(t, ctx, ts, accessToken, aliceReg.OrgID, "Dev", "")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var group struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&group); err != nil {
		t.Fatalf("decode group: %v", err)
	}

	// Add Bob to the group.
	addResp := doAddGroupMember(t, ctx, ts, accessToken, aliceReg.OrgID, group.ID, bobReg.UserID)
	defer addResp.Body.Close() //nolint:errcheck,gosec // G104
	if addResp.StatusCode != http.StatusNoContent {
		t.Fatalf("add group member: got %d, want 204", addResp.StatusCode)
	}

	// List members — should include Bob.
	listResp := doListGroupMembers(t, ctx, ts, accessToken, aliceReg.OrgID, group.ID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list group members: got %d, want 200", listResp.StatusCode)
	}

	var membersEnvelope struct {
		Items []struct {
			UserID string `json:"user_id"`
			Email  string `json:"email"`
		} `json:"items"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&membersEnvelope); err != nil {
		t.Fatalf("decode members: %v", err)
	}
	if len(membersEnvelope.Items) != 1 {
		t.Fatalf("got %d members, want 1", len(membersEnvelope.Items))
	}
	if membersEnvelope.Items[0].UserID != bobReg.UserID {
		t.Errorf("member user_id = %q, want %q", membersEnvelope.Items[0].UserID, bobReg.UserID)
	}

	// Remove Bob from the group.
	removeResp := doRemoveGroupMember(t, ctx, ts, accessToken, aliceReg.OrgID, group.ID, bobReg.UserID)
	defer removeResp.Body.Close() //nolint:errcheck,gosec // G104
	if removeResp.StatusCode != http.StatusNoContent {
		t.Fatalf("remove group member: got %d, want 204", removeResp.StatusCode)
	}

	// List should now be empty.
	listResp2 := doListGroupMembers(t, ctx, ts, accessToken, aliceReg.OrgID, group.ID)
	defer listResp2.Body.Close() //nolint:errcheck,gosec // G104
	var members2Envelope struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listResp2.Body).Decode(&members2Envelope); err != nil {
		t.Fatalf("decode members2: %v", err)
	}
	if len(members2Envelope.Items) != 0 {
		t.Errorf("after remove, got %d members, want 0", len(members2Envelope.Items))
	}
}

// ── Cross-org group isolation ─────────────────────────────────────────────────

// TestCrossOrg_GroupAccess verifies that a user from org A cannot access org B's groups.
func TestCrossOrg_GroupAccess(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Alice owns org A with a group.
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceLoginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer aliceLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLoginResp, "access_token")

	createResp := doCreateGroup(t, ctx, ts, aliceToken, aliceReg.OrgID, "Eng", "")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create group: got %d", createResp.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Bob owns org B, tries to access Alice's group.
	doRegister(t, ctx, ts, "bob@example.com", "test-password-1234")
	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "test-password-1234")
	defer bobLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLoginResp, "access_token")

	t.Run("list groups", func(t *testing.T) {
		t.Parallel()
		resp := doListGroups(t, ctx, ts, bobToken, aliceReg.OrgID)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org list groups: got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("get group", func(t *testing.T) {
		t.Parallel()
		resp := doGetGroup(t, ctx, ts, bobToken, aliceReg.OrgID, created.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org get group: got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("update group", func(t *testing.T) {
		t.Parallel()
		resp := doUpdateGroup(t, ctx, ts, bobToken, aliceReg.OrgID, created.ID, "Hacked", "")
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org update group: got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("delete group", func(t *testing.T) {
		t.Parallel()
		resp := doDeleteGroup(t, ctx, ts, bobToken, aliceReg.OrgID, created.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org delete group: got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("add member", func(t *testing.T) {
		t.Parallel()
		resp := doAddGroupMember(t, ctx, ts, bobToken, aliceReg.OrgID, created.ID, uuid.New().String())
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org add group member: got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("list members", func(t *testing.T) {
		t.Parallel()
		resp := doListGroupMembers(t, ctx, ts, bobToken, aliceReg.OrgID, created.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org list group members: got %d, want 403", resp.StatusCode)
		}
	})
}

// TestGetGroup_NotFound verifies that GET /groups/{id} returns 404 for a non-existent group.
func TestGetGroup_NotFound(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	fakeGroupID := uuid.New().String()
	resp := doGetGroup(t, ctx, ts, accessToken, aliceReg.OrgID, fakeGroupID)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("get non-existent group: got %d, want 404", resp.StatusCode)
	}
}

// TestAddGroupMember_Duplicate verifies that adding a member who is already in the group
// does not cause a 500 error. The store layer should handle the duplicate gracefully.
func TestAddGroupMember_Duplicate(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceOrgID, _ := uuid.Parse(aliceReg.OrgID)
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	// Bob is a member of Alice's org.
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, aliceOrgID, bobUserID, "member"); err != nil {
		t.Fatalf("add Bob: %v", err)
	}

	// Create a group.
	createResp := doCreateGroup(t, ctx, ts, accessToken, aliceReg.OrgID, "Dev", "")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var group struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&group); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Add Bob to the group.
	resp1 := doAddGroupMember(t, ctx, ts, accessToken, aliceReg.OrgID, group.ID, bobReg.UserID)
	defer resp1.Body.Close() //nolint:errcheck,gosec // G104
	if resp1.StatusCode != http.StatusNoContent {
		t.Fatalf("first add: got %d, want 204", resp1.StatusCode)
	}

	// Add Bob again — should not return 500.
	resp2 := doAddGroupMember(t, ctx, ts, accessToken, aliceReg.OrgID, group.ID, bobReg.UserID)
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode == http.StatusInternalServerError {
		t.Error("duplicate add returned 500, expected a non-error status")
	}
}

// TestDeleteGroup_NonExistent verifies that DELETE /groups/{id} returns 404 for a
// non-existent group, not a silent 204.
func TestDeleteGroup_NonExistent(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	fakeGroupID := uuid.New().String()
	resp := doDeleteGroup(t, ctx, ts, accessToken, aliceReg.OrgID, fakeGroupID)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("delete non-existent group: got %d, want 404", resp.StatusCode)
	}
}

// TestAddGroupMember_NonExistentGroup verifies that adding a member to a non-existent
// group returns 404, not 500 from an FK violation.
func TestAddGroupMember_NonExistentGroup(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	fakeGroupID := uuid.New().String()
	resp := doAddGroupMember(t, ctx, ts, accessToken, aliceReg.OrgID, fakeGroupID, aliceReg.UserID)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("add member to non-existent group: got %d, want 404", resp.StatusCode)
	}
}

// TestRemoveGroupMember_NonExistentGroup verifies that removing a member from a
// non-existent group returns 404, not a silent 204.
func TestRemoveGroupMember_NonExistentGroup(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	fakeGroupID := uuid.New().String()
	resp := doRemoveGroupMember(t, ctx, ts, accessToken, aliceReg.OrgID, fakeGroupID, aliceReg.UserID)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("remove member from non-existent group: got %d, want 404", resp.StatusCode)
	}
}

// TestCreateGroup_EmptyName verifies that POST /groups with empty name returns 422
// with RFC 9457 problem details and field-level error location.
func TestCreateGroup_EmptyName(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	resp := doCreateGroup(t, ctx, ts, accessToken, aliceReg.OrgID, "", "Description")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("empty name: got %d, want 422", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var problem map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	errs, ok := problem["errors"].([]any)
	if !ok || len(errs) == 0 {
		t.Fatal("expected errors array with at least one entry")
	}
	err0, _ := errs[0].(map[string]any)
	if err0["location"] != "body.name" {
		t.Errorf("errors[0].location = %v, want body.name", err0["location"])
	}
}

// ── Contract tests ────────────────────────────────────────────────────────────

// doCreateGroupRaw calls POST /api/v1/orgs/{orgID}/groups with a raw JSON body.
func doCreateGroupRaw(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, rawJSON string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/groups", bytes.NewBufferString(rawJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("create group raw: %v", err)
	}
	return resp
}

// TestCreateGroup_MalformedJSON verifies that POST /groups with invalid JSON returns 400
// with application/problem+json content type.
func TestCreateGroup_MalformedJSON(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	resp := doCreateGroupRaw(t, ctx, ts, accessToken, aliceReg.OrgID, "{bad json")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed JSON: got %d, want 400", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
}

// TestCreateGroup_LocationHeader verifies that POST /groups returns a Location header.
func TestCreateGroup_LocationHeader(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	resp := doCreateGroup(t, ctx, ts, accessToken, aliceReg.OrgID, "Eng", "")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create group: got %d, want 201", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("expected Location header on 201 response")
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantSuffix := "/groups/" + out.ID
	if len(loc) < len(wantSuffix) || loc[len(loc)-len(wantSuffix):] != wantSuffix {
		t.Errorf("Location = %q, want suffix %q", loc, wantSuffix)
	}
}

// TestListGroups_Envelope verifies that GET /groups returns {items: [...]} envelope.
func TestListGroups_Envelope(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	r1 := doCreateGroup(t, ctx, ts, accessToken, aliceReg.OrgID, "Eng", "")
	defer r1.Body.Close() //nolint:errcheck,gosec // G104

	listResp := doListGroups(t, ctx, ts, accessToken, aliceReg.OrgID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list groups: got %d, want 200", listResp.StatusCode)
	}

	var envelope struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(envelope.Items) != 1 {
		t.Errorf("got %d items, want 1", len(envelope.Items))
	}
}

// TestUpdateGroup_OmittedNamePreserved verifies that PATCH with only description
// preserves the existing name (pointer DTO behavior).
func TestUpdateGroup_OmittedNamePreserved(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	createResp := doCreateGroup(t, ctx, ts, accessToken, aliceReg.OrgID, "Original", "desc")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Send PATCH with only description, omitting name entirely.
	updateResp := doUpdateGroupRaw(t, ctx, ts, accessToken, aliceReg.OrgID, created.ID, `{"description":"updated desc"}`)
	defer updateResp.Body.Close() //nolint:errcheck,gosec // G104
	if updateResp.StatusCode != http.StatusOK {
		t.Fatalf("update: got %d, want 200", updateResp.StatusCode)
	}

	var out struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(updateResp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Name != "Original" {
		t.Errorf("name = %q, want %q (should be preserved)", out.Name, "Original")
	}
	if out.Description != "updated desc" {
		t.Errorf("description = %q, want %q", out.Description, "updated desc")
	}
}

// TestUpdateGroup_EmptyName verifies that PATCH with an empty name string returns 422.
func TestUpdateGroup_EmptyName(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	createResp := doCreateGroup(t, ctx, ts, accessToken, aliceReg.OrgID, "Eng", "")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	updateResp := doUpdateGroupRaw(t, ctx, ts, accessToken, aliceReg.OrgID, created.ID, `{"name":""}`)
	defer updateResp.Body.Close() //nolint:errcheck,gosec // G104
	if updateResp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("empty name: got %d, want 422", updateResp.StatusCode)
	}
	if ct := updateResp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
}

// TestGetGroup_NotFound_ProblemJSON verifies that GET /groups/{id} for an unknown UUID
// returns 404 with application/problem+json content type.
func TestGetGroup_NotFound_ProblemJSON(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	fakeGroupID := uuid.New().String()
	resp := doGetGroup(t, ctx, ts, accessToken, aliceReg.OrgID, fakeGroupID)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("get non-existent group: got %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
}

// TestListGroupMembers_Envelope verifies that GET /groups/{id}/members returns
// {items: [...]} envelope.
func TestListGroupMembers_Envelope(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	createResp := doCreateGroup(t, ctx, ts, accessToken, aliceReg.OrgID, "Eng", "")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	listResp := doListGroupMembers(t, ctx, ts, accessToken, aliceReg.OrgID, created.ID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list members: got %d, want 200", listResp.StatusCode)
	}

	var envelope struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Items should be an empty array (not null).
	if envelope.Items == nil {
		t.Error("items should be an empty array, not null")
	}
}
