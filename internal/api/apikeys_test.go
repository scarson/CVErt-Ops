// ABOUTME: Integration tests for API key management: create, list, revoke.
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

// doCreateAPIKey calls POST /api/v1/orgs/{orgID}/api-keys.
func doCreateAPIKey(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, name, role string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q,"role":%q}`, name, role)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/api-keys", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	return resp
}

// doListAPIKeys calls GET /api/v1/orgs/{orgID}/api-keys.
func doListAPIKeys(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/api-keys", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("list api keys: %v", err)
	}
	return resp
}

// doRevokeAPIKey calls DELETE /api/v1/orgs/{orgID}/api-keys/{id}.
func doRevokeAPIKey(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, keyID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, ts.URL+"/api/v1/orgs/"+orgID+"/api-keys/"+keyID, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("revoke api key: %v", err)
	}
	return resp
}

// TestCreateAPIKey_Success verifies that a member+ can create an API key and
// that raw_key is present in the response but absent from list results.
func TestCreateAPIKey_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	resp := doCreateAPIKey(t, ctx, ts, accessToken, aliceReg.OrgID, "CI Key", "member")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create api key: got %d, want 201", resp.StatusCode)
	}

	var out struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Role      string `json:"role"`
		RawKey    string `json:"raw_key"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.ID == "" {
		t.Error("id is empty")
	}
	if out.Name != "CI Key" {
		t.Errorf("name = %q, want %q", out.Name, "CI Key")
	}
	if out.Role != "member" {
		t.Errorf("role = %q, want %q", out.Role, "member")
	}
	if out.RawKey == "" {
		t.Error("raw_key is empty — must be shown once")
	}
	if out.CreatedAt == "" {
		t.Error("created_at is empty")
	}
}

// TestCreateAPIKey_RoleEscalation verifies that a member cannot create a key
// with a role higher than their own (admin).
func TestCreateAPIKey_RoleEscalation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Alice is the org owner.
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	aliceOrgID, _ := uuid.Parse(aliceReg.OrgID)

	// Bob registers separately, then is added as a member to Alice's org.
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "password456")
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, aliceOrgID, bobUserID, "member"); err != nil {
		t.Fatalf("add Bob as member: %v", err)
	}

	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "password456")
	defer bobLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLoginResp, "access_token")

	// Bob (member) tries to create an admin-role key — must be rejected.
	resp := doCreateAPIKey(t, ctx, ts, bobToken, aliceReg.OrgID, "Escalation Key", "admin")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("role escalation: got %d, want 403", resp.StatusCode)
	}
}

// TestListAPIKeys_Success verifies that GET /api-keys returns keys without key_hash.
func TestListAPIKeys_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	// Create two keys.
	r1 := doCreateAPIKey(t, ctx, ts, accessToken, aliceReg.OrgID, "Key One", "member")
	defer r1.Body.Close() //nolint:errcheck,gosec // G104
	if r1.StatusCode != http.StatusCreated {
		t.Fatalf("create key one: %d", r1.StatusCode)
	}
	r2 := doCreateAPIKey(t, ctx, ts, accessToken, aliceReg.OrgID, "Key Two", "viewer")
	defer r2.Body.Close() //nolint:errcheck,gosec // G104
	if r2.StatusCode != http.StatusCreated {
		t.Fatalf("create key two: %d", r2.StatusCode)
	}

	listResp := doListAPIKeys(t, ctx, ts, accessToken, aliceReg.OrgID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list api keys: got %d, want 200", listResp.StatusCode)
	}

	var out []map[string]any
	if err := json.NewDecoder(listResp.Body).Decode(&out); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("list returned %d keys, want 2", len(out))
	}
	for _, entry := range out {
		if _, hasRawKey := entry["raw_key"]; hasRawKey {
			t.Error("list response must not contain raw_key")
		}
		if _, hasHash := entry["key_hash"]; hasHash {
			t.Error("list response must not contain key_hash")
		}
		if entry["id"] == "" {
			t.Error("id is empty")
		}
	}
}

// TestRevokeAPIKey_OwnKey verifies that a member can revoke their own API key.
func TestRevokeAPIKey_OwnKey(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	createResp := doCreateAPIKey(t, ctx, ts, accessToken, aliceReg.OrgID, "My Key", "member")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create key: %d", createResp.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create resp: %v", err)
	}

	revokeResp := doRevokeAPIKey(t, ctx, ts, accessToken, aliceReg.OrgID, created.ID)
	defer revokeResp.Body.Close() //nolint:errcheck,gosec // G104
	if revokeResp.StatusCode != http.StatusNoContent {
		t.Errorf("revoke own key: got %d, want 204", revokeResp.StatusCode)
	}

	// Verify the key is revoked in the DB.
	keyID, _ := uuid.Parse(created.ID)
	orgID, _ := uuid.Parse(aliceReg.OrgID)
	key, err := db.GetOrgAPIKey(ctx, orgID, keyID)
	if err != nil {
		t.Fatalf("get key: %v", err)
	}
	if key == nil {
		t.Fatal("key not found in DB")
	}
	if !key.RevokedAt.Valid {
		t.Error("key should be revoked")
	}
}

// TestRevokeAPIKey_AsAdmin verifies that an admin can revoke another member's key.
func TestRevokeAPIKey_AsAdmin(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Alice is the org owner.
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	aliceOrgID, _ := uuid.Parse(aliceReg.OrgID)

	// Bob is a member of Alice's org.
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "password456")
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, aliceOrgID, bobUserID, "member"); err != nil {
		t.Fatalf("add Bob: %v", err)
	}
	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "password456")
	defer bobLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLoginResp, "access_token")

	// Bob creates his own key.
	bobCreateResp := doCreateAPIKey(t, ctx, ts, bobToken, aliceReg.OrgID, "Bob Key", "member")
	defer bobCreateResp.Body.Close() //nolint:errcheck,gosec // G104
	if bobCreateResp.StatusCode != http.StatusCreated {
		t.Fatalf("Bob create key: %d", bobCreateResp.StatusCode)
	}
	var bobKey struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(bobCreateResp.Body).Decode(&bobKey); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Alice (owner) revokes Bob's key.
	aliceLoginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer aliceLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLoginResp, "access_token")

	revokeResp := doRevokeAPIKey(t, ctx, ts, aliceToken, aliceReg.OrgID, bobKey.ID)
	defer revokeResp.Body.Close() //nolint:errcheck,gosec // G104
	if revokeResp.StatusCode != http.StatusNoContent {
		t.Errorf("admin revoke any key: got %d, want 204", revokeResp.StatusCode)
	}
}

// TestRevokeAPIKey_NotOwner verifies that a member cannot revoke another member's key.
func TestRevokeAPIKey_NotOwner(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Alice is the org owner.
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "password123")
	aliceOrgID, _ := uuid.Parse(aliceReg.OrgID)
	aliceLoginResp := doLogin(t, ctx, ts, "alice@example.com", "password123")
	defer aliceLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLoginResp, "access_token")

	// Bob is a member of Alice's org.
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "password456")
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, aliceOrgID, bobUserID, "member"); err != nil {
		t.Fatalf("add Bob: %v", err)
	}
	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "password456")
	defer bobLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLoginResp, "access_token")

	// Alice creates a key.
	aliceCreateResp := doCreateAPIKey(t, ctx, ts, aliceToken, aliceReg.OrgID, "Alice Key", "member")
	defer aliceCreateResp.Body.Close() //nolint:errcheck,gosec // G104
	if aliceCreateResp.StatusCode != http.StatusCreated {
		t.Fatalf("Alice create key: %d", aliceCreateResp.StatusCode)
	}
	var aliceKey struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(aliceCreateResp.Body).Decode(&aliceKey); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Bob (member) tries to revoke Alice's key — must be rejected.
	revokeResp := doRevokeAPIKey(t, ctx, ts, bobToken, aliceReg.OrgID, aliceKey.ID)
	defer revokeResp.Body.Close() //nolint:errcheck,gosec // G104
	if revokeResp.StatusCode != http.StatusForbidden {
		t.Errorf("member revoke other key: got %d, want 403", revokeResp.StatusCode)
	}
}
