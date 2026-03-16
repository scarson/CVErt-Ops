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
	req.Header.Set("X-Requested-By", "CVErt-Ops")
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
	req.Header.Set("X-Requested-By", "CVErt-Ops")
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

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
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
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceOrgID, _ := uuid.Parse(aliceReg.OrgID)

	// Bob registers separately, then is added as a member to Alice's org.
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, aliceOrgID, bobUserID, "member"); err != nil {
		t.Fatalf("add Bob as member: %v", err)
	}

	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
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

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
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

	var envelope struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(envelope.Items) != 2 {
		t.Fatalf("list returned %d keys, want 2", len(envelope.Items))
	}
	for _, entry := range envelope.Items {
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

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
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
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceOrgID, _ := uuid.Parse(aliceReg.OrgID)

	// Bob is a member of Alice's org.
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, aliceOrgID, bobUserID, "member"); err != nil {
		t.Fatalf("add Bob: %v", err)
	}
	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
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
	aliceLoginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
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
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceOrgID, _ := uuid.Parse(aliceReg.OrgID)
	aliceLoginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer aliceLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLoginResp, "access_token")

	// Bob is a member of Alice's org.
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, aliceOrgID, bobUserID, "member"); err != nil {
		t.Fatalf("add Bob: %v", err)
	}
	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
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

// ── Additional API key tests ──────────────────────────────────────────────────

// TestCreateAPIKey_ViewerForbidden verifies that a viewer cannot create API keys.
// The route requires member+ role via RequireOrgRole(RoleMember) middleware.
func TestCreateAPIKey_ViewerForbidden(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceOrgID, _ := uuid.Parse(aliceReg.OrgID)

	// Bob is a viewer in Alice's org.
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, aliceOrgID, bobUserID, "viewer"); err != nil {
		t.Fatalf("add Bob as viewer: %v", err)
	}

	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
	defer bobLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLoginResp, "access_token")

	resp := doCreateAPIKey(t, ctx, ts, bobToken, aliceReg.OrgID, "Sneaky Key", "viewer")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer create api key: got %d, want 403", resp.StatusCode)
	}
}

// TestCreateAPIKey_InvalidRole verifies that creating a key with an invalid role returns 422.
func TestCreateAPIKey_InvalidRole(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	resp := doCreateAPIKey(t, ctx, ts, accessToken, aliceReg.OrgID, "Bad Key", "superadmin")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("invalid role: got %d, want 422", resp.StatusCode)
	}
}

// TestRevokeAPIKey_Idempotent verifies that revoking an already-revoked key does not error.
func TestRevokeAPIKey_Idempotent(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	createResp := doCreateAPIKey(t, ctx, ts, accessToken, aliceReg.OrgID, "Revoke Twice", "member")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create key: %d", createResp.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// First revoke.
	resp1 := doRevokeAPIKey(t, ctx, ts, accessToken, aliceReg.OrgID, created.ID)
	defer resp1.Body.Close() //nolint:errcheck,gosec // G104
	if resp1.StatusCode != http.StatusNoContent {
		t.Fatalf("first revoke: got %d, want 204", resp1.StatusCode)
	}

	// Second revoke — should not return 500.
	resp2 := doRevokeAPIKey(t, ctx, ts, accessToken, aliceReg.OrgID, created.ID)
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode == http.StatusInternalServerError {
		t.Error("second revoke returned 500 — should be idempotent")
	}
}

// TestCrossOrg_APIKeyAccess verifies that a user from org A cannot access org B's API keys.
func TestCrossOrg_APIKeyAccess(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Alice owns org A, Bob owns org B.
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	doRegister(t, ctx, ts, "bob@example.com", "test-password-1234")

	// Alice creates a key in her org.
	aliceLoginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer aliceLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLoginResp, "access_token")

	createResp := doCreateAPIKey(t, ctx, ts, aliceToken, aliceReg.OrgID, "Alice Key", "member")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create key: %d", createResp.StatusCode)
	}
	var aliceKey struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&aliceKey); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Bob tries to access Alice's org's API keys.
	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "test-password-1234")
	defer bobLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLoginResp, "access_token")

	t.Run("list keys", func(t *testing.T) {
		t.Parallel()
		resp := doListAPIKeys(t, ctx, ts, bobToken, aliceReg.OrgID)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org list api keys: got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("create key", func(t *testing.T) {
		t.Parallel()
		resp := doCreateAPIKey(t, ctx, ts, bobToken, aliceReg.OrgID, "Hacked Key", "viewer")
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org create api key: got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("revoke key", func(t *testing.T) {
		t.Parallel()
		resp := doRevokeAPIKey(t, ctx, ts, bobToken, aliceReg.OrgID, aliceKey.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org revoke api key: got %d, want 403", resp.StatusCode)
		}
	})
}

// ── Contract tests ────────────────────────────────────────────────────────────

// doCreateAPIKeyRaw calls POST /api/v1/orgs/{orgID}/api-keys with a raw JSON body.
func doCreateAPIKeyRaw(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, rawJSON string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/api-keys", bytes.NewBufferString(rawJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("create api key raw: %v", err)
	}
	return resp
}

// TestCreateAPIKey_MalformedJSON verifies that POST /api-keys with invalid JSON returns 400
// with application/problem+json content type.
func TestCreateAPIKey_MalformedJSON(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	resp := doCreateAPIKeyRaw(t, ctx, ts, accessToken, aliceReg.OrgID, "{bad json")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed JSON: got %d, want 400", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
}

// TestCreateAPIKey_LocationHeader verifies that POST /api-keys returns a Location header.
func TestCreateAPIKey_LocationHeader(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	resp := doCreateAPIKey(t, ctx, ts, accessToken, aliceReg.OrgID, "Location Key", "member")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create api key: got %d, want 201", resp.StatusCode)
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
	wantSuffix := "/api-keys/" + out.ID
	if len(loc) < len(wantSuffix) || loc[len(loc)-len(wantSuffix):] != wantSuffix {
		t.Errorf("Location = %q, want suffix %q", loc, wantSuffix)
	}
}

// TestListAPIKeys_Envelope verifies that GET /api-keys returns {items: [...]} envelope.
func TestListAPIKeys_Envelope(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	// Create one key.
	r1 := doCreateAPIKey(t, ctx, ts, accessToken, aliceReg.OrgID, "Env Key", "member")
	defer r1.Body.Close() //nolint:errcheck,gosec // G104

	listResp := doListAPIKeys(t, ctx, ts, accessToken, aliceReg.OrgID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list: got %d, want 200", listResp.StatusCode)
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

// TestCreateAPIKey_ValidationError_ProblemJSON verifies that validation errors
// return 422 with application/problem+json and field-level error locations.
func TestCreateAPIKey_ValidationError_ProblemJSON(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	// Empty name should return 422.
	resp := doCreateAPIKeyRaw(t, ctx, ts, accessToken, aliceReg.OrgID, `{"name":"","role":"member"}`)
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
