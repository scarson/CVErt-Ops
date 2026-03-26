// ABOUTME: Integration tests for SCIM admin endpoints (config CRUD, token rotation, group mapping).
// ABOUTME: Uses standard auth (cookie-based), enterprise tier gating, and owner/admin RBAC.
package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/secure"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// ── SCIM admin test helpers ─────────────────────────────────────────────────

// scimAdminEnv holds the test environment for SCIM admin tests.
type scimAdminEnv struct {
	srv   *Server
	ts    *httptest.Server
	db    *testutil.TestDB
	ew    *secure.EventWriter
	orgID uuid.UUID
	token string // owner access token
}

func newSCIMAdminEnv(t *testing.T) *scimAdminEnv {
	t.Helper()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	cfg := &config.Config{ //nolint:exhaustruct,gosec // test: only relevant fields; G101 false positive
		JWTSecret:           "scim-admin-test-secret-32-bytes!",
		RegistrationMode:    "open",
		Argon2MaxConcurrent: 5,
		MFAPendingTokenTTL:  5 * time.Minute,
		SSOEncryptionKey:    hex.EncodeToString([]byte("12345678901234567890123456789012")),
	}
	ew := secure.NewEventWriter(db.Store)
	srv, err := NewServer(db.Store, cfg, ServerDeps{EventWriter: ew})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.Close)

	// Register owner and set enterprise tier.
	reg := doRegister(t, ctx, ts, "scim-admin-owner@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "scim-admin-owner@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	ownerToken := cookieValue(loginResp, "access_token")

	orgID := mustParseUUID(t, reg.OrgID)
	if err := db.UpdateOrgTier(ctx, orgID, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	srv.tierCache.Invalidate(orgID)

	return &scimAdminEnv{
		srv:   srv,
		ts:    ts,
		db:    db,
		ew:    ew,
		orgID: orgID,
		token: ownerToken,
	}
}

// createSSOForSCIM creates an SSO connection prerequisite.
func (env *scimAdminEnv) createSSOForSCIM(t *testing.T) {
	t.Helper()
	body := `{"display_name":"SCIM Test IdP","issuer_url":"https://idp.test.com","client_id":"test-client","client_secret":"test-secret"}`
	resp := doCreateSSO(t, context.Background(), env.ts, env.token, env.orgID.String(), body)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create SSO: got %d, want 201. Body: %s", resp.StatusCode, b)
	}
}

func doSCIMConfigCreate(t *testing.T, ts *httptest.Server, token, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		ts.URL+"/api/v1/orgs/"+orgID+"/sso/scim", nil)
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("SCIM config create: %v", err)
	}
	return resp
}

func doSCIMConfigGet(t *testing.T, ts *httptest.Server, token, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		ts.URL+"/api/v1/orgs/"+orgID+"/sso/scim", nil)
	req.Header.Set("Cookie", "access_token="+token)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("SCIM config get: %v", err)
	}
	return resp
}

func doSCIMConfigPatch(t *testing.T, ts *httptest.Server, token, orgID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPatch,
		ts.URL+"/api/v1/orgs/"+orgID+"/sso/scim", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("SCIM config patch: %v", err)
	}
	return resp
}

func doSCIMConfigDelete(t *testing.T, ts *httptest.Server, token, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete,
		ts.URL+"/api/v1/orgs/"+orgID+"/sso/scim", nil)
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("SCIM config delete: %v", err)
	}
	return resp
}

func doSCIMTokenRotate(t *testing.T, ts *httptest.Server, token, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		ts.URL+"/api/v1/orgs/"+orgID+"/sso/scim/rotate-token", nil)
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("SCIM token rotate: %v", err)
	}
	return resp
}

func doSCIMGroupsList(t *testing.T, ts *httptest.Server, token, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		ts.URL+"/api/v1/orgs/"+orgID+"/sso/scim/groups", nil)
	req.Header.Set("Cookie", "access_token="+token)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("SCIM groups list: %v", err)
	}
	return resp
}

func doSCIMGroupMappingPatch(t *testing.T, ts *httptest.Server, token, orgID, groupID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPatch,
		ts.URL+"/api/v1/orgs/"+orgID+"/sso/scim/groups/"+groupID+"/mapping", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("SCIM group mapping patch: %v", err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out
}

// ── Config CRUD tests ───────────────────────────────────────────────────────

func TestSCIMConfig_Create(t *testing.T) {
	t.Parallel()
	env := newSCIMAdminEnv(t)
	env.createSSOForSCIM(t)

	resp := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d, want 201. Body: %s", resp.StatusCode, b)
	}

	body := readBody(t, resp)
	if body["id"] == nil || body["id"] == "" {
		t.Error("id should be set")
	}
	if body["org_id"] != env.orgID.String() {
		t.Errorf("org_id = %v, want %s", body["org_id"], env.orgID)
	}
	if body["enabled"] != false {
		t.Errorf("enabled = %v, want false", body["enabled"])
	}
	if body["default_role"] != "viewer" {
		t.Errorf("default_role = %v, want viewer", body["default_role"])
	}
	if body["token"] == nil || body["token"] == "" {
		t.Error("token should be returned on create")
	}
	if body["token_prefix"] == nil || body["token_prefix"] == "" {
		t.Error("token_prefix should be set")
	}

	// Verify the security event was emitted.
	events := flushAndQueryEvents(t, env.ew, env.db, secure.EventSCIMTokenCreated)
	if len(events) == 0 {
		t.Error("expected EventSCIMTokenCreated security event")
	}
}

func TestSCIMConfig_Create_RequiresSSO(t *testing.T) {
	t.Parallel()
	env := newSCIMAdminEnv(t)
	// No SSO connection created.

	resp := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create without SSO: got %d, want 400. Body: %s", resp.StatusCode, b)
	}
}

func TestSCIMConfig_Create_EnterpriseOnly(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	cfg := &config.Config{ //nolint:exhaustruct,gosec // test: only relevant fields; G101 false positive
		JWTSecret:           "scim-tier-test-secret-32-bytes!!",
		RegistrationMode:    "open",
		Argon2MaxConcurrent: 5,
		MFAPendingTokenTTL:  5 * time.Minute,
		SSOEncryptionKey:    hex.EncodeToString([]byte("12345678901234567890123456789012")),
	}
	srv, err := NewServer(db.Store, cfg, ServerDeps{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.Close)

	reg := doRegister(t, ctx, ts, "scim-free-tier@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "scim-free-tier@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Org defaults to "free" tier — SCIM should be blocked.
	resp := doSCIMConfigCreate(t, ts, token, reg.OrgID)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("free tier create: got %d, want 403. Body: %s", resp.StatusCode, b)
	}
}

func TestSCIMConfig_Create_Duplicate(t *testing.T) {
	t.Parallel()
	env := newSCIMAdminEnv(t)
	env.createSSOForSCIM(t)

	// First create.
	resp1 := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer resp1.Body.Close() //nolint:errcheck,gosec // G104
	if resp1.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp1.Body)
		t.Fatalf("first create: got %d, want 201. Body: %s", resp1.StatusCode, b)
	}

	// Second create → 409.
	resp2 := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("duplicate create: got %d, want 409. Body: %s", resp2.StatusCode, b)
	}
}

func TestSCIMConfig_Get_TokenMasked(t *testing.T) {
	t.Parallel()
	env := newSCIMAdminEnv(t)
	env.createSSOForSCIM(t)

	// Create config.
	createResp := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create: got %d. Body: %s", createResp.StatusCode, b)
	}

	// GET should not return token.
	getResp := doSCIMConfigGet(t, env.ts, env.token, env.orgID.String())
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	if getResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(getResp.Body)
		t.Fatalf("get: got %d. Body: %s", getResp.StatusCode, b)
	}
	body := readBody(t, getResp)
	if body["token"] != nil {
		t.Errorf("GET should not return token, got: %v", body["token"])
	}
	if body["token_prefix"] == nil || body["token_prefix"] == "" {
		t.Error("GET should return token_prefix")
	}
	if body["updated_at"] == nil || body["updated_at"] == "" {
		t.Error("GET should return updated_at")
	}
}

func TestSCIMConfig_Enable_Disable(t *testing.T) {
	t.Parallel()
	env := newSCIMAdminEnv(t)
	env.createSSOForSCIM(t)

	createResp := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create: got %d. Body: %s", createResp.StatusCode, b)
	}

	// Enable.
	resp1 := doSCIMConfigPatch(t, env.ts, env.token, env.orgID.String(), `{"enabled":true}`)
	defer resp1.Body.Close() //nolint:errcheck,gosec // G104
	if resp1.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp1.Body)
		t.Fatalf("patch enable: got %d. Body: %s", resp1.StatusCode, b)
	}
	body := readBody(t, resp1)
	if body["enabled"] != true {
		t.Errorf("after enable: enabled = %v, want true", body["enabled"])
	}

	// Disable.
	resp2 := doSCIMConfigPatch(t, env.ts, env.token, env.orgID.String(), `{"enabled":false}`)
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("patch disable: got %d. Body: %s", resp2.StatusCode, b)
	}
	body2 := readBody(t, resp2)
	if body2["enabled"] != false {
		t.Errorf("after disable: enabled = %v, want false", body2["enabled"])
	}

	// Update default_role.
	resp3 := doSCIMConfigPatch(t, env.ts, env.token, env.orgID.String(), `{"default_role":"member"}`)
	defer resp3.Body.Close() //nolint:errcheck,gosec // G104
	if resp3.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp3.Body)
		t.Fatalf("patch default_role: got %d. Body: %s", resp3.StatusCode, b)
	}
	body3 := readBody(t, resp3)
	if body3["default_role"] != "member" {
		t.Errorf("default_role = %v, want member", body3["default_role"])
	}

	// Invalid default_role.
	resp4 := doSCIMConfigPatch(t, env.ts, env.token, env.orgID.String(), `{"default_role":"admin"}`)
	defer resp4.Body.Close() //nolint:errcheck,gosec // G104
	if resp4.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp4.Body)
		t.Fatalf("patch invalid role: got %d, want 400. Body: %s", resp4.StatusCode, b)
	}
}

func TestSCIMConfig_Delete(t *testing.T) {
	t.Parallel()
	env := newSCIMAdminEnv(t)
	env.createSSOForSCIM(t)

	createResp := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create: got %d. Body: %s", createResp.StatusCode, b)
	}

	// Delete.
	resp := doSCIMConfigDelete(t, env.ts, env.token, env.orgID.String())
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("delete: got %d, want 204. Body: %s", resp.StatusCode, b)
	}

	// GET after delete → 404.
	getResp := doSCIMConfigGet(t, env.ts, env.token, env.orgID.String())
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("get after delete: got %d, want 404", getResp.StatusCode)
	}

	// Idempotent delete → still 204.
	resp2 := doSCIMConfigDelete(t, env.ts, env.token, env.orgID.String())
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusNoContent {
		t.Errorf("idempotent delete: got %d, want 204", resp2.StatusCode)
	}
}

func TestSCIMConfig_Delete_GroupsSurvive(t *testing.T) {
	t.Parallel()
	env := newSCIMAdminEnv(t)
	ctx := context.Background()
	env.createSSOForSCIM(t)

	createResp := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create: got %d. Body: %s", createResp.StatusCode, b)
	}

	// Create a SCIM group directly via store.
	_, err := env.db.CreateSCIMGroup(ctx, env.orgID, nil, "Engineering")
	if err != nil {
		t.Fatalf("create scim group: %v", err)
	}

	// Delete SCIM config.
	resp := doSCIMConfigDelete(t, env.ts, env.token, env.orgID.String())
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("delete: got %d. Body: %s", resp.StatusCode, b)
	}

	// SCIM groups should survive (they reference org directly, not config).
	groups, err := env.db.ListSCIMGroups(ctx, env.orgID)
	if err != nil {
		t.Fatalf("list scim groups after delete: %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("expected 1 scim group to survive config delete, got %d", len(groups))
	}
}

func TestSCIMConfig_RotateToken(t *testing.T) {
	t.Parallel()
	env := newSCIMAdminEnv(t)
	env.createSSOForSCIM(t)

	// Create config.
	createResp := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create: got %d. Body: %s", createResp.StatusCode, b)
	}
	createBody := readBody(t, createResp)
	oldToken := createBody["token"].(string)

	// Rotate token.
	rotateResp := doSCIMTokenRotate(t, env.ts, env.token, env.orgID.String())
	defer rotateResp.Body.Close() //nolint:errcheck,gosec // G104
	if rotateResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(rotateResp.Body)
		t.Fatalf("rotate: got %d, want 200. Body: %s", rotateResp.StatusCode, b)
	}
	rotateBody := readBody(t, rotateResp)
	newToken := rotateBody["token"].(string)
	newPrefix := rotateBody["token_prefix"].(string)

	if newToken == oldToken {
		t.Error("new token should differ from old token")
	}
	if newPrefix == "" {
		t.Error("new token_prefix should be set")
	}

	// Verify old token hash no longer matches.
	oldHash := auth.HashSCIMToken(oldToken)
	cfg, err := env.db.LookupSCIMConfigByTokenHash(context.Background(), oldHash)
	if err != nil {
		t.Fatalf("lookup by old hash: %v", err)
	}
	if cfg != nil {
		t.Error("old token hash should no longer resolve to a config")
	}

	// Verify new token hash resolves.
	newHash := auth.HashSCIMToken(newToken)
	cfg, err = env.db.LookupSCIMConfigByTokenHash(context.Background(), newHash)
	if err != nil {
		t.Fatalf("lookup by new hash: %v", err)
	}
	if cfg == nil {
		t.Error("new token hash should resolve to the config")
	}

	// Verify security event.
	events := flushAndQueryEvents(t, env.ew, env.db, secure.EventSCIMTokenRotated)
	if len(events) == 0 {
		t.Error("expected EventSCIMTokenRotated security event")
	}
}

func TestSCIMConfig_RBAC(t *testing.T) {
	t.Parallel()
	env := newSCIMAdminEnv(t)
	ctx := context.Background()
	env.createSSOForSCIM(t)

	// Create a viewer in the same org.
	viewerReg := doRegister(t, ctx, env.ts, "scim-rbac-viewer@example.com", "test-password-1234")
	viewerID := mustParseUUID(t, viewerReg.UserID)
	if err := env.db.CreateOrgMember(ctx, env.orgID, viewerID, "viewer"); err != nil {
		t.Fatalf("create viewer member: %v", err)
	}
	viewerLogin := doLogin(t, ctx, env.ts, "scim-rbac-viewer@example.com", "test-password-1234")
	defer viewerLogin.Body.Close() //nolint:errcheck,gosec // G104
	viewerToken := cookieValue(viewerLogin, "access_token")

	// Create an admin in the same org.
	adminReg := doRegister(t, ctx, env.ts, "scim-rbac-admin@example.com", "test-password-1234")
	adminID := mustParseUUID(t, adminReg.UserID)
	if err := env.db.CreateOrgMember(ctx, env.orgID, adminID, "admin"); err != nil {
		t.Fatalf("create admin member: %v", err)
	}
	adminLogin := doLogin(t, ctx, env.ts, "scim-rbac-admin@example.com", "test-password-1234")
	defer adminLogin.Body.Close() //nolint:errcheck,gosec // G104
	adminToken := cookieValue(adminLogin, "access_token")

	// Viewer cannot create SCIM config (owner-only).
	resp := doSCIMConfigCreate(t, env.ts, viewerToken, env.orgID.String())
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer create: got %d, want 403", resp.StatusCode)
	}

	// Admin cannot create SCIM config (owner-only).
	resp2 := doSCIMConfigCreate(t, env.ts, adminToken, env.orgID.String())
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("admin create: got %d, want 403", resp2.StatusCode)
	}

	// Owner creates config for further tests.
	createResp := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(createResp.Body)
		t.Fatalf("owner create: got %d. Body: %s", createResp.StatusCode, b)
	}

	// Admin CAN get SCIM config.
	getResp := doSCIMConfigGet(t, env.ts, adminToken, env.orgID.String())
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	if getResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(getResp.Body)
		t.Errorf("admin get: got %d, want 200. Body: %s", getResp.StatusCode, b)
	}

	// Viewer cannot get SCIM config (admin+ required).
	getResp2 := doSCIMConfigGet(t, env.ts, viewerToken, env.orgID.String())
	defer getResp2.Body.Close() //nolint:errcheck,gosec // G104
	if getResp2.StatusCode != http.StatusForbidden {
		t.Errorf("viewer get: got %d, want 403", getResp2.StatusCode)
	}

	// Admin cannot patch (owner-only).
	patchResp := doSCIMConfigPatch(t, env.ts, adminToken, env.orgID.String(), `{"enabled":true}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusForbidden {
		t.Errorf("admin patch: got %d, want 403", patchResp.StatusCode)
	}

	// Admin cannot delete (owner-only).
	delResp := doSCIMConfigDelete(t, env.ts, adminToken, env.orgID.String())
	defer delResp.Body.Close() //nolint:errcheck,gosec // G104
	if delResp.StatusCode != http.StatusForbidden {
		t.Errorf("admin delete: got %d, want 403", delResp.StatusCode)
	}

	// Admin cannot rotate token (owner-only).
	rotResp := doSCIMTokenRotate(t, env.ts, adminToken, env.orgID.String())
	defer rotResp.Body.Close() //nolint:errcheck,gosec // G104
	if rotResp.StatusCode != http.StatusForbidden {
		t.Errorf("admin rotate: got %d, want 403", rotResp.StatusCode)
	}

	// Admin CAN list groups.
	groupsResp := doSCIMGroupsList(t, env.ts, adminToken, env.orgID.String())
	defer groupsResp.Body.Close() //nolint:errcheck,gosec // G104
	if groupsResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(groupsResp.Body)
		t.Errorf("admin list groups: got %d, want 200. Body: %s", groupsResp.StatusCode, b)
	}
}

// ── Group Mapping tests ─────────────────────────────────────────────────────

func TestGroupMapping_SetRole(t *testing.T) {
	t.Parallel()
	env := newSCIMAdminEnv(t)
	ctx := context.Background()
	env.createSSOForSCIM(t)

	// Create SCIM config.
	createResp := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create config: got %d. Body: %s", createResp.StatusCode, b)
	}

	// Create a SCIM group.
	scimGroup, err := env.db.CreateSCIMGroup(ctx, env.orgID, nil, "Admins")
	if err != nil {
		t.Fatalf("create scim group: %v", err)
	}

	// Create a member in the org for role recomputation testing.
	memberReg := doRegister(t, ctx, env.ts, "scim-mapping-member@example.com", "test-password-1234")
	memberID := mustParseUUID(t, memberReg.UserID)
	if err := env.db.CreateOrgMember(ctx, env.orgID, memberID, "viewer"); err != nil {
		t.Fatalf("create org member: %v", err)
	}

	// Add member to the SCIM group.
	if err := env.db.AddSCIMGroupMember(ctx, scimGroup.ID, memberID, env.orgID); err != nil {
		t.Fatalf("add scim group member: %v", err)
	}

	// Set mapped_role → "admin".
	resp := doSCIMGroupMappingPatch(t, env.ts, env.token, env.orgID.String(),
		scimGroup.ID.String(), `{"mapped_role":"admin"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("set role mapping: got %d, want 200. Body: %s", resp.StatusCode, b)
	}

	body := readBody(t, resp)
	if body["mapped_role"] != "admin" {
		t.Errorf("mapped_role = %v, want admin", body["mapped_role"])
	}

	// Verify the member's role was recomputed.
	member, err := env.db.GetOrgMemberFull(ctx, env.orgID, memberID)
	if err != nil {
		t.Fatalf("get member: %v", err)
	}
	if member == nil {
		t.Fatal("member should exist")
	}
	if member.Role != "admin" {
		t.Errorf("member role = %q, want admin (recomputed from SCIM group mapping)", member.Role)
	}
}

func TestGroupMapping_SetNotificationGroup(t *testing.T) {
	t.Parallel()
	env := newSCIMAdminEnv(t)
	ctx := context.Background()
	env.createSSOForSCIM(t)

	createResp := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create config: got %d. Body: %s", createResp.StatusCode, b)
	}

	// Create notification group.
	notifGroup := env.db.MustCreateGroup(t, ctx, env.orgID, "Security Team", "Security notifications")

	// Create a SCIM group.
	scimGroup, err := env.db.CreateSCIMGroup(ctx, env.orgID, nil, "Security")
	if err != nil {
		t.Fatalf("create scim group: %v", err)
	}

	// Create a member and add to SCIM group.
	memberReg := doRegister(t, ctx, env.ts, "scim-notif-member@example.com", "test-password-1234")
	memberID := mustParseUUID(t, memberReg.UserID)
	if err := env.db.CreateOrgMember(ctx, env.orgID, memberID, "viewer"); err != nil {
		t.Fatalf("create org member: %v", err)
	}
	if err := env.db.AddSCIMGroupMember(ctx, scimGroup.ID, memberID, env.orgID); err != nil {
		t.Fatalf("add scim group member: %v", err)
	}

	// Set mapped_group_id.
	body := `{"mapped_group_id":"` + notifGroup.ID.String() + `"}`
	resp := doSCIMGroupMappingPatch(t, env.ts, env.token, env.orgID.String(),
		scimGroup.ID.String(), body)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("set group mapping: got %d, want 200. Body: %s", resp.StatusCode, b)
	}

	result := readBody(t, resp)
	if result["mapped_group_id"] != notifGroup.ID.String() {
		t.Errorf("mapped_group_id = %v, want %s", result["mapped_group_id"], notifGroup.ID)
	}
}

func TestGroupMapping_ClearMapping(t *testing.T) {
	t.Parallel()
	env := newSCIMAdminEnv(t)
	ctx := context.Background()
	env.createSSOForSCIM(t)

	createResp := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create config: got %d. Body: %s", createResp.StatusCode, b)
	}

	// Create SCIM group with a mapped role.
	scimGroup, err := env.db.CreateSCIMGroup(ctx, env.orgID, nil, "DevOps")
	if err != nil {
		t.Fatalf("create scim group: %v", err)
	}
	admin := "admin"
	if err := env.db.UpdateSCIMGroupMapping(ctx, env.orgID, scimGroup.ID, &admin, nil); err != nil {
		t.Fatalf("set initial mapping: %v", err)
	}

	// Create member in SCIM group.
	memberReg := doRegister(t, ctx, env.ts, "scim-clear-member@example.com", "test-password-1234")
	memberID := mustParseUUID(t, memberReg.UserID)
	if err := env.db.CreateOrgMember(ctx, env.orgID, memberID, "admin"); err != nil {
		t.Fatalf("create org member: %v", err)
	}
	if err := env.db.AddSCIMGroupMember(ctx, scimGroup.ID, memberID, env.orgID); err != nil {
		t.Fatalf("add scim group member: %v", err)
	}

	// Clear mapped_role by sending empty string.
	resp := doSCIMGroupMappingPatch(t, env.ts, env.token, env.orgID.String(),
		scimGroup.ID.String(), `{"mapped_role":""}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("clear mapping: got %d, want 200. Body: %s", resp.StatusCode, b)
	}

	result := readBody(t, resp)
	if result["mapped_role"] != nil {
		t.Errorf("mapped_role should be null after clear, got %v", result["mapped_role"])
	}

	// Verify the member's role was recomputed to the default ("viewer").
	member, err := env.db.GetOrgMemberFull(ctx, env.orgID, memberID)
	if err != nil {
		t.Fatalf("get member: %v", err)
	}
	if member == nil {
		t.Fatal("member should exist")
	}
	if member.Role != "viewer" {
		t.Errorf("member role = %q, want viewer (recomputed to default after mapping cleared)", member.Role)
	}
}

func TestGroupMapping_CrossOrgGroupId(t *testing.T) {
	t.Parallel()
	env := newSCIMAdminEnv(t)
	ctx := context.Background()
	env.createSSOForSCIM(t)

	createResp := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create config: got %d. Body: %s", createResp.StatusCode, b)
	}

	// Create a SCIM group in our org.
	scimGroup, err := env.db.CreateSCIMGroup(ctx, env.orgID, nil, "CrossOrgTest")
	if err != nil {
		t.Fatalf("create scim group: %v", err)
	}

	// Create a different org and a notification group in it.
	otherOrg := env.db.MustCreateOrg(t, ctx, "Other Org")
	otherGroup := env.db.MustCreateGroup(t, ctx, otherOrg.ID, "Other Org Group", "wrong org")

	// Try to set mapped_group_id to a group from a different org → 400.
	body := `{"mapped_group_id":"` + otherGroup.ID.String() + `"}`
	resp := doSCIMGroupMappingPatch(t, env.ts, env.token, env.orgID.String(),
		scimGroup.ID.String(), body)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("cross-org group: got %d, want 400. Body: %s", resp.StatusCode, b)
	}
}

func TestGroupMapping_SoftDeletedGroupId(t *testing.T) {
	t.Parallel()
	env := newSCIMAdminEnv(t)
	ctx := context.Background()
	env.createSSOForSCIM(t)

	createResp := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create config: got %d. Body: %s", createResp.StatusCode, b)
	}

	// Create and soft-delete a notification group.
	notifGroup := env.db.MustCreateGroup(t, ctx, env.orgID, "Deleted Group", "will be deleted")
	if err := env.db.SoftDeleteGroup(ctx, env.orgID, notifGroup.ID); err != nil {
		t.Fatalf("soft delete group: %v", err)
	}

	// Create a SCIM group.
	scimGroup, err := env.db.CreateSCIMGroup(ctx, env.orgID, nil, "SoftDelTest")
	if err != nil {
		t.Fatalf("create scim group: %v", err)
	}

	// Try to map to soft-deleted group → 400.
	body := `{"mapped_group_id":"` + notifGroup.ID.String() + `"}`
	resp := doSCIMGroupMappingPatch(t, env.ts, env.token, env.orgID.String(),
		scimGroup.ID.String(), body)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("soft-deleted group: got %d, want 400. Body: %s", resp.StatusCode, b)
	}
}
