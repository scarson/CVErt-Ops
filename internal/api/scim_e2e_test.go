// ABOUTME: End-to-end SCIM integration tests simulating real IdP provisioning workflows.
// ABOUTME: Multi-step sequences through the full HTTP stack (SCIM + admin endpoints).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/secure"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// scimE2EEnv bundles a test server with both SCIM and admin routes for e2e tests.
type scimE2EEnv struct {
	ts           *httptest.Server
	srv          *Server
	db           *testutil.TestDB
	orgID        uuid.UUID
	scimConfigID uuid.UUID
	rawToken     string
}

// newSCIME2EEnv creates a SCIM e2e test environment with only SCIM handlers mounted.
func newSCIME2EEnv(t *testing.T) *scimE2EEnv {
	t.Helper()

	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := db.CreateOrg(ctx, "scim-e2e-"+uuid.New().String()[:8])
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	ssoConn, err := db.CreateSSOConnection(ctx, org.ID, "E2E IdP",
		"https://idp.example.com", "client-id", []byte("encrypted"), nil, true)
	if err != nil {
		t.Fatalf("CreateSSOConnection: %v", err)
	}

	rawToken, tokenHash, tokenPrefix, err := auth.GenerateSCIMToken()
	if err != nil {
		t.Fatalf("GenerateSCIMToken: %v", err)
	}

	scimCfg, err := db.CreateSCIMConfig(ctx, org.ID, ssoConn.ID, true, tokenHash, tokenPrefix, "viewer")
	if err != nil {
		t.Fatalf("CreateSCIMConfig: %v", err)
	}

	ew := secure.NewEventWriter(db.Store)
	cfg := &config.Config{ //nolint:exhaustruct,gosec // test: only relevant fields; G101 false positive
		JWTSecret: "scim-e2e-test-secret-32-bytes-min",
	}
	srv, err := NewServer(db.Store, cfg, ServerDeps{EventWriter: ew})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)

	r := chi.NewRouter()
	r.Route("/api/v1/orgs/{org_id}/scim/v2", func(sub chi.Router) {
		sub.Use(srv.requireSCIMAuth)
		// Users
		sub.Post("/Users", srv.scimCreateUser)
		sub.Get("/Users", srv.scimListUsers)
		sub.Get("/Users/{id}", srv.scimGetUser)
		sub.Put("/Users/{id}", srv.scimReplaceUser)
		sub.Patch("/Users/{id}", srv.scimPatchUser)
		sub.Delete("/Users/{id}", srv.scimDeleteUser)
		// Groups
		sub.Post("/Groups", srv.scimCreateGroup)
		sub.Get("/Groups", srv.scimListGroups)
		sub.Get("/Groups/{id}", srv.scimGetGroup)
		sub.Put("/Groups/{id}", srv.scimReplaceGroup)
		sub.Patch("/Groups/{id}", srv.scimPatchGroup)
		sub.Delete("/Groups/{id}", srv.scimDeleteGroup)
	})

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	return &scimE2EEnv{
		ts:           ts,
		srv:          srv,
		db:           db,
		orgID:        org.ID,
		scimConfigID: scimCfg.ID,
		rawToken:     rawToken,
	}
}

// scimReq makes an authenticated SCIM request and returns the response.
func (env *scimE2EEnv) scimReq(t *testing.T, method, path string, body any) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	rawURL := fmt.Sprintf("%s/api/v1/orgs/%s/scim/v2%s", env.ts.URL, env.orgID, path)
	req, err := http.NewRequestWithContext(context.Background(), method, rawURL, bodyReader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+env.rawToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	resp, err := env.ts.Client().Do(req) //nolint:gosec // G704: httptest URL
	if err != nil {
		t.Fatalf("request %s %s: %v", method, path, err)
	}
	return resp
}

// scimReqWithToken makes a SCIM request with a specific bearer token.
func (env *scimE2EEnv) scimReqWithToken(t *testing.T, method, path, token string) *http.Response {
	t.Helper()
	rawURL := fmt.Sprintf("%s/api/v1/orgs/%s/scim/v2%s", env.ts.URL, env.orgID, path)
	req, err := http.NewRequestWithContext(context.Background(), method, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := env.ts.Client().Do(req) //nolint:gosec // G704: httptest URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return resp
}

// readSCIMBody reads and parses a JSON response body.
func readSCIMBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode body: %v (raw: %s)", err, string(body))
	}
	return out
}

// ── Test 1: Full Provisioning Lifecycle ─────────────────────────────────────────

func TestSCIME2E_FullProvisioningLifecycle(t *testing.T) {
	t.Parallel()
	env := newSCIME2EEnv(t)

	// Step 1: Provision user via POST /Users.
	createBody := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"externalId":  "lifecycle-ext-001",
		"userName":    "lifecycle@example.com",
		"displayName": "Lifecycle User",
		"active":      true,
	}

	resp := env.scimReq(t, http.MethodPost, "/Users", createBody)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("POST /Users: got %d, want 201 (body: %s)", resp.StatusCode, string(body))
	}
	assertSCIMContentType(t, resp)

	user := decodeSCIMUser(t, resp)
	if user.ID == "" {
		t.Fatal("user ID is empty")
	}
	userID := user.ID
	if user.UserName != "lifecycle@example.com" {
		t.Errorf("userName = %q, want %q", user.UserName, "lifecycle@example.com")
	}
	if !user.Active {
		t.Error("active = false, want true")
	}

	// Step 2: Verify user exists via GET /Users/{id}.
	resp2 := env.scimReq(t, http.MethodGet, "/Users/"+userID, nil)
	defer resp2.Body.Close() //nolint:errcheck
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body) //nolint:errcheck
		t.Fatalf("GET /Users/{id}: got %d, want 200 (body: %s)", resp2.StatusCode, string(body))
	}
	user2 := decodeSCIMUser(t, resp2)
	if user2.UserName != "lifecycle@example.com" {
		t.Errorf("GET user userName = %q, want %q", user2.UserName, "lifecycle@example.com")
	}

	// Step 3: Deactivate via PATCH (active=false).
	deactivatePatch := SCIMPatchOp{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []SCIMPatchOperation{
			{Op: "replace", Path: "active", Value: json.RawMessage(`false`)},
		},
	}

	resp3 := env.scimReq(t, http.MethodPatch, "/Users/"+userID, deactivatePatch)
	defer resp3.Body.Close() //nolint:errcheck
	if resp3.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp3.Body) //nolint:errcheck
		t.Fatalf("PATCH deactivate: got %d, want 200 (body: %s)", resp3.StatusCode, string(body))
	}
	user3 := decodeSCIMUser(t, resp3)
	if user3.Active {
		t.Error("after deactivate: active = true, want false")
	}

	// Step 4: Verify deactivated via GET.
	resp4 := env.scimReq(t, http.MethodGet, "/Users/"+userID, nil)
	defer resp4.Body.Close() //nolint:errcheck
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("GET after deactivate: got %d, want 200", resp4.StatusCode)
	}
	user4 := decodeSCIMUser(t, resp4)
	if user4.Active {
		t.Error("GET after deactivate: active = true, want false")
	}

	// Step 5: Reactivate via PATCH (active=true).
	reactivatePatch := SCIMPatchOp{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []SCIMPatchOperation{
			{Op: "replace", Path: "active", Value: json.RawMessage(`true`)},
		},
	}

	resp5 := env.scimReq(t, http.MethodPatch, "/Users/"+userID, reactivatePatch)
	defer resp5.Body.Close() //nolint:errcheck
	if resp5.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp5.Body) //nolint:errcheck
		t.Fatalf("PATCH reactivate: got %d, want 200 (body: %s)", resp5.StatusCode, string(body))
	}
	user5 := decodeSCIMUser(t, resp5)
	if !user5.Active {
		t.Error("after reactivate: active = false, want true")
	}

	// Step 6: Verify active again via GET.
	resp6 := env.scimReq(t, http.MethodGet, "/Users/"+userID, nil)
	defer resp6.Body.Close() //nolint:errcheck
	user6 := decodeSCIMUser(t, resp6)
	if !user6.Active {
		t.Error("GET after reactivate: active = false, want true")
	}

	// Step 7: Deprovision via DELETE.
	resp7 := env.scimReq(t, http.MethodDelete, "/Users/"+userID, nil)
	defer resp7.Body.Close() //nolint:errcheck
	if resp7.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp7.Body) //nolint:errcheck
		t.Fatalf("DELETE: got %d, want 204 (body: %s)", resp7.StatusCode, string(body))
	}
}

// ── Test 2: Group Role Mapping ──────────────────────────────────────────────────

func TestSCIME2E_GroupRoleMapping(t *testing.T) {
	t.Parallel()
	env := newSCIME2EEnv(t)
	ctx := context.Background()

	// Provision a user via SCIM.
	createBody := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"externalId":  "role-map-ext-001",
		"userName":    "rolemap@example.com",
		"displayName": "Role Map User",
		"active":      true,
	}

	resp := env.scimReq(t, http.MethodPost, "/Users", createBody)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("POST /Users: got %d, want 201 (body: %s)", resp.StatusCode, string(body))
	}
	user := decodeSCIMUser(t, resp)
	userUUID, err := uuid.Parse(user.ID)
	if err != nil {
		t.Fatalf("parse user ID: %v", err)
	}

	// Verify initial role is "viewer" (default_role).
	member, err := env.db.GetOrgMemberFull(ctx, env.orgID, userUUID)
	if err != nil || member == nil {
		t.Fatalf("GetOrgMemberFull: %v", err)
	}
	if member.Role != "viewer" {
		t.Errorf("initial role = %q, want viewer", member.Role)
	}

	// Create SCIM group via POST /Groups.
	groupBody := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Admins",
	}
	groupResp := env.scimReq(t, http.MethodPost, "/Groups", groupBody)
	defer groupResp.Body.Close() //nolint:errcheck
	if groupResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(groupResp.Body) //nolint:errcheck
		t.Fatalf("POST /Groups: got %d, want 201 (body: %s)", groupResp.StatusCode, string(body))
	}
	var group SCIMGroup
	if err := json.NewDecoder(groupResp.Body).Decode(&group); err != nil {
		t.Fatalf("decode group: %v", err)
	}
	groupUUID, err := uuid.Parse(group.ID)
	if err != nil {
		t.Fatalf("parse group ID: %v", err)
	}

	// Set mapped_role="admin" via store (simulating admin action).
	adminRole := "admin"
	if err := env.db.UpdateSCIMGroupMapping(ctx, env.orgID, groupUUID, &adminRole, nil); err != nil {
		t.Fatalf("UpdateSCIMGroupMapping: %v", err)
	}

	// Add user to group via SCIM PATCH /Groups/{id}.
	addMemberPatch := SCIMPatchOp{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []SCIMPatchOperation{
			{
				Op:   "add",
				Path: "members",
				Value: json.RawMessage(fmt.Sprintf(
					`[{"value":"%s"}]`, user.ID)),
			},
		},
	}

	patchResp := env.scimReq(t, http.MethodPatch, "/Groups/"+group.ID, addMemberPatch)
	defer patchResp.Body.Close() //nolint:errcheck
	if patchResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(patchResp.Body) //nolint:errcheck
		t.Fatalf("PATCH add member: got %d, want 200 (body: %s)", patchResp.StatusCode, string(body))
	}

	// Verify user's role was recomputed to "admin".
	member, err = env.db.GetOrgMemberFull(ctx, env.orgID, userUUID)
	if err != nil || member == nil {
		t.Fatalf("GetOrgMemberFull after add: %v", err)
	}
	if member.Role != "admin" {
		t.Errorf("role after group add = %q, want admin", member.Role)
	}

	// Remove member from group via SCIM PATCH /Groups/{id}.
	removeMemberPatch := SCIMPatchOp{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []SCIMPatchOperation{
			{
				Op:   "remove",
				Path: fmt.Sprintf(`members[value eq "%s"]`, user.ID),
			},
		},
	}

	removeResp := env.scimReq(t, http.MethodPatch, "/Groups/"+group.ID, removeMemberPatch)
	defer removeResp.Body.Close() //nolint:errcheck
	if removeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(removeResp.Body) //nolint:errcheck
		t.Fatalf("PATCH remove member: got %d, want 200 (body: %s)", removeResp.StatusCode, string(body))
	}

	// Verify role reverted to default "viewer".
	member, err = env.db.GetOrgMemberFull(ctx, env.orgID, userUUID)
	if err != nil || member == nil {
		t.Fatalf("GetOrgMemberFull after remove: %v", err)
	}
	if member.Role != "viewer" {
		t.Errorf("role after group remove = %q, want viewer", member.Role)
	}
}

// ── Test 3: Entra ID Compatibility ──────────────────────────────────────────────

func TestSCIME2E_EntraIDCompatibility(t *testing.T) {
	t.Parallel()
	env := newSCIME2EEnv(t)

	// Provision a user first.
	createBody := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"externalId":  "entra-ext-001",
		"userName":    "entra@example.com",
		"displayName": "Entra User",
		"active":      true,
	}
	resp := env.scimReq(t, http.MethodPost, "/Users", createBody)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("POST /Users: got %d, want 201 (body: %s)", resp.StatusCode, string(body))
	}
	user := decodeSCIMUser(t, resp)

	// Quirk 1: Capitalized op "Replace" (not "replace").
	patchCapitalized := SCIMPatchOp{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []SCIMPatchOperation{
			{Op: "Replace", Path: "displayName", Value: json.RawMessage(`"Entra Updated"`)},
		},
	}
	resp2 := env.scimReq(t, http.MethodPatch, "/Users/"+user.ID, patchCapitalized)
	defer resp2.Body.Close() //nolint:errcheck
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body) //nolint:errcheck
		t.Fatalf("PATCH capitalized op: got %d, want 200 (body: %s)", resp2.StatusCode, string(body))
	}
	user2 := decodeSCIMUser(t, resp2)
	if user2.DisplayName != "Entra Updated" {
		t.Errorf("displayName after capitalized Replace = %q, want %q", user2.DisplayName, "Entra Updated")
	}

	// Quirk 2: String boolean "False" for active field.
	patchStringBool := SCIMPatchOp{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []SCIMPatchOperation{
			{Op: "Replace", Path: "active", Value: json.RawMessage(`"False"`)},
		},
	}
	resp3 := env.scimReq(t, http.MethodPatch, "/Users/"+user.ID, patchStringBool)
	defer resp3.Body.Close() //nolint:errcheck
	if resp3.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp3.Body) //nolint:errcheck
		t.Fatalf("PATCH string boolean: got %d, want 200 (body: %s)", resp3.StatusCode, string(body))
	}
	user3 := decodeSCIMUser(t, resp3)
	if user3.Active {
		t.Error("active = true after string 'False', want false")
	}

	// Quirk 3: Group member removal via value-array format.
	// First, create a group and add the user.
	groupBody := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Entra Group",
		"members":     []map[string]any{{"value": user.ID}},
	}
	groupResp := env.scimReq(t, http.MethodPost, "/Groups", groupBody)
	defer groupResp.Body.Close() //nolint:errcheck
	if groupResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(groupResp.Body) //nolint:errcheck
		t.Fatalf("POST /Groups: got %d, want 201 (body: %s)", groupResp.StatusCode, string(body))
	}
	var group SCIMGroup
	if err := json.NewDecoder(groupResp.Body).Decode(&group); err != nil {
		t.Fatalf("decode group: %v", err)
	}

	// Remove via Entra ID value-array format: {op: "remove", path: "members", value: [{value: "uuid"}]}
	removeEntra := SCIMPatchOp{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []SCIMPatchOperation{
			{
				Op:    "Remove",
				Path:  "members",
				Value: json.RawMessage(fmt.Sprintf(`[{"value":"%s"}]`, user.ID)),
			},
		},
	}
	removeResp := env.scimReq(t, http.MethodPatch, "/Groups/"+group.ID, removeEntra)
	defer removeResp.Body.Close() //nolint:errcheck
	if removeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(removeResp.Body) //nolint:errcheck
		t.Fatalf("PATCH Entra remove member: got %d, want 200 (body: %s)", removeResp.StatusCode, string(body))
	}

	// Verify group now has no members.
	getGroupResp := env.scimReq(t, http.MethodGet, "/Groups/"+group.ID, nil)
	defer getGroupResp.Body.Close() //nolint:errcheck
	var groupAfter SCIMGroup
	if err := json.NewDecoder(getGroupResp.Body).Decode(&groupAfter); err != nil {
		t.Fatalf("decode group after remove: %v", err)
	}
	if len(groupAfter.Members) != 0 {
		t.Errorf("group members after Entra remove = %d, want 0", len(groupAfter.Members))
	}
}

// ── Test 4: Test Connection Patterns ────────────────────────────────────────────

func TestSCIME2E_TestConnectionPatterns(t *testing.T) {
	t.Parallel()
	env := newSCIME2EEnv(t)

	// Entra ID test connection: GET /Users?filter=id eq "{random-uuid}"
	// Expects 200 with totalResults: 0 and empty Resources array.
	randomUUID := uuid.New().String()
	entraFilter := fmt.Sprintf(`id eq "%s"`, randomUUID)
	rawURL := fmt.Sprintf("%s/api/v1/orgs/%s/scim/v2/Users", env.ts.URL, env.orgID)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+env.rawToken)
	q := req.URL.Query()
	q.Set("filter", entraFilter)
	req.URL.RawQuery = q.Encode()

	resp, err := env.ts.Client().Do(req) //nolint:gosec // G704: httptest URL
	if err != nil {
		t.Fatalf("Entra test connection: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("Entra test: got %d, want 200 (body: %s)", resp.StatusCode, string(body))
	}
	assertSCIMContentType(t, resp)

	entraList := decodeSCIMList(t, resp)
	if entraList.TotalResults != 0 {
		t.Errorf("Entra totalResults = %d, want 0", entraList.TotalResults)
	}
	if entraList.Resources == nil {
		t.Error("Entra Resources is nil, want empty array")
	}

	// Okta test connection: GET /Users?startIndex=1&count=1
	// Expects 200 with pagination envelope.
	oktaResp := env.scimReq(t, http.MethodGet, "/Users?startIndex=1&count=1", nil)
	defer oktaResp.Body.Close() //nolint:errcheck

	if oktaResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(oktaResp.Body) //nolint:errcheck
		t.Fatalf("Okta test: got %d, want 200 (body: %s)", oktaResp.StatusCode, string(body))
	}
	assertSCIMContentType(t, oktaResp)

	oktaList := decodeSCIMList(t, oktaResp)
	// Must have pagination envelope fields.
	if oktaList.StartIndex != 1 {
		t.Errorf("Okta startIndex = %d, want 1", oktaList.StartIndex)
	}
	if oktaList.ItemsPerPage < 0 {
		t.Errorf("Okta itemsPerPage = %d, want >= 0", oktaList.ItemsPerPage)
	}
	// Resources must be an array (even if empty).
	if oktaList.Resources == nil {
		t.Error("Okta Resources is nil, want array")
	}
}

// ── Test 5: Cross-Org Isolation ─────────────────────────────────────────────────

func TestSCIME2E_CrossOrgIsolation(t *testing.T) {
	t.Parallel()

	// Org A setup.
	envA := newSCIME2EEnv(t)

	// Provision user in org A.
	createBody := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"externalId":  "cross-org-ext-001",
		"userName":    "crossorg@example.com",
		"displayName": "Cross Org User",
		"active":      true,
	}
	resp := envA.scimReq(t, http.MethodPost, "/Users", createBody)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("POST user in org A: got %d, want 201 (body: %s)", resp.StatusCode, string(body))
	}
	userA := decodeSCIMUser(t, resp)

	// Org B setup (separate env with its own DB, org, and token).
	envB := newSCIME2EEnv(t)

	// Try to GET org A's user via org B's SCIM endpoint with org B's token.
	// This uses org B's URL path but targets user A's ID.
	resp2 := envB.scimReq(t, http.MethodGet, "/Users/"+userA.ID, nil)
	defer resp2.Body.Close() //nolint:errcheck

	if resp2.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp2.Body) //nolint:errcheck
		t.Fatalf("cross-org GET: got %d, want 404 (body: %s)", resp2.StatusCode, string(body))
	}
	assertSCIMContentType(t, resp2)
}

// ── Test 6: Token Rotation ──────────────────────────────────────────────────────

func TestSCIME2E_TokenRotation(t *testing.T) {
	t.Parallel()
	env := newSCIME2EEnv(t)
	ctx := context.Background()

	// Verify current token works.
	resp := env.scimReq(t, http.MethodGet, "/Users?startIndex=1&count=1", nil)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-rotation GET: got %d, want 200", resp.StatusCode)
	}

	// Rotate token via store (simulating admin token rotation).
	oldToken := env.rawToken
	newRawToken, newHash, newPrefix, err := auth.GenerateSCIMToken()
	if err != nil {
		t.Fatalf("GenerateSCIMToken: %v", err)
	}
	if err := env.db.RotateSCIMToken(ctx, env.orgID, newHash, newPrefix); err != nil {
		t.Fatalf("RotateSCIMToken: %v", err)
	}

	// Old token should now be rejected.
	resp2 := env.scimReqWithToken(t, http.MethodGet, "/Users?startIndex=1&count=1", oldToken)
	defer resp2.Body.Close() //nolint:errcheck
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("old token after rotation: got %d, want 401", resp2.StatusCode)
	}
	assertSCIMContentType(t, resp2)

	// New token should work.
	env.rawToken = newRawToken
	resp3 := env.scimReq(t, http.MethodGet, "/Users?startIndex=1&count=1", nil)
	defer resp3.Body.Close() //nolint:errcheck
	if resp3.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp3.Body) //nolint:errcheck
		t.Fatalf("new token after rotation: got %d, want 200 (body: %s)", resp3.StatusCode, string(body))
	}

	_ = newPrefix // used only for store call
}

// ── Test 7: Error Content-Type ──────────────────────────────────────────────────

func TestSCIME2E_ErrorContentType(t *testing.T) {
	t.Parallel()
	env := newSCIME2EEnv(t)

	// Error 1: Invalid token → 401.
	resp1 := env.scimReqWithToken(t, http.MethodGet, "/Users", "invalid-token-value")
	defer resp1.Body.Close() //nolint:errcheck
	if resp1.StatusCode != http.StatusUnauthorized {
		t.Errorf("invalid token: got %d, want 401", resp1.StatusCode)
	}
	ct1 := resp1.Header.Get("Content-Type")
	if ct1 != "application/scim+json" {
		t.Errorf("401 Content-Type = %q, want %q", ct1, "application/scim+json")
	}

	// Error 2: Not-found user → 404.
	fakeID := uuid.New().String()
	resp2 := env.scimReq(t, http.MethodGet, "/Users/"+fakeID, nil)
	defer resp2.Body.Close() //nolint:errcheck
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("not found: got %d, want 404", resp2.StatusCode)
	}
	ct2 := resp2.Header.Get("Content-Type")
	if ct2 != "application/scim+json" {
		t.Errorf("404 Content-Type = %q, want %q", ct2, "application/scim+json")
	}

	// Error 3: Invalid filter → 400.
	rawURL := fmt.Sprintf("%s/api/v1/orgs/%s/scim/v2/Users", env.ts.URL, env.orgID)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+env.rawToken)
	q := req.URL.Query()
	q.Set("filter", `userName sw "test"`) // "sw" (starts-with) is unsupported
	req.URL.RawQuery = q.Encode()
	resp3, err := env.ts.Client().Do(req) //nolint:gosec // G704: httptest URL
	if err != nil {
		t.Fatalf("invalid filter request: %v", err)
	}
	defer resp3.Body.Close() //nolint:errcheck
	if resp3.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp3.Body) //nolint:errcheck
		t.Errorf("invalid filter: got %d, want 400 (body: %s)", resp3.StatusCode, string(body))
	}
	ct3 := resp3.Header.Get("Content-Type")
	if ct3 != "application/scim+json" {
		t.Errorf("400 Content-Type = %q, want %q", ct3, "application/scim+json")
	}

	// Verify all error bodies are valid JSON with SCIM error schema.
	// (Re-test 401 with body parsing)
	resp4 := env.scimReqWithToken(t, http.MethodGet, "/Users", "bad-token")
	defer resp4.Body.Close() //nolint:errcheck
	errBody := readSCIMBody(t, resp4)
	schemas, ok := errBody["schemas"].([]any)
	if !ok || len(schemas) == 0 {
		t.Error("401 error body missing schemas array")
	} else {
		schemaStr, _ := schemas[0].(string)
		if schemaStr != "urn:ietf:params:scim:api:messages:2.0:Error" {
			t.Errorf("401 error schema = %q, want SCIM Error schema", schemaStr)
		}
	}
}
