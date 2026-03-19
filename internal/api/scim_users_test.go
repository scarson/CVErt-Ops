// ABOUTME: Integration tests for SCIM 2.0 User handlers (create, get, list, put, patch, delete).
// ABOUTME: Uses testcontainer Postgres with full migration stack and SCIM auth middleware.
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

// scimUserTestEnv bundles a test server with SCIM user handlers mounted.
type scimUserTestEnv struct {
	ts           *httptest.Server
	srv          *Server
	db           *testutil.TestDB
	orgID        uuid.UUID
	scimConfigID uuid.UUID
	rawToken     string
}

// newSCIMUserTestEnv sets up a test environment with SCIM user handlers.
func newSCIMUserTestEnv(t *testing.T) *scimUserTestEnv {
	t.Helper()

	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := db.CreateOrg(ctx, "scim-user-test-org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	ssoConn, err := db.CreateSSOConnection(ctx, org.ID, "Test IdP",
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
	cfg := &config.Config{ //nolint:exhaustruct,gosec // test: only relevant fields set; G101 false positive on test-only JWT secret
		JWTSecret: "scim-user-test-secret-32bytes-min",
	}
	srv, err := NewServer(db.Store, cfg, ServerDeps{EventWriter: ew})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)

	r := chi.NewRouter()
	r.Route("/api/v1/orgs/{org_id}/scim/v2", func(sub chi.Router) {
		sub.Use(srv.requireSCIMAuth)
		sub.Post("/Users", srv.scimCreateUser)
		sub.Get("/Users", srv.scimListUsers)
		sub.Get("/Users/{id}", srv.scimGetUser)
		sub.Put("/Users/{id}", srv.scimReplaceUser)
		sub.Patch("/Users/{id}", srv.scimPatchUser)
		sub.Delete("/Users/{id}", srv.scimDeleteUser)
	})

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	return &scimUserTestEnv{
		ts:           ts,
		srv:          srv,
		db:           db,
		orgID:        org.ID,
		scimConfigID: scimCfg.ID,
		rawToken:     rawToken,
	}
}

// scimRequest makes an HTTP request to the SCIM endpoint.
// path should include the path after /scim/v2 (e.g., "/Users" or "/Users/{id}").
// Query parameters in path are properly handled by net/url.
func (env *scimUserTestEnv) scimRequest(t *testing.T, method, path string, body any) *http.Response {
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
		t.Fatalf("request: %v", err)
	}
	return resp
}

// scimRequestWithFilter makes a GET request with a filter query param.
func (env *scimUserTestEnv) scimRequestWithFilter(t *testing.T, path, filter string) *http.Response {
	t.Helper()
	rawURL := fmt.Sprintf("%s/api/v1/orgs/%s/scim/v2%s", env.ts.URL, env.orgID, path)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+env.rawToken)
	q := req.URL.Query()
	q.Set("filter", filter)
	req.URL.RawQuery = q.Encode()
	resp, err := env.ts.Client().Do(req) //nolint:gosec // G704: httptest URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return resp
}

// decodeSCIMUser decodes a SCIMUser from the response body.
func decodeSCIMUser(t *testing.T, resp *http.Response) SCIMUser {
	t.Helper()
	var user SCIMUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		t.Fatalf("decode SCIM user: %v", err)
	}
	return user
}

// decodeSCIMList decodes a SCIMListResponse from the response body.
func decodeSCIMList(t *testing.T, resp *http.Response) SCIMListResponse {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var list SCIMListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode SCIM list: %v (body: %s)", err, string(body))
	}
	return list
}

// assertContentType checks the Content-Type is application/scim+json.
func assertSCIMContentType(t *testing.T, resp *http.Response) {
	t.Helper()
	ct := resp.Header.Get("Content-Type")
	if ct != "application/scim+json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/scim+json")
	}
}

// ── User Provisioning Tests ────────────────────────────────────────────────────

func TestSCIMCreateUser_NewUser(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)

	reqBody := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"externalId":  "ext-new-001",
		"userName":    "newuser@example.com",
		"displayName": "New User",
		"active":      true,
	}

	resp := env.scimRequest(t, http.MethodPost, "/Users", reqBody)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 201 (body: %s)", resp.StatusCode, string(body))
	}
	assertSCIMContentType(t, resp)

	user := decodeSCIMUser(t, resp)
	if len(user.Schemas) != 1 || user.Schemas[0] != "urn:ietf:params:scim:schemas:core:2.0:User" {
		t.Errorf("schemas = %v, want User schema", user.Schemas)
	}
	if user.UserName != "newuser@example.com" {
		t.Errorf("userName = %q, want %q", user.UserName, "newuser@example.com")
	}
	if user.DisplayName != "New User" {
		t.Errorf("displayName = %q, want %q", user.DisplayName, "New User")
	}
	if user.ExternalID != "ext-new-001" {
		t.Errorf("externalId = %q, want %q", user.ExternalID, "ext-new-001")
	}
	if !user.Active {
		t.Error("active = false, want true")
	}
	if user.ID == "" {
		t.Error("id is empty")
	}
	if user.Meta.ResourceType != "User" {
		t.Errorf("meta.resourceType = %q, want %q", user.Meta.ResourceType, "User")
	}
}

func TestSCIMCreateUser_ExistingByExternalId_Active(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	// Pre-create user, identity, and membership.
	user := env.db.MustCreateUser(t, ctx, "existing-ext@example.com", "Existing", "", 0)
	provider := fmt.Sprintf("scim:%s", env.scimConfigID)
	if err := env.db.UpsertUserIdentity(ctx, user.ID, provider, "ext-exist-001", user.Email); err != nil {
		t.Fatalf("UpsertUserIdentity: %v", err)
	}
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "viewer"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	reqBody := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"externalId":  "ext-exist-001",
		"userName":    "existing-ext@example.com",
		"displayName": "Existing",
		"active":      true,
	}

	resp := env.scimRequest(t, http.MethodPost, "/Users", reqBody)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, string(body))
	}
	assertSCIMContentType(t, resp)

	scimUser := decodeSCIMUser(t, resp)
	if scimUser.ID != user.ID.String() {
		t.Errorf("id = %q, want %q", scimUser.ID, user.ID.String())
	}
	if !scimUser.Active {
		t.Error("active = false, want true")
	}
}

func TestSCIMCreateUser_ExistingByExternalId_Deactivated(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	user := env.db.MustCreateUser(t, ctx, "deactivated-ext@example.com", "Deactivated", "", 0)
	provider := fmt.Sprintf("scim:%s", env.scimConfigID)
	if err := env.db.UpsertUserIdentity(ctx, user.ID, provider, "ext-deact-001", user.Email); err != nil {
		t.Fatalf("UpsertUserIdentity: %v", err)
	}
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "viewer"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}
	if err := env.db.DeactivateOrgMember(ctx, env.orgID, user.ID); err != nil {
		t.Fatalf("DeactivateOrgMember: %v", err)
	}

	reqBody := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"externalId":  "ext-deact-001",
		"userName":    "deactivated-ext@example.com",
		"displayName": "Deactivated",
		"active":      true,
	}

	resp := env.scimRequest(t, http.MethodPost, "/Users", reqBody)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, string(body))
	}

	scimUser := decodeSCIMUser(t, resp)
	if !scimUser.Active {
		t.Error("active = false, want true (should have been reactivated)")
	}
}

func TestSCIMCreateUser_ExistingByEmail_OrgMember(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	user := env.db.MustCreateUser(t, ctx, "email-member@example.com", "Email Member", "", 0)
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	reqBody := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"externalId":  "ext-email-member-001",
		"userName":    "email-member@example.com",
		"displayName": "Email Member",
		"active":      true,
	}

	resp := env.scimRequest(t, http.MethodPost, "/Users", reqBody)
	defer resp.Body.Close() //nolint:errcheck

	// Already a member, linking identity → 200.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, string(body))
	}

	scimUser := decodeSCIMUser(t, resp)
	if scimUser.ID != user.ID.String() {
		t.Errorf("id = %q, want %q", scimUser.ID, user.ID.String())
	}

	// Verify SCIM identity was linked.
	provider := fmt.Sprintf("scim:%s", env.scimConfigID)
	linked, err := env.db.GetUserByProviderID(ctx, provider, "ext-email-member-001")
	if err != nil {
		t.Fatalf("GetUserByProviderID: %v", err)
	}
	if linked == nil {
		t.Error("SCIM identity was not linked")
	}
}

func TestSCIMCreateUser_ExistingByEmail_NotMember(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	user := env.db.MustCreateUser(t, ctx, "email-nonmember@example.com", "Not Member", "", 0)
	_ = user

	reqBody := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"externalId":  "ext-nonmember-001",
		"userName":    "email-nonmember@example.com",
		"displayName": "Not Member",
		"active":      true,
	}

	resp := env.scimRequest(t, http.MethodPost, "/Users", reqBody)
	defer resp.Body.Close() //nolint:errcheck

	// Creates membership → 201.
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 201 (body: %s)", resp.StatusCode, string(body))
	}

	scimUser := decodeSCIMUser(t, resp)
	if scimUser.ID != user.ID.String() {
		t.Errorf("id = %q, want %q", scimUser.ID, user.ID.String())
	}
}

func TestSCIMCreateUser_TierMemberLimit(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	// Create enough members to exhaust the free tier limit (5).
	for i := 0; i < 5; i++ {
		u := env.db.MustCreateUser(t, ctx,
			fmt.Sprintf("tier-limit-%d@example.com", i),
			fmt.Sprintf("Limit User %d", i), "", 0)
		if err := env.db.CreateOrgMember(ctx, env.orgID, u.ID, "member"); err != nil {
			t.Fatalf("CreateOrgMember: %v", err)
		}
	}

	reqBody := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"externalId":  "ext-over-limit",
		"userName":    "over-limit@example.com",
		"displayName": "Over Limit",
		"active":      true,
	}

	resp := env.scimRequest(t, http.MethodPost, "/Users", reqBody)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 403 (body: %s)", resp.StatusCode, string(body))
	}
	assertSCIMContentType(t, resp)
}

func TestSCIMCreateUser_SCIMExempt_Deactivated(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	user := env.db.MustCreateUser(t, ctx, "exempt@example.com", "Exempt", "", 0)
	provider := fmt.Sprintf("scim:%s", env.scimConfigID)
	if err := env.db.UpsertUserIdentity(ctx, user.ID, provider, "ext-exempt-001", user.Email); err != nil {
		t.Fatalf("UpsertUserIdentity: %v", err)
	}
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "viewer"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}
	if err := env.db.UpdateOrgMemberSCIMExempt(ctx, env.orgID, user.ID, true); err != nil {
		t.Fatalf("UpdateOrgMemberSCIMExempt: %v", err)
	}
	if err := env.db.DeactivateOrgMember(ctx, env.orgID, user.ID); err != nil {
		t.Fatalf("DeactivateOrgMember: %v", err)
	}

	reqBody := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"externalId":  "ext-exempt-001",
		"userName":    "exempt@example.com",
		"displayName": "Exempt",
		"active":      true,
	}

	resp := env.scimRequest(t, http.MethodPost, "/Users", reqBody)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, string(body))
	}

	scimUser := decodeSCIMUser(t, resp)
	// Exempt user should NOT be reactivated.
	if scimUser.Active {
		t.Error("active = true, want false (exempt user should stay deactivated)")
	}
}

// ── User Read/List Tests ───────────────────────────────────────────────────────

func TestSCIMGetUser_Found(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	user := env.db.MustCreateUser(t, ctx, "getuser@example.com", "Get User", "", 0)
	provider := fmt.Sprintf("scim:%s", env.scimConfigID)
	if err := env.db.UpsertUserIdentity(ctx, user.ID, provider, "ext-get-001", user.Email); err != nil {
		t.Fatalf("UpsertUserIdentity: %v", err)
	}
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	resp := env.scimRequest(t, http.MethodGet, "/Users/"+user.ID.String(), nil)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, string(body))
	}
	assertSCIMContentType(t, resp)

	scimUser := decodeSCIMUser(t, resp)
	if scimUser.UserName != "getuser@example.com" {
		t.Errorf("userName = %q, want %q", scimUser.UserName, "getuser@example.com")
	}
	if scimUser.DisplayName != "Get User" {
		t.Errorf("displayName = %q, want %q", scimUser.DisplayName, "Get User")
	}
	if scimUser.ExternalID != "ext-get-001" {
		t.Errorf("externalId = %q, want %q", scimUser.ExternalID, "ext-get-001")
	}
	if !scimUser.Active {
		t.Error("active = false, want true")
	}
}

func TestSCIMGetUser_NotFound(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)

	fakeID := uuid.New()
	resp := env.scimRequest(t, http.MethodGet, "/Users/"+fakeID.String(), nil)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	assertSCIMContentType(t, resp)
}

func TestSCIMGetUser_CrossOrg(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	// Create user in a different org.
	otherOrg, err := env.db.CreateOrg(ctx, "other-org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	user := env.db.MustCreateUser(t, ctx, "crossorg@example.com", "Cross Org", "", 0)
	if err := env.db.CreateOrgMember(ctx, otherOrg.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	// Try to get this user via our org's SCIM.
	resp := env.scimRequest(t, http.MethodGet, "/Users/"+user.ID.String(), nil)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (cross-org isolation)", resp.StatusCode)
	}
	assertSCIMContentType(t, resp)
}

func TestSCIMListUsers_FilterByUserName(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	user := env.db.MustCreateUser(t, ctx, "filteruser@example.com", "Filter User", "", 0)
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}
	// Add another user that should NOT match the filter.
	other := env.db.MustCreateUser(t, ctx, "other-filter@example.com", "Other", "", 0)
	if err := env.db.CreateOrgMember(ctx, env.orgID, other.ID, "viewer"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	resp := env.scimRequestWithFilter(t, "/Users", `userName eq "filteruser@example.com"`)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, string(body))
	}
	assertSCIMContentType(t, resp)

	list := decodeSCIMList(t, resp)
	if list.TotalResults != 1 {
		t.Errorf("totalResults = %d, want 1", list.TotalResults)
	}
	if len(list.Resources) != 1 {
		t.Fatalf("Resources length = %d, want 1", len(list.Resources))
	}
}

func TestSCIMListUsers_FilterById(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	user := env.db.MustCreateUser(t, ctx, "filterid@example.com", "Filter By ID", "", 0)
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	resp := env.scimRequestWithFilter(t, "/Users",
		fmt.Sprintf(`id eq "%s"`, user.ID.String()))
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, string(body))
	}

	list := decodeSCIMList(t, resp)
	if list.TotalResults != 1 {
		t.Errorf("totalResults = %d, want 1", list.TotalResults)
	}
}

func TestSCIMListUsers_EmptyResult(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)

	resp := env.scimRequestWithFilter(t, "/Users",
		`userName eq "nonexistent@example.com"`)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	assertSCIMContentType(t, resp)

	list := decodeSCIMList(t, resp)
	if list.TotalResults != 0 {
		t.Errorf("totalResults = %d, want 0", list.TotalResults)
	}
	if list.Resources == nil {
		t.Error("Resources is nil, want empty array")
	}
}

func TestSCIMListUsers_Pagination(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	// Create 5 users.
	for i := 0; i < 5; i++ {
		u := env.db.MustCreateUser(t, ctx,
			fmt.Sprintf("page-%d@example.com", i),
			fmt.Sprintf("Page User %d", i), "", 0)
		if err := env.db.CreateOrgMember(ctx, env.orgID, u.ID, "member"); err != nil {
			t.Fatalf("CreateOrgMember: %v", err)
		}
	}

	// Request page 1 with count=2.
	resp := env.scimRequest(t, http.MethodGet, "/Users?startIndex=1&count=2", nil)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, string(body))
	}

	list := decodeSCIMList(t, resp)
	if list.TotalResults != 5 {
		t.Errorf("totalResults = %d, want 5", list.TotalResults)
	}
	if list.ItemsPerPage != 2 {
		t.Errorf("itemsPerPage = %d, want 2", list.ItemsPerPage)
	}
	if list.StartIndex != 1 {
		t.Errorf("startIndex = %d, want 1", list.StartIndex)
	}
	if len(list.Resources) != 2 {
		t.Errorf("Resources length = %d, want 2", len(list.Resources))
	}

	// Request page 2.
	resp2 := env.scimRequest(t, http.MethodGet, "/Users?startIndex=3&count=2", nil)
	defer resp2.Body.Close() //nolint:errcheck

	list2 := decodeSCIMList(t, resp2)
	if list2.StartIndex != 3 {
		t.Errorf("startIndex = %d, want 3", list2.StartIndex)
	}
	if len(list2.Resources) != 2 {
		t.Errorf("Resources length = %d, want 2", len(list2.Resources))
	}
}

// ── User Update Tests ──────────────────────────────────────────────────────────

func TestSCIMReplaceUser_Success(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	user := env.db.MustCreateUser(t, ctx, "replace@example.com", "Original Name", "", 0)
	provider := fmt.Sprintf("scim:%s", env.scimConfigID)
	if err := env.db.UpsertUserIdentity(ctx, user.ID, provider, "ext-replace-001", user.Email); err != nil {
		t.Fatalf("UpsertUserIdentity: %v", err)
	}
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	active := true
	reqBody := scimUserRequest{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ExternalID:  "ext-replace-001",
		UserName:    "replaced@example.com",
		DisplayName: "Replaced Name",
		Active:      &active,
	}

	resp := env.scimRequest(t, http.MethodPut, "/Users/"+user.ID.String(), reqBody)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, string(body))
	}
	assertSCIMContentType(t, resp)

	scimUser := decodeSCIMUser(t, resp)
	if scimUser.UserName != "replaced@example.com" {
		t.Errorf("userName = %q, want %q", scimUser.UserName, "replaced@example.com")
	}
	if scimUser.DisplayName != "Replaced Name" {
		t.Errorf("displayName = %q, want %q", scimUser.DisplayName, "Replaced Name")
	}

	// Verify in DB.
	updated, err := env.db.GetUserByID(ctx, user.ID)
	if err != nil || updated == nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if updated.Email != "replaced@example.com" {
		t.Errorf("DB email = %q, want %q", updated.Email, "replaced@example.com")
	}
	if updated.DisplayName != "Replaced Name" {
		t.Errorf("DB displayName = %q, want %q", updated.DisplayName, "Replaced Name")
	}
}

func TestSCIMPatchUser_ReplaceActive(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	user := env.db.MustCreateUser(t, ctx, "patch-active@example.com", "Patch Active", "", 0)
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "viewer"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	reqBody := SCIMPatchOp{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []SCIMPatchOperation{
			{
				Op:    "replace",
				Path:  "active",
				Value: json.RawMessage(`false`),
			},
		},
	}

	resp := env.scimRequest(t, http.MethodPatch, "/Users/"+user.ID.String(), reqBody)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, string(body))
	}

	scimUser := decodeSCIMUser(t, resp)
	if scimUser.Active {
		t.Error("active = true, want false")
	}

	// Verify in DB.
	member, err := env.db.GetOrgMemberFull(ctx, env.orgID, user.ID)
	if err != nil {
		t.Fatalf("GetOrgMemberFull: %v", err)
	}
	if !member.DeactivatedAt.Valid {
		t.Error("deactivated_at is NULL, want non-NULL")
	}
}

func TestSCIMPatchUser_CaseInsensitiveOp(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	user := env.db.MustCreateUser(t, ctx, "patch-case@example.com", "Case Test", "", 0)
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "viewer"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	// Entra ID sends "Replace" with capital R.
	reqBody := SCIMPatchOp{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []SCIMPatchOperation{
			{
				Op:    "Replace",
				Path:  "active",
				Value: json.RawMessage(`false`),
			},
		},
	}

	resp := env.scimRequest(t, http.MethodPatch, "/Users/"+user.ID.String(), reqBody)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, string(body))
	}

	scimUser := decodeSCIMUser(t, resp)
	if scimUser.Active {
		t.Error("active = true, want false (case-insensitive op)")
	}
}

func TestSCIMPatchUser_StringBoolean(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	user := env.db.MustCreateUser(t, ctx, "patch-strbool@example.com", "Str Bool", "", 0)
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "viewer"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	// Entra ID sends "False" as a string instead of a JSON boolean.
	reqBody := SCIMPatchOp{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []SCIMPatchOperation{
			{
				Op:    "replace",
				Path:  "active",
				Value: json.RawMessage(`"False"`),
			},
		},
	}

	resp := env.scimRequest(t, http.MethodPatch, "/Users/"+user.ID.String(), reqBody)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, string(body))
	}

	scimUser := decodeSCIMUser(t, resp)
	if scimUser.Active {
		t.Error("active = true, want false (string boolean coercion)")
	}
}

func TestSCIMPatchUser_SoleOwner(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	owner := env.db.MustCreateUser(t, ctx, "sole-owner-patch@example.com", "Sole Owner", "", 0)
	if err := env.db.CreateOrgMember(ctx, env.orgID, owner.ID, "owner"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	reqBody := SCIMPatchOp{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []SCIMPatchOperation{
			{
				Op:    "replace",
				Path:  "active",
				Value: json.RawMessage(`false`),
			},
		},
	}

	resp := env.scimRequest(t, http.MethodPatch, "/Users/"+owner.ID.String(), reqBody)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 400 (body: %s)", resp.StatusCode, string(body))
	}
	assertSCIMContentType(t, resp)
}

// ── User Deprovision Tests ─────────────────────────────────────────────────────

func TestSCIMDeleteUser_Success(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	user := env.db.MustCreateUser(t, ctx, "delete@example.com", "Delete Me", "", 0)
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	resp := env.scimRequest(t, http.MethodDelete, "/Users/"+user.ID.String(), nil)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 204 (body: %s)", resp.StatusCode, string(body))
	}

	// Verify deactivated in DB.
	member, err := env.db.GetOrgMemberFull(ctx, env.orgID, user.ID)
	if err != nil {
		t.Fatalf("GetOrgMemberFull: %v", err)
	}
	if member == nil || !member.DeactivatedAt.Valid {
		t.Error("member should be deactivated after DELETE")
	}
}

func TestSCIMDeleteUser_NotFound(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)

	fakeID := uuid.New()
	resp := env.scimRequest(t, http.MethodDelete, "/Users/"+fakeID.String(), nil)
	defer resp.Body.Close() //nolint:errcheck

	// Idempotent — 204 even for non-existent users.
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204 (idempotent)", resp.StatusCode)
	}
}

func TestSCIMDeleteUser_SCIMExempt(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	user := env.db.MustCreateUser(t, ctx, "exempt-delete@example.com", "Exempt Delete", "", 0)
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}
	if err := env.db.UpdateOrgMemberSCIMExempt(ctx, env.orgID, user.ID, true); err != nil {
		t.Fatalf("UpdateOrgMemberSCIMExempt: %v", err)
	}

	resp := env.scimRequest(t, http.MethodDelete, "/Users/"+user.ID.String(), nil)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}

	// Verify NOT deactivated.
	member, err := env.db.GetOrgMemberFull(ctx, env.orgID, user.ID)
	if err != nil {
		t.Fatalf("GetOrgMemberFull: %v", err)
	}
	if member == nil {
		t.Fatal("member is nil")
	}
	if member.DeactivatedAt.Valid {
		t.Error("exempt user should NOT be deactivated")
	}
}

func TestSCIMDeleteUser_SoleOwner(t *testing.T) {
	t.Parallel()
	env := newSCIMUserTestEnv(t)
	ctx := context.Background()

	owner := env.db.MustCreateUser(t, ctx, "sole-owner-delete@example.com", "Sole Owner", "", 0)
	if err := env.db.CreateOrgMember(ctx, env.orgID, owner.ID, "owner"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	resp := env.scimRequest(t, http.MethodDelete, "/Users/"+owner.ID.String(), nil)
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("status = %d, want 400 (body: %s)", resp.StatusCode, string(body))
	}
	assertSCIMContentType(t, resp)
}
