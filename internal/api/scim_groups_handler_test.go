// ABOUTME: Integration tests for SCIM 2.0 Group handlers (RFC 7644).
// ABOUTME: Uses real Postgres via testutil.NewTestDB and httptest.Server with SCIM auth.
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// scimGroupTestEnv bundles a test server with SCIM group routes mounted.
type scimGroupTestEnv struct {
	ts       *httptest.Server
	srv      *Server
	db       *testutil.TestDB
	orgID    uuid.UUID
	configID uuid.UUID
	rawToken string
	baseURL  string // e.g. http://host/api/v1/orgs/{org_id}/scim/v2
}

// newSCIMGroupTestEnv creates a full SCIM test environment with group routes.
func newSCIMGroupTestEnv(t *testing.T) *scimGroupTestEnv {
	t.Helper()

	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org := db.MustCreateOrg(t, ctx, "scim-group-test-"+uuid.New().String()[:8])

	// SSO connection (FK for scim_configs).
	ssoConn, err := db.CreateSSOConnection(ctx, org.ID, "Test IdP",
		"https://idp.example.com", "client-id", []byte("encrypted"), nil, true)
	require.NoError(t, err, "CreateSSOConnection")

	rawToken, tokenHash, tokenPrefix, err := auth.GenerateSCIMToken()
	require.NoError(t, err, "GenerateSCIMToken")

	scimCfg, err := db.CreateSCIMConfig(ctx, org.ID, ssoConn.ID, true, tokenHash, tokenPrefix, "viewer")
	require.NoError(t, err, "CreateSCIMConfig")

	cfg := &config.Config{ //nolint:exhaustruct,gosec // test: only relevant fields set; G101: test-only credential
		JWTSecret:           "scim-group-test-secret-32bytesmin",
		Argon2MaxConcurrent: 1,
	}
	srv, err := NewServer(db.Store, cfg, ServerDeps{})
	require.NoError(t, err, "NewServer")
	t.Cleanup(srv.Close)

	r := chi.NewRouter()
	r.Route("/api/v1/orgs/{org_id}/scim/v2", func(sub chi.Router) {
		sub.Use(srv.requireSCIMAuth)
		sub.Post("/Groups", srv.scimCreateGroup)
		sub.Get("/Groups", srv.scimListGroups)
		sub.Get("/Groups/{id}", srv.scimGetGroup)
		sub.Put("/Groups/{id}", srv.scimReplaceGroup)
		sub.Patch("/Groups/{id}", srv.scimPatchGroup)
		sub.Delete("/Groups/{id}", srv.scimDeleteGroup)
	})

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	env := &scimGroupTestEnv{
		ts:       ts,
		srv:      srv,
		db:       db,
		orgID:    org.ID,
		configID: scimCfg.ID,
		rawToken: rawToken,
		baseURL:  fmt.Sprintf("%s/api/v1/orgs/%s/scim/v2", ts.URL, org.ID),
	}

	return env
}

// scimRequest makes an authenticated SCIM request.
func (env *scimGroupTestEnv) scimRequest(t *testing.T, method, path string, body any) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, env.baseURL+path, bodyReader) //nolint:noctx // test code
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+env.rawToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}

	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: test httptest URL is not user-controlled
	require.NoError(t, err)
	return resp
}

// createTestUser creates a user and adds them as a member of the test org.
func (env *scimGroupTestEnv) createTestUser(t *testing.T, ctx context.Context, role string) uuid.UUID {
	t.Helper()
	user := env.db.MustCreateUser(t, ctx, uuid.New().String()+"@example.com", "Test User", "hash", 1)
	err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, role)
	require.NoError(t, err, "CreateOrgMember")
	return user.ID
}

// ── Tests ────────────────────────────────────────────────────────────────

func TestSCIMCreateGroup_Basic(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)

	resp := env.scimRequest(t, "POST", "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Engineering",
		"externalId":  "ext-eng-001",
	})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "application/scim+json", resp.Header.Get("Content-Type"))

	var group SCIMGroup
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&group))
	assert.Equal(t, "Engineering", group.DisplayName)
	assert.Equal(t, "ext-eng-001", group.ExternalID)
	assert.NotEmpty(t, group.ID)
	assert.Equal(t, "Group", group.Meta.ResourceType)
	assert.Empty(t, group.Members)
}

func TestSCIMCreateGroup_WithMembers(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)
	ctx := context.Background()

	userID := env.createTestUser(t, ctx, "viewer")

	resp := env.scimRequest(t, "POST", "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Team Alpha",
		"members": []map[string]string{
			{"value": userID.String()},
		},
	})
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var group SCIMGroup
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&group))
	assert.Equal(t, "Team Alpha", group.DisplayName)
	require.Len(t, group.Members, 1)
	assert.Equal(t, userID.String(), group.Members[0].Value)
}

func TestSCIMGetGroup_WithMembers(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)
	ctx := context.Background()

	userID := env.createTestUser(t, ctx, "viewer")

	// Create group with member.
	createResp := env.scimRequest(t, "POST", "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "DevOps",
		"members":     []map[string]string{{"value": userID.String()}},
	})
	defer createResp.Body.Close()
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	var created SCIMGroup
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&created))

	// GET the group.
	getResp := env.scimRequest(t, "GET", "/Groups/"+created.ID, nil)
	defer getResp.Body.Close()

	require.Equal(t, http.StatusOK, getResp.StatusCode)
	assert.Equal(t, "application/scim+json", getResp.Header.Get("Content-Type"))

	var got SCIMGroup
	require.NoError(t, json.NewDecoder(getResp.Body).Decode(&got))
	assert.Equal(t, "DevOps", got.DisplayName)
	require.Len(t, got.Members, 1)
	assert.Equal(t, userID.String(), got.Members[0].Value)
}

func TestSCIMGetGroup_NotFound(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)

	resp := env.scimRequest(t, "GET", "/Groups/"+uuid.New().String(), nil)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSCIMListGroups_FilterByDisplayName(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)

	// Create two groups.
	r1 := env.scimRequest(t, "POST", "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Frontend",
	})
	require.Equal(t, http.StatusCreated, r1.StatusCode)
	_ = r1.Body.Close()

	r2 := env.scimRequest(t, "POST", "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Backend",
	})
	require.Equal(t, http.StatusCreated, r2.StatusCode)
	_ = r2.Body.Close()

	// Filter by displayName. URL-encode the filter value.
	resp := env.scimRequest(t, "GET", `/Groups?filter=displayName+eq+"Frontend"`, nil)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var listResp SCIMListResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&listResp))
	assert.Equal(t, 1, listResp.TotalResults)
	require.Len(t, listResp.Resources, 1)

	// Verify the returned group is Frontend.
	raw, err := json.Marshal(listResp.Resources[0])
	require.NoError(t, err)
	var group SCIMGroup
	require.NoError(t, json.Unmarshal(raw, &group))
	assert.Equal(t, "Frontend", group.DisplayName)
}

func TestSCIMListGroups_NoFilter(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)

	ra := env.scimRequest(t, "POST", "/Groups", map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "displayName": "A",
	})
	require.Equal(t, http.StatusCreated, ra.StatusCode)
	_ = ra.Body.Close()

	rb := env.scimRequest(t, "POST", "/Groups", map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "displayName": "B",
	})
	require.Equal(t, http.StatusCreated, rb.StatusCode)
	_ = rb.Body.Close()

	resp := env.scimRequest(t, "GET", "/Groups", nil)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var listResp SCIMListResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&listResp))
	assert.Equal(t, 2, listResp.TotalResults)
	assert.Len(t, listResp.Resources, 2)
}

func TestSCIMPatchGroup_AddMembers(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)
	ctx := context.Background()

	userID := env.createTestUser(t, ctx, "viewer")

	// Create empty group.
	createResp := env.scimRequest(t, "POST", "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "PatchTest",
	})
	defer createResp.Body.Close()
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	var created SCIMGroup
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&created))

	// PATCH add member.
	patchResp := env.scimRequest(t, "PATCH", "/Groups/"+created.ID, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{
				"op":   "add",
				"path": "members",
				"value": []map[string]string{
					{"value": userID.String()},
				},
			},
		},
	})
	defer patchResp.Body.Close()

	require.Equal(t, http.StatusOK, patchResp.StatusCode)

	var patched SCIMGroup
	require.NoError(t, json.NewDecoder(patchResp.Body).Decode(&patched))
	require.Len(t, patched.Members, 1)
	assert.Equal(t, userID.String(), patched.Members[0].Value)
}

func TestSCIMPatchGroup_RemoveMembers_Standard(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)
	ctx := context.Background()

	userID := env.createTestUser(t, ctx, "viewer")

	// Create group with member.
	createResp := env.scimRequest(t, "POST", "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "RemoveStd",
		"members":     []map[string]string{{"value": userID.String()}},
	})
	defer createResp.Body.Close()
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	var created SCIMGroup
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&created))
	require.Len(t, created.Members, 1)

	// PATCH remove member using standard path filter format.
	patchResp := env.scimRequest(t, "PATCH", "/Groups/"+created.ID, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{
				"op":   "remove",
				"path": fmt.Sprintf(`members[value eq "%s"]`, userID.String()),
			},
		},
	})
	defer patchResp.Body.Close()

	require.Equal(t, http.StatusOK, patchResp.StatusCode)

	var patched SCIMGroup
	require.NoError(t, json.NewDecoder(patchResp.Body).Decode(&patched))
	assert.Empty(t, patched.Members)
}

func TestSCIMPatchGroup_RemoveMembers_EntraID(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)
	ctx := context.Background()

	userID := env.createTestUser(t, ctx, "viewer")

	// Create group with member.
	createResp := env.scimRequest(t, "POST", "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "RemoveEntra",
		"members":     []map[string]string{{"value": userID.String()}},
	})
	defer createResp.Body.Close()
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	var created SCIMGroup
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&created))
	require.Len(t, created.Members, 1)

	// PATCH remove member using Entra ID format (value array).
	patchResp := env.scimRequest(t, "PATCH", "/Groups/"+created.ID, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{
				"op":   "Remove",
				"path": "members",
				"value": []map[string]string{
					{"value": userID.String()},
				},
			},
		},
	})
	defer patchResp.Body.Close()

	require.Equal(t, http.StatusOK, patchResp.StatusCode)

	var patched SCIMGroup
	require.NoError(t, json.NewDecoder(patchResp.Body).Decode(&patched))
	assert.Empty(t, patched.Members)
}

func TestSCIMPatchGroup_UpdateDisplayName(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)

	// Create group.
	createResp := env.scimRequest(t, "POST", "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "OldName",
	})
	defer createResp.Body.Close()
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	var created SCIMGroup
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&created))

	// PATCH replace displayName.
	patchResp := env.scimRequest(t, "PATCH", "/Groups/"+created.ID, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{
				"op":    "Replace",
				"path":  "displayName",
				"value": "NewName",
			},
		},
	})
	defer patchResp.Body.Close()

	require.Equal(t, http.StatusOK, patchResp.StatusCode)

	var patched SCIMGroup
	require.NoError(t, json.NewDecoder(patchResp.Body).Decode(&patched))
	assert.Equal(t, "NewName", patched.DisplayName)
}

func TestSCIMReplaceGroup_MemberDiff(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)
	ctx := context.Background()

	user1 := env.createTestUser(t, ctx, "viewer")
	user2 := env.createTestUser(t, ctx, "viewer")

	// Create group with user1.
	createResp := env.scimRequest(t, "POST", "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "ReplaceTest",
		"members":     []map[string]string{{"value": user1.String()}},
	})
	defer createResp.Body.Close()
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	var created SCIMGroup
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&created))
	require.Len(t, created.Members, 1)

	// PUT with user2 only (removes user1, adds user2).
	putResp := env.scimRequest(t, "PUT", "/Groups/"+created.ID, map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "ReplaceTest Updated",
		"members":     []map[string]string{{"value": user2.String()}},
	})
	defer putResp.Body.Close()

	require.Equal(t, http.StatusOK, putResp.StatusCode)

	var replaced SCIMGroup
	require.NoError(t, json.NewDecoder(putResp.Body).Decode(&replaced))
	assert.Equal(t, "ReplaceTest Updated", replaced.DisplayName)
	require.Len(t, replaced.Members, 1)
	assert.Equal(t, user2.String(), replaced.Members[0].Value)
}

func TestSCIMDeleteGroup_CascadesMembers(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)
	ctx := context.Background()

	userID := env.createTestUser(t, ctx, "viewer")

	// Create group with member.
	createResp := env.scimRequest(t, "POST", "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "DeleteTest",
		"members":     []map[string]string{{"value": userID.String()}},
	})
	defer createResp.Body.Close()
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	var created SCIMGroup
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&created))

	// DELETE the group.
	delResp := env.scimRequest(t, "DELETE", "/Groups/"+created.ID, nil)
	defer delResp.Body.Close()

	require.Equal(t, http.StatusNoContent, delResp.StatusCode)

	// Verify group is gone.
	getResp := env.scimRequest(t, "GET", "/Groups/"+created.ID, nil)
	defer getResp.Body.Close()
	assert.Equal(t, http.StatusNotFound, getResp.StatusCode)

	// Verify members are gone.
	memberIDs, err := env.db.ListSCIMGroupMembers(ctx, uuid.MustParse(created.ID))
	require.NoError(t, err)
	assert.Empty(t, memberIDs)
}

func TestSCIMDeleteGroup_RecomputesRoles(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)
	ctx := context.Background()

	userID := env.createTestUser(t, ctx, "viewer")

	// Create a SCIM group with mapped_role=admin and add the user.
	group, err := env.db.CreateSCIMGroup(ctx, env.orgID, nil, "AdminGroup")
	require.NoError(t, err)
	adminRole := "admin"
	require.NoError(t, env.db.UpdateSCIMGroupMapping(ctx, group.ID, &adminRole, nil))
	require.NoError(t, env.db.AddSCIMGroupMember(ctx, group.ID, userID, env.orgID))

	// Recompute role to set user to admin.
	require.NoError(t, env.srv.recomputeSCIMRole(ctx, env.orgID, userID, "viewer"))
	member, err := env.db.GetOrgMemberFull(ctx, env.orgID, userID)
	require.NoError(t, err)
	require.Equal(t, "admin", member.Role)

	// DELETE the group via SCIM.
	delResp := env.scimRequest(t, "DELETE", "/Groups/"+group.ID.String(), nil)
	defer delResp.Body.Close()
	require.Equal(t, http.StatusNoContent, delResp.StatusCode)

	// Verify role was recomputed back to default (viewer).
	member, err = env.db.GetOrgMemberFull(ctx, env.orgID, userID)
	require.NoError(t, err)
	require.Equal(t, "viewer", member.Role)
}

func TestSCIMDeleteGroup_Idempotent(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)

	// Delete a non-existent group — should return 204.
	resp := env.scimRequest(t, "DELETE", "/Groups/"+uuid.New().String(), nil)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestSCIMCreateGroup_MissingDisplayName(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)

	resp := env.scimRequest(t, "POST", "/Groups", map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
	})
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var scimErr SCIMError
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&scimErr))
	assert.Equal(t, "invalidValue", scimErr.SCIMType)
}

func TestSCIMPatchGroup_NotFound(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)

	resp := env.scimRequest(t, "PATCH", "/Groups/"+uuid.New().String(), map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "replace", "path": "displayName", "value": "X"},
		},
	})
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSCIMReplaceGroup_NotFound(t *testing.T) {
	t.Parallel()
	env := newSCIMGroupTestEnv(t)

	resp := env.scimRequest(t, "PUT", "/Groups/"+uuid.New().String(), map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "NoSuchGroup",
	})
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}
