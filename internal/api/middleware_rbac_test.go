// ABOUTME: Tests for RequireOrgRole middleware (RBAC enforcement + API key role cap).
// ABOUTME: Uses package api to access unexported context keys and Server fields.
package api

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// buildRBACTestServer builds an httptest server with RequireAuthenticated + RequireOrgRole
// wrapped around a handler that writes the effective role into gotRole.
// Uses chi router so the {org_id} URL param is resolved.
func buildRBACTestServer(t *testing.T, srv *Server, minRole Role) (*httptest.Server, *Role) {
	t.Helper()
	var gotRole Role
	r := chi.NewRouter()
	r.With(
		srv.RequireAuthenticated(),
		srv.RequireOrgRole(minRole),
	).Get("/orgs/{org_id}/resource", func(w http.ResponseWriter, r *http.Request) {
		gotRole, _ = r.Context().Value(ctxRole).(Role)
		w.WriteHeader(http.StatusOK)
	})
	return httptest.NewServer(r), &gotRole
}

// newRBACServer creates a Server backed by db.Store with the given JWT secret.
func newRBACServer(t *testing.T, db *testutil.TestDB, jwtSecret string) *Server {
	t.Helper()
	cfg := &config.Config{JWTSecret: jwtSecret} //nolint:exhaustruct // test: only JWT secret needed
	srv, err := NewServer(db.Store, cfg, ServerDeps{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func TestRequireOrgRole_SufficientRole_200(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := db.CreateOrg(ctx, "RBACOrg1")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	user, err := db.CreateUser(ctx, "rbac_admin@example.com", "RBACAdmin", "", 0)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.CreateOrgMember(ctx, org.ID, user.ID, "admin"); err != nil {
		t.Fatalf("create member: %v", err)
	}

	token, err := auth.IssueAccessToken([]byte("rbactestsecret"), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newRBACServer(t, db, "rbactestsecret")
	ts, gotRole := buildRBACTestServer(t, srv, RoleMember)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/orgs/"+org.ID.String()+"/resource", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Errorf("admin accessing member-gated resource: got %d, want 200", resp.StatusCode)
	}
	if *gotRole != RoleAdmin {
		t.Errorf("ctxRole = %v, want RoleAdmin (%d)", *gotRole, RoleAdmin)
	}
}

func TestRequireOrgRole_InsufficientRole_403(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "RBACOrg2")
	user, _ := db.CreateUser(ctx, "rbac_viewer@example.com", "RBACViewer", "", 0)
	_ = db.CreateOrgMember(ctx, org.ID, user.ID, "viewer")

	token, _ := auth.IssueAccessToken([]byte("rbactestsecret2"), user.ID, 1, 15*time.Minute)

	srv := newRBACServer(t, db, "rbactestsecret2")
	ts, _ := buildRBACTestServer(t, srv, RoleAdmin)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/orgs/"+org.ID.String()+"/resource", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer accessing admin-gated resource: got %d, want 403", resp.StatusCode)
	}
	assertRFC9457Response(t, resp, http.StatusForbidden)
}

func TestRequireOrgRole_NotAMember_403(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "RBACOrg3")
	// user is deliberately NOT added to the org.
	user, _ := db.CreateUser(ctx, "rbac_outsider@example.com", "RBACOutsider", "", 0)

	token, _ := auth.IssueAccessToken([]byte("rbactestsecret3"), user.ID, 1, 15*time.Minute)

	srv := newRBACServer(t, db, "rbactestsecret3")
	ts, _ := buildRBACTestServer(t, srv, RoleViewer)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/orgs/"+org.ID.String()+"/resource", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-member: got %d, want 403", resp.StatusCode)
	}
}

func TestRequireOrgRole_APIKeyRoleCapped_403(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "RBACOrg4")
	user, _ := db.CreateUser(ctx, "rbac_keycap@example.com", "RBACKeyCap", "", 0)
	_ = db.CreateOrgMember(ctx, org.ID, user.ID, "admin")

	// API key role = viewer → capped below the org role (admin).
	rawKey, keyHash, _ := auth.GenerateAPIKey()
	_, err := db.CreateAPIKey(ctx, org.ID, user.ID, keyHash, "low-key", "viewer", sql.NullTime{})
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}

	srv := newRBACServer(t, db, "rbactestsecret4")
	// Require admin — effective role = min(admin, viewer) = viewer → 403.
	ts, _ := buildRBACTestServer(t, srv, RoleAdmin)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/orgs/"+org.ID.String()+"/resource", nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer-capped API key accessing admin resource: got %d, want 403", resp.StatusCode)
	}
}

// Ensure Role type and parseRole are correct (no DB needed).
func TestParseRole(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input string
		want  Role
	}{
		{"owner", RoleOwner},
		{"admin", RoleAdmin},
		{"member", RoleMember},
		{"viewer", RoleViewer},
		{"unknown", RoleViewer},
		{"", RoleViewer},
	}
	for _, tc := range cases {
		got := parseRole(tc.input)
		if got != tc.want {
			t.Errorf("parseRole(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// Ensure roles are ordered correctly for comparison.
func TestRoleOrdering(t *testing.T) {
	t.Parallel()
	if RoleViewer >= RoleMember || RoleMember >= RoleAdmin || RoleAdmin >= RoleOwner {
		t.Error("role ordering: want viewer < member < admin < owner")
	}
}

// TestRequireOrgRole_NoUserID_401 verifies that RequireOrgRole returns 401
// when no userID is in the context (RequireAuthenticated was not called).
func TestRequireOrgRole_NoUserID_401(t *testing.T) {
	t.Parallel()
	srv := &Server{} //nolint:exhaustruct // test: only middleware under test

	handler := srv.RequireOrgRole(RoleViewer)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Use chi router to provide {org_id} URL param.
	r := chi.NewRouter()
	r.With(func(_ http.Handler) http.Handler { return handler }).
		Get("/orgs/{org_id}/resource", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

	req := httptest.NewRequest(http.MethodGet, "/orgs/"+uuid.New().String()+"/resource", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no userID in context: got %d, want 401", rec.Code)
	}
}

// TestRequireOrgRole_InvalidOrgID_400 verifies that RequireOrgRole returns 400
// when the org_id URL parameter is not a valid UUID.
func TestRequireOrgRole_InvalidOrgID_400(t *testing.T) {
	t.Parallel()
	srv := &Server{} //nolint:exhaustruct // test: only middleware under test
	userID := uuid.New()

	r := chi.NewRouter()
	r.With(
		// Inject a fake userID into context (simulating RequireAuthenticated).
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), ctxUserID, userID)
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		},
		srv.RequireOrgRole(RoleViewer),
	).Get("/orgs/{org_id}/resource", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/orgs/not-a-uuid/resource", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid org_id: got %d, want 400", rec.Code)
	}
}

// TestRequireOrgRole_ExactRoleMatch verifies that each role level grants access
// when it exactly meets the minimum required role.
func TestRequireOrgRole_ExactRoleMatch(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		orgRole string
		minRole Role
	}{
		{"owner meets owner", "owner", RoleOwner},
		{"admin meets admin", "admin", RoleAdmin},
		{"member meets member", "member", RoleMember},
		{"viewer meets viewer", "viewer", RoleViewer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db := testutil.NewTestDB(t)
			ctx := context.Background()

			org, err := db.CreateOrg(ctx, "ExactRole-"+tc.orgRole)
			if err != nil {
				t.Fatalf("create org: %v", err)
			}
			user, err := db.CreateUser(ctx, tc.orgRole+"exact@example.com", "ExactRole", "", 0)
			if err != nil {
				t.Fatalf("create user: %v", err)
			}
			if err := db.CreateOrgMember(ctx, org.ID, user.ID, tc.orgRole); err != nil {
				t.Fatalf("create member: %v", err)
			}

			token, err := auth.IssueAccessToken([]byte("exactrolesecret"), user.ID, 1, 15*time.Minute)
			if err != nil {
				t.Fatalf("issue token: %v", err)
			}

			srv := newRBACServer(t, db, "exactrolesecret")
			ts, gotRole := buildRBACTestServer(t, srv, tc.minRole)
			t.Cleanup(ts.Close)

			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/orgs/"+org.ID.String()+"/resource", nil)
			req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
			resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close() //nolint:errcheck
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s accessing %v-gated resource: got %d, want 200", tc.orgRole, tc.minRole, resp.StatusCode)
			}
			wantRole := parseRole(tc.orgRole)
			if *gotRole != wantRole {
				t.Errorf("ctxRole = %v, want %v", *gotRole, wantRole)
			}
		})
	}
}

// TestRequireOrgRole_APIKeyRoleNotCapped verifies that when the API key role
// is >= the org role, the effective role equals the org role (no cap applied).
func TestRequireOrgRole_APIKeyRoleNotCapped(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "RBACOrg5")
	user, _ := db.CreateUser(ctx, "rbac_keyhigh@example.com", "RBACKeyHigh", "", 0)
	_ = db.CreateOrgMember(ctx, org.ID, user.ID, "member")

	// API key role = admin → higher than the org role (member), so no capping.
	rawKey, keyHash, _ := auth.GenerateAPIKey()
	_, err := db.CreateAPIKey(ctx, org.ID, user.ID, keyHash, "high-key", "admin", sql.NullTime{})
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}

	srv := newRBACServer(t, db, "rbactestsecret5")
	ts, gotRole := buildRBACTestServer(t, srv, RoleMember)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/orgs/"+org.ID.String()+"/resource", nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Errorf("API key (admin) with org role (member) accessing member resource: got %d, want 200", resp.StatusCode)
	}
	// Effective role should be the org role (member), not capped by the higher API key role.
	if *gotRole != RoleMember {
		t.Errorf("ctxRole = %v, want RoleMember (%d)", *gotRole, RoleMember)
	}
}

// TestRequireOrgRole_APIKeyCrossOrg_403 verifies that an API key scoped to org A
// cannot be used to access org B's resources, even if the user is a member of both.
func TestRequireOrgRole_APIKeyCrossOrg_403(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgA, _ := db.CreateOrg(ctx, "RBACOrgA")
	orgB, _ := db.CreateOrg(ctx, "RBACOrgB")
	user, _ := db.CreateUser(ctx, "rbac_crossorg@example.com", "RBACCrossOrg", "", 0)
	// User is a member of both orgs.
	_ = db.CreateOrgMember(ctx, orgA.ID, user.ID, "admin")
	_ = db.CreateOrgMember(ctx, orgB.ID, user.ID, "admin")

	// Create an API key scoped to org A.
	rawKey, keyHash, _ := auth.GenerateAPIKey()
	_, err := db.CreateAPIKey(ctx, orgA.ID, user.ID, keyHash, "orgA-key", "admin", sql.NullTime{})
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}

	srv := newRBACServer(t, db, "rbactestsecret6")
	ts, _ := buildRBACTestServer(t, srv, RoleViewer)
	t.Cleanup(ts.Close)

	// Use org A's API key to access org B's resource — must be rejected.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/orgs/"+orgB.ID.String()+"/resource", nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("API key from org A accessing org B: got %d, want 403", resp.StatusCode)
	}
}

// TestRequireOrgRole_APIKeySameOrg_200 verifies that an API key scoped to org A
// can access org A's resources normally.
func TestRequireOrgRole_APIKeySameOrg_200(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "RBACOrgSame")
	user, _ := db.CreateUser(ctx, "rbac_sameorg@example.com", "RBACSameOrg", "", 0)
	_ = db.CreateOrgMember(ctx, org.ID, user.ID, "admin")

	rawKey, keyHash, _ := auth.GenerateAPIKey()
	_, err := db.CreateAPIKey(ctx, org.ID, user.ID, keyHash, "same-org-key", "admin", sql.NullTime{})
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}

	srv := newRBACServer(t, db, "rbactestsecret7")
	ts, gotRole := buildRBACTestServer(t, srv, RoleViewer)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/orgs/"+org.ID.String()+"/resource", nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Errorf("API key accessing same org: got %d, want 200", resp.StatusCode)
	}
	if *gotRole != RoleAdmin {
		t.Errorf("ctxRole = %v, want RoleAdmin (%d)", *gotRole, RoleAdmin)
	}
}

// Suppress unused import when uuid is not referenced directly.
var _ = uuid.UUID{}
