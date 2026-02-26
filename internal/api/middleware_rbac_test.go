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
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
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

// Suppress unused import when uuid is not referenced directly.
var _ = uuid.UUID{}
