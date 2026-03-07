// ABOUTME: Tests for RequireSiteAdmin middleware — verifies non-admin gets 403, admin gets 200.
// ABOUTME: Uses real Postgres via testutil.NewTestDB for accurate integration testing.
package api

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestRequireSiteAdmin_NonAdmin_403(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create a regular user (not site admin).
	user, err := db.CreateUser(ctx, "nonadmin@example.com", "Regular", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret := "testsecret"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	handler := srv.RequireAuthenticated()(srv.RequireSiteAdmin()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin user: got %d, want 403", resp.StatusCode)
	}
}

func TestRequireSiteAdmin_Admin_200(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create a user and promote to site admin.
	user, err := db.CreateUser(ctx, "admin@example.com", "Admin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, user.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	secret := "testsecret"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	handler := srv.RequireAuthenticated()(srv.RequireSiteAdmin()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Errorf("site admin user: got %d, want 200", resp.StatusCode)
	}
}

func TestRequireSiteAdmin_NoAuth_401(t *testing.T) {
	t.Parallel()
	srv := newAuthTestServer(t, "testsecret", nil)
	// RequireSiteAdmin without RequireAuthenticated — should get 401 because no userID in context.
	handler := srv.RequireSiteAdmin()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no auth context: got %d, want 401", resp.StatusCode)
	}
}

func TestRequireSiteAdmin_UnknownUser_500(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)

	// Capture expected error log to keep test output pristine.
	var buf bytes.Buffer
	origHandler := slog.Default().Handler()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(slog.New(origHandler)) })

	fakeUserID := uuid.New()

	srv := newAuthTestServer(t, "testsecret", db)
	// Manually inject ctxUserID with a non-existent user, then RequireSiteAdmin.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ctxUserID, fakeUserID)
		srv.RequireSiteAdmin()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(w, r.WithContext(ctx))
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	// Unknown user ID → IsSiteAdmin returns sql.ErrNoRows → 500.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("unknown user: got %d, want 500", resp.StatusCode)
	}
	if !strings.Contains(buf.String(), "check site admin") {
		t.Errorf("expected 'check site admin' in log output, got: %s", buf.String())
	}
}
