// ABOUTME: Integration tests for auth HTTP handlers (register, login, refresh, logout, me).
// ABOUTME: Uses real Postgres via testutil.NewTestDB and the full srv.Handler() stack.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// newRegisterServer creates a full Server + httptest.Server for auth handler tests.
func newRegisterServer(t *testing.T, db *testutil.TestDB, regMode string) (*Server, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:           "regtestsecret",
		RegistrationMode:    regMode,
		Argon2MaxConcurrent: 5,
	}
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

func TestRegisterFirstUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")

	body := `{"email":"first@example.com","password":"password123","display_name":"First User"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104: body close in test

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first registration: got %d, want 201", resp.StatusCode)
	}

	var respBody struct {
		UserID string `json:"user_id"`
		OrgID  string `json:"org_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if respBody.UserID == "" {
		t.Error("user_id missing from response")
	}
	if respBody.OrgID == "" {
		t.Error("org_id missing from response (first user should get a default org)")
	}

	// Verify DB state.
	userID, err := uuid.Parse(respBody.UserID)
	if err != nil {
		t.Fatalf("parse user_id: %v", err)
	}
	orgID, err := uuid.Parse(respBody.OrgID)
	if err != nil {
		t.Fatalf("parse org_id: %v", err)
	}

	user, err := db.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		t.Fatalf("user not found in DB: %v", err)
	}
	if user.Email != "first@example.com" {
		t.Errorf("user email = %q, want %q", user.Email, "first@example.com")
	}

	roleStr, err := db.GetOrgMemberRole(ctx, orgID, userID)
	if err != nil || roleStr == nil {
		t.Fatalf("org member role not found: %v", err)
	}
	if *roleStr != "owner" {
		t.Errorf("org member role = %q, want %q", *roleStr, "owner")
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")

	body := `{"email":"dup@example.com","password":"password123"}`

	// First registration — should succeed.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // G104: body close in test
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first registration: got %d, want 201", resp.StatusCode)
	}

	// Second registration with same email — should return 409.
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := ts.Client().Do(req2) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104: body close in test
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("duplicate email: got %d, want 409", resp2.StatusCode)
	}
}
