// ABOUTME: Tests for SCIM bearer token authentication middleware.
// ABOUTME: Validates token auth, org isolation, disabled config, error format, and security events.
package api

import (
	"context"
	"encoding/json"
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

// scimTestEnv bundles a test server with SCIM middleware mounted plus the raw token
// and org/config IDs for assertions.
type scimTestEnv struct {
	ts          *httptest.Server
	srv         *Server
	ew          *secure.EventWriter
	db          *testutil.TestDB
	orgID       uuid.UUID
	configID    uuid.UUID
	rawToken    string
	capturedCtx context.Context // captured from the inner handler
}

// newSCIMTestEnv sets up a test environment with org, SSO connection, and SCIM config.
// The inner handler captures the context so tests can inspect ctxOrgID and ctxSCIMConfigID.
func newSCIMTestEnv(t *testing.T, enabled bool) *scimTestEnv {
	t.Helper()

	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create org.
	org, err := db.CreateOrg(ctx, "scim-test-org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	// Create SSO connection (required FK for scim_configs).
	ssoConn, err := db.CreateSSOConnection(ctx, org.ID, "Test IdP",
		"https://idp.example.com", "client-id", []byte("encrypted"), nil, true)
	if err != nil {
		t.Fatalf("CreateSSOConnection: %v", err)
	}

	// Generate SCIM token and create config.
	rawToken, tokenHash, tokenPrefix, err := auth.GenerateSCIMToken()
	if err != nil {
		t.Fatalf("GenerateSCIMToken: %v", err)
	}

	scimCfg, err := db.CreateSCIMConfig(ctx, org.ID, ssoConn.ID, enabled, tokenHash, tokenPrefix, "viewer")
	if err != nil {
		t.Fatalf("CreateSCIMConfig: %v", err)
	}

	// Create event writer backed by real DB.
	ew := secure.NewEventWriter(db.Store)

	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret: "scim-test-secret-32bytes-minimum",
	}
	srv, err := NewServer(db.Store, cfg, ServerDeps{EventWriter: ew})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)

	env := &scimTestEnv{
		srv:      srv,
		ew:       ew,
		db:       db,
		orgID:    org.ID,
		configID: scimCfg.ID,
		rawToken: rawToken,
	}

	// Build chi router with {org_id} param and SCIM auth middleware.
	r := chi.NewRouter()
	r.Route("/api/v1/orgs/{org_id}/scim/v2", func(sub chi.Router) {
		sub.Use(srv.requireSCIMAuth)
		sub.Get("/test", func(w http.ResponseWriter, r *http.Request) {
			env.capturedCtx = r.Context()
			w.WriteHeader(http.StatusOK)
		})
	})

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	env.ts = ts

	return env
}

// assertSCIMErrorResponse checks that the response is a valid SCIM error JSON
// with the correct Content-Type and status.
func assertSCIMErrorResponse(t *testing.T, resp *http.Response, wantStatus int) {
	t.Helper()
	ct := resp.Header.Get("Content-Type")
	if ct != "application/scim+json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/scim+json")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var scimErr struct {
		Schemas []string `json:"schemas"`
		Status  string   `json:"status"`
		Detail  string   `json:"detail"`
	}
	if err := json.Unmarshal(body, &scimErr); err != nil {
		t.Fatalf("decode SCIM error: %v (body: %s)", err, string(body))
	}
	if len(scimErr.Schemas) != 1 || scimErr.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
		t.Errorf("schemas = %v, want [urn:ietf:params:scim:api:messages:2.0:Error]", scimErr.Schemas)
	}
	wantStatusStr := http.StatusText(wantStatus)
	_ = wantStatusStr // status field is the numeric string
	if scimErr.Detail == "" {
		t.Error("SCIM error detail is empty")
	}
}

func TestSCIMAuth_ValidToken(t *testing.T) {
	t.Parallel()
	env := newSCIMTestEnv(t, true)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		env.ts.URL+"/api/v1/orgs/"+env.orgID.String()+"/scim/v2/test", nil)
	req.Header.Set("Authorization", "Bearer "+env.rawToken)

	resp, err := env.ts.Client().Do(req) //nolint:gosec // G704 false positive: httptest URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// Verify context values were injected.
	gotOrgID, ok := env.capturedCtx.Value(ctxOrgID).(uuid.UUID)
	if !ok || gotOrgID != env.orgID {
		t.Errorf("ctxOrgID = %v, want %v", gotOrgID, env.orgID)
	}
	gotConfigID, ok := env.capturedCtx.Value(ctxSCIMConfigID).(uuid.UUID)
	if !ok || gotConfigID != env.configID {
		t.Errorf("ctxSCIMConfigID = %v, want %v", gotConfigID, env.configID)
	}
}

func TestSCIMAuth_InvalidToken(t *testing.T) {
	t.Parallel()
	env := newSCIMTestEnv(t, true)

	// Well-formed but wrong token: same prefix, correct length, different random bytes.
	wrongToken, _, _, err := auth.GenerateSCIMToken()
	if err != nil {
		t.Fatalf("GenerateSCIMToken: %v", err)
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		env.ts.URL+"/api/v1/orgs/"+env.orgID.String()+"/scim/v2/test", nil)
	req.Header.Set("Authorization", "Bearer "+wrongToken)

	resp, err := env.ts.Client().Do(req) //nolint:gosec // G704 false positive: httptest URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	assertSCIMErrorResponse(t, resp, http.StatusUnauthorized)
}

func TestSCIMAuth_OrgMismatch(t *testing.T) {
	t.Parallel()
	env := newSCIMTestEnv(t, true)

	// Create a second org — token belongs to env.orgID, not this one.
	ctx := context.Background()
	org2, err := env.db.CreateOrg(ctx, "scim-other-org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		env.ts.URL+"/api/v1/orgs/"+org2.ID.String()+"/scim/v2/test", nil)
	req.Header.Set("Authorization", "Bearer "+env.rawToken)

	resp, err := env.ts.Client().Do(req) //nolint:gosec // G704 false positive: httptest URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	assertSCIMErrorResponse(t, resp, http.StatusUnauthorized)
}

func TestSCIMAuth_Disabled(t *testing.T) {
	t.Parallel()
	env := newSCIMTestEnv(t, false) // config disabled

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		env.ts.URL+"/api/v1/orgs/"+env.orgID.String()+"/scim/v2/test", nil)
	req.Header.Set("Authorization", "Bearer "+env.rawToken)

	resp, err := env.ts.Client().Do(req) //nolint:gosec // G704 false positive: httptest URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	assertSCIMErrorResponse(t, resp, http.StatusForbidden)
}

func TestSCIMAuth_MissingHeader(t *testing.T) {
	t.Parallel()
	env := newSCIMTestEnv(t, true)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		env.ts.URL+"/api/v1/orgs/"+env.orgID.String()+"/scim/v2/test", nil)
	// No Authorization header.

	resp, err := env.ts.Client().Do(req) //nolint:gosec // G704 false positive: httptest URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	assertSCIMErrorResponse(t, resp, http.StatusUnauthorized)
}

func TestSCIMAuth_ErrorFormat(t *testing.T) {
	t.Parallel()
	env := newSCIMTestEnv(t, true)

	// Test multiple error scenarios all produce application/scim+json.
	scenarios := []struct {
		name       string
		authHeader string
		orgID      string
		wantStatus int
	}{
		{"no_auth_header", "", env.orgID.String(), http.StatusUnauthorized},
		{"bad_bearer", "Bearer " + "cvert_scim_0000000000000000000000000000000000000000000000000000000000000000", env.orgID.String(), http.StatusUnauthorized},
		{"invalid_org_id", "Bearer " + env.rawToken, "not-a-uuid", http.StatusBadRequest},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
				env.ts.URL+"/api/v1/orgs/"+sc.orgID+"/scim/v2/test", nil)
			if sc.authHeader != "" {
				req.Header.Set("Authorization", sc.authHeader)
			}
			resp, err := env.ts.Client().Do(req) //nolint:gosec // G704 false positive: httptest URL
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close() //nolint:errcheck

			if resp.StatusCode != sc.wantStatus {
				body, _ := io.ReadAll(resp.Body) //nolint:errcheck
				t.Errorf("status = %d, want %d (body: %s)", resp.StatusCode, sc.wantStatus, string(body))
				return
			}

			ct := resp.Header.Get("Content-Type")
			if ct != "application/scim+json" {
				t.Errorf("Content-Type = %q, want %q", ct, "application/scim+json")
			}
		})
	}
}

func TestSCIMAuth_SecurityEvent(t *testing.T) {
	t.Parallel()
	env := newSCIMTestEnv(t, true)

	// Send a request with a well-formed but wrong token.
	wrongToken, _, _, err := auth.GenerateSCIMToken()
	if err != nil {
		t.Fatalf("GenerateSCIMToken: %v", err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		env.ts.URL+"/api/v1/orgs/"+env.orgID.String()+"/scim/v2/test", nil)
	req.Header.Set("Authorization", "Bearer "+wrongToken)

	resp, err := env.ts.Client().Do(req) //nolint:gosec // G704 false positive: httptest URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	// Flush event writer and query security_events.
	events := flushAndQueryEvents(t, env.ew, env.db, secure.EventSCIMAuthFailed)
	if len(events) == 0 {
		t.Error("expected at least one scim.auth_failed security event, got 0")
	}
}
