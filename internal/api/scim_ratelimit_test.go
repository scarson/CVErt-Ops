// ABOUTME: Tests for the dedicated SCIM per-org rate limiter.
// ABOUTME: Validates per-org enforcement, cross-org independence, and SCIM error format.
package api

import (
	"context"
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

// scimRLTestEnv bundles a test server with SCIM auth + rate limiter mounted.
type scimRLTestEnv struct {
	ts       *httptest.Server
	srv      *Server
	db       *testutil.TestDB
	orgID    uuid.UUID
	rawToken string
}

// newSCIMRLTestEnv sets up a test environment for SCIM rate limiter tests.
// The rate limit is set to rateLimit req/sec.
func newSCIMRLTestEnv(t *testing.T, rateLimit float64) *scimRLTestEnv {
	t.Helper()

	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := db.CreateOrg(ctx, "scim-rl-org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	ssoConn, err := db.CreateSSOConnection(ctx, org.ID, "RL IdP",
		"https://idp.example.com", "client-id", []byte("encrypted"), nil, true)
	if err != nil {
		t.Fatalf("CreateSSOConnection: %v", err)
	}

	rawToken, tokenHash, tokenPrefix, err := auth.GenerateSCIMToken()
	if err != nil {
		t.Fatalf("GenerateSCIMToken: %v", err)
	}

	_, err = db.CreateSCIMConfig(ctx, org.ID, ssoConn.ID, true, tokenHash, tokenPrefix, "viewer")
	if err != nil {
		t.Fatalf("CreateSCIMConfig: %v", err)
	}

	ew := secure.NewEventWriter(db.Store)

	cfg := &config.Config{ //nolint:exhaustruct,gosec // test: only relevant fields set; G101 false positive
		JWTSecret:     "scim-rl-test-secret-32bytes-min",
		SCIMRateLimit: rateLimit,
	}
	srv, err := NewServer(db.Store, cfg, ServerDeps{EventWriter: ew})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)

	r := chi.NewRouter()
	r.Route("/api/v1/orgs/{org_id}/scim/v2", func(sub chi.Router) {
		sub.Use(srv.requireSCIMAuth)
		sub.Use(srv.scimRateLimit())
		sub.Get("/test", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	return &scimRLTestEnv{
		ts:       ts,
		srv:      srv,
		db:       db,
		orgID:    org.ID,
		rawToken: rawToken,
	}
}

func TestSCIMRateLimit_EnforcesLimit(t *testing.T) {
	t.Parallel()
	// 2 req/sec — first 2 succeed, rest get 429.
	env := newSCIMRLTestEnv(t, 2)

	var successCount, limitedCount int
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
			env.ts.URL+"/api/v1/orgs/"+env.orgID.String()+"/scim/v2/test", nil)
		req.Header.Set("Authorization", "Bearer "+env.rawToken)

		resp, err := env.ts.Client().Do(req) //nolint:gosec // G704 false positive: httptest URL
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		switch resp.StatusCode {
		case http.StatusOK:
			successCount++
		case http.StatusTooManyRequests:
			limitedCount++
			// Verify SCIM error format on 429 responses.
			ct := resp.Header.Get("Content-Type")
			if ct != "application/scim+json" {
				t.Errorf("429 Content-Type = %q, want %q", ct, "application/scim+json")
			}
		default:
			body, _ := io.ReadAll(resp.Body) //nolint:errcheck
			t.Errorf("request %d: unexpected status %d (body: %s)", i, resp.StatusCode, string(body))
		}
		resp.Body.Close() //nolint:errcheck,gosec // G104: test cleanup
	}

	if successCount == 0 {
		t.Error("expected at least 1 successful request, got 0")
	}
	if limitedCount == 0 {
		t.Error("expected at least 1 rate-limited request, got 0")
	}
	t.Logf("success=%d limited=%d", successCount, limitedCount)
}

func TestSCIMRateLimit_PerOrg(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create two orgs, each with SCIM config.
	orgA, err := db.CreateOrg(ctx, "scim-rl-orgA")
	if err != nil {
		t.Fatalf("CreateOrg A: %v", err)
	}
	ssoA, err := db.CreateSSOConnection(ctx, orgA.ID, "IdP A",
		"https://idp-a.example.com", "client-a", []byte("enc"), nil, true)
	if err != nil {
		t.Fatalf("CreateSSOConnection A: %v", err)
	}
	rawA, hashA, prefA, err := auth.GenerateSCIMToken()
	if err != nil {
		t.Fatalf("GenerateSCIMToken A: %v", err)
	}
	_, err = db.CreateSCIMConfig(ctx, orgA.ID, ssoA.ID, true, hashA, prefA, "viewer")
	if err != nil {
		t.Fatalf("CreateSCIMConfig A: %v", err)
	}

	orgB, err := db.CreateOrg(ctx, "scim-rl-orgB")
	if err != nil {
		t.Fatalf("CreateOrg B: %v", err)
	}
	ssoB, err := db.CreateSSOConnection(ctx, orgB.ID, "IdP B",
		"https://idp-b.example.com", "client-b", []byte("enc"), nil, true)
	if err != nil {
		t.Fatalf("CreateSSOConnection B: %v", err)
	}
	rawB, hashB, prefB, err := auth.GenerateSCIMToken()
	if err != nil {
		t.Fatalf("GenerateSCIMToken B: %v", err)
	}
	_, err = db.CreateSCIMConfig(ctx, orgB.ID, ssoB.ID, true, hashB, prefB, "viewer")
	if err != nil {
		t.Fatalf("CreateSCIMConfig B: %v", err)
	}

	ew := secure.NewEventWriter(db.Store)
	cfg := &config.Config{ //nolint:exhaustruct,gosec // test: only relevant fields set; G101 false positive
		JWTSecret:     "scim-rl-perorg-secret-32bytes-m",
		SCIMRateLimit: 2, // 2 req/sec
	}
	srv, err := NewServer(db.Store, cfg, ServerDeps{EventWriter: ew})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)

	r := chi.NewRouter()
	r.Route("/api/v1/orgs/{org_id}/scim/v2", func(sub chi.Router) {
		sub.Use(srv.requireSCIMAuth)
		sub.Use(srv.scimRateLimit())
		sub.Get("/test", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	// Exhaust org A's rate limit.
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
			ts.URL+"/api/v1/orgs/"+orgA.ID.String()+"/scim/v2/test", nil)
		req.Header.Set("Authorization", "Bearer "+rawA)
		resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: httptest URL
		if err != nil {
			t.Fatalf("orgA request %d: %v", i, err)
		}
		resp.Body.Close() //nolint:errcheck,gosec // G104: test cleanup
	}

	// Org B should still succeed.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		ts.URL+"/api/v1/orgs/"+orgB.ID.String()+"/scim/v2/test", nil)
	req.Header.Set("Authorization", "Bearer "+rawB)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: httptest URL
	if err != nil {
		t.Fatalf("orgB request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Errorf("orgB status = %d, want 200 (body: %s)", resp.StatusCode, string(body))
	}
}
