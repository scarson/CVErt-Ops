// ABOUTME: Generates the OpenAPI 3.1 spec from huma route registrations without a database.
// ABOUTME: Run with GENERATE_OPENAPI=1 to write openapi.json to the repo root.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/scarson/cvert-ops/internal/config"
)

func TestOpenAPISpec(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:   "test-secret-for-openapi-generation",
		ExternalURL: "http://localhost:8080",
		FrontendURL: "/",
	}
	srv, err := NewServer(nil, cfg, ServerDeps{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	handler := srv.Handler()

	// Merge spec-only Chi route declarations into the production huma API.
	specAPI := newSpecOnlyAPI()
	registerAllSpecOps(specAPI)
	mergeSpecPaths(srv.humaAPI, specAPI)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/openapi.json: status %d, body: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.Bytes()

	// Verify valid JSON.
	var spec map[string]any
	if err := json.Unmarshal(body, &spec); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Verify OpenAPI 3.1 version.
	if v, ok := spec["openapi"]; !ok {
		t.Error("missing 'openapi' field")
	} else if s, ok := v.(string); !ok || len(s) < 3 || s[:3] != "3.1" {
		t.Errorf("unexpected openapi version: %v", v)
	}

	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatal("missing or invalid 'paths' field")
	}

	// Assert every expected path exists in the merged spec.
	expectedPaths := []string{
		// Auth (huma-registered)
		"/auth/register", "/auth/login", "/auth/refresh", "/auth/logout",
		"/auth/me", "/auth/change-password",
		"/auth/invitations/{token}", "/auth/invitations/{token}/accept",
		"/auth/providers", "/auth/forgot-password", "/auth/reset-password",
		"/auth/verify-email", "/auth/resend-verification",

		// CVEs (huma-registered)
		"/cves", "/cves/{cve_id}", "/cves/{cve_id}/sources",

		// Spec-only: Groups
		"/orgs/{org_id}/groups",
		"/orgs/{org_id}/groups/{group_id}",
		"/orgs/{org_id}/groups/{group_id}/members",
		"/orgs/{org_id}/groups/{group_id}/members/{user_id}",

		// Spec-only: Orgs
		"/orgs",
		"/orgs/{org_id}",
		"/orgs/{org_id}/members",
		"/orgs/{org_id}/members/{user_id}",
		"/orgs/{org_id}/invitations",
		"/orgs/{org_id}/invitations/{id}",
		"/orgs/{org_id}/invitations/{id}/resend",

		// Spec-only: API Keys
		"/orgs/{org_id}/api-keys",
		"/orgs/{org_id}/api-keys/{id}",

		// Spec-only: Watchlists
		"/orgs/{org_id}/watchlists",
		"/orgs/{org_id}/watchlists/{id}",
		"/orgs/{org_id}/watchlists/{id}/items",
		"/orgs/{org_id}/watchlists/{id}/items/{item_id}",

		// Spec-only: Alert Rules
		"/orgs/{org_id}/alert-rules",
		"/orgs/{org_id}/alert-rules/{id}",
		"/orgs/{org_id}/alert-rules/validate",
		"/orgs/{org_id}/alert-rules/{id}/dry-run",
		"/orgs/{org_id}/alert-rules/{id}/channels",
		"/orgs/{org_id}/alert-rules/{id}/channels/{channel_id}",

		// Spec-only: Alert Events
		"/orgs/{org_id}/alert-events",

		// Spec-only: Channels
		"/orgs/{org_id}/channels",
		"/orgs/{org_id}/channels/{id}",
		"/orgs/{org_id}/channels/{id}/rotate-secret",
		"/orgs/{org_id}/channels/{id}/clear-secondary",
		"/orgs/{org_id}/channels/{id}/test",

		// Spec-only: Deliveries
		"/orgs/{org_id}/deliveries",
		"/orgs/{org_id}/deliveries/{id}",
		"/orgs/{org_id}/deliveries/{id}/replay",

		// Spec-only: Reports
		"/orgs/{org_id}/reports",
		"/orgs/{org_id}/reports/{id}",
		"/orgs/{org_id}/reports/{id}/channels",
		"/orgs/{org_id}/reports/{id}/channels/{channel_id}",

		// Spec-only: Saved Searches
		"/orgs/{org_id}/saved-searches",
		"/orgs/{org_id}/saved-searches/{id}",
		"/orgs/{org_id}/saved-searches/{id}/execute",

		// Spec-only: SSO
		"/orgs/{org_id}/sso",
		"/orgs/{org_id}/sso/domains",
		"/auth/discover",

		// Spec-only: Audit Log
		"/orgs/{org_id}/audit-log",

		// Spec-only: AI
		"/orgs/{org_id}/ai/nl-search",
		"/orgs/{org_id}/ai/summarize/{cve_id}",

		// Spec-only: Ingest
		"/orgs/{org_id}/ingest",

		// Spec-only: Org Tier
		"/orgs/{org_id}/tier",

		// Spec-only: Admin Feeds
		"/admin/feeds",
		"/admin/feeds/{feed}/run",
		"/admin/feeds/{feed}/pause",
		"/admin/feeds/{feed}/resume",
		"/admin/feeds/{feed}/logs",

		// Spec-only: Admin System
		"/admin/reindex",
		"/admin/config",
		"/admin/audit-log",
		"/admin/version",
		"/admin/doctor",

		// Spec-only: Admin Orgs
		"/admin/orgs",
		"/admin/orgs/{org_id}",
		"/admin/orgs/{org_id}/usage",

		// Spec-only: Admin Users
		"/admin/users",
		"/admin/users/{user_id}/disable",
		"/admin/users/{user_id}/enable",
		"/admin/users/{user_id}/unlock",
		"/admin/users/{user_id}/reset-password",

		// Spec-only: Admin Deliveries
		"/admin/deliveries",
		"/admin/deliveries/{id}/retry",
		"/admin/deliveries/retry-failed",
	}
	for _, p := range expectedPaths {
		if _, ok := paths[p]; !ok {
			t.Errorf("missing expected path: %s", p)
		}
	}

	// Write to repo root when GENERATE_OPENAPI is set.
	if os.Getenv("GENERATE_OPENAPI") != "" {
		pretty, err := json.MarshalIndent(spec, "", "  ")
		if err != nil {
			t.Fatalf("marshal indent: %v", err)
		}
		outPath := filepath.Join("..", "..", "openapi.json")
		if err := os.WriteFile(outPath, append(pretty, '\n'), 0644); err != nil { //nolint:gosec // G306: OpenAPI spec is a repo artifact meant to be world-readable
			t.Fatalf("write %s: %v", outPath, err)
		}
		t.Logf("wrote %s (%d bytes)", outPath, len(pretty))
	}
}
