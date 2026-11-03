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

// buildOpenAPISpec serves the production huma spec merged with the spec-only
// Chi route declarations and returns it decoded.
func buildOpenAPISpec(t *testing.T) map[string]any {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:   "test-secret-for-openapi-generation",
		ExternalURL: "http://localhost:8080",
		FrontendURL: "/",
	}
	srv, err := NewServer(nil, cfg, ServerDeps{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)

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

	// Verify valid JSON.
	var spec map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &spec); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	return spec
}

func TestOpenAPISpec(t *testing.T) {
	spec := buildOpenAPISpec(t)

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
		"/orgs/{org_id}/members/{user_id}/reset-mfa",
		"/orgs/{org_id}/members/{user_id}/force-password-reset",
		"/orgs/{org_id}/members/{user_id}/require-mfa",
		"/orgs/{org_id}/mfa-settings",
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
		"/orgs/{org_id}/sso/link",
		"/orgs/{org_id}/sso/scim",
		"/orgs/{org_id}/sso/scim/rotate-token",
		"/orgs/{org_id}/sso/scim/groups",
		"/orgs/{org_id}/sso/scim/groups/{id}/mapping",
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

// TestOpenAPISpec_SuccessStatusMatchesHandler verifies that endpoints whose
// handlers answer 201 Created, 202 Accepted, 204 No Content or 302 Found
// document that status, and do not document a 200 the handler never sends.
func TestOpenAPISpec_SuccessStatusMatchesHandler(t *testing.T) {
	spec := buildOpenAPISpec(t)
	paths := spec["paths"].(map[string]any)

	tests := []struct {
		path         string
		method       string
		wantStatuses []string
		wantLocation bool
		noBody       bool
	}{
		{path: "/admin/reindex", method: "post", wantStatuses: []string{"202"}},
		{path: "/admin/feeds/{feed}/run", method: "post", wantStatuses: []string{"202"}},
		{path: "/orgs/{org_id}/ingest", method: "post", wantStatuses: []string{"202"}},
		{path: "/orgs/{org_id}/invitations", method: "post", wantStatuses: []string{"202"}, wantLocation: true},
		// 201 when the rule is created ready, 202 when it needs an activation scan.
		{path: "/orgs/{org_id}/alert-rules", method: "post", wantStatuses: []string{"201", "202"}, wantLocation: true},

		// 201 Created with the new resource and its Location.
		{path: "/auth/register", method: "post", wantStatuses: []string{"201"}},
		{path: "/orgs", method: "post", wantStatuses: []string{"201"}, wantLocation: true},
		{path: "/orgs/{org_id}/api-keys", method: "post", wantStatuses: []string{"201"}, wantLocation: true},
		{path: "/orgs/{org_id}/channels", method: "post", wantStatuses: []string{"201"}, wantLocation: true},
		{path: "/orgs/{org_id}/groups", method: "post", wantStatuses: []string{"201"}, wantLocation: true},
		{path: "/orgs/{org_id}/reports", method: "post", wantStatuses: []string{"201"}, wantLocation: true},
		{path: "/orgs/{org_id}/saved-searches", method: "post", wantStatuses: []string{"201"}, wantLocation: true},
		{path: "/orgs/{org_id}/sso", method: "post", wantStatuses: []string{"201"}, wantLocation: true},
		{path: "/orgs/{org_id}/watchlists", method: "post", wantStatuses: []string{"201"}, wantLocation: true},
		{path: "/orgs/{org_id}/watchlists/{id}/items", method: "post", wantStatuses: []string{"201"}, wantLocation: true},

		// 201 Created with a body but no Location: neither handler creates an addressable resource.
		{path: "/orgs/{org_id}/members/{user_id}/require-mfa", method: "post", wantStatuses: []string{"201"}},
		{path: "/orgs/{org_id}/sso/scim", method: "post", wantStatuses: []string{"201"}},

		// 204 No Content.
		{path: "/auth/mfa/methods/{method}", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/members/{user_id}", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/invitations/{id}", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/api-keys/{id}", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/watchlists/{id}", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/watchlists/{id}/items/{item_id}", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/channels/{id}", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/channels/{id}/clear-secondary", method: "post", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/deliveries/{id}/replay", method: "post", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/alert-rules/{id}", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/alert-rules/{id}/channels/{channel_id}", method: "put", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/alert-rules/{id}/channels/{channel_id}", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/reports/{id}", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/reports/{id}/channels/{channel_id}", method: "put", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/reports/{id}/channels/{channel_id}", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/saved-searches/{id}", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/sso", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/groups/{group_id}", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/groups/{group_id}/members", method: "post", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/groups/{group_id}/members/{user_id}", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/members/{user_id}/require-mfa", method: "delete", wantStatuses: []string{"204"}, noBody: true},
		{path: "/orgs/{org_id}/sso/scim", method: "delete", wantStatuses: []string{"204"}, noBody: true},

		// 302 Found redirecting the browser to the identity provider.
		{path: "/orgs/{org_id}/sso/link", method: "get", wantStatuses: []string{"302"}, wantLocation: true, noBody: true},
	}
	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			item, ok := paths[tc.path].(map[string]any)
			if !ok {
				t.Fatalf("path %s missing from spec", tc.path)
			}
			op, ok := item[tc.method].(map[string]any)
			if !ok {
				t.Fatalf("%s %s missing from spec", tc.method, tc.path)
			}
			responses := op["responses"].(map[string]any)

			if _, ok := responses["200"]; ok {
				t.Errorf("documents 200, which the handler never returns")
			}
			if _, ok := responses["default"]; !ok {
				t.Errorf("no default error response documented")
			}
			for _, status := range tc.wantStatuses {
				resp, ok := responses[status].(map[string]any)
				if !ok {
					t.Errorf("response %s not documented", status)
					continue
				}
				content, _ := resp["content"].(map[string]any)
				if tc.noBody {
					if len(content) != 0 {
						t.Errorf("response %s documents a body, which the handler never sends", status)
					}
				} else if _, ok := content["application/json"]; !ok {
					t.Errorf("response %s has no application/json body", status)
				}
				if tc.wantLocation {
					headers, _ := resp["headers"].(map[string]any)
					if _, ok := headers["Location"]; !ok {
						t.Errorf("response %s does not document the Location header", status)
					}
				}
			}
		})
	}
}
