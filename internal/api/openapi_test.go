// ABOUTME: Tests the served OpenAPI spec without a database: coverage of every route, schemas, statuses.
// ABOUTME: Run with GENERATE_OPENAPI=1 to write openapi.json to the repo root.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/scarson/cvert-ops/internal/config"
)

// newOpenAPITestHandler returns the production handler of a server with no database.
func newOpenAPITestHandler(t *testing.T) http.Handler {
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
	return srv.Handler()
}

// fetchSpec requests a spec document from handler and returns it decoded.
func fetchSpec(t *testing.T, handler http.Handler, path string) map[string]any {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d, body: %s", path, rec.Code, rec.Body.String())
	}
	var spec map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &spec); err != nil {
		t.Fatalf("GET %s: invalid JSON: %v", path, err)
	}
	return spec
}

// buildOpenAPISpec returns the spec the production server serves.
func buildOpenAPISpec(t *testing.T) map[string]any {
	t.Helper()
	return fetchSpec(t, newOpenAPITestHandler(t), "/api/v1/openapi.json")
}

// undocumentedRoutePrefixes lists route families deliberately left out of the
// spec, under /api/v1.
var undocumentedRoutePrefixes = []string{
	"/auth/oauth/", // browser redirects to and from OAuth providers
	"/auth/oidc/",  // browser redirects to and from OIDC providers
	"/docs",        // huma's API documentation page
	"/openapi",     // huma's spec documents
	"/schemas/",    // huma's JSON schema documents
}

// isUndocumentedRoute reports whether a route under /api/v1 is deliberately
// left out of the spec.
func isUndocumentedRoute(path string) bool {
	// SCIM v2 is defined by RFC 7644, which clients implement directly.
	if strings.HasPrefix(path, "/orgs/{org_id}/scim/v2/") {
		return true
	}
	for _, prefix := range undocumentedRoutePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// TestOpenAPISpec_MatchesRoutes fails when a route has no spec entry, or a spec
// entry has no route. Spec-only declarations are written by hand beside chi
// routes, so nothing else keeps the two together.
func TestOpenAPISpec_MatchesRoutes(t *testing.T) {
	handler := newOpenAPITestHandler(t)
	routes, ok := handler.(chi.Routes)
	if !ok {
		t.Fatalf("Handler() returned %T, which does not expose its routes", handler)
	}

	const apiPrefix = "/api/v1"
	served := map[string]bool{}
	err := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		path, underAPI := strings.CutPrefix(route, apiPrefix)
		if !underAPI {
			return nil
		}
		path = strings.TrimSuffix(path, "/")
		if !isUndocumentedRoute(path) {
			served[method+" "+path] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk routes: %v", err)
	}

	documented := map[string]bool{}
	paths := fetchSpec(t, handler, apiPrefix+"/openapi.json")["paths"].(map[string]any)
	for path, item := range paths {
		for method := range item.(map[string]any) {
			documented[strings.ToUpper(method)+" "+path] = true
		}
	}

	for route := range served {
		if !documented[route] {
			t.Errorf("%s is routed but not in the spec", route)
		}
	}
	for op := range documented {
		if !served[op] {
			t.Errorf("%s is in the spec but not routed", op)
		}
	}
}

// TestOpenAPIDocsPage_LoadsSpecFromBasePath verifies the documentation page asks
// for the spec where it is served.
func TestOpenAPIDocsPage_LoadsSpecFromBasePath(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/docs", nil)
	rec := httptest.NewRecorder()
	newOpenAPITestHandler(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/docs: status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "/api/v1/openapi") {
		t.Errorf("docs page does not load the spec from /api/v1: %s", rec.Body.String())
	}
}

// TestOpenAPISpec_ServedDocumentsDescribeBasePath verifies a client reading the
// spec can reach the API, in both the 3.1 document and the 3.0 downgrade that
// code generators consume.
func TestOpenAPISpec_ServedDocumentsDescribeBasePath(t *testing.T) {
	handler := newOpenAPITestHandler(t)
	for _, doc := range []string{"/api/v1/openapi.json", "/api/v1/openapi-3.0.json"} {
		t.Run(doc, func(t *testing.T) {
			spec := fetchSpec(t, handler, doc)
			servers, _ := spec["servers"].([]any)
			if len(servers) != 1 {
				t.Fatalf("servers = %v, want one entry", spec["servers"])
			}
			if got := servers[0].(map[string]any)["url"]; got != "/api/v1" {
				t.Errorf("server url = %v, want /api/v1", got)
			}
			paths := spec["paths"].(map[string]any)
			if _, ok := paths["/orgs/{org_id}/watchlists"]; !ok {
				t.Error("chi-backed route /orgs/{org_id}/watchlists missing from the served document")
			}
			if _, ok := paths["/cves"]; !ok {
				t.Error("huma route /cves missing from the served document")
			}
		})
	}
}

// TestOpenAPISpec_SchemaNamesFitGeneratedClients verifies a client generated from
// the 3.0 document compiles. oapi-codegen emits a Go type for each schema and, for
// each operation, types named after its operation ID; a schema with one of those
// names redeclares the type, and the generated package does not build.
func TestOpenAPISpec_SchemaNamesFitGeneratedClients(t *testing.T) {
	spec := fetchSpec(t, newOpenAPITestHandler(t), "/api/v1/openapi-3.0.json")

	schemas := spec["components"].(map[string]any)["schemas"].(map[string]any)
	wellFormed := regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)
	for name := range schemas {
		if !wellFormed.MatchString(name) {
			t.Errorf("schema %q is not a plain type name; give the body a named Go type", name)
		}
	}

	for path, item := range spec["paths"].(map[string]any) {
		for method, raw := range item.(map[string]any) {
			op, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			operationID, _ := op["operationId"].(string)
			var goName strings.Builder
			for _, part := range strings.Split(operationID, "-") {
				goName.WriteString(strings.ToUpper(part[:1]) + part[1:])
			}
			for _, suffix := range []string{"Response", "Params", "JSONBody", "JSONRequestBody"} {
				if _, taken := schemas[goName.String()+suffix]; taken {
					t.Errorf("%s %s: schema %s has the name a generated client gives this operation's type",
						strings.ToUpper(method), path, goName.String()+suffix)
				}
			}
		}
	}
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

	// Write to repo root when GENERATE_OPENAPI is set; otherwise the committed
	// file, which the web client's types are generated from, must match.
	outPath := filepath.Join("..", "..", "openapi.json")
	if os.Getenv("GENERATE_OPENAPI") != "" {
		pretty, err := json.MarshalIndent(spec, "", "  ")
		if err != nil {
			t.Fatalf("marshal indent: %v", err)
		}
		if err := os.WriteFile(outPath, append(pretty, '\n'), 0644); err != nil { //nolint:gosec // G306: OpenAPI spec is a repo artifact meant to be world-readable
			t.Fatalf("write %s: %v", outPath, err)
		}
		t.Logf("wrote %s (%d bytes)", outPath, len(pretty))
		return
	}
	committedBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read %s: %v", outPath, err)
	}
	// Compared parsed: a Windows checkout holds the file with CRLF line endings.
	var committed map[string]any
	if err := json.Unmarshal(committedBytes, &committed); err != nil {
		t.Fatalf("parse %s: %v", outPath, err)
	}
	if !reflect.DeepEqual(spec, committed) {
		t.Errorf("%s does not match the served spec. Regenerate it with GENERATE_OPENAPI=1 go test -run '^TestOpenAPISpec$' ./internal/api/, then cd web && npm run generate-api", outPath)
	}
}

// TestOpenAPISpec_EmbeddedFieldsDocumented verifies that response schemas
// built by embedding another DTO document the embedded DTO's fields, which
// encoding/json promotes into the response body.
func TestOpenAPISpec_EmbeddedFieldsDocumented(t *testing.T) {
	spec := buildOpenAPISpec(t)
	schemas := spec["components"].(map[string]any)["schemas"].(map[string]any)

	tests := []struct {
		schema       string
		wantRequired []string
		wantOptional []string
	}{
		// signing_secret is sent only for webhook channels.
		{schema: "ChannelCreateEntry", wantRequired: []string{"id", "org_id", "name", "type", "config", "created_at", "updated_at"}, wantOptional: []string{"signing_secret"}},
		{schema: "DeliveryDetail", wantRequired: []string{"id", "org_id", "status", "created_at", "payload"}},
	}
	for _, tc := range tests {
		t.Run(tc.schema, func(t *testing.T) {
			s, ok := schemas[tc.schema].(map[string]any)
			if !ok {
				t.Fatalf("schema %s missing from spec", tc.schema)
			}
			props, _ := s["properties"].(map[string]any)
			required := map[string]bool{}
			reqList, _ := s["required"].([]any)
			for _, r := range reqList {
				required[r.(string)] = true
			}
			for _, f := range tc.wantRequired {
				if _, ok := props[f]; !ok {
					t.Errorf("property %s not documented", f)
				}
				if !required[f] {
					t.Errorf("property %s not marked required", f)
				}
			}
			for _, f := range tc.wantOptional {
				if _, ok := props[f]; !ok {
					t.Errorf("property %s not documented", f)
				}
				if required[f] {
					t.Errorf("property %s marked required, but the handler can omit it", f)
				}
			}
		})
	}
}

// TestOpenAPISpec_PatchBodiesOptional verifies that PATCH request schemas mark
// no field required: the handlers keep the current value for an omitted field.
func TestOpenAPISpec_PatchBodiesOptional(t *testing.T) {
	spec := buildOpenAPISpec(t)
	schemas := spec["components"].(map[string]any)["schemas"].(map[string]any)

	for _, name := range []string{
		"PatchAlertRuleBody",
		"PatchChannelBody",
		"PatchReportBody",
		"PatchSCIMConfigBody",
		"PatchSCIMGroupMappingBody",
		"PatchSSOBody",
		"PatchWatchlistBody",
	} {
		t.Run(name, func(t *testing.T) {
			s, ok := schemas[name].(map[string]any)
			if !ok {
				t.Fatalf("schema %s missing from spec", name)
			}
			if req, ok := s["required"]; ok {
				t.Errorf("required = %v, want no required fields", req)
			}
		})
	}
}

// TestOpenAPISpec_PatchClearableFieldsNullable verifies that PATCH fields the
// handlers clear on JSON null are documented as nullable strings.
func TestOpenAPISpec_PatchClearableFieldsNullable(t *testing.T) {
	spec := buildOpenAPISpec(t)
	schemas := spec["components"].(map[string]any)["schemas"].(map[string]any)

	tests := []struct {
		schema string
		field  string
	}{
		{schema: "PatchWatchlistBody", field: "group_id"},
		{schema: "PatchSCIMGroupMappingBody", field: "mapped_group_id"},
	}
	for _, tt := range tests {
		t.Run(tt.schema+"."+tt.field, func(t *testing.T) {
			s, ok := schemas[tt.schema].(map[string]any)
			if !ok {
				t.Fatalf("schema %s missing from spec", tt.schema)
			}
			prop, ok := s["properties"].(map[string]any)[tt.field].(map[string]any)
			if !ok {
				t.Fatalf("property %s missing from %s", tt.field, tt.schema)
			}
			got := fmt.Sprint(prop["type"])
			if got != "[string null]" {
				t.Errorf("type = %s, want [string null]", got)
			}
		})
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
		contentType  string // body media type when not application/json
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

		// 302 Found redirecting the browser to the identity provider; http.Redirect
		// adds a short HTML body naming the target.
		{path: "/orgs/{org_id}/sso/link", method: "get", wantStatuses: []string{"302"}, wantLocation: true, contentType: "text/html"},
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
				contentType := tc.contentType
				if contentType == "" {
					contentType = "application/json"
				}
				if tc.noBody {
					if len(content) != 0 {
						t.Errorf("response %s documents a body, which the handler never sends", status)
					}
				} else if _, ok := content[contentType]; !ok {
					t.Errorf("response %s has no %s body", status, contentType)
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
