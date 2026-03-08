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
	srv, err := NewServer(nil, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	handler := srv.Handler()

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

	// Spot-check expected paths from huma-registered routes.
	for _, p := range []string{"/auth/register", "/auth/login", "/cves", "/cves/{cve_id}"} {
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
