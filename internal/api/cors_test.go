// ABOUTME: Unit tests for CORS middleware configuration and origin filtering.
// ABOUTME: Validates wildcard rejection and origin parsing behavior.
package api

import (
	"testing"

	"github.com/scarson/cvert-ops/internal/config"
)

func TestCORSOrigins_WildcardRejected(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		CORSAllowedOrigins: "*",
	}
	srv := &Server{cfg: cfg} //nolint:exhaustruct // test: only cfg needed
	origins := srv.corsOrigins()
	if len(origins) != 0 {
		t.Fatalf("corsOrigins: got %v, want empty (wildcard should be rejected)", origins)
	}
}

func TestCORSOrigins_WildcardAmongOthers(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		CORSAllowedOrigins: "https://app.example.com, *, https://admin.example.com",
	}
	srv := &Server{cfg: cfg} //nolint:exhaustruct // test: only cfg needed
	origins := srv.corsOrigins()

	// Wildcard should be filtered out, leaving only the valid origins.
	if len(origins) != 2 {
		t.Fatalf("corsOrigins: got %v (len=%d), want 2 valid origins", origins, len(origins))
	}
	if origins[0] != "https://app.example.com" || origins[1] != "https://admin.example.com" {
		t.Fatalf("corsOrigins: got %v, want [https://app.example.com https://admin.example.com]", origins)
	}
}

func TestCORSMiddleware_WildcardReturnsNil(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		CORSAllowedOrigins: "*",
	}
	srv := &Server{cfg: cfg} //nolint:exhaustruct // test: only cfg needed
	middleware := srv.corsMiddleware()
	if middleware != nil {
		t.Fatal("corsMiddleware should return nil when only wildcard origin is configured")
	}
}

func TestCORSOrigins_ValidOrigins(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		CORSAllowedOrigins: "https://app.example.com,https://admin.example.com",
	}
	srv := &Server{cfg: cfg} //nolint:exhaustruct // test: only cfg needed
	origins := srv.corsOrigins()
	if len(origins) != 2 {
		t.Fatalf("corsOrigins: got %d origins, want 2", len(origins))
	}
}
