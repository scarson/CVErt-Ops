// ABOUTME: Unit tests for server.go internals (argon2 semaphore, OAuth redirect URLs, auditLog).
// ABOUTME: Tests unexported methods and fields; uses package api (internal test file).
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/config"
)

// ── Argon2 semaphore ──────────────────────────────────────────────────────────

// TestAcquireArgon2_AllowsUpToN verifies that the channel-based semaphore
// allows exactly N concurrent acquisitions, then rejects the N+1th.
func TestAcquireArgon2_AllowsUpToN(t *testing.T) {
	t.Parallel()

	const maxConcurrent = 3
	cfg := &config.Config{Argon2MaxConcurrent: maxConcurrent} //nolint:exhaustruct // test
	srv, err := NewServer(nil, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)

	// Acquire all N slots.
	for i := 0; i < maxConcurrent; i++ {
		if !srv.acquireArgon2() {
			t.Fatalf("acquireArgon2 returned false on slot %d (should succeed)", i)
		}
	}

	// The N+1th acquisition must fail (non-blocking).
	if srv.acquireArgon2() {
		t.Error("acquireArgon2 succeeded beyond max concurrent — semaphore is broken")
	}

	// Release one slot and verify re-acquisition works.
	srv.releaseArgon2()
	if !srv.acquireArgon2() {
		t.Error("acquireArgon2 failed after release — slot was not freed")
	}

	// Clean up: release all held slots.
	for i := 0; i < maxConcurrent; i++ {
		srv.releaseArgon2()
	}
}

// TestAcquireArgon2_SingleSlot exercises the edge case of a 1-slot semaphore.
func TestAcquireArgon2_SingleSlot(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{Argon2MaxConcurrent: 1} //nolint:exhaustruct // test
	srv, err := NewServer(nil, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)

	if !srv.acquireArgon2() {
		t.Fatal("first acquire should succeed")
	}
	if srv.acquireArgon2() {
		t.Error("second acquire should fail with only 1 slot")
	}

	srv.releaseArgon2()

	if !srv.acquireArgon2() {
		t.Error("acquire after release should succeed")
	}
	srv.releaseArgon2()
}

// ── OAuth redirect URL formation ──────────────────────────────────────────────

// TestGitHubOAuthRedirectURL verifies that the GitHub OAuth redirect URL is
// computed from ExternalURL + the expected callback path.
func TestGitHubOAuthRedirectURL(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{ //nolint:exhaustruct // test: only OAuth-relevant fields
		Argon2MaxConcurrent: 1,
		ExternalURL:         "https://vuln.example.com",
		GitHubClientID:      "test-client-id",
		GitHubClientSecret:  "test-client-secret",
	}
	srv, err := NewServer(nil, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)

	if srv.ghOAuth == nil {
		t.Fatal("ghOAuth should be configured when GitHubClientID is set")
	}

	want := "https://vuln.example.com/api/v1/auth/oauth/github/callback"
	if srv.ghOAuth.RedirectURL != want {
		t.Errorf("GitHub redirect URL = %q, want %q", srv.ghOAuth.RedirectURL, want)
	}
}

// TestGitHubOAuth_Disabled verifies that ghOAuth is nil when GitHubClientID
// is empty (optional OAuth providers should not be configured).
func TestGitHubOAuth_Disabled(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{Argon2MaxConcurrent: 1} //nolint:exhaustruct // test
	srv, err := NewServer(nil, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)

	if srv.ghOAuth != nil {
		t.Error("ghOAuth should be nil when GitHubClientID is empty")
	}
}

// ── auditLog helper ───────────────────────────────────────────────────────────

// TestAuditLog_NilWriter is already covered in audit_integration_test.go.

// TestAuditLog_NilWriterWithUserContext verifies that auditLog completes without
// panic when the audit writer is nil but a user ID is present in context
// (exercising the ActorID extraction path before the nil-writer early return).
func TestAuditLog_NilWriterWithUserContext(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{Argon2MaxConcurrent: 1} //nolint:exhaustruct // test
	srv, err := NewServer(nil, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)

	// Set up a request with a user ID in context. Even though the writer is nil,
	// auditLog should not panic.
	uid := uuid.New()
	ctx := context.WithValue(context.Background(), ctxUserID, uid)
	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)

	// auditLog with nil writer returns immediately — this exercises the nil check.
	srv.auditLog(req, audit.Entry{Action: "test.action"})
}
