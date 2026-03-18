// ABOUTME: Tests for POST /api/v1/admin/reload-config endpoint.
// ABOUTME: Verifies site admin auth, secrets file reload, no-file case, and invalid file handling.
package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestAdminReloadConfig_RequiresSiteAdmin(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "nonadmin@example.com", "Regular", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret := "test-jwt-secret-for-admin-reload!"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/admin/reload-config", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin: got %d, want 403", resp.StatusCode)
	}
}

func TestAdminReloadConfig_ReloadsFromSecretsFile(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "admin@example.com", "Admin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, user.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	secret := "test-jwt-secret-for-admin-reload!"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	// Write a temp secrets file with a valid SMTP host value.
	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "secrets.env")
	if err := os.WriteFile(secretsPath, []byte("SMTP_HOST=mail.example.com\nSMTP_PORT=587\n"), 0o600); err != nil {
		t.Fatalf("write secrets file: %v", err)
	}

	// Seed the config holder with empty values.
	holder := config.NewHolder(&config.ReloadableConfig{})

	srv := newAuthTestServer(t, secret, db)
	srv.cfg.SecretsFile = secretsPath
	srv.configHolder = holder
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/admin/reload-config", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	var body struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Message != "config reloaded" {
		t.Errorf("message = %q, want %q", body.Message, "config reloaded")
	}

	// Verify the holder was updated.
	rc := holder.Load()
	if rc.SMTPHost != "mail.example.com" {
		t.Errorf("SMTPHost = %q, want %q", rc.SMTPHost, "mail.example.com")
	}
	if rc.SMTPPort != 587 {
		t.Errorf("SMTPPort = %d, want %d", rc.SMTPPort, 587)
	}
}

func TestAdminReloadConfig_NoSecretsFile_200(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "admin@example.com", "Admin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, user.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	secret := "test-jwt-secret-for-admin-reload!"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	// No SecretsFile configured (empty string).
	srv.configHolder = config.NewHolder(&config.ReloadableConfig{})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/admin/reload-config", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	var body struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Message != "no secrets file configured" {
		t.Errorf("message = %q, want %q", body.Message, "no secrets file configured")
	}
}

func TestAdminReloadConfig_InvalidConfig_400(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "admin@example.com", "Admin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, user.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	secret := "test-jwt-secret-for-admin-reload!"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	// Write a secrets file with an invalid JWT secret (too short).
	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "secrets.env")
	if err := os.WriteFile(secretsPath, []byte("JWT_SECRET=short\n"), 0o600); err != nil {
		t.Fatalf("write secrets file: %v", err)
	}

	initialRC := &config.ReloadableConfig{SMTPHost: "original.example.com"}
	holder := config.NewHolder(initialRC)

	srv := newAuthTestServer(t, secret, db)
	srv.cfg.SecretsFile = secretsPath
	srv.configHolder = holder
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/admin/reload-config", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.StatusCode)
	}

	// Verify old config is retained.
	rc := holder.Load()
	if rc.SMTPHost != "original.example.com" {
		t.Errorf("SMTPHost = %q, want %q (old config should be retained)", rc.SMTPHost, "original.example.com")
	}
}

func TestAdminReloadConfig_CallsRescan(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "admin@example.com", "Admin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, user.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	secret := "test-jwt-secret-for-admin-reload!"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	// Write a valid secrets file with a JWT secret (32+ bytes).
	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "secrets.env")
	if err := os.WriteFile(secretsPath, []byte("JWT_SECRET=this-is-a-valid-jwt-secret-32bytes!\n"), 0o600); err != nil {
		t.Fatalf("write secrets file: %v", err)
	}

	holder := config.NewHolder(&config.ReloadableConfig{})

	srv := newAuthTestServer(t, secret, db)
	srv.cfg.SecretsFile = secretsPath
	srv.configHolder = holder

	var rescanCalled atomic.Bool
	srv.rescanFunc = func() { rescanCalled.Store(true) }

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/admin/reload-config", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	if !rescanCalled.Load() {
		t.Error("rescanFunc was not called after successful config reload")
	}
}

func TestAdminReloadConfig_DoesNotLeakErrorDetails(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "admin@example.com", "Admin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, user.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	secret := "test-jwt-secret-for-admin-reload!"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	holder := config.NewHolder(&config.ReloadableConfig{})

	srv := newAuthTestServer(t, secret, db)
	srv.cfg.SecretsFile = "/tmp/no-such-file-xyz.env"
	srv.configHolder = holder
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/admin/reload-config", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	bodyStr := string(bodyBytes)

	// Must not leak file path details.
	if strings.Contains(bodyStr, "/tmp/no-such-file") {
		t.Errorf("response body leaks file path: %s", bodyStr)
	}

	// Must contain generic guidance.
	if !strings.Contains(bodyStr, "check server logs") {
		t.Errorf("response body missing generic message, got: %s", bodyStr)
	}
}
