// ABOUTME: Tests for admin system endpoints (config, reindex, audit log).
// ABOUTME: Verifies secret redaction in config endpoint and admin auth enforcement.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestAdminConfigHandler_SecretsRedacted(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "config-admin@example.com", "ConfigAdmin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, user.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	jwtSecret := "test-jwt-secret-for-config-redaction"
	token, err := auth.IssueAccessToken([]byte(jwtSecret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	cfg := &config.Config{ //nolint:exhaustruct // test: only fields needed for redaction
		JWTSecret:          jwtSecret,
		DatabaseURL:        "postgres://user:pass@localhost/db",
		DatabaseURLMigrate: "postgres://admin:secret@localhost/db",
		SMTPPassword:       "smtp-secret-password",
		SSOEncryptionKey:   "0123456789abcdef0123456789abcdef",
		GeminiAPIKey:       "gemini-api-key-value",
		NVDAPIKey:          "nvd-api-key-value",
	}
	srv, _ := NewServer(db.Store, cfg, ServerDeps{})
	t.Cleanup(srv.Close)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/admin/config", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Every secret field must be redacted to "***", not the actual value.
	secretFields := map[string]string{
		"jwt_secret":           cfg.JWTSecret,
		"database_url":         cfg.DatabaseURL,
		"database_url_migrate": cfg.DatabaseURLMigrate,
		"smtp_password":        cfg.SMTPPassword,
		"sso_encryption_key":   cfg.SSOEncryptionKey,
		"gemini_api_key":       cfg.GeminiAPIKey,
		"nvd_api_key":          cfg.NVDAPIKey,
	}
	for field, realValue := range secretFields {
		val, ok := body[field].(string)
		if !ok {
			t.Errorf("secret field %q missing from response", field)
			continue
		}
		if val == realValue {
			t.Errorf("secret field %q contains actual secret value — not redacted", field)
		}
		if val != "***" {
			t.Errorf("secret field %q = %q, want %q", field, val, "***")
		}
	}
}

func TestAdminConfigHandler_EmptySecrets_EmptyString(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "config-empty@example.com", "ConfigEmpty", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, user.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	jwtSecret := "test-jwt-secret-for-config-empty"
	token, err := auth.IssueAccessToken([]byte(jwtSecret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	// Config with empty optional secrets.
	cfg := &config.Config{ //nolint:exhaustruct // test: minimal config
		JWTSecret: jwtSecret,
	}
	srv, _ := NewServer(db.Store, cfg, ServerDeps{})
	t.Cleanup(srv.Close)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/admin/config", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Empty secrets should be empty strings, not "***".
	emptyFields := []string{"database_url", "smtp_password", "sso_encryption_key", "gemini_api_key", "nvd_api_key"}
	for _, field := range emptyFields {
		val, ok := body[field].(string)
		if ok && val != "" {
			t.Errorf("empty secret field %q = %q, want empty string", field, val)
		}
	}
}

func TestAdminConfigHandler_NonAdmin_403(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "config-nonadmin@example.com", "Regular", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	jwtSecret := "test-jwt-secret-for-config-nonadmin"
	token, err := auth.IssueAccessToken([]byte(jwtSecret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, jwtSecret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/admin/config", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin: got %d, want 403", resp.StatusCode)
	}
}

func TestRedactSecret(t *testing.T) {
	t.Parallel()
	if got := redactSecret("my-secret"); got != "***" {
		t.Errorf("redactSecret(non-empty) = %q, want %q", got, "***")
	}
	if got := redactSecret(""); got != "" {
		t.Errorf("redactSecret(empty) = %q, want empty", got)
	}
}
