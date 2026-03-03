// ABOUTME: Unit tests for config package — IsDevelopment, LogValue masking, and defaults.
// ABOUTME: Uses env vars directly (no network or Postgres dependency).
package config

import (
	"log/slog"
	"testing"
)

func TestIsDevelopment(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		appEnv string
		want   bool
	}{
		{"development", "development", true},
		{"production", "production", false},
		{"staging", "staging", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{AppEnv: tc.appEnv} //nolint:exhaustruct // test: only relevant field
			if got := cfg.IsDevelopment(); got != tc.want {
				t.Errorf("IsDevelopment() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMasked(t *testing.T) {
	t.Parallel()
	if got := masked(""); got != "" {
		t.Errorf(`masked("") = %q, want ""`, got)
	}
	if got := masked("supersecret"); got != "***" {
		t.Errorf(`masked("supersecret") = %q, want "***"`, got)
	}
}

func TestLogValue_MasksSecrets(t *testing.T) {
	t.Parallel()
	cfg := &Config{ //nolint:exhaustruct,gosec // test: only relevant fields; G101 false positive on test fixtures
		JWTSecret:          "my-jwt-secret-for-test",
		GeminiAPIKey:       "gk-12345",
		GitHubClientSecret: "ghs-secret",
		GoogleClientSecret: "ggl-secret",
		SMTPPassword:       "smtp-pass",
		NVDAPIKey:          "nvd-key",
		SSOEncryptionKey:   "sso-key",
	}

	logVal := cfg.LogValue()
	attrs := logVal.Group()

	for _, attr := range attrs {
		switch attr.Key {
		case "jwt_secret", "gemini_api_key", "github_client_secret",
			"google_client_secret", "smtp_password", "nvd_api_key",
			"sso_encryption_key":
			if attr.Value.String() != "***" {
				t.Errorf("LogValue: %s = %q, want masked (***)", attr.Key, attr.Value.String())
			}
		}
	}
}

func TestLogValue_EmptySecretsNotMasked(t *testing.T) {
	t.Parallel()
	cfg := &Config{} //nolint:exhaustruct // test: empty config

	logVal := cfg.LogValue()
	attrs := logVal.Group()

	for _, attr := range attrs {
		switch attr.Key {
		case "jwt_secret", "gemini_api_key", "github_client_secret",
			"google_client_secret", "smtp_password", "nvd_api_key",
			"sso_encryption_key":
			if attr.Value.String() != "" {
				t.Errorf("LogValue: %s = %q for empty secret, want empty", attr.Key, attr.Value.String())
			}
		}
	}
}

// Silence unused import warning for slog.
var _ = slog.Default
