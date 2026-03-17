// ABOUTME: Unit tests for config package — IsDevelopment, LogValue masking, and defaults.
// ABOUTME: Uses env vars directly (no network or Postgres dependency).
package config

import (
	"testing"
	"time"
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

func TestLoad_Defaults(t *testing.T) {
	// Set only the required env vars; all envDefault fields should get defaults.
	t.Setenv("DATABASE_URL", "postgres://test:test@localhost/test")
	t.Setenv("JWT_SECRET", "test-secret-for-defaults")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	defaults := []struct {
		name string
		got  any
		want any
	}{
		// Database
		{"DBMaxConns", cfg.DBMaxConns, int32(25)},
		{"DBMaxConnIdleTime", cfg.DBMaxConnIdleTime, 5 * time.Minute},
		{"DBStatementTimeoutMS", cfg.DBStatementTimeoutMS, 14000},
		{"DBLongStatementTimeoutMS", cfg.DBLongStatementTimeoutMS, 120000},
		{"DBQueryExecMode", cfg.DBQueryExecMode, "simple_protocol"},
		// Server
		{"ListenAddr", cfg.ListenAddr, ":8080"},
		{"AppEnv", cfg.AppEnv, "development"},
		{"ExternalURL", cfg.ExternalURL, "http://localhost:8080"},
		{"ShutdownTimeoutSeconds", cfg.ShutdownTimeoutSeconds, 60},
		{"RegistrationMode", cfg.RegistrationMode, "invite-only"},
		// Auth
		{"JWTAlgorithm", cfg.JWTAlgorithm, "HS256"},
		{"CookieSecure", cfg.CookieSecure, false},
		{"Argon2MaxConcurrent", cfg.Argon2MaxConcurrent, 5},
		// Email
		{"SMTPHost", cfg.SMTPHost, "localhost"},
		{"SMTPPort", cfg.SMTPPort, 1025},
		{"SMTPFrom", cfg.SMTPFrom, "cvert-ops@localhost"},
		{"SMTPTLS", cfg.SMTPTLS, false},
		// AI
		{"GeminiModel", cfg.GeminiModel, "gemini-2.0-flash"},
		{"GeminiTimeout", cfg.GeminiTimeout, 30 * time.Second},
		{"AIQuotaEnabled", cfg.AIQuotaEnabled, true},
		{"AINLSearchLimitFree", cfg.AINLSearchLimitFree, 10},
		{"AINLSearchLimitPro", cfg.AINLSearchLimitPro, 100},
		{"AINLSearchLimitEnterprise", cfg.AINLSearchLimitEnterprise, 1000},
		{"AISummarizeLimitFree", cfg.AISummarizeLimitFree, 5},
		{"AISummarizeLimitPro", cfg.AISummarizeLimitPro, 50},
		{"AISummarizeLimitEnterprise", cfg.AISummarizeLimitEnterprise, 500},
		{"AICacheNLSearchTTL", cfg.AICacheNLSearchTTL, 1 * time.Hour},
		{"AICacheSummarizeTTL", cfg.AICacheSummarizeTTL, 24 * time.Hour},
		{"AILogRetentionDays", cfg.AILogRetentionDays, 90},
		{"GeminiMock", cfg.GeminiMock, false},
		// Notifications
		{"NotifyMaxConcurrentPerOrg", cfg.NotifyMaxConcurrentPerOrg, 5},
		{"NotifyDebounceSeconds", cfg.NotifyDebounceSeconds, 120},
		{"WebhookSecretGraceHours", cfg.WebhookSecretGraceHours, 24},
		{"NotifyClaimBatchSize", cfg.NotifyClaimBatchSize, 50},
		{"NotifyMaxAttempts", cfg.NotifyMaxAttempts, 4},
		{"NotifyBackoffBaseSeconds", cfg.NotifyBackoffBaseSeconds, 30},
		// Rate limiting
		{"RateLimitEvictTTL", cfg.RateLimitEvictTTL, 15 * time.Minute},
		// Data retention
		{"RetentionCleanupEnabled", cfg.RetentionCleanupEnabled, true},
		{"RetentionCleanupBatchSize", cfg.RetentionCleanupBatchSize, 10000},
		{"RetentionRawPayloadDays", cfg.RetentionRawPayloadDays, 90},
		{"RetentionFeedFetchLogDays", cfg.RetentionFeedFetchLogDays, 90},
		{"RetentionAlertEventsDays", cfg.RetentionAlertEventsDays, 365},
		{"RetentionNotifDeliveriesDays", cfg.RetentionNotifDeliveriesDays, 90},
		{"RetentionAuditLogDays", cfg.RetentionAuditLogDays, 365},
		{"RetentionJobQueueHours", cfg.RetentionJobQueueHours, 24},
		{"RetentionMaxRuntimeSeconds", cfg.RetentionMaxRuntimeSeconds, 300},
		// MFA
		{"MFARequiredSiteAdmins", cfg.MFARequiredSiteAdmins, false},
		{"MFARequiredOrgOwners", cfg.MFARequiredOrgOwners, false},
		{"MFAEmailOTPTTL", cfg.MFAEmailOTPTTL, 10 * time.Minute},
		{"MFAEmailOTPMaxPerHour", cfg.MFAEmailOTPMaxPerHour, 5},
		{"MFAChallengeMaxAttempts", cfg.MFAChallengeMaxAttempts, 3},
		{"MFAPendingTokenTTL", cfg.MFAPendingTokenTTL, 5 * time.Minute},
		// Logging
		{"LogLevel", cfg.LogLevel, "info"},
		{"LogFormat", cfg.LogFormat, "json"},
	}

	for _, tc := range defaults {
		if tc.got != tc.want {
			t.Errorf("%s: got %v (%T), want %v (%T)", tc.name, tc.got, tc.got, tc.want, tc.want)
		}
	}
}

func TestMFAConfigDefaults(t *testing.T) {
	// Set only required vars, let MFA fields use defaults.
	t.Setenv("JWT_SECRET", "test-secret-min-32-chars-long-xx")
	t.Setenv("DATABASE_URL", "postgres://localhost/test")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.MFARequiredSiteAdmins != false {
		t.Errorf("MFARequiredSiteAdmins: got %v, want false", cfg.MFARequiredSiteAdmins)
	}
	if cfg.MFARequiredOrgOwners != false {
		t.Errorf("MFARequiredOrgOwners: got %v, want false", cfg.MFARequiredOrgOwners)
	}
	if cfg.MFAEmailOTPTTL != 10*time.Minute {
		t.Errorf("MFAEmailOTPTTL: got %v, want %v", cfg.MFAEmailOTPTTL, 10*time.Minute)
	}
	if cfg.MFAEmailOTPMaxPerHour != 5 {
		t.Errorf("MFAEmailOTPMaxPerHour: got %v, want 5", cfg.MFAEmailOTPMaxPerHour)
	}
	if cfg.MFAChallengeMaxAttempts != 3 {
		t.Errorf("MFAChallengeMaxAttempts: got %v, want 3", cfg.MFAChallengeMaxAttempts)
	}
	if cfg.MFAPendingTokenTTL != 5*time.Minute {
		t.Errorf("MFAPendingTokenTTL: got %v, want %v", cfg.MFAPendingTokenTTL, 5*time.Minute)
	}
}
