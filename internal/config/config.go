// ABOUTME: Parses all application configuration from environment variables via caarlos0/env.
// ABOUTME: Call Load() once at startup; pass the resulting Config to subcommands.
package config

import (
	"log/slog"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config holds all application configuration sourced from environment variables.
// Field defaults match .env.example. Sensitive fields are masked in String().
type Config struct {
	// ── Database ─────────────────────────────────────────────────────────────────
	DatabaseURL string `env:"DATABASE_URL,required"`
	// DatabaseURLMigrate is the connection string used by `cvert-ops migrate`.
	// Should use a superuser/DDL role. Falls back to DatabaseURL if unset.
	DatabaseURLMigrate       string        `env:"DATABASE_URL_MIGRATE"`
	DBMaxConns               int32         `env:"DB_MAX_CONNS"           envDefault:"25"`
	DBMaxConnIdleTime        time.Duration `env:"DB_MAX_CONN_IDLE_TIME"  envDefault:"5m"`
	DBStatementTimeoutMS     int           `env:"DB_STATEMENT_TIMEOUT_MS"      envDefault:"14000"`
	DBLongStatementTimeoutMS int           `env:"DB_LONG_STATEMENT_TIMEOUT_MS" envDefault:"120000"`
	// DBQueryExecMode: "simple_protocol" (PgBouncer-compatible) or "extended_protocol".
	DBQueryExecMode string `env:"DB_QUERY_EXEC_MODE" envDefault:"simple_protocol"`

	// ── Server ───────────────────────────────────────────────────────────────────
	ListenAddr             string `env:"LISTEN_ADDR"              envDefault:":8080"`
	MetricsPort            string `env:"METRICS_PORT"             envDefault:"9090"`
	AppEnv                 string `env:"APP_ENV"                  envDefault:"development"`
	ExternalURL            string `env:"EXTERNAL_URL"             envDefault:"http://localhost:8080"`
	FrontendURL            string `env:"FRONTEND_URL"             envDefault:"/"`
	ShutdownTimeoutSeconds int    `env:"SHUTDOWN_TIMEOUT_SECONDS" envDefault:"60"`
	RegistrationMode       string `env:"REGISTRATION_MODE"        envDefault:"invite-only"`

	// ── Auth — JWT ───────────────────────────────────────────────────────────────
	JWTSecret         string `env:"JWT_SECRET,required"`
	JWTSecretPrevious string `env:"JWT_SECRET_PREVIOUS"`
	JWTAlgorithm      string `env:"JWT_ALGORITHM" envDefault:"HS256"`

	// ── Auth — Cookies ───────────────────────────────────────────────────────────
	// Must be false for http://localhost; must be true in production with TLS.
	CookieSecure bool `env:"COOKIE_SECURE" envDefault:"false"`

	// ── Auth — Argon2id ──────────────────────────────────────────────────────────
	// Max simultaneous hash operations; each allocates ~19.5 MB.
	Argon2MaxConcurrent int `env:"ARGON2_MAX_CONCURRENT" envDefault:"5"`

	// ── Auth — Password Reset ────────────────────────────────────────────────
	PasswordResetTokenTTL   time.Duration `env:"PASSWORD_RESET_TOKEN_TTL"    envDefault:"1h"`
	PasswordResetMaxPerHour int           `env:"PASSWORD_RESET_MAX_PER_HOUR" envDefault:"3"`

	// ── Auth — Email Verification ────────────────────────────────────────────
	EmailVerificationTokenTTL   time.Duration `env:"EMAIL_VERIFICATION_TOKEN_TTL"       envDefault:"24h"`
	EmailVerificationMaxPerHour int           `env:"EMAIL_VERIFICATION_MAX_PER_HOUR" envDefault:"3"`

	// ── Auth — Account Lockout ───────────────────────────────────────────────
	LockoutThreshold int           `env:"LOCKOUT_THRESHOLD" envDefault:"5"`
	LockoutDuration  time.Duration `env:"LOCKOUT_DURATION"  envDefault:"15m"`

	// ── Auth — MFA ──────────────────────────────────────────────────────────
	MFARequiredSiteAdmins   bool          `env:"MFA_REQUIRED_SITE_ADMINS"   envDefault:"false"`
	MFARequiredOrgOwners    bool          `env:"MFA_REQUIRED_ORG_OWNERS"    envDefault:"false"`
	MFAEmailOTPTTL          time.Duration `env:"MFA_EMAIL_OTP_TTL"          envDefault:"10m"`
	MFAEmailOTPMaxPerHour   int           `env:"MFA_EMAIL_OTP_MAX_PER_HOUR" envDefault:"5"`
	MFAChallengeMaxAttempts int           `env:"MFA_CHALLENGE_MAX_ATTEMPTS" envDefault:"3"`
	MFAPendingTokenTTL      time.Duration `env:"MFA_PENDING_TOKEN_TTL"      envDefault:"5m"`

	// ── CORS ─────────────────────────────────────────────────────────────────
	// Comma-separated list of allowed origins (e.g. "https://app.example.com,https://admin.example.com").
	// Empty in production disables CORS. In development, defaults to localhost dev servers.
	CORSAllowedOrigins string `env:"CORS_ALLOWED_ORIGINS"`

	// ── OAuth — GitHub ───────────────────────────────────────────────────────────
	GitHubClientID     string `env:"GITHUB_CLIENT_ID"`
	GitHubClientSecret string `env:"GITHUB_CLIENT_SECRET"`

	// ── OAuth — Google ───────────────────────────────────────────────────────────
	GoogleClientID     string `env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `env:"GOOGLE_CLIENT_SECRET"`

	// ── Email — SMTP ─────────────────────────────────────────────────────────────
	SMTPHost     string `env:"SMTP_HOST" envDefault:"localhost"`
	SMTPPort     int    `env:"SMTP_PORT" envDefault:"1025"`
	SMTPFrom     string `env:"SMTP_FROM" envDefault:"cvert-ops@localhost"`
	SMTPUsername string `env:"SMTP_USERNAME"`
	SMTPPassword string `env:"SMTP_PASSWORD"`
	SMTPTLS      bool   `env:"SMTP_TLS"  envDefault:"false"`

	// ── AI — Google Gemini ───────────────────────────────────────────────────────
	GeminiAPIKey string `env:"GEMINI_API_KEY"`
	GeminiModel  string `env:"GEMINI_MODEL" envDefault:"gemini-2.0-flash"`

	// ── AI — Quotas & Behavior ───────────────────────────────────────────────────
	GeminiTimeout              time.Duration `env:"GEMINI_TIMEOUT"                  envDefault:"30s"`
	AIQuotaEnabled             bool          `env:"AI_QUOTA_ENABLED"                envDefault:"true"`
	AINLSearchLimitFree        int           `env:"AI_NL_SEARCH_LIMIT_FREE"         envDefault:"10"`
	AINLSearchLimitPro         int           `env:"AI_NL_SEARCH_LIMIT_PRO"          envDefault:"100"`
	AINLSearchLimitEnterprise  int           `env:"AI_NL_SEARCH_LIMIT_ENTERPRISE"   envDefault:"1000"`
	AISummarizeLimitFree       int           `env:"AI_SUMMARIZE_LIMIT_FREE"         envDefault:"5"`
	AISummarizeLimitPro        int           `env:"AI_SUMMARIZE_LIMIT_PRO"          envDefault:"50"`
	AISummarizeLimitEnterprise int           `env:"AI_SUMMARIZE_LIMIT_ENTERPRISE"   envDefault:"500"`
	AICacheNLSearchTTL         time.Duration `env:"AI_CACHE_NL_SEARCH_TTL"          envDefault:"1h"`
	AICacheSummarizeTTL        time.Duration `env:"AI_CACHE_SUMMARIZE_TTL"          envDefault:"24h"`
	AILogRetentionDays         int           `env:"AI_LOG_RETENTION_DAYS"            envDefault:"90"`
	GeminiMock                 bool          `env:"GEMINI_MOCK"                     envDefault:"false"`

	// ── SIEM — Syslog forwarding ────────────────────────────────────────────────
	SIEMSyslogAddr   string `env:"SIEM_SYSLOG_ADDR"`                     // e.g., "udp://splunk:514"; empty = disabled
	SIEMSyslogFormat string `env:"SIEM_SYSLOG_FORMAT" envDefault:"json"` // "json" or "cef"

	// ── Secrets file (SIGHUP reload) ─────────────────────────────────────────────
	SecretsFile string `env:"CVERTOPS_SECRETS_FILE"`

	// ── Feed adapters ────────────────────────────────────────────────────────────
	NVDAPIKey string `env:"NVD_API_KEY"`
	FeedsDir  string `env:"CVERTOPS_FEEDS_DIR"`

	// ── Notifications ────────────────────────────────────────────────────────────
	NotifyMaxConcurrentPerOrg int `env:"NOTIFY_MAX_CONCURRENT_PER_ORG" envDefault:"5"`
	NotifyDebounceSeconds     int `env:"NOTIFY_DEBOUNCE_SECONDS"       envDefault:"120"`
	WebhookSecretGraceHours   int `env:"WEBHOOK_SECRET_GRACE_HOURS"    envDefault:"24"`
	NotifyClaimBatchSize      int `env:"NOTIFY_CLAIM_BATCH_SIZE"       envDefault:"50"`
	NotifyMaxAttempts         int `env:"NOTIFY_MAX_ATTEMPTS"           envDefault:"4"`
	NotifyBackoffBaseSeconds  int `env:"NOTIFY_BACKOFF_BASE_SECONDS"   envDefault:"30"`

	// ── Rate limiting ────────────────────────────────────────────────────────────
	// Comma-separated CIDRs of trusted reverse proxies; empty = no proxy.
	TrustedProxies    string        `env:"TRUSTED_PROXIES"`
	RateLimitEvictTTL time.Duration `env:"RATE_LIMIT_EVICT_TTL" envDefault:"15m"`

	// ── SSO ─────────────────────────────────────────────────────────────────────
	SSOEncryptionKey         string `env:"SSO_ENCRYPTION_KEY"`          // 32-byte hex key; required if SSO is used
	SSOEncryptionKeyPrevious string `env:"SSO_ENCRYPTION_KEY_PREVIOUS"` // previous key for rotation

	// ── Feed scheduler ──────────────────────────────────────────────────────────
	FeedSchedulerEnabled bool `env:"FEED_SCHEDULER_ENABLED" envDefault:"true"`

	// ── Data retention ───────────────────────────────────────────────────────────
	RetentionCleanupEnabled   bool `env:"RETENTION_CLEANUP_ENABLED"    envDefault:"true"`
	RetentionCleanupBatchSize int  `env:"RETENTION_CLEANUP_BATCH_SIZE" envDefault:"10000"`
	// Per-table retention windows.
	RetentionRawPayloadDays      int `env:"RETENTION_RAW_PAYLOAD_DAYS"              envDefault:"90"`
	RetentionFeedFetchLogDays    int `env:"RETENTION_FEED_FETCH_LOG_DAYS"           envDefault:"90"`
	RetentionAlertEventsDays     int `env:"RETENTION_ALERT_EVENTS_DAYS"             envDefault:"365"`
	RetentionNotifDeliveriesDays int `env:"RETENTION_NOTIFICATION_DELIVERIES_DAYS"  envDefault:"90"`
	RetentionAuditLogDays        int `env:"RETENTION_AUDIT_LOG_DAYS"                envDefault:"365"`
	RetentionJobQueueHours       int `env:"RETENTION_JOB_QUEUE_HOURS"               envDefault:"24"`
	RetentionSecurityEventsDays  int `env:"RETENTION_SECURITY_EVENTS_DAYS"          envDefault:"90"`
	RetentionMaxRuntimeSeconds   int `env:"RETENTION_MAX_RUNTIME_SECONDS"           envDefault:"300"`

	// ── Logging ──────────────────────────────────────────────────────────────────
	LogLevel  string `env:"LOG_LEVEL"  envDefault:"info"`
	LogFormat string `env:"LOG_FORMAT" envDefault:"json"`
}

// Load parses and returns Config from environment variables.
// Returns an error if any required field is missing.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// IsDevelopment reports whether the application is running in development mode.
func (c *Config) IsDevelopment() bool {
	return c.AppEnv == "development"
}

// LogValue implements slog.LogValuer, masking credential fields so that
// logging a *Config never leaks secrets into log output.
func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("listen_addr", c.ListenAddr),
		slog.String("app_env", c.AppEnv),
		slog.String("external_url", c.ExternalURL),
		slog.String("frontend_url", c.FrontendURL),
		slog.Bool("cookie_secure", c.CookieSecure),
		slog.String("registration_mode", c.RegistrationMode),
		slog.String("jwt_secret", masked(c.JWTSecret)),
		slog.String("jwt_secret_previous", masked(c.JWTSecretPrevious)),
		slog.String("github_client_id", c.GitHubClientID),
		slog.String("github_client_secret", masked(c.GitHubClientSecret)),
		slog.String("google_client_id", c.GoogleClientID),
		slog.String("google_client_secret", masked(c.GoogleClientSecret)),
		slog.String("smtp_password", masked(c.SMTPPassword)),
		slog.String("gemini_api_key", masked(c.GeminiAPIKey)),
		slog.Bool("ai_quota_enabled", c.AIQuotaEnabled),
		slog.Duration("gemini_timeout", c.GeminiTimeout),
		slog.Bool("gemini_mock", c.GeminiMock),
		slog.String("nvd_api_key", masked(c.NVDAPIKey)),
		slog.String("sso_encryption_key", masked(c.SSOEncryptionKey)),
		slog.String("sso_encryption_key_previous", masked(c.SSOEncryptionKeyPrevious)),
		slog.String("siem_syslog_addr", c.SIEMSyslogAddr),
		slog.String("siem_syslog_format", c.SIEMSyslogFormat),
	)
}

// masked returns "***" if s is non-empty, otherwise "".
func masked(s string) string {
	if s == "" {
		return ""
	}
	return "***"
}
