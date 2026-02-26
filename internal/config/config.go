// Package config parses and validates all application configuration from
// environment variables using caarlos0/env/v11.
//
// Call [Load] once at startup; pass the resulting [Config] to subcommands.
// Server exits if any field tagged "required" is missing.
package config

import (
	"time"

	"github.com/caarlos0/env/v11"
)

// Config holds all application configuration sourced from environment variables.
// Field defaults match .env.example. Sensitive fields are masked in String().
type Config struct {
	// ── Database ─────────────────────────────────────────────────────────────────
	DatabaseURL          string        `env:"DATABASE_URL,required"`
	DBMaxConns           int32         `env:"DB_MAX_CONNS"           envDefault:"25"`
	DBMaxConnIdleTime    time.Duration `env:"DB_MAX_CONN_IDLE_TIME"  envDefault:"5m"`
	DBStatementTimeoutMS int           `env:"DB_STATEMENT_TIMEOUT_MS" envDefault:"14000"`
	// DBQueryExecMode: "simple_protocol" (PgBouncer-compatible) or "extended_protocol".
	DBQueryExecMode string `env:"DB_QUERY_EXEC_MODE" envDefault:"simple_protocol"`

	// ── Server ───────────────────────────────────────────────────────────────────
	ListenAddr             string `env:"LISTEN_ADDR"              envDefault:":8080"`
	AppEnv                 string `env:"APP_ENV"                  envDefault:"development"`
	ExternalURL            string `env:"EXTERNAL_URL"             envDefault:"http://localhost:8080"`
	ShutdownTimeoutSeconds int    `env:"SHUTDOWN_TIMEOUT_SECONDS" envDefault:"60"`
	RegistrationMode       string `env:"REGISTRATION_MODE"        envDefault:"open"`

	// ── Auth — JWT ───────────────────────────────────────────────────────────────
	JWTSecret    string `env:"JWT_SECRET,required"`
	JWTAlgorithm string `env:"JWT_ALGORITHM" envDefault:"HS256"`

	// ── Auth — Cookies ───────────────────────────────────────────────────────────
	// Must be false for http://localhost; must be true in production with TLS.
	CookieSecure bool `env:"COOKIE_SECURE" envDefault:"false"`

	// ── Auth — Argon2id ──────────────────────────────────────────────────────────
	// Max simultaneous hash operations; each allocates ~19.5 MB.
	Argon2MaxConcurrent int `env:"ARGON2_MAX_CONCURRENT" envDefault:"5"`

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

	// ── Feed adapters ────────────────────────────────────────────────────────────
	NVDAPIKey string `env:"NVD_API_KEY"`

	// ── Notifications ────────────────────────────────────────────────────────────
	NotifyMaxConcurrentPerOrg int `env:"NOTIFY_MAX_CONCURRENT_PER_ORG" envDefault:"5"`
	NotifyDebounceSeconds     int `env:"NOTIFY_DEBOUNCE_SECONDS"       envDefault:"120"`
	WebhookSecretGraceHours   int `env:"WEBHOOK_SECRET_GRACE_HOURS"    envDefault:"24"`

	// ── Rate limiting ────────────────────────────────────────────────────────────
	// Comma-separated CIDRs of trusted reverse proxies; empty = no proxy.
	TrustedProxies    string        `env:"TRUSTED_PROXIES"`
	RateLimitEvictTTL time.Duration `env:"RATE_LIMIT_EVICT_TTL" envDefault:"15m"`

	// ── Data retention ───────────────────────────────────────────────────────────
	RetentionCleanupEnabled   bool `env:"RETENTION_CLEANUP_ENABLED"    envDefault:"true"`
	RetentionCleanupBatchSize int  `env:"RETENTION_CLEANUP_BATCH_SIZE" envDefault:"10000"`

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
