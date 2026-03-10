// ABOUTME: Concrete health check implementations for the doctor framework.
// ABOUTME: Covers DB connectivity, migrations, RLS, JWT, SMTP, disk, encryption, and feeds.
package doctor

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/scarson/cvert-ops/internal/crypto"
)

// ── Database connectivity ────────────────────────────────────────────────────

// DBConnectivityCheck verifies the database is reachable and responds within 1s.
type DBConnectivityCheck struct {
	DB *pgxpool.Pool
}

func (c *DBConnectivityCheck) Name() string { return "database_connectivity" }

func (c *DBConnectivityCheck) Run(ctx context.Context) (string, string, error) {
	if c.DB == nil {
		return StatusFail, "database pool is nil", nil
	}
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	start := time.Now()
	if err := c.DB.Ping(ctx); err != nil {
		return StatusFail, fmt.Sprintf("ping failed: %v", err), nil
	}
	latency := time.Since(start)
	return StatusPass, fmt.Sprintf("connected (latency %s)", latency.Round(time.Millisecond)), nil
}

// ── Migration currency ──────────────────────────────────────────────────────

// MigrationCheck verifies the applied schema version matches the expected version.
type MigrationCheck struct {
	DB              *pgxpool.Pool
	ExpectedVersion int
}

func (c *MigrationCheck) Name() string { return "migration_currency" }

func (c *MigrationCheck) Run(ctx context.Context) (string, string, error) {
	if c.DB == nil {
		return StatusFail, "database pool is nil", nil
	}
	var version int
	err := c.DB.QueryRow(ctx,
		"SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1",
	).Scan(&version)
	if err != nil {
		return StatusFail, fmt.Sprintf("query failed: %v", err), nil
	}
	if version != c.ExpectedVersion {
		return StatusWarn, fmt.Sprintf("schema version %d, expected %d", version, c.ExpectedVersion), nil
	}
	return StatusPass, fmt.Sprintf("schema version %d (current)", version), nil
}

// ── DB role permissions ─────────────────────────────────────────────────────

// DBRoleCheck verifies the app DB role has NOBYPASSRLS and is not SUPERUSER.
type DBRoleCheck struct {
	DB *pgxpool.Pool
}

func (c *DBRoleCheck) Name() string { return "db_role_permissions" }

func (c *DBRoleCheck) Run(ctx context.Context) (string, string, error) {
	if c.DB == nil {
		return StatusFail, "database pool is nil", nil
	}
	var rolsuper, rolbypassrls bool
	err := c.DB.QueryRow(ctx,
		"SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
	).Scan(&rolsuper, &rolbypassrls)
	if err != nil {
		return StatusFail, fmt.Sprintf("query pg_roles: %v", err), nil
	}
	if rolsuper {
		return StatusFail, "app role is SUPERUSER — must not be", nil
	}
	if rolbypassrls {
		return StatusFail, "app role has BYPASSRLS — must have NOBYPASSRLS", nil
	}
	return StatusPass, "role has NOBYPASSRLS, no SUPERUSER", nil
}

// ── RLS enforcement ─────────────────────────────────────────────────────────

// RLSCheck verifies all org-scoped tables have row-level security enabled.
type RLSCheck struct {
	DB *pgxpool.Pool
	// Tables is the list of org-scoped table names that must have RLS enabled.
	Tables []string
}

func (c *RLSCheck) Name() string { return "rls_enforcement" }

func (c *RLSCheck) Run(ctx context.Context) (string, string, error) {
	if c.DB == nil {
		return StatusFail, "database pool is nil", nil
	}
	if len(c.Tables) == 0 {
		return StatusWarn, "no org-scoped tables configured for RLS check", nil
	}

	var missing []string
	for _, table := range c.Tables {
		var enabled bool
		err := c.DB.QueryRow(ctx,
			"SELECT relrowsecurity FROM pg_class WHERE relname = $1 AND relkind = 'r'",
			table,
		).Scan(&enabled)
		if err != nil {
			missing = append(missing, fmt.Sprintf("%s (query error: %v)", table, err))
			continue
		}
		if !enabled {
			missing = append(missing, table)
		}
	}

	if len(missing) > 0 {
		return StatusFail, fmt.Sprintf("RLS not enabled on: %v", missing), nil
	}
	return StatusPass, fmt.Sprintf("all %d org-scoped tables have RLS enabled", len(c.Tables)), nil
}

// ── Encryption sentinel ─────────────────────────────────────────────────────

// EncryptionSentinelCheck verifies the encryption sentinel can be decrypted.
type EncryptionSentinelCheck struct {
	DB  *pgxpool.Pool
	Key [32]byte
}

func (c *EncryptionSentinelCheck) Name() string { return "encryption_sentinel" }

func (c *EncryptionSentinelCheck) Run(ctx context.Context) (string, string, error) {
	if c.DB == nil {
		return StatusFail, "database pool is nil", nil
	}

	var value []byte
	err := c.DB.QueryRow(ctx,
		"SELECT value FROM system_settings WHERE key = 'encryption_sentinel'",
	).Scan(&value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Sentinel not yet written — first serve hasn't run.
			return StatusWarn, "encryption sentinel not initialized — run `serve` once", nil
		}
		return StatusFail, fmt.Sprintf("query system_settings: %v", err), nil
	}

	_, err = crypto.Decrypt(c.Key, value)
	if err != nil {
		return StatusFail, fmt.Sprintf("sentinel decryption failed: %v — encryption key may have changed", err), nil
	}
	return StatusPass, "encryption sentinel decrypted successfully", nil
}

// ── JWT configuration ───────────────────────────────────────────────────────

// JWTCheck verifies the JWT secret meets minimum length requirements.
type JWTCheck struct {
	Secret string
}

func (c *JWTCheck) Name() string { return "jwt_configuration" }

func (c *JWTCheck) Run(_ context.Context) (string, string, error) {
	if len(c.Secret) < 32 {
		return StatusFail, fmt.Sprintf("JWT_SECRET is %d bytes, minimum 32 required", len(c.Secret)), nil
	}
	return StatusPass, "JWT_SECRET meets minimum length (>= 32 bytes)", nil
}

// ── SMTP connectivity ───────────────────────────────────────────────────────

// SMTPCheck verifies SMTP connectivity by dialing the configured host.
// If Host is empty, the check passes with a skip message.
type SMTPCheck struct {
	Host string
	Port int
}

func (c *SMTPCheck) Name() string { return "smtp_connectivity" }

func (c *SMTPCheck) Run(_ context.Context) (string, string, error) {
	if c.Host == "" {
		return StatusPass, "SMTP not configured — skipped", nil
	}
	addr := net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return StatusFail, fmt.Sprintf("SMTP dial %s failed: %v", addr, err), nil
	}
	conn.Close()
	return StatusPass, fmt.Sprintf("SMTP reachable at %s", addr), nil
}

// ── Disk/temp space ─────────────────────────────────────────────────────────

// DiskCheck verifies a writable temp directory exists.
type DiskCheck struct{}

func (c *DiskCheck) Name() string { return "disk_temp_space" }

func (c *DiskCheck) Run(_ context.Context) (string, string, error) {
	f, err := os.CreateTemp("", "cvert-doctor-*")
	if err != nil {
		return StatusFail, fmt.Sprintf("cannot create temp file: %v", err), nil
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return StatusPass, fmt.Sprintf("writable temp directory: %s", os.TempDir()), nil
}

// ── Feed schedule ───────────────────────────────────────────────────────────

// FeedCheck verifies feeds are not permanently failing.
type FeedCheck struct {
	DB *pgxpool.Pool
	// FailureThreshold is the number of consecutive failures that triggers a warning.
	FailureThreshold int
}

func (c *FeedCheck) Name() string { return "feed_schedule" }

func (c *FeedCheck) Run(ctx context.Context) (string, string, error) {
	if c.DB == nil {
		return StatusFail, "database pool is nil", nil
	}

	threshold := c.FailureThreshold
	if threshold <= 0 {
		threshold = 10
	}

	rows, err := c.DB.Query(ctx,
		"SELECT feed_name, consecutive_failures, last_error FROM feed_sync_state WHERE consecutive_failures >= $1",
		threshold,
	)
	if err != nil {
		return StatusFail, fmt.Sprintf("query feed_sync_state: %v", err), nil
	}
	defer rows.Close()

	var failing []string
	for rows.Next() {
		var name string
		var lastErr *string
		var failures int
		if err := rows.Scan(&name, &failures, &lastErr); err != nil {
			return StatusFail, fmt.Sprintf("scan row: %v", err), nil
		}
		detail := fmt.Sprintf("%s (%d consecutive failures)", name, failures)
		if lastErr != nil && *lastErr != "" {
			detail += fmt.Sprintf(": %s", *lastErr)
		}
		failing = append(failing, detail)
	}
	if err := rows.Err(); err != nil {
		return StatusFail, fmt.Sprintf("rows iteration: %v", err), nil
	}

	if len(failing) > 0 {
		return StatusWarn, fmt.Sprintf("feeds with persistent failures: %v", failing), nil
	}
	return StatusPass, "all feeds healthy", nil
}

// StandardChecksConfig holds parameters for constructing the standard health check suite.
type StandardChecksConfig struct {
	DB                    *pgxpool.Pool
	ExpectedSchemaVersion int
	SSOEncryptionKey      string
	JWTSecret             string
	SMTPHost              string
	SMTPPort              int
	SMTPUsername          string
}

// StandardChecks returns the full suite of health checks configured from the
// given parameters. Used by both CLI and API doctor endpoints.
func StandardChecks(c StandardChecksConfig) []Check {
	var encKey [32]byte
	if c.SSOEncryptionKey != "" {
		decoded, err := hex.DecodeString(c.SSOEncryptionKey)
		if err == nil && len(decoded) == 32 {
			copy(encKey[:], decoded)
		}
	}

	smtpHost := c.SMTPHost
	// Default SMTP host is "localhost" — treat as unconfigured unless explicitly
	// set with a real hostname and non-default port or credentials.
	if smtpHost == "localhost" && c.SMTPUsername == "" {
		smtpHost = ""
	}

	return []Check{
		&DBConnectivityCheck{DB: c.DB},
		&MigrationCheck{DB: c.DB, ExpectedVersion: c.ExpectedSchemaVersion},
		&DBRoleCheck{DB: c.DB},
		&RLSCheck{DB: c.DB, Tables: OrgScopedTables()},
		&EncryptionSentinelCheck{DB: c.DB, Key: encKey},
		&JWTCheck{Secret: c.JWTSecret},
		&SMTPCheck{Host: smtpHost, Port: c.SMTPPort},
		&DiskCheck{},
		&FeedCheck{DB: c.DB},
	}
}

// OrgScopedTables returns the list of tables that must have RLS enabled.
// Maintained here so both CLI and API doctor checks use the same list.
func OrgScopedTables() []string {
	return []string{
		"org_members",
		"api_keys",
		"groups",
		"group_members",
		"org_invitations",
		"watchlists",
		"watchlist_items",
		"alert_rules",
		"alert_rule_runs",
		"alert_events",
		"notification_channels",
		"alert_rule_channels",
		"notification_deliveries",
		"scheduled_reports",
		"report_channels",
		"ai_usage_counters",
		"ai_quota_overrides",
		"ai_cache",
		"ai_request_log",
		"saved_searches",
		"audit_log",
		"sso_connections",
		"sso_email_domains",
	}
}
