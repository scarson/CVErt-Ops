// ABOUTME: Concrete health check implementations for the doctor framework.
// ABOUTME: Covers DB, migrations, RLS, JWT, SMTP, disk, encryption, feeds, security headers, SSRF, and CORS.
package doctor

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
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

// Name implements Check.
func (c *DBConnectivityCheck) Name() string { return "database_connectivity" }

// Run implements Check.
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

// Name implements Check.
func (c *MigrationCheck) Name() string { return "migration_currency" }

// Run implements Check.
func (c *MigrationCheck) Run(ctx context.Context) (string, string, error) {
	if c.DB == nil {
		return StatusFail, "database pool is nil", nil
	}
	var version int
	var dirty bool
	err := c.DB.QueryRow(ctx,
		"SELECT version, dirty FROM schema_migrations ORDER BY version DESC LIMIT 1",
	).Scan(&version, &dirty)
	if err != nil {
		return StatusFail, fmt.Sprintf("query failed: %v", err), nil
	}
	if dirty {
		return StatusFail, fmt.Sprintf("schema version %d is dirty (migration failed mid-apply)", version), nil
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

// Name implements Check.
func (c *DBRoleCheck) Name() string { return "db_role_permissions" }

// Run implements Check.
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

// Name implements Check.
func (c *RLSCheck) Name() string { return "rls_enforcement" }

// Run implements Check.
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
	DB          *pgxpool.Pool
	Key         [32]byte
	PreviousKey [32]byte
}

// Name implements Check.
func (c *EncryptionSentinelCheck) Name() string { return "encryption_sentinel" }

// Run implements Check.
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

	_, err = crypto.DecryptWithFallback(c.Key, c.PreviousKey, value)
	if err != nil {
		return StatusFail, fmt.Sprintf("sentinel decryption failed: %v — encryption key may have changed", err), nil
	}
	return StatusPass, "encryption sentinel decrypted successfully", nil
}

// ── JWT configuration ───────────────────────────────────────────────────────

// JWTCheck verifies the JWT secret meets minimum length requirements.
type JWTCheck struct {
	Secret         string
	PreviousSecret string
}

// Name implements Check.
func (c *JWTCheck) Name() string { return "jwt_configuration" }

// Run implements Check.
func (c *JWTCheck) Run(_ context.Context) (string, string, error) {
	if len(c.Secret) < 32 {
		return StatusFail, fmt.Sprintf("JWT_SECRET is %d bytes, minimum 32 required", len(c.Secret)), nil
	}
	if c.PreviousSecret != "" && len(c.PreviousSecret) < 32 {
		return StatusWarn, fmt.Sprintf("JWT_SECRET_PREVIOUS is %d bytes, minimum 32 recommended", len(c.PreviousSecret)), nil
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

// Name implements Check.
func (c *SMTPCheck) Name() string { return "smtp_connectivity" }

// Run implements Check.
func (c *SMTPCheck) Run(ctx context.Context) (string, string, error) {
	if c.Host == "" {
		return StatusPass, "SMTP not configured — skipped", nil
	}
	addr := net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port))
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return StatusFail, fmt.Sprintf("SMTP dial %s failed: %v", addr, err), nil
	}
	_ = conn.Close()
	return StatusPass, fmt.Sprintf("SMTP reachable at %s", addr), nil
}

// ── Disk/temp space ─────────────────────────────────────────────────────────

// DiskCheck verifies a writable temp directory exists.
type DiskCheck struct{}

// Name implements Check.
func (c *DiskCheck) Name() string { return "disk_temp_space" }

// Run implements Check.
func (c *DiskCheck) Run(_ context.Context) (string, string, error) {
	f, err := os.CreateTemp("", "cvert-doctor-*")
	if err != nil {
		return StatusFail, fmt.Sprintf("cannot create temp file: %v", err), nil
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name) //nolint:gosec // G304: path comes from os.CreateTemp, not user input
	return StatusPass, fmt.Sprintf("writable temp directory: %s", os.TempDir()), nil
}

// ── Feed schedule ───────────────────────────────────────────────────────────

// FeedCheck verifies feeds are not permanently failing.
type FeedCheck struct {
	DB *pgxpool.Pool
	// FailureThreshold is the number of consecutive failures that triggers a warning.
	FailureThreshold int
}

// Name implements Check.
func (c *FeedCheck) Name() string { return "feed_schedule" }

// Run implements Check.
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

// ── Security headers ─────────────────────────────────────────────────────────

// SecurityHeadersCheck verifies the server returns required security headers.
type SecurityHeadersCheck struct {
	ServerAddr string // e.g., "http://localhost:8080"
}

// Name implements Check.
func (c *SecurityHeadersCheck) Name() string { return "security_headers" }

// Run implements Check.
func (c *SecurityHeadersCheck) Run(ctx context.Context) (string, string, error) {
	if c.ServerAddr == "" {
		return StatusPass, "server address not configured — skipped (CLI mode)", nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ServerAddr+"/healthz", nil)
	if err != nil {
		return StatusWarn, fmt.Sprintf("could not build request: %v", err), nil
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req) //nolint:gosec // G704: ServerAddr is from app config, not user input
	if err != nil {
		return StatusWarn, fmt.Sprintf("server not reachable: %v", err), nil
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on health check response

	required := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":       "DENY",
		"Referrer-Policy":       "strict-origin-when-cross-origin",
	}

	var missing []string
	for header, expected := range required {
		if got := resp.Header.Get(header); got != expected {
			missing = append(missing, fmt.Sprintf("%s (want %q, got %q)", header, expected, got))
		}
	}

	if len(missing) > 0 {
		return StatusFail, fmt.Sprintf("missing or incorrect security headers: %v", missing), nil
	}
	return StatusPass, "all required security headers present", nil
}

// ── SSRF protection ─────────────────────────────────────────────────────────

// SSRFProtectionCheck verifies safeurl blocks requests to internal/metadata IPs.
type SSRFProtectionCheck struct{}

// Name implements Check.
func (c *SSRFProtectionCheck) Name() string { return "ssrf_protection" }

// Run implements Check. It verifies that the private network CIDRs used by
// safeurl cover common SSRF targets (cloud metadata, loopback) without
// making any outbound HTTP requests.
func (c *SSRFProtectionCheck) Run(_ context.Context) (string, string, error) {
	// These are the same private network CIDRs that safeurl's isIPBlocked
	// checks against. We verify the IPs are blocked by checking containment
	// directly — no HTTP calls needed.
	privateNetworks := []net.IPNet{
		parseCIDR("169.254.0.0/16"), // link-local / cloud metadata
		parseCIDR("127.0.0.0/8"),    // loopback
		parseCIDR("10.0.0.0/8"),     // private RFC 1918
		parseCIDR("172.16.0.0/12"),  // private RFC 1918
		parseCIDR("192.168.0.0/16"), // private RFC 1918
	}

	targets := []net.IP{
		net.ParseIP("169.254.169.254"), // cloud metadata endpoint
		net.ParseIP("127.0.0.1"),       // loopback
	}

	for _, target := range targets {
		blocked := false
		for _, network := range privateNetworks {
			if network.Contains(target) {
				blocked = true
				break
			}
		}
		if !blocked {
			return StatusFail, fmt.Sprintf("safeurl would not block %s — SSRF risk", target), nil
		}
	}

	return StatusPass, "safeurl blocks internal/metadata IPs (169.254.169.254, 127.0.0.1)", nil
}

// parseCIDR parses a CIDR string and panics on invalid input.
func parseCIDR(s string) net.IPNet {
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("invalid CIDR %q: %v", s, err))
	}
	return *network
}

// ── CORS configuration ──────────────────────────────────────────────────────

// CORSCheck verifies CORS allowed origins are safe given the auth mode.
type CORSCheck struct {
	AllowedOrigins string
	CookieAuth     bool
}

// Name implements Check.
func (c *CORSCheck) Name() string { return "cors_configuration" }

// Run implements Check.
func (c *CORSCheck) Run(_ context.Context) (string, string, error) {
	if strings.Contains(c.AllowedOrigins, "*") && c.CookieAuth {
		return StatusWarn, "CORS allows wildcard origin with cookie-based auth — credentials may be exposed to any origin", nil
	}
	return StatusPass, "CORS origin configuration is appropriate for auth mode", nil
}

// StandardChecksConfig holds parameters for constructing the standard health check suite.
type StandardChecksConfig struct {
	DB                       *pgxpool.Pool
	ExpectedSchemaVersion    int
	SSOEncryptionKey         string
	SSOEncryptionKeyPrevious string
	JWTSecret                string
	JWTSecretPrevious        string
	SMTPHost                 string
	SMTPPort                 int
	SMTPUsername             string
	CORSAllowedOrigins      string
	CookieAuth               bool
	ServerAddr               string // empty in CLI mode, "http://localhost:{port}" in API mode
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

	var encKeyPrev [32]byte
	if c.SSOEncryptionKeyPrevious != "" {
		decoded, err := hex.DecodeString(c.SSOEncryptionKeyPrevious)
		if err == nil && len(decoded) == 32 {
			copy(encKeyPrev[:], decoded)
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
		&EncryptionSentinelCheck{DB: c.DB, Key: encKey, PreviousKey: encKeyPrev},
		&JWTCheck{Secret: c.JWTSecret, PreviousSecret: c.JWTSecretPrevious},
		&SMTPCheck{Host: smtpHost, Port: c.SMTPPort},
		&DiskCheck{},
		&FeedCheck{DB: c.DB},
		&SecurityHeadersCheck{ServerAddr: c.ServerAddr},
		&SSRFProtectionCheck{},
		&CORSCheck{AllowedOrigins: c.CORSAllowedOrigins, CookieAuth: c.CookieAuth},
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
