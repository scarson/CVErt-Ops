// ABOUTME: Tests for the doctor check framework and individual health checks.
// ABOUTME: Unit tests for checks that don't need Postgres; integration tests for DB checks.
package doctor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestRun_CollectsResults(t *testing.T) {
	t.Parallel()
	checks := []Check{
		&stubCheck{name: "pass-check", status: StatusPass, message: "ok"},
		&stubCheck{name: "fail-check", status: StatusFail, message: "broken"},
	}
	results := Run(context.Background(), checks)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Status != StatusPass {
		t.Errorf("results[0].Status = %q, want %q", results[0].Status, StatusPass)
	}
	if results[1].Status != StatusFail {
		t.Errorf("results[1].Status = %q, want %q", results[1].Status, StatusFail)
	}
}

func TestRun_ErrorOverridesStatus(t *testing.T) {
	t.Parallel()
	checks := []Check{
		&errorCheck{name: "error-check"},
	}
	results := Run(context.Background(), checks)
	if results[0].Status != StatusFail {
		t.Errorf("error check status = %q, want %q", results[0].Status, StatusFail)
	}
	if results[0].Error == "" {
		t.Error("error check should have error message")
	}
}

func TestHasFailures_TrueWhenFail(t *testing.T) {
	t.Parallel()
	results := []Result{
		{Status: StatusPass},
		{Status: StatusFail},
	}
	if !HasFailures(results) {
		t.Error("HasFailures should return true when a fail exists")
	}
}

func TestHasFailures_FalseWhenAllPass(t *testing.T) {
	t.Parallel()
	results := []Result{
		{Status: StatusPass},
		{Status: StatusWarn},
	}
	if HasFailures(results) {
		t.Error("HasFailures should return false when no fails")
	}
}

// ── JWT check ────────────────────────────────────────────────────────────────

func TestJWTCheck_Pass(t *testing.T) {
	t.Parallel()
	c := &JWTCheck{Secret: "this-is-at-least-32-bytes-long!!"}
	status, _, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusPass {
		t.Errorf("status = %q, want %q", status, StatusPass)
	}
}

func TestJWTCheck_Fail_TooShort(t *testing.T) {
	t.Parallel()
	c := &JWTCheck{Secret: "short"}
	status, _, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusFail {
		t.Errorf("status = %q, want %q", status, StatusFail)
	}
}

// ── Disk check ───────────────────────────────────────────────────────────────

func TestDiskCheck_Pass(t *testing.T) {
	t.Parallel()
	c := &DiskCheck{}
	status, _, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusPass {
		t.Errorf("status = %q, want %q", status, StatusPass)
	}
}

// ── SMTP check ───────────────────────────────────────────────────────────────

func TestSMTPCheck_NotConfigured_Pass(t *testing.T) {
	t.Parallel()
	c := &SMTPCheck{} // no host configured
	status, msg, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusPass {
		t.Errorf("status = %q, want %q", status, StatusPass)
	}
	if msg == "" {
		t.Error("expected message about SMTP not configured")
	}
}

func TestSMTPCheck_Unreachable_Fail(t *testing.T) {
	t.Parallel()
	c := &SMTPCheck{Host: "192.0.2.1", Port: 25} // TEST-NET, unreachable
	status, _, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusFail {
		t.Errorf("status = %q, want %q", status, StatusFail)
	}
}

// ── JWT check — previous secret ──────────────────────────────────────────────

func TestJWTCheck_PreviousSecretTooShort_Warn(t *testing.T) {
	t.Parallel()
	c := &JWTCheck{
		Secret:         "this-is-at-least-32-bytes-long!!",
		PreviousSecret: "short",
	}
	status, msg, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusWarn {
		t.Errorf("status = %q, want %q", status, StatusWarn)
	}
	if msg == "" {
		t.Error("expected message about previous key being too short")
	}
}

func TestJWTCheck_PreviousSecretAdequate_Pass(t *testing.T) {
	t.Parallel()
	c := &JWTCheck{
		Secret:         "this-is-at-least-32-bytes-long!!",
		PreviousSecret: "this-is-at-least-32-bytes-long!!",
	}
	status, _, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusPass {
		t.Errorf("status = %q, want %q", status, StatusPass)
	}
}

func TestJWTCheck_PreviousSecretEmpty_Pass(t *testing.T) {
	t.Parallel()
	c := &JWTCheck{
		Secret:         "this-is-at-least-32-bytes-long!!",
		PreviousSecret: "",
	}
	status, _, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusPass {
		t.Errorf("status = %q, want %q", status, StatusPass)
	}
}

// ── SecurityHeaders check ───────────────────────────────────────────────────

func TestSecurityHeadersCheck_Name(t *testing.T) {
	t.Parallel()
	c := &SecurityHeadersCheck{}
	if c.Name() != "security_headers" {
		t.Errorf("Name() = %q, want %q", c.Name(), "security_headers")
	}
}

func TestSecurityHeadersCheck_AllPresent_Pass(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := &SecurityHeadersCheck{ServerAddr: ts.URL}
	status, _, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusPass {
		t.Errorf("status = %q, want %q", status, StatusPass)
	}
}

func TestSecurityHeadersCheck_MissingHeaders_Fail(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Only set one of the three required headers.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := &SecurityHeadersCheck{ServerAddr: ts.URL}
	status, _, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusFail {
		t.Errorf("status = %q, want %q", status, StatusFail)
	}
}

func TestSecurityHeadersCheck_EmptyServerAddr_Pass(t *testing.T) {
	t.Parallel()
	c := &SecurityHeadersCheck{ServerAddr: ""}
	status, _, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusPass {
		t.Errorf("status = %q, want %q", status, StatusPass)
	}
}

func TestSecurityHeadersCheck_Unreachable_Warn(t *testing.T) {
	t.Parallel()
	c := &SecurityHeadersCheck{ServerAddr: "http://192.0.2.1:1"} // TEST-NET, unreachable
	status, _, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusWarn {
		t.Errorf("status = %q, want %q", status, StatusWarn)
	}
}

// ── SSRF protection check ───────────────────────────────────────────────────

func TestSSRFProtectionCheck_Name(t *testing.T) {
	t.Parallel()
	c := &SSRFProtectionCheck{}
	if c.Name() != "ssrf_protection" {
		t.Errorf("Name() = %q, want %q", c.Name(), "ssrf_protection")
	}
}

func TestSSRFProtectionCheck_Pass(t *testing.T) {
	t.Parallel()
	c := &SSRFProtectionCheck{}
	status, _, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusPass {
		t.Errorf("status = %q, want %q", status, StatusPass)
	}
}

// ── CORS check ──────────────────────────────────────────────────────────────

func TestCORSCheck_Name(t *testing.T) {
	t.Parallel()
	c := &CORSCheck{}
	if c.Name() != "cors_configuration" {
		t.Errorf("Name() = %q, want %q", c.Name(), "cors_configuration")
	}
}

func TestCORSCheck_WildcardWithCookies_Warn(t *testing.T) {
	t.Parallel()
	c := &CORSCheck{AllowedOrigins: "*", CookieAuth: true}
	status, _, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusWarn {
		t.Errorf("status = %q, want %q", status, StatusWarn)
	}
}

func TestCORSCheck_SpecificOriginWithCookies_Pass(t *testing.T) {
	t.Parallel()
	c := &CORSCheck{AllowedOrigins: "https://example.com", CookieAuth: true}
	status, _, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusPass {
		t.Errorf("status = %q, want %q", status, StatusPass)
	}
}

func TestCORSCheck_WildcardNoCookies_Pass(t *testing.T) {
	t.Parallel()
	c := &CORSCheck{AllowedOrigins: "*", CookieAuth: false}
	status, _, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusPass {
		t.Errorf("status = %q, want %q", status, StatusPass)
	}
}

// ── StandardChecks ──────────────────────────────────────────────────────────

func TestStandardChecks_ReturnsAllTwelveChecks(t *testing.T) {
	t.Parallel()
	checks := StandardChecks(StandardChecksConfig{
		DB:                    nil, // nil is fine — we just verify the slice length
		ExpectedSchemaVersion: 34,
		JWTSecret:             "test-secret",
	})
	if got := len(checks); got != 12 {
		t.Errorf("StandardChecks returned %d checks, want 12", got)
	}
}

func TestStandardChecks_SMTPLocalhostTreatedAsUnconfigured(t *testing.T) {
	t.Parallel()
	checks := StandardChecks(StandardChecksConfig{
		SMTPHost: "localhost",
		// No SMTPUsername → treated as unconfigured.
	})
	// Find the SMTP check and verify it passes (skips).
	for _, c := range checks {
		if c.Name() == "smtp_connectivity" {
			status, _, err := c.Run(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if status != StatusPass {
				t.Errorf("SMTP check with localhost/no-user: status = %q, want %q", status, StatusPass)
			}
			return
		}
	}
	t.Fatal("smtp_connectivity check not found in StandardChecks")
}

// ── MigrationCheck dirty flag (integration) ─────────────────────────────────

func TestMigrationCheck_Dirty_ReturnsFail(t *testing.T) {
	t.Parallel()

	db := testutil.NewTestDB(t)
	pool := db.Pool()
	ctx := context.Background()

	// Read current schema version.
	var version int
	if err := pool.QueryRow(ctx, "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1").Scan(&version); err != nil {
		t.Fatalf("read schema version: %v", err)
	}

	// Set dirty flag.
	if _, err := pool.Exec(ctx, "UPDATE schema_migrations SET dirty = true WHERE version = $1", version); err != nil {
		t.Fatalf("set dirty flag: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "UPDATE schema_migrations SET dirty = false WHERE version = $1", version)
	})

	check := &MigrationCheck{DB: pool, ExpectedVersion: version}
	status, msg, err := check.Run(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusFail {
		t.Errorf("status = %q, want %q", status, StatusFail)
	}
	if msg == "" {
		t.Error("expected message mentioning dirty migration")
	}
}

// ── stub helpers ─────────────────────────────────────────────────────────────

type stubCheck struct {
	name    string
	status  string
	message string
}

func (s *stubCheck) Name() string { return s.name }
func (s *stubCheck) Run(_ context.Context) (string, string, error) {
	return s.status, s.message, nil
}

type errorCheck struct {
	name string
}

func (e *errorCheck) Name() string { return e.name }
func (e *errorCheck) Run(_ context.Context) (string, string, error) {
	return "", "", context.DeadlineExceeded
}
