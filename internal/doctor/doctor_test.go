// ABOUTME: Tests for the doctor check framework and individual health checks.
// ABOUTME: Unit tests for checks that don't need Postgres; integration tests for DB checks.
package doctor

import (
	"context"
	"testing"
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

// ── StandardChecks ──────────────────────────────────────────────────────────

func TestStandardChecks_ReturnsAllNineChecks(t *testing.T) {
	t.Parallel()
	checks := StandardChecks(StandardChecksConfig{
		DB:                    nil, // nil is fine — we just verify the slice length
		ExpectedSchemaVersion: 34,
		JWTSecret:             "test-secret",
	})
	if got := len(checks); got != 9 {
		t.Errorf("StandardChecks returned %d checks, want 9", got)
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
