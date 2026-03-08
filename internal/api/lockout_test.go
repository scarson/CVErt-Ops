// ABOUTME: Unit tests for the account lockout manager.
// ABOUTME: Uses injectable clock for deterministic time-based testing.
package api

import (
	"testing"
	"time"
)

func TestLockout_Allow(t *testing.T) {
	t.Parallel()
	m := newLockoutManager(5, 15*time.Minute, time.Now)

	allowed, retryAfter := m.Check("test@example.com")
	if !allowed {
		t.Error("expected allowed on first attempt")
	}
	if retryAfter != 0 {
		t.Errorf("retryAfter = %v, want 0", retryAfter)
	}
}

func TestLockout_ThresholdReached(t *testing.T) {
	t.Parallel()
	m := newLockoutManager(5, 15*time.Minute, time.Now)

	for range 5 {
		m.RecordFailure("locked@example.com")
	}

	allowed, retryAfter := m.Check("locked@example.com")
	if allowed {
		t.Error("expected locked after 5 failures")
	}
	if retryAfter <= 0 {
		t.Errorf("retryAfter = %v, want > 0", retryAfter)
	}
}

func TestLockout_ResetOnSuccess(t *testing.T) {
	t.Parallel()
	m := newLockoutManager(5, 15*time.Minute, time.Now)

	for range 4 {
		m.RecordFailure("reset@example.com")
	}
	m.RecordSuccess("reset@example.com")

	// After success, counter is reset — one more failure is attempt 1, not 5.
	m.RecordFailure("reset@example.com")
	allowed, _ := m.Check("reset@example.com")
	if !allowed {
		t.Error("expected allowed after success reset + 1 failure")
	}
}

func TestLockout_Expiry(t *testing.T) {
	t.Parallel()
	now := time.Now()
	clock := func() time.Time { return now }
	m := newLockoutManager(5, 15*time.Minute, clock)

	for range 5 {
		m.RecordFailure("expiry@example.com")
	}

	// Still locked.
	allowed, _ := m.Check("expiry@example.com")
	if allowed {
		t.Error("expected locked immediately after threshold")
	}

	// Advance past lockout duration.
	now = now.Add(16 * time.Minute)

	allowed, retryAfter := m.Check("expiry@example.com")
	if !allowed {
		t.Error("expected allowed after lockout expired")
	}
	if retryAfter != 0 {
		t.Errorf("retryAfter = %v, want 0", retryAfter)
	}
}

func TestLockout_Concurrent(t *testing.T) {
	t.Parallel()
	m := newLockoutManager(100, 15*time.Minute, time.Now)

	// Hammer RecordFailure and Check from 10 goroutines simultaneously.
	// This verifies no data races under concurrent access.
	const goroutines = 10
	const iterations = 50
	done := make(chan struct{}, goroutines)

	for g := range goroutines {
		go func(id int) {
			email := "concurrent@example.com"
			for range iterations {
				m.RecordFailure(email)
				m.Check(email)
				if id%2 == 0 {
					m.RecordSuccess(email)
				}
			}
			done <- struct{}{}
		}(g)
	}

	for range goroutines {
		<-done
	}

	// If we got here without a panic or race detector failure, the test passes.
	// Just verify the manager is still functional.
	allowed, _ := m.Check("concurrent@example.com")
	_ = allowed // result depends on timing; we just care it didn't crash
}

func TestLockout_DifferentEmails(t *testing.T) {
	t.Parallel()
	m := newLockoutManager(5, 15*time.Minute, time.Now)

	for range 5 {
		m.RecordFailure("locked@example.com")
	}

	// Different email should still be allowed.
	allowed, _ := m.Check("other@example.com")
	if !allowed {
		t.Error("expected different email to be allowed")
	}

	// Original email should be locked.
	allowed, _ = m.Check("locked@example.com")
	if allowed {
		t.Error("expected original email to be locked")
	}
}
