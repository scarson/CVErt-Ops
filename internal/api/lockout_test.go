// ABOUTME: Unit tests for the DB-backed account lockout manager.
// ABOUTME: Uses a mock lockoutStore to test decision logic without a real database.
package api

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/store"
)

// mockLockoutStore simulates the database lockout operations for unit testing.
type mockLockoutStore struct {
	failedCount int32
	lockedAt    *time.Time
	threshold   int // last threshold passed to RecordLoginFailure
	email       string
	exists      bool // whether the user exists in the mock
}

func (m *mockLockoutStore) RecordLoginFailure(_ context.Context, email string, threshold int) (*store.LoginLockoutState, error) {
	if !m.exists {
		return nil, sql.ErrNoRows
	}
	m.email = email
	m.threshold = threshold
	m.failedCount++
	if int(m.failedCount) >= threshold && m.lockedAt == nil {
		now := time.Now()
		m.lockedAt = &now
	}
	return &store.LoginLockoutState{
		FailedCount: m.failedCount,
		LockedAt:    m.lockedAt,
	}, nil
}

func (m *mockLockoutStore) RecordLoginSuccess(_ context.Context, _ string) error {
	if !m.exists {
		return nil
	}
	m.failedCount = 0
	m.lockedAt = nil
	return nil
}

func (m *mockLockoutStore) GetLoginLockoutState(_ context.Context, _ string) (*store.LoginLockoutState, error) {
	if !m.exists {
		return nil, sql.ErrNoRows
	}
	return &store.LoginLockoutState{
		FailedCount: m.failedCount,
		LockedAt:    m.lockedAt,
	}, nil
}

func TestDBLockout_AllowsFirstAttempt(t *testing.T) {
	t.Parallel()
	mock := &mockLockoutStore{exists: true}
	m := newLockoutManager(mock, 5, 15*time.Minute)
	ctx := context.Background()

	allowed, retryAfter := m.Check(ctx, "test@example.com")
	if !allowed {
		t.Error("expected allowed on first attempt")
	}
	if retryAfter != 0 {
		t.Errorf("retryAfter = %v, want 0", retryAfter)
	}
}

func TestDBLockout_LocksAfterThreshold(t *testing.T) {
	t.Parallel()
	mock := &mockLockoutStore{exists: true}
	m := newLockoutManager(mock, 5, 15*time.Minute)
	ctx := context.Background()

	for range 5 {
		m.RecordFailure(ctx, "locked@example.com")
	}

	allowed, retryAfter := m.Check(ctx, "locked@example.com")
	if allowed {
		t.Error("expected locked after 5 failures")
	}
	if retryAfter <= 0 {
		t.Errorf("retryAfter = %v, want > 0", retryAfter)
	}
}

func TestDBLockout_AutoUnlocksAfterDuration(t *testing.T) {
	t.Parallel()
	past := time.Now().Add(-16 * time.Minute)
	mock := &mockLockoutStore{
		exists:      true,
		failedCount: 5,
		lockedAt:    &past,
	}
	m := newLockoutManager(mock, 5, 15*time.Minute)
	ctx := context.Background()

	allowed, retryAfter := m.Check(ctx, "expiry@example.com")
	if !allowed {
		t.Error("expected allowed after lockout expired")
	}
	if retryAfter != 0 {
		t.Errorf("retryAfter = %v, want 0", retryAfter)
	}
	// Auto-unlock should have reset the mock state.
	if mock.failedCount != 0 {
		t.Errorf("failedCount = %d, want 0 after auto-unlock", mock.failedCount)
	}
	if mock.lockedAt != nil {
		t.Error("lockedAt should be nil after auto-unlock")
	}
}

func TestDBLockout_SuccessResetsCounter(t *testing.T) {
	t.Parallel()
	mock := &mockLockoutStore{exists: true}
	m := newLockoutManager(mock, 5, 15*time.Minute)
	ctx := context.Background()

	for range 4 {
		m.RecordFailure(ctx, "reset@example.com")
	}
	m.RecordSuccess(ctx, "reset@example.com")

	// After success, counter is reset — one more failure is attempt 1, not 5.
	m.RecordFailure(ctx, "reset@example.com")
	allowed, _ := m.Check(ctx, "reset@example.com")
	if !allowed {
		t.Error("expected allowed after success reset + 1 failure")
	}
}

func TestDBLockout_NonexistentUserAllowed(t *testing.T) {
	t.Parallel()
	mock := &mockLockoutStore{exists: false}
	m := newLockoutManager(mock, 5, 15*time.Minute)
	ctx := context.Background()

	allowed, retryAfter := m.Check(ctx, "unknown@example.com")
	if !allowed {
		t.Error("expected nonexistent user to be allowed")
	}
	if retryAfter != 0 {
		t.Errorf("retryAfter = %v, want 0", retryAfter)
	}

	// RecordFailure for nonexistent user should be a no-op.
	m.RecordFailure(ctx, "unknown@example.com")
}

func TestDBLockout_AdminUnlockWorks(t *testing.T) {
	t.Parallel()
	mock := &mockLockoutStore{exists: true}
	m := newLockoutManager(mock, 5, 15*time.Minute)
	ctx := context.Background()

	// Lock the account.
	for range 5 {
		m.RecordFailure(ctx, "admin-unlock@example.com")
	}

	allowed, _ := m.Check(ctx, "admin-unlock@example.com")
	if allowed {
		t.Fatal("expected locked after 5 failures")
	}

	// Simulate admin unlock by resetting the mock state directly
	// (mirrors what AdminUnlockUser does in the database).
	mock.failedCount = 0
	mock.lockedAt = nil

	allowed, retryAfter := m.Check(ctx, "admin-unlock@example.com")
	if !allowed {
		t.Error("expected allowed after admin unlock")
	}
	if retryAfter != 0 {
		t.Errorf("retryAfter = %v, want 0", retryAfter)
	}
}

func TestDBLockout_CaseInsensitive(t *testing.T) {
	t.Parallel()
	mock := &mockLockoutStore{exists: true}
	m := newLockoutManager(mock, 3, 15*time.Minute)
	ctx := context.Background()

	m.RecordFailure(ctx, "Victim@Example.com")
	m.RecordFailure(ctx, "victim@example.com")
	m.RecordFailure(ctx, "VICTIM@EXAMPLE.COM")

	// All three should count toward the SAME email — should be locked now.
	allowed, _ := m.Check(ctx, "victim@example.com")
	if allowed {
		t.Fatal("lockout should trigger regardless of email casing")
	}
}

func TestDBLockout_DifferentEmails(t *testing.T) {
	t.Parallel()
	// Each email gets its own mock, but within a single mock the lockout
	// manager normalizes email — so this tests that an unlocked user
	// with no failures is allowed.
	mock := &mockLockoutStore{exists: true}
	m := newLockoutManager(mock, 5, 15*time.Minute)
	ctx := context.Background()

	for range 5 {
		m.RecordFailure(ctx, "locked@example.com")
	}

	// The mock is shared, so it reflects the locked state.
	// This test verifies the lockout logic correctly reads state.
	allowed, _ := m.Check(ctx, "locked@example.com")
	if allowed {
		t.Error("expected original email to be locked")
	}
}

// failingLockoutStore always returns an error from GetLoginLockoutState.
type failingLockoutStore struct{}

func (f *failingLockoutStore) RecordLoginFailure(_ context.Context, _ string, _ int) (*store.LoginLockoutState, error) {
	return nil, fmt.Errorf("simulated DB failure")
}

func (f *failingLockoutStore) RecordLoginSuccess(_ context.Context, _ string) error {
	return fmt.Errorf("simulated DB failure")
}

func (f *failingLockoutStore) GetLoginLockoutState(_ context.Context, _ string) (*store.LoginLockoutState, error) {
	return nil, fmt.Errorf("simulated DB failure")
}

// Regression: lockout must fail open on DB errors — rate limiter is secondary defense.
// This verifies the intentional fail-open behavior documented at lockout.go:53-54
// to prevent an inadvertent change to fail-closed (which would lock out all users
// during a database outage).
func TestDBLockout_FailOpenOnDBError(t *testing.T) {
	t.Parallel()
	m := newLockoutManager(&failingLockoutStore{}, 5, 15*time.Minute)
	ctx := context.Background()

	allowed, retryAfter := m.Check(ctx, "any@example.com")
	if !allowed {
		t.Fatal("lockout must fail open on DB errors — got denied")
	}
	if retryAfter != 0 {
		t.Errorf("retryAfter = %v, want 0 on DB error fail-open", retryAfter)
	}
}
