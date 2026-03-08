// ABOUTME: In-memory account lockout manager to prevent brute-force login attacks.
// ABOUTME: Locks accounts after repeated failed login attempts for a configurable duration.
package api

import (
	"sync"
	"time"
)

// loginAttempt tracks failed login attempts for a single email address.
type loginAttempt struct {
	count    int
	lockedAt time.Time // zero value if not locked
}

// lockoutManager tracks failed login attempts and temporarily locks accounts.
// Thread-safe via sync.Mutex. Uses an injectable clock for testing.
type lockoutManager struct {
	mu        sync.Mutex
	attempts  map[string]*loginAttempt
	threshold int
	duration  time.Duration
	now       func() time.Time
}

// newLockoutManager creates a lockout manager with the given threshold and duration.
// The now function is used for clock injection in tests.
func newLockoutManager(threshold int, duration time.Duration, now func() time.Time) *lockoutManager {
	return &lockoutManager{
		attempts:  make(map[string]*loginAttempt),
		threshold: threshold,
		duration:  duration,
		now:       now,
	}
}

// Check returns whether the email is allowed to attempt login.
// If locked, retryAfter indicates the remaining lockout duration.
func (m *lockoutManager) Check(email string) (allowed bool, retryAfter time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	a, ok := m.attempts[email]
	if !ok {
		return true, 0
	}

	// Not locked yet (below threshold).
	if a.count < m.threshold {
		return true, 0
	}

	// Locked — check if lockout has expired.
	remaining := m.duration - m.now().Sub(a.lockedAt)
	if remaining <= 0 {
		// Lockout expired — reset and allow.
		delete(m.attempts, email)
		return true, 0
	}

	return false, remaining
}

// RecordFailure increments the failure count for an email.
// When the threshold is reached, the account becomes locked.
func (m *lockoutManager) RecordFailure(email string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	a, ok := m.attempts[email]
	if !ok {
		a = &loginAttempt{}
		m.attempts[email] = a
	}
	a.count++
	if a.count >= m.threshold && a.lockedAt.IsZero() {
		a.lockedAt = m.now()
	}
}

// RecordSuccess resets the failure count for an email.
func (m *lockoutManager) RecordSuccess(email string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.attempts, email)
}
