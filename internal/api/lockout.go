// ABOUTME: In-memory account lockout manager to prevent brute-force login attacks.
// ABOUTME: Locks accounts after repeated failed login attempts for a configurable duration.
package api

import (
	"strings"
	"sync"
	"time"
)

// loginAttempt tracks failed login attempts for a single email address.
type loginAttempt struct {
	count        int
	lockedAt     time.Time // zero value if not locked
	lastActivity time.Time // set on every RecordFailure
}

// lockoutManager tracks failed login attempts and temporarily locks accounts.
// Thread-safe via sync.Mutex. Uses an injectable clock for testing.
type lockoutManager struct {
	mu        sync.Mutex
	attempts  map[string]*loginAttempt
	threshold int
	duration  time.Duration
	evictTTL  time.Duration
	now       func() time.Time
	done      chan struct{}
}

// newLockoutManager creates a lockout manager with the given threshold, duration,
// and evict TTL. Starts a background cleanup goroutine that evicts stale entries.
// The now function is used for clock injection in tests.
func newLockoutManager(threshold int, duration time.Duration, now func() time.Time) *lockoutManager {
	m := &lockoutManager{
		attempts:  make(map[string]*loginAttempt),
		threshold: threshold,
		duration:  duration,
		evictTTL:  duration, // default: entries idle longer than lockout window are safe to evict
		now:       now,
		done:      make(chan struct{}),
	}
	go m.cleanupLoop()
	return m
}

// Stop terminates the background cleanup goroutine.
func (m *lockoutManager) Stop() {
	close(m.done)
}

// Len returns the number of tracked email entries (for testing).
func (m *lockoutManager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.attempts)
}

// Check returns whether the email is allowed to attempt login.
// If locked, retryAfter indicates the remaining lockout duration.
func (m *lockoutManager) Check(email string) (allowed bool, retryAfter time.Duration) {
	email = strings.ToLower(email)
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
	email = strings.ToLower(email)
	m.mu.Lock()
	defer m.mu.Unlock()

	a, ok := m.attempts[email]
	if !ok {
		a = &loginAttempt{}
		m.attempts[email] = a
	}
	a.count++
	a.lastActivity = m.now()
	if a.count >= m.threshold && a.lockedAt.IsZero() {
		a.lockedAt = m.now()
	}
}

// RecordSuccess resets the failure count for an email.
func (m *lockoutManager) RecordSuccess(email string) {
	email = strings.ToLower(email)
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.attempts, email)
}

// evictStale removes entries that are idle longer than evictTTL and below the
// lockout threshold. Also removes expired lockouts (lockedAt + duration < now).
func (m *lockoutManager) evictStale() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	cutoff := now.Add(-m.evictTTL)
	for email, a := range m.attempts {
		if a.count >= m.threshold {
			// Locked entry — only evict if the lockout has expired.
			if !a.lockedAt.IsZero() && now.Sub(a.lockedAt) >= m.duration {
				delete(m.attempts, email)
			}
			continue
		}
		// Sub-threshold entry — evict if idle past evictTTL.
		if a.lastActivity.Before(cutoff) {
			delete(m.attempts, email)
		}
	}
}

// cleanupLoop periodically evicts stale entries. Mirrors ipRateLimiter.cleanupLoop.
func (m *lockoutManager) cleanupLoop() {
	interval := m.evictTTL / 2
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.evictStale()
		case <-m.done:
			return
		}
	}
}
