// ABOUTME: DB-backed account lockout manager to prevent brute-force login attacks.
// ABOUTME: Locks accounts after repeated failed login attempts for a configurable duration.
package api

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/scarson/cvert-ops/internal/store"
)

// lockoutStore defines the database operations needed by the lockout manager.
type lockoutStore interface {
	RecordLoginFailure(ctx context.Context, email string, threshold int) (*store.LoginLockoutState, error)
	RecordLoginSuccess(ctx context.Context, email string) error
	GetLoginLockoutState(ctx context.Context, email string) (*store.LoginLockoutState, error)
}

// lockoutManager tracks failed login attempts and temporarily locks accounts
// using the database as the source of truth. Survives server restarts and
// works across multi-instance deployments.
type lockoutManager struct {
	store     lockoutStore
	threshold int
	duration  time.Duration
}

// newLockoutManager creates a lockout manager backed by the given store.
func newLockoutManager(s lockoutStore, threshold int, duration time.Duration) *lockoutManager {
	return &lockoutManager{
		store:     s,
		threshold: threshold,
		duration:  duration,
	}
}

// Check returns whether the email is allowed to attempt login.
// If locked, retryAfter indicates the remaining lockout duration.
// Nonexistent users are always allowed (timing normalization handles them).
func (m *lockoutManager) Check(ctx context.Context, email string) (allowed bool, retryAfter time.Duration) {
	email = strings.ToLower(email)

	state, err := m.store.GetLoginLockoutState(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return true, 0
		}
		slog.ErrorContext(ctx, "lockout: get state", "error", err)
		// Fail open on DB errors — rate limiter provides a secondary defense.
		return true, 0
	}

	if state.LockedAt == nil {
		return true, 0
	}

	remaining := m.duration - time.Since(*state.LockedAt)
	if remaining <= 0 {
		// Lockout expired — reset state so the user can try again.
		if err := m.store.RecordLoginSuccess(ctx, email); err != nil {
			slog.ErrorContext(ctx, "lockout: auto-unlock", "error", err)
		}
		return true, 0
	}

	return false, remaining
}

// RecordFailure increments the failure count for an email.
// When the threshold is reached, the account becomes locked.
// Nonexistent users are silently ignored.
func (m *lockoutManager) RecordFailure(ctx context.Context, email string) {
	email = strings.ToLower(email)

	_, err := m.store.RecordLoginFailure(ctx, email, m.threshold)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return
		}
		slog.ErrorContext(ctx, "lockout: record failure", "error", err)
	}
}

// RecordSuccess resets the failure count for an email.
func (m *lockoutManager) RecordSuccess(ctx context.Context, email string) {
	email = strings.ToLower(email)

	if err := m.store.RecordLoginSuccess(ctx, email); err != nil {
		slog.ErrorContext(ctx, "lockout: record success", "error", err)
	}
}
