// ABOUTME: Tests for per-feed circuit breaker behavior.
// ABOUTME: Verifies open-after-failures, half-open probe, and close-on-success transitions.
package feed

import (
	"errors"
	"testing"
	"time"

	"github.com/sony/gobreaker/v2"
)

func TestBreaker_OpensAfterConsecutiveFailures(t *testing.T) {
	t.Parallel()

	cb := NewBreaker("test-feed", 3, 100*time.Millisecond)
	testErr := errors.New("upstream error")

	// 3 consecutive failures should open the breaker.
	for i := 0; i < 3; i++ {
		_, _ = cb.Execute(func() (struct{}, error) {
			return struct{}{}, testErr
		})
	}

	// Next call should get ErrOpenState.
	_, err := cb.Execute(func() (struct{}, error) {
		return struct{}{}, nil
	})
	if !errors.Is(err, gobreaker.ErrOpenState) {
		t.Errorf("expected ErrOpenState after 3 failures, got: %v", err)
	}
}

func TestBreaker_HalfOpenAllowsProbe(t *testing.T) {
	t.Parallel()

	cb := NewBreaker("test-feed-probe", 2, 50*time.Millisecond)
	testErr := errors.New("upstream error")

	// Trip the breaker.
	for i := 0; i < 2; i++ {
		_, _ = cb.Execute(func() (struct{}, error) {
			return struct{}{}, testErr
		})
	}

	// Wait for timeout to enter half-open.
	time.Sleep(100 * time.Millisecond)

	// The probe request should succeed and close the breaker.
	_, err := cb.Execute(func() (struct{}, error) {
		return struct{}{}, nil
	})
	if err != nil {
		t.Errorf("expected probe to succeed in half-open state, got: %v", err)
	}

	// Subsequent calls should also succeed (breaker is closed again).
	_, err = cb.Execute(func() (struct{}, error) {
		return struct{}{}, nil
	})
	if err != nil {
		t.Errorf("expected success after breaker closed, got: %v", err)
	}
}

func TestBreaker_SuccessDoesNotTrip(t *testing.T) {
	t.Parallel()

	cb := NewBreaker("test-feed-ok", 3, 100*time.Millisecond)

	// 10 successful calls should not trip the breaker.
	for i := 0; i < 10; i++ {
		_, err := cb.Execute(func() (struct{}, error) {
			return struct{}{}, nil
		})
		if err != nil {
			t.Fatalf("unexpected error on call %d: %v", i, err)
		}
	}
}
