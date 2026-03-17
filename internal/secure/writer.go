// ABOUTME: Async, non-blocking security event writer for the security event pipeline.
// ABOUTME: Rate-limits by (event_type, actor_ip) and writes via fire-and-forget goroutines.
package secure

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
)

// Event represents a security event to be recorded.
type Event struct {
	Type       string
	Severity   string
	ActorIP    string
	ActorEmail string
	UserID     *uuid.UUID
	OrgID      *uuid.UUID
	Details    map[string]any
}

// EventWriter writes security events asynchronously. Write failures are
// logged via slog and never propagated to callers.
type EventWriter struct {
	store       *store.Store
	rateLimiter *eventRateLimiter
	wg          sync.WaitGroup
}

// NewEventWriter creates an EventWriter with default rate limiting:
// 10 events per minute per (event_type, actor_ip), 5-minute TTL for stale entries.
func NewEventWriter(s *store.Store) *EventWriter {
	return &EventWriter{
		store:       s,
		rateLimiter: newEventRateLimiter(10, time.Minute, 5*time.Minute, nil),
	}
}

// Write records a security event asynchronously. If the rate limit for the
// event's (type, actor_ip) key is exceeded, the event is dropped with a log
// message. Write errors are logged, never returned or panicked.
func (w *EventWriter) Write(ctx context.Context, event Event) {
	key := event.Type + "|" + event.ActorIP
	if !w.rateLimiter.Allow(key) {
		slog.Warn("security event rate limited",
			"event_type", event.Type,
			"actor_ip", event.ActorIP,
		)
		return
	}

	// Detach from request context so the goroutine survives handler return.
	ctx = context.WithoutCancel(ctx)

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("security event writer panic", "recover", r)
			}
		}()

		err := w.store.InsertSecurityEvent(ctx, store.InsertSecurityEventParams{
			EventType:  event.Type,
			Severity:   event.Severity,
			ActorIP:    event.ActorIP,
			ActorEmail: event.ActorEmail,
			UserID:     event.UserID,
			OrgID:      event.OrgID,
			Details:    event.Details,
		})
		if err != nil {
			slog.Error("security event write failed",
				"event_type", event.Type,
				"error", err,
			)
		}
	}()
}

// Stop stops the rate limiter eviction goroutine and waits for all pending
// writes to complete.
func (w *EventWriter) Stop() {
	w.rateLimiter.Stop()
	w.wg.Wait()
}
