// ABOUTME: Async, non-blocking security event writer for the security event pipeline.
// ABOUTME: Rate-limits by (event_type, actor_ip) and writes via bounded goroutine pool.
package secure

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/metrics"
	"github.com/scarson/cvert-ops/internal/store"
)

const (
	// writerConcurrency is the maximum number of concurrent DB write goroutines.
	writerConcurrency = 50

	// writerTimeout caps how long a single event write can take.
	writerTimeout = 10 * time.Second

	// stopTimeout caps how long Stop waits for in-flight writes to drain.
	stopTimeout = 10 * time.Second
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
// logged via slog and never propagated to callers. When a SyslogWriter is
// configured, events are also forwarded to a remote syslog endpoint.
type EventWriter struct {
	store       *store.Store
	rateLimiter *eventRateLimiter
	syslog      atomic.Pointer[SyslogWriter]
	wg          sync.WaitGroup
	sem         chan struct{}
}

// NewEventWriter creates an EventWriter with default rate limiting:
// 10 events per minute per (event_type, actor_ip), 5-minute TTL for stale entries.
func NewEventWriter(s *store.Store) *EventWriter {
	return &EventWriter{
		store:       s,
		rateLimiter: newEventRateLimiter(10, time.Minute, 5*time.Minute, nil),
		sem:         make(chan struct{}, writerConcurrency),
	}
}

// SetSyslog attaches an optional SyslogWriter. When set, non-rate-limited
// events are forwarded to the syslog endpoint in addition to the database.
// Safe for concurrent use with Write.
func (w *EventWriter) SetSyslog(sw *SyslogWriter) {
	w.syslog.Store(sw)
}

// Write records a security event asynchronously. If the rate limit for the
// event's (type, actor_ip) key is exceeded, the event is dropped with a log
// message. If all concurrency slots are occupied, the event is dropped.
// Write errors are logged, never returned or panicked.
func (w *EventWriter) Write(ctx context.Context, event Event) {
	key := event.Type + "|" + event.ActorIP
	if !w.rateLimiter.Allow(key) {
		slog.Warn("security event rate limited",
			"event_type", event.Type,
			"actor_ip", event.ActorIP,
		)
		metrics.SecurityEventsDropped.Inc()
		return
	}

	// Acquire a concurrency slot; drop the event if all slots are busy.
	select {
	case w.sem <- struct{}{}:
		// Got a slot.
	default:
		slog.Warn("security event writer at capacity, dropping event",
			"event_type", event.Type)
		metrics.SecurityEventsDropped.Inc()
		return
	}

	// Detach from request context so the goroutine survives handler return.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writerTimeout)

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		defer func() { <-w.sem }()
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("security event writer panic", "recover", r)
			}
		}()

		err := w.store.InsertSecurityEvent(writeCtx, store.InsertSecurityEventParams{
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
			metrics.SecurityEventsWriteFailed.Inc()
		} else {
			metrics.SecurityEventsTotal.WithLabelValues(event.Type, event.Severity).Inc()
		}

		// Forward to syslog independently of DB result.
		if sw := w.syslog.Load(); sw != nil {
			if sErr := sw.Send(event); sErr != nil {
				slog.Error("security event syslog send failed",
					"event_type", event.Type,
					"error", sErr,
				)
			}
		}
	}()
}

// Stop stops the rate limiter eviction goroutine, waits for all pending
// writes to complete (with a timeout), and closes the syslog connection
// if configured.
func (w *EventWriter) Stop() {
	w.rateLimiter.Stop()

	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		// All writes drained.
	case <-time.After(stopTimeout):
		slog.Warn("security event writer: timed out waiting for pending writes")
	}

	if sw := w.syslog.Load(); sw != nil {
		if err := sw.Close(); err != nil {
			slog.Error("syslog close failed", "error", err)
		}
	}
}
