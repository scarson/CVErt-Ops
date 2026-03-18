// ABOUTME: Per-feed circuit breaker using sony/gobreaker to prevent cascading failures.
// ABOUTME: Opens after consecutive failures, allows a probe after timeout, closes on success.
package feed

import (
	"log/slog"
	"time"

	"github.com/sony/gobreaker/v2"

	"github.com/scarson/cvert-ops/internal/metrics"
)

// DefaultBreakerFailures is the number of consecutive failures before the breaker opens.
const DefaultBreakerFailures = 5

// DefaultBreakerTimeout is how long the breaker stays open before allowing a probe.
const DefaultBreakerTimeout = 5 * time.Minute

// NewBreaker creates a circuit breaker for a feed adapter. Opens after
// consecutiveFailures consecutive failures. Stays open for timeout before
// allowing a single probe request (half-open). A successful probe closes
// the breaker. The constructor does NOT make any network calls.
func NewBreaker(name string, consecutiveFailures uint32, timeout time.Duration) *gobreaker.CircuitBreaker[struct{}] {
	return gobreaker.NewCircuitBreaker[struct{}](gobreaker.Settings{
		Name: name,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= consecutiveFailures
		},
		Timeout: timeout,
		OnStateChange: func(name string, from, to gobreaker.State) {
			slog.Warn("feed circuit breaker state change",
				"feed", name,
				"from", from.String(),
				"to", to.String(),
			)
			// Map gobreaker state to a numeric gauge: 0=closed, 1=half-open, 2=open.
			var val float64
			switch to {
			case gobreaker.StateClosed:
				val = 0
			case gobreaker.StateHalfOpen:
				val = 1
			case gobreaker.StateOpen:
				val = 2
			}
			metrics.FeedCircuitBreakerState.WithLabelValues(name).Set(val)
		},
	})
}
