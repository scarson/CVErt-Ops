// ABOUTME: Bridges generic feed configs with the ingest scheduler and handler.
// ABOUTME: Converts configs to schedule entries and builds an adapter factory for the worker.
package generic

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/ingest"
)

// ScheduleEntries converts a slice of generic feed configs into scheduler
// entries with intervals derived from their cron expressions.
func ScheduleEntries(configs []Config) []ingest.FeedScheduleEntry {
	entries := make([]ingest.FeedScheduleEntry, 0, len(configs))
	for _, cfg := range configs {
		if cfg.Schedule == "" {
			continue // no schedule means manual/webhook-only
		}
		entries = append(entries, ingest.FeedScheduleEntry{
			FeedName: cfg.Name,
			Queue:    "feed_ingest",
			Interval: cronToInterval(cfg.Schedule),
		})
	}
	return entries
}

// AdapterFactory returns an ingest.AdapterFactory that creates generic adapters
// for known generic feed names, falling back to the built-in factory for others.
func AdapterFactory(configs []Config) ingest.AdapterFactory {
	byName := make(map[string]*Config, len(configs))
	for i := range configs {
		byName[configs[i].Name] = &configs[i]
	}
	return func(feedName string, client *http.Client) (feed.Adapter, error) {
		if cfg, ok := byName[feedName]; ok {
			return NewAdapter(cfg, client), nil
		}
		return ingest.NewAdapter(feedName, client)
	}
}

// cronToInterval converts common cron expressions to a rough interval for the
// scheduler's interval-based timing model. Handles:
//   - "*/N * * * *" → N minutes
//   - "0 */N * * *" → N hours
//   - "0 0 * * *"   → 24 hours
//
// Defaults to 24 hours for complex expressions that don't match common patterns.
func cronToInterval(expr string) time.Duration {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return 24 * time.Hour
	}

	minute, hour := fields[0], fields[1]

	// "*/N * * * *" → every N minutes.
	if strings.HasPrefix(minute, "*/") {
		if n, err := strconv.Atoi(minute[2:]); err == nil && n > 0 {
			return time.Duration(n) * time.Minute
		}
	}

	// "0 */N * * *" → every N hours.
	if minute == "0" && strings.HasPrefix(hour, "*/") {
		if n, err := strconv.Atoi(hour[2:]); err == nil && n > 0 {
			return time.Duration(n) * time.Hour
		}
	}

	// "0 0 * * *" → daily.
	if minute == "0" && hour == "0" {
		return 24 * time.Hour
	}

	// "N M * * *" → fixed time, assume daily.
	if _, errM := strconv.Atoi(minute); errM == nil {
		if _, errH := strconv.Atoi(hour); errH == nil {
			return 24 * time.Hour
		}
	}

	return 24 * time.Hour
}

