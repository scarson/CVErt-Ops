// ABOUTME: Tests for the scheduler bridge — cron-to-interval conversion and entry building.
// ABOUTME: Verifies cronToInterval handles common patterns and ScheduleEntries filters correctly.
package generic

import (
	"testing"
	"time"
)

func TestCronToInterval(t *testing.T) {
	t.Parallel()
	tests := []struct {
		cron string
		want time.Duration
	}{
		{"*/30 * * * *", 30 * time.Minute},
		{"*/5 * * * *", 5 * time.Minute},
		{"0 */4 * * *", 4 * time.Hour},
		{"0 */1 * * *", 1 * time.Hour},
		{"0 0 * * *", 24 * time.Hour},
		{"30 2 * * *", 24 * time.Hour},   // fixed time → daily
		{"0 0 * * 1", 24 * time.Hour},    // weekly → defaults to daily
		{"", 24 * time.Hour},             // empty → default
		{"bad", 24 * time.Hour},          // invalid → default
	}
	for _, tc := range tests {
		got := cronToInterval(tc.cron)
		if got != tc.want {
			t.Errorf("cronToInterval(%q) = %v, want %v", tc.cron, got, tc.want)
		}
	}
}

func TestScheduleEntries_FiltersEmptySchedule(t *testing.T) {
	t.Parallel()
	configs := []Config{
		{Name: "feed-a", Schedule: "0 */6 * * *"},
		{Name: "feed-b", Schedule: ""},         // no schedule → skipped
		{Name: "feed-c", Schedule: "*/15 * * * *"},
	}
	entries := ScheduleEntries(configs)
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	if entries[0].FeedName != "feed-a" {
		t.Errorf("entry[0].FeedName = %q, want feed-a", entries[0].FeedName)
	}
	if entries[0].Interval != 6*time.Hour {
		t.Errorf("entry[0].Interval = %v, want 6h", entries[0].Interval)
	}
	if entries[1].FeedName != "feed-c" {
		t.Errorf("entry[1].FeedName = %q, want feed-c", entries[1].FeedName)
	}
	if entries[1].Interval != 15*time.Minute {
		t.Errorf("entry[1].Interval = %v, want 15m", entries[1].Interval)
	}
}

func TestAdapterFactory_GenericOverride(t *testing.T) {
	t.Parallel()
	configs := []Config{
		{Name: "my-scanner", URL: "http://example.com", Format: "json",
			Mapping: MappingConfig{Root: "items", Fields: map[string]string{"cve_id": "id"}}},
	}
	factory := AdapterFactory(configs)

	// Generic feed → returns a generic adapter (no error).
	adapter, err := factory("my-scanner", nil)
	if err != nil {
		t.Fatalf("factory(my-scanner): %v", err)
	}
	if adapter == nil {
		t.Fatal("factory(my-scanner) returned nil adapter")
	}

	// Built-in feed → delegates to ingest.NewAdapter.
	adapter, err = factory("nvd", nil)
	if err != nil {
		t.Fatalf("factory(nvd): %v", err)
	}
	if adapter == nil {
		t.Fatal("factory(nvd) returned nil adapter")
	}

	// Unknown feed → returns error from built-in factory.
	_, err = factory("nonexistent", nil)
	if err == nil {
		t.Fatal("factory(nonexistent) expected error, got nil")
	}
}
