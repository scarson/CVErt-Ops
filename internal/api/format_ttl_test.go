// ABOUTME: Unit tests for formatTTL duration-to-human-readable conversion.
// ABOUTME: Covers edge cases: zero, sub-minute, minutes, hours, days, and multi-day durations.
package api

import (
	"testing"
	"time"
)

func TestFormatTTL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"zero", 0, "0 minutes"},
		{"sub_minute", 30 * time.Second, "0 minutes"},
		{"one_minute", 1 * time.Minute, "1 minute"},
		{"45_minutes", 45 * time.Minute, "45 minutes"},
		{"one_hour", 1 * time.Hour, "1 hour"},
		{"two_hours", 2 * time.Hour, "2 hours"},
		{"90_minutes", 90 * time.Minute, "1 hour"},
		{"one_day", 24 * time.Hour, "1 day"},
		{"two_days", 48 * time.Hour, "2 days"},
		{"seven_days", 7 * 24 * time.Hour, "7 days"},
		{"36_hours", 36 * time.Hour, "36 hours"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatTTL(tt.d)
			if got != tt.want {
				t.Errorf("formatTTL(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}
