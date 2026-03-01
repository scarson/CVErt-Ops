// ABOUTME: Unit tests for digest runner helpers: severity expansion, time parsing, scheduling.
// ABOUTME: Pure function tests — no DB or network required.
package notify

import (
	"testing"
	"time"
)

func TestExpandSeverityThreshold(t *testing.T) {
	t.Parallel()
	cases := []struct {
		threshold string
		want      []string
	}{
		{"", nil},
		{"critical", []string{"critical"}},
		{"high", []string{"critical", "high"}},
		{"medium", []string{"critical", "high", "medium"}},
		{"low", []string{"critical", "high", "low", "medium"}},
		{"unknown", nil}, // unknown threshold returns nil (not in severityRank map)
	}
	for _, tc := range cases {
		t.Run(tc.threshold, func(t *testing.T) {
			got := expandSeverityThreshold(tc.threshold)
			if tc.want == nil {
				if got != nil {
					t.Errorf("expandSeverityThreshold(%q) = %v, want nil", tc.threshold, got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("expandSeverityThreshold(%q) = %v, want %v", tc.threshold, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("expandSeverityThreshold(%q)[%d] = %q, want %q", tc.threshold, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestParseTimeOfDay(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input   string
		h, m, s int
		wantErr bool
	}{
		{"09:00", 9, 0, 0, false},
		{"14:30:15", 14, 30, 15, false},
		{"00:00:00", 0, 0, 0, false},
		{"23:59:59", 23, 59, 59, false},
		{"bad", 0, 0, 0, true},
		{"25:00", 0, 0, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			h, m, s, err := parseTimeOfDay(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("parseTimeOfDay(%q) = (%d,%d,%d,nil), want error", tc.input, h, m, s)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTimeOfDay(%q) error: %v", tc.input, err)
			}
			if h != tc.h || m != tc.m || s != tc.s {
				t.Errorf("parseTimeOfDay(%q) = (%d,%d,%d), want (%d,%d,%d)", tc.input, h, m, s, tc.h, tc.m, tc.s)
			}
		})
	}
}

func TestAdvanceNextRunAt(t *testing.T) {
	t.Parallel()
	// Advance from 2025-03-08 14:00 EST (day before spring-forward).
	// The next day (March 9) at 14:00 is EDT (UTC-4), so UTC = 18:00.
	// This verifies AddDate handles the DST transition (not Add(24h) which gives 15:00 EDT).
	loc, _ := time.LoadLocation("America/New_York")
	base := time.Date(2025, 3, 8, 14, 0, 0, 0, loc).UTC() // 19:00 UTC (EST = UTC-5)

	next, err := advanceNextRunAt(base, "America/New_York")
	if err != nil {
		t.Fatalf("advanceNextRunAt: %v", err)
	}
	// March 9 14:00 EDT = 18:00 UTC (EDT = UTC-4, one hour less than EST).
	expected := time.Date(2025, 3, 9, 18, 0, 0, 0, time.UTC)
	if !next.Equal(expected) {
		t.Errorf("advanceNextRunAt DST = %v, want %v", next, expected)
	}

	// Regular non-DST day.
	regularBase := time.Date(2025, 6, 15, 14, 0, 0, 0, time.UTC)
	regularNext, err := advanceNextRunAt(regularBase, "UTC")
	if err != nil {
		t.Fatalf("advanceNextRunAt (regular): %v", err)
	}
	expectedRegular := time.Date(2025, 6, 16, 14, 0, 0, 0, time.UTC)
	if !regularNext.Equal(expectedRegular) {
		t.Errorf("advanceNextRunAt regular = %v, want %v", regularNext, expectedRegular)
	}
}

func TestComputeNextRunAt(t *testing.T) {
	t.Parallel()
	// Depends on time.Now() so we can only test basic properties:
	// - Result is in the future
	// - Invalid timezone returns error
	// - Invalid time format returns error

	next, err := ComputeNextRunAt("09:00:00", "America/New_York")
	if err != nil {
		t.Fatalf("ComputeNextRunAt: %v", err)
	}
	if !next.After(time.Now().Add(-1 * time.Second)) {
		t.Errorf("ComputeNextRunAt result %v should be in the future", next)
	}

	_, err = ComputeNextRunAt("09:00:00", "Invalid/Timezone")
	if err == nil {
		t.Error("ComputeNextRunAt with invalid timezone should return error")
	}

	_, err = ComputeNextRunAt("bad-time", "UTC")
	if err == nil {
		t.Error("ComputeNextRunAt with invalid time should return error")
	}
}
