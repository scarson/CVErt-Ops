// ABOUTME: Regression tests for feed utility bug fixes: ParseTime RFC1123 and ResolveCanonicalID determinism.
// ABOUTME: These tests validate fixes for Phase 1 bugs #6 and #9.
package feed

import (
	"testing"
	"time"
)

// ── ParseTime RFC1123 ─────────────────────────────────────────────────────────

func TestParseTimeRFC1123(t *testing.T) {
	t.Parallel()

	// Some upstream feeds use RFC1123 timestamps (e.g., "Mon, 02 Jan 2006 15:04:05 MST").
	got := ParseTime("Mon, 15 Mar 2024 10:30:00 UTC")
	if got.IsZero() {
		t.Fatal("ParseTime(RFC1123) returned zero time")
	}
	want := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ParseTime(RFC1123) = %v, want %v", got, want)
	}
}

func TestParseTimeRFC1123Z(t *testing.T) {
	t.Parallel()

	// RFC1123Z uses numeric timezone offset instead of zone name.
	got := ParseTime("Fri, 15 Mar 2024 10:30:00 +0000")
	if got.IsZero() {
		t.Fatal("ParseTime(RFC1123Z) returned zero time")
	}
	if got.Year() != 2024 || got.Month() != 3 || got.Day() != 15 {
		t.Errorf("ParseTime(RFC1123Z) = %v: wrong date", got)
	}
}

// ── ResolveCanonicalID determinism ────────────────────────────────────────────

func TestResolveCanonicalIDDeterministic(t *testing.T) {
	t.Parallel()

	// When multiple CVE aliases exist, the result must be deterministic
	// regardless of the order they appear in the input slice.
	aliasesA := []string{"PYSEC-1", "CVE-2024-99999", "CVE-2024-00001"}
	aliasesB := []string{"CVE-2024-00001", "PYSEC-1", "CVE-2024-99999"}

	gotA := ResolveCanonicalID("GHSA-xxxx", aliasesA)
	gotB := ResolveCanonicalID("GHSA-xxxx", aliasesB)

	if gotA != gotB {
		t.Errorf("ResolveCanonicalID non-deterministic: aliasesA=%q aliasesB=%q", gotA, gotB)
	}
	// Should pick the lexicographically smallest CVE ID.
	if gotA != "CVE-2024-00001" {
		t.Errorf("ResolveCanonicalID = %q, want CVE-2024-00001 (lexicographically first)", gotA)
	}
}
