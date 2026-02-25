package feed

import (
	"testing"
	"time"
)

// ── ParseTime ─────────────────────────────────────────────────────────────────

func TestParseTimeRFC3339Nano(t *testing.T) {
	t.Parallel()

	got := ParseTime("2024-03-15T10:30:00.123456789Z")
	want := time.Date(2024, 3, 15, 10, 30, 0, 123456789, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ParseTime(RFC3339Nano) = %v, want %v", got, want)
	}
}

func TestParseTimeRFC3339(t *testing.T) {
	t.Parallel()

	got := ParseTime("2024-03-15T10:30:00Z")
	want := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ParseTime(RFC3339) = %v, want %v", got, want)
	}
}

func TestParseTimeNoTimezone(t *testing.T) {
	t.Parallel()

	// Feeds sometimes omit the timezone suffix; we must still parse it.
	got := ParseTime("2024-03-15T10:30:00")
	if got.IsZero() {
		t.Fatal("ParseTime(no-tz) returned zero time")
	}
	if got.Year() != 2024 || got.Month() != 3 || got.Day() != 15 {
		t.Errorf("ParseTime(no-tz) = %v: wrong date", got)
	}
}

func TestParseTimeDateOnly(t *testing.T) {
	t.Parallel()

	got := ParseTime("2024-03-15")
	if got.IsZero() {
		t.Fatal("ParseTime(date-only) returned zero time")
	}
	if got.Year() != 2024 || got.Month() != 3 || got.Day() != 15 {
		t.Errorf("ParseTime(date-only) = %v: wrong date", got)
	}
}

func TestParseTimeInvalidReturnsZero(t *testing.T) {
	t.Parallel()

	got := ParseTime("not-a-date")
	if !got.IsZero() {
		t.Errorf("ParseTime(invalid) = %v, want zero", got)
	}
}

func TestParseTimeEmptyReturnsZero(t *testing.T) {
	t.Parallel()

	got := ParseTime("")
	if !got.IsZero() {
		t.Errorf("ParseTime(\"\") = %v, want zero", got)
	}
}

func TestParseTimeReturnsUTC(t *testing.T) {
	t.Parallel()

	got := ParseTime("2024-03-15T10:30:00Z")
	if got.Location() != time.UTC {
		t.Errorf("ParseTime returned location %v, want UTC", got.Location())
	}
}

// ── ParseTimePtr ──────────────────────────────────────────────────────────────

func TestParseTimePtrNilOnEmpty(t *testing.T) {
	t.Parallel()

	if got := ParseTimePtr(""); got != nil {
		t.Errorf("ParseTimePtr(\"\") = %v, want nil", got)
	}
}

func TestParseTimePtrNilOnInvalid(t *testing.T) {
	t.Parallel()

	if got := ParseTimePtr("not-a-date"); got != nil {
		t.Errorf("ParseTimePtr(invalid) = %v, want nil", got)
	}
}

func TestParseTimePtrNonNilOnValid(t *testing.T) {
	t.Parallel()

	got := ParseTimePtr("2024-03-15T10:30:00Z")
	if got == nil {
		t.Fatal("ParseTimePtr(valid) = nil, want non-nil")
	}
	if got.Year() != 2024 {
		t.Errorf("ParseTimePtr year = %d, want 2024", got.Year())
	}
}

// ── StripNullBytes ────────────────────────────────────────────────────────────

func TestStripNullBytesRemovesNulls(t *testing.T) {
	t.Parallel()

	input := "hello\x00world\x00"
	got := StripNullBytes(input)
	want := "helloworld"
	if got != want {
		t.Errorf("StripNullBytes(%q) = %q, want %q", input, got, want)
	}
}

func TestStripNullBytesNoOpOnCleanString(t *testing.T) {
	t.Parallel()

	input := "no null bytes here"
	if got := StripNullBytes(input); got != input {
		t.Errorf("StripNullBytes(%q) = %q, want unchanged", input, got)
	}
}

func TestStripNullBytesJSONRemovesNulls(t *testing.T) {
	t.Parallel()

	input := []byte(`{"k":"v` + "\x00" + `alue"}`)
	got := StripNullBytesJSON(input)
	for _, b := range got {
		if b == 0 {
			t.Errorf("StripNullBytesJSON left a null byte in output")
		}
	}
}

// ── ResolveCanonicalID ────────────────────────────────────────────────────────

func TestResolveCanonicalIDReturnsAlias(t *testing.T) {
	t.Parallel()

	// GHSA record with a CVE alias — CVE ID should be returned.
	got := ResolveCanonicalID("GHSA-1234-5678-9012", []string{"CVE-2024-12345"})
	if got != "CVE-2024-12345" {
		t.Errorf("ResolveCanonicalID = %q, want %q", got, "CVE-2024-12345")
	}
}

func TestResolveCanonicalIDNoAlias(t *testing.T) {
	t.Parallel()

	// No CVE alias: native ID is returned unchanged.
	got := ResolveCanonicalID("GHSA-1234-5678-9012", []string{"PYSEC-2024-123"})
	if got != "GHSA-1234-5678-9012" {
		t.Errorf("ResolveCanonicalID = %q, want %q", got, "GHSA-1234-5678-9012")
	}
}

func TestResolveCanonicalIDEmptyAliases(t *testing.T) {
	t.Parallel()

	got := ResolveCanonicalID("GHSA-1234-5678-9012", nil)
	if got != "GHSA-1234-5678-9012" {
		t.Errorf("ResolveCanonicalID(nil aliases) = %q, want native ID", got)
	}
}

func TestResolveCanonicalIDFirstCVEAlias(t *testing.T) {
	t.Parallel()

	// Multiple aliases; the first CVE match should be returned.
	got := ResolveCanonicalID("GHSA-xxxx", []string{"PYSEC-1", "CVE-2024-00001", "CVE-2024-00002"})
	if got != "CVE-2024-00001" {
		t.Errorf("ResolveCanonicalID = %q, want first CVE alias", got)
	}
}

func TestResolveCanonicalIDNativeIsAlreadyCVE(t *testing.T) {
	t.Parallel()

	// When the native ID is itself a CVE ID, still check aliases for the
	// canonical form — but if none found, return nativeID.
	got := ResolveCanonicalID("CVE-2024-99999", []string{"GHSA-xxxx"})
	if got != "CVE-2024-99999" {
		t.Errorf("ResolveCanonicalID = %q, want native CVE ID", got)
	}
}
