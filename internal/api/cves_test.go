package api

import (
	"testing"
	"time"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// ── cursor encode/decode ──────────────────────────────────────────────────────

func TestCursorRoundTrip(t *testing.T) {
	t.Parallel()

	// Build a synthetic Cfe row with a known date and ID.
	ts := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	row := generated.Cfe{
		CveID:                 "CVE-2024-99999",
		DateModifiedCanonical: ts,
	}

	encoded := encodeCursor(row)
	if encoded == "" {
		t.Fatal("encodeCursor returned empty string")
	}

	decoded, err := decodeCursor(encoded)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if decoded == nil {
		t.Fatal("decodeCursor returned nil")
	}
	if decoded.CVEID != "CVE-2024-99999" {
		t.Errorf("CVEID = %q, want %q", decoded.CVEID, "CVE-2024-99999")
	}

	// SortDate must round-trip back to the same instant.
	parsed, err := time.Parse(time.RFC3339Nano, decoded.SortDate)
	if err != nil {
		t.Fatalf("parse SortDate %q: %v", decoded.SortDate, err)
	}
	if !parsed.UTC().Equal(ts) {
		t.Errorf("SortDate round-trip: got %v, want %v", parsed.UTC(), ts)
	}
}

func TestDecodeCursorEmpty(t *testing.T) {
	t.Parallel()

	cur, err := decodeCursor("")
	if err != nil {
		t.Fatalf("decodeCursor(\"\") should return nil,nil; got error %v", err)
	}
	if cur != nil {
		t.Errorf("decodeCursor(\"\") = %+v, want nil", cur)
	}
}

func TestDecodeCursorInvalidBase64(t *testing.T) {
	t.Parallel()

	_, err := decodeCursor("!!!not-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

func TestDecodeCursorMissingCVEID(t *testing.T) {
	t.Parallel()

	// Valid base64 of JSON with no cve_id.
	_, err := decodeCursor("e30") // base64url of "{}"
	if err == nil {
		t.Error("expected error for cursor missing cve_id, got nil")
	}
}

// ── nilIfEmpty ────────────────────────────────────────────────────────────────

func TestNilIfEmpty(t *testing.T) {
	t.Parallel()

	if got := nilIfEmpty(""); got != nil {
		t.Errorf("nilIfEmpty(\"\") = %v, want nil", got)
	}

	s := "hello"
	got := nilIfEmpty(s)
	if got == nil {
		t.Fatal("nilIfEmpty(non-empty) returned nil")
	}
	if *got != s {
		t.Errorf("nilIfEmpty(%q) = %q, want %q", s, *got, s)
	}
}

// ── parseQueryDate ────────────────────────────────────────────────────────────

func TestParseQueryDate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantNil bool
		wantUTC time.Time
	}{
		{
			name:    "RFC3339",
			input:   "2026-02-25T12:00:00Z",
			wantUTC: time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC),
		},
		{
			name:    "date only",
			input:   "2026-02-25",
			wantUTC: time.Date(2026, 2, 25, 0, 0, 0, 0, time.UTC),
		},
		{
			name:    "invalid",
			input:   "not-a-date",
			wantNil: true,
		},
		{
			name:    "empty",
			input:   "",
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseQueryDate(tc.input)
			if tc.wantNil {
				if got != nil {
					t.Errorf("parseQueryDate(%q) = %v, want nil", tc.input, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("parseQueryDate(%q) = nil, want %v", tc.input, tc.wantUTC)
			}
			if !got.UTC().Equal(tc.wantUTC) {
				t.Errorf("parseQueryDate(%q) = %v, want %v", tc.input, got.UTC(), tc.wantUTC)
			}
		})
	}
}

// ── ListCVEsInput.resolveOptionalFilters ─────────────────────────────────────

// TestResolveOptionalFilters tests the filter parsing logic directly via the
// internal helper, avoiding the need to implement the full huma.Context interface.
func TestResolveOptionalFilters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		params      map[string]string
		wantErrs    int
		wantCVSSMin *float64
		wantCVSSMax *float64
		wantEPSSMin *float64
		wantEPSSMax *float64
		wantKEV     *bool
		wantExploit *bool
	}{
		{
			name:   "all empty — no filters",
			params: map[string]string{},
		},
		{
			name:        "valid cvss_min",
			params:      map[string]string{"cvss_min": "7.5"},
			wantCVSSMin: floatPtr(7.5),
		},
		{
			name:        "cvss_min zero is valid",
			params:      map[string]string{"cvss_min": "0"},
			wantCVSSMin: floatPtr(0),
		},
		{
			name:        "valid epss_max",
			params:      map[string]string{"epss_max": "0.95"},
			wantEPSSMax: floatPtr(0.95),
		},
		{
			name:     "cvss_min out of range",
			params:   map[string]string{"cvss_min": "11"},
			wantErrs: 1,
		},
		{
			name:     "epss_min negative",
			params:   map[string]string{"epss_min": "-0.1"},
			wantErrs: 1,
		},
		{
			name:     "cvss_max not a number",
			params:   map[string]string{"cvss_max": "high"},
			wantErrs: 1,
		},
		{
			name:    "in_cisa_kev true",
			params:  map[string]string{"in_cisa_kev": "true"},
			wantKEV: boolPtr(true),
		},
		{
			name:    "in_cisa_kev false — false is a valid filter value",
			params:  map[string]string{"in_cisa_kev": "false"},
			wantKEV: boolPtr(false),
		},
		{
			name:        "exploit_available true",
			params:      map[string]string{"exploit_available": "true"},
			wantExploit: boolPtr(true),
		},
		{
			name:        "multiple valid params",
			params:      map[string]string{"cvss_min": "5", "cvss_max": "9", "in_cisa_kev": "true"},
			wantCVSSMin: floatPtr(5),
			wantCVSSMax: floatPtr(9),
			wantKEV:     boolPtr(true),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			input := &ListCVEsInput{}
			// Simulate huma binding the string fields.
			input.InCISAKEV = tc.params["in_cisa_kev"]
			input.ExploitAvail = tc.params["exploit_available"]

			queryFn := func(name string) string { return tc.params[name] }
			errs := input.resolveOptionalFilters(queryFn)

			if len(errs) != tc.wantErrs {
				t.Errorf("resolveOptionalFilters errors: got %d, want %d — %v", len(errs), tc.wantErrs, errs)
			}
			if tc.wantErrs > 0 {
				return
			}

			checkFloatPtr(t, "CVSSMin", input.CVSSMin, tc.wantCVSSMin)
			checkFloatPtr(t, "CVSSMax", input.CVSSMax, tc.wantCVSSMax)
			checkFloatPtr(t, "EPSSMin", input.EPSSMin, tc.wantEPSSMin)
			checkFloatPtr(t, "EPSSMax", input.EPSSMax, tc.wantEPSSMax)
			checkBoolPtr(t, "inCISAKEVBool", input.inCISAKEVBool, tc.wantKEV)
			checkBoolPtr(t, "exploitAvailBool", input.exploitAvailBool, tc.wantExploit)
		})
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func floatPtr(f float64) *float64 { return &f }
func boolPtr(b bool) *bool        { return &b }

func checkFloatPtr(t *testing.T, name string, got, want *float64) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Errorf("%s: got %v, want nil", name, *got)
		}
		return
	}
	if got == nil {
		t.Errorf("%s: got nil, want %v", name, *want)
		return
	}
	if *got != *want {
		t.Errorf("%s: got %v, want %v", name, *got, *want)
	}
}

func checkBoolPtr(t *testing.T, name string, got, want *bool) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Errorf("%s: got %v, want nil", name, *got)
		}
		return
	}
	if got == nil {
		t.Errorf("%s: got nil, want %v", name, *want)
		return
	}
	if *got != *want {
		t.Errorf("%s: got %v, want %v", name, *got, *want)
	}
}
