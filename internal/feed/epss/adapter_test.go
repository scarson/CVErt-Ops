package epss

import (
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
)

// TestParseLine1 verifies that model_version and score_date are correctly
// extracted from the EPSS CSV comment line. score_date is a full RFC3339
// timestamp, not just a date (verified 2026-02-25 against live feed).
func TestParseLine1(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		input         string
		wantModel     string
		wantScoreDate string
		wantErr       bool
	}{
		{
			name:          "canonical format with newline",
			input:         "#model_version:v2025.03.14,score_date:2026-02-25T12:55:00Z\n",
			wantModel:     "v2025.03.14",
			wantScoreDate: "2026-02-25T12:55:00Z",
		},
		{
			name:          "canonical format without newline",
			input:         "#model_version:v2025.03.14,score_date:2026-02-25T12:55:00Z",
			wantModel:     "v2025.03.14",
			wantScoreDate: "2026-02-25T12:55:00Z",
		},
		{
			name:          "windows line endings",
			input:         "#model_version:v2025.03.14,score_date:2026-02-25T12:55:00Z\r\n",
			wantModel:     "v2025.03.14",
			wantScoreDate: "2026-02-25T12:55:00Z",
		},
		{
			name:          "model_version before score_date (standard order)",
			input:         "#model_version:v2024.01.01,score_date:2026-01-01T10:00:00Z",
			wantModel:     "v2024.01.01",
			wantScoreDate: "2026-01-01T10:00:00Z",
		},
		{
			name:    "missing score_date returns error",
			input:   "#model_version:v2025.03.14",
			wantErr: true,
		},
		{
			name:    "empty line returns error",
			input:   "",
			wantErr: true,
		},
		{
			name:          "score_date RFC3339 timestamp preserved — colons in value not lost",
			input:         "#model_version:v2025.03.14,score_date:2026-02-25T12:55:00Z",
			wantScoreDate: "2026-02-25T12:55:00Z",
			// Verify the time value from the timestamp is non-zero when parsed.
			wantModel: "v2025.03.14",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cur, err := parseLine1(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (cursor=%+v)", cur)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cur.ModelVersion != tc.wantModel {
				t.Errorf("model_version = %q, want %q", cur.ModelVersion, tc.wantModel)
			}
			if cur.ScoreDate != tc.wantScoreDate {
				t.Errorf("score_date = %q, want %q", cur.ScoreDate, tc.wantScoreDate)
			}
		})
	}
}

// TestParseLine1ScoreDateIsRFC3339 verifies that the score_date extracted from
// line 1 parses as a valid RFC3339 timestamp with a time component. This guards
// against the stale training-data assumption that score_date is a plain date.
func TestParseLine1ScoreDateIsRFC3339(t *testing.T) {
	t.Parallel()

	line := "#model_version:v2025.03.14,score_date:2026-02-25T12:55:00Z\n"
	cur, err := parseLine1(line)
	if err != nil {
		t.Fatalf("parseLine1: %v", err)
	}

	// feed.ParseTime must be able to parse it.
	parsed := feed.ParseTime(cur.ScoreDate)
	if parsed.IsZero() {
		t.Fatalf("feed.ParseTime(%q) returned zero time", cur.ScoreDate)
	}

	// The time component must be non-zero (i.e. it's not just a date).
	_, m, s := parsed.Clock()
	if m == 0 && s == 0 && parsed.Hour() == 0 {
		t.Errorf("score_date %q parsed as midnight — expected a full RFC3339 timestamp with time", cur.ScoreDate)
	}

	// Confirm the expected UTC date.
	wantDate := time.Date(2026, 2, 25, 0, 0, 0, 0, time.UTC)
	if !parsed.UTC().Truncate(24 * time.Hour).Equal(wantDate) {
		t.Errorf("parsed date = %v, want %v", parsed.UTC().Truncate(24*time.Hour), wantDate)
	}
}

// TestAdapterRateLimiterNonNil verifies that New always initialises the
// per-adapter rate limiter. A nil limiter would panic on Wait.
func TestAdapterRateLimiterNonNil(t *testing.T) {
	t.Parallel()

	a := New(nil)
	if a == nil {
		t.Fatal("New returned nil")
	}
	if a.rateLimiter == nil {
		t.Fatal("rateLimiter is nil — adapter would panic on Apply")
	}
	if a.client == nil {
		t.Fatal("client is nil — adapter would panic on Apply")
	}
}

// TestNullByteStripping verifies that CVE IDs containing null bytes are cleaned
// before being written to the database (Postgres TEXT rejects \x00).
func TestNullByteStripping(t *testing.T) {
	t.Parallel()

	dirty := "CVE-2024-1234\x005"
	cleaned := feed.StripNullBytes(dirty)
	want := "CVE-2024-12345"
	if cleaned != want {
		t.Errorf("StripNullBytes(%q) = %q, want %q", dirty, cleaned, want)
	}

	// Null-only input should become empty — adapter skips empty CVE IDs.
	empty := feed.StripNullBytes("\x00\x00")
	if empty != "" {
		t.Errorf("StripNullBytes all-null = %q, want empty", empty)
	}
}
