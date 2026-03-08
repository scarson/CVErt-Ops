package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"

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

// TestApply_SameDayCursorSkips verifies that Apply short-circuits when the
// cursor's ScoreDate has the same UTC date as today. No HTTP request or DB
// interaction should occur — the same cursor JSON is returned unchanged.
func TestApply_SameDayCursorSkips(t *testing.T) {
	t.Parallel()

	// Build a cursor with today's date as ScoreDate.
	today := time.Now().UTC()
	scoreDate := today.Format(time.RFC3339)
	cur := Cursor{
		ScoreDate:    scoreDate,
		ModelVersion: "v2025.03.14",
	}
	cursorJSON, err := json.Marshal(cur)
	if err != nil {
		t.Fatalf("marshal cursor: %v", err)
	}

	adapter := New(nil)

	// Pass nil store — the short-circuit path never touches the store or HTTP client.
	result, err := adapter.Apply(context.Background(), nil, cursorJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The returned cursor should be identical to the input (no work done).
	if string(result) != string(cursorJSON) {
		t.Errorf("Apply returned cursor %s, want unchanged %s", string(result), string(cursorJSON))
	}
}

// makeEPSSGzip builds a gzip-compressed EPSS CSV with the given rows.
func makeEPSSGzip(t *testing.T, rows []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	// Line 1: comment with model_version and score_date (yesterday to avoid same-day skip).
	yesterday := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	fmt.Fprintf(gz, "#model_version:v2025.03.14,score_date:%s\n", yesterday) //nolint:errcheck // test helper
	// Line 2: header.
	fmt.Fprintln(gz, "cve,epss,percentile") //nolint:errcheck // test helper
	for _, r := range rows {
		fmt.Fprintln(gz, r) //nolint:errcheck // test helper
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func TestApply_SkipsPoisonRows(t *testing.T) {
	// Not parallel: mutates slog.Default.
	var applied []string

	body := makeEPSSGzip(t, []string{
		"CVE-2024-0001,0.5,0.9",
		"CVE-2024-0002,0.3,0.7", // poison row
		"CVE-2024-0003,0.8,0.95",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(body) //nolint:errcheck,gosec // test helper
	}))
	defer srv.Close()

	// Capture slog output to verify warning is logged.
	var logBuf bytes.Buffer
	origHandler := slog.Default().Handler()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(slog.New(origHandler)) })

	// Route all requests to the test server (Apply uses a hardcoded feedURL constant).
	adapter := &Adapter{
		client:      feed.WrapClientWithUA(&http.Client{Transport: &redirectTransport{target: srv.URL}}),
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
		applyRowFn: func(_ context.Context, _ *sql.DB, cveID string, _ float64, _ time.Time) error {
			if cveID == "CVE-2024-0002" {
				return fmt.Errorf("simulated DB error")
			}
			applied = append(applied, cveID)
			return nil
		},
	}

	result, err := adapter.Apply(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("Apply should succeed despite poison row, got: %v", err)
	}

	// Verify cursor was returned.
	if len(result) == 0 {
		t.Fatal("expected non-empty cursor")
	}

	// Verify rows 1 and 3 were applied, but not 2.
	if len(applied) != 2 {
		t.Fatalf("applied %d rows, want 2", len(applied))
	}
	if applied[0] != "CVE-2024-0001" || applied[1] != "CVE-2024-0003" {
		t.Errorf("applied = %v, want [CVE-2024-0001 CVE-2024-0003]", applied)
	}

	// Verify warning was logged.
	if !strings.Contains(logBuf.String(), "skipping row with DB error") {
		t.Errorf("expected warning log about skipping row, got: %s", logBuf.String())
	}
}

// redirectTransport routes all requests to the given target URL.
type redirectTransport struct {
	target string
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newReq := req.Clone(req.Context())
	newReq.URL.Scheme = "http"
	newReq.URL.Host = strings.TrimPrefix(t.target, "http://")
	return http.DefaultTransport.RoundTrip(newReq) //nolint:gosec // G704: test URL
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
