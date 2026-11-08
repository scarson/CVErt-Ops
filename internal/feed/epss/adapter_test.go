package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

// captureWarnings routes slog warnings to the returned buffer until the test
// ends. It replaces the global logger, so the calling test must not be parallel.
func captureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	origHandler := slog.Default().Handler()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(slog.New(origHandler)) })
	return &buf
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
	logBuf := captureWarnings(t)

	// Route all requests to the test server (Apply uses a hardcoded feedURL constant).
	// The batch holding the poison row fails, so its rows are applied one at a time.
	adapter := &Adapter{
		client:      feed.WrapClientWithUA(&http.Client{Transport: &redirectTransport{target: srv.URL}}),
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
		batchSize:   3,
		applyBatchFn: func(_ context.Context, _ *sql.DB, _ []scoreRow, _ time.Time) error {
			return fmt.Errorf("simulated DB error")
		},
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

// A row that fails because the job context ended is not a poison row. The run
// must report the interruption, or the handler records a partial run as complete
// and the same-day cursor check skips the remaining rows until the next day's file.
func TestApply_ContextEndsDuringRows_ReturnsError(t *testing.T) {
	var attempted []string

	body := makeEPSSGzip(t, []string{
		"CVE-2024-0001,0.5,0.9",
		"CVE-2024-0002,0.3,0.7",
		"CVE-2024-0003,0.8,0.95",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(body) //nolint:errcheck,gosec // test helper
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	adapter := &Adapter{
		client:      feed.WrapClientWithUA(&http.Client{Transport: &redirectTransport{target: srv.URL}}),
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
		batchSize:   1,
		applyBatchFn: func(ctx context.Context, _ *sql.DB, rows []scoreRow, _ time.Time) error {
			attempted = append(attempted, rows[0].cveID)
			if rows[0].cveID == "CVE-2024-0002" {
				cancel()
				return ctx.Err()
			}
			return nil
		},
		applyRowFn: func(_ context.Context, _ *sql.DB, cveID string, _ float64, _ time.Time) error {
			t.Errorf("row %s applied one at a time after the context ended", cveID)
			return nil
		},
	}

	result, err := adapter.Apply(ctx, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply error = %v, want context.Canceled", err)
	}
	if result != nil {
		t.Errorf("Apply returned cursor %s, want nil for an interrupted run", result)
	}
	if len(attempted) != 2 {
		t.Errorf("attempted rows = %v, want the run to stop at the interrupted row", attempted)
	}
}

// A context that ends while a failed batch is being applied row by row also
// stops the run, rather than skipping each remaining row as a poison row.
func TestApply_ContextEndsDuringRowFallback_ReturnsError(t *testing.T) {
	// Not parallel: mutates slog.Default.
	var attempted []string
	logBuf := captureWarnings(t)

	body := makeEPSSGzip(t, []string{
		"CVE-2024-0001,0.5,0.9",
		"CVE-2024-0002,0.3,0.7",
		"CVE-2024-0003,0.8,0.95",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(body) //nolint:errcheck,gosec // test helper
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	adapter := &Adapter{
		client:      feed.WrapClientWithUA(&http.Client{Transport: &redirectTransport{target: srv.URL}}),
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
		batchSize:   3,
		applyBatchFn: func(_ context.Context, _ *sql.DB, _ []scoreRow, _ time.Time) error {
			return fmt.Errorf("simulated DB error")
		},
		applyRowFn: func(ctx context.Context, _ *sql.DB, cveID string, _ float64, _ time.Time) error {
			attempted = append(attempted, cveID)
			if cveID == "CVE-2024-0002" {
				cancel()
				return ctx.Err()
			}
			return nil
		},
	}

	result, err := adapter.Apply(ctx, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply error = %v, want context.Canceled", err)
	}
	if result != nil {
		t.Errorf("Apply returned cursor %s, want nil for an interrupted run", result)
	}
	if len(attempted) != 2 {
		t.Errorf("attempted rows = %v, want the run to stop at the interrupted row", attempted)
	}
	if !strings.Contains(logBuf.String(), "batch failed; applying its rows one at a time") {
		t.Errorf("expected warning about the failed batch, got: %s", logBuf.String())
	}
	if strings.Contains(logBuf.String(), "skipping row with DB error") {
		t.Errorf("interrupted row was logged as a poison row: %s", logBuf.String())
	}
}

// Apply hands rows to the database in batches of batchSize, in file order, and
// applies a final short batch. Rows that are skipped before the database (an
// empty CVE ID or an unparseable score) are not part of any batch.
func TestApply_AppliesRowsInBatches(t *testing.T) {
	// Not parallel: mutates slog.Default.
	logBuf := captureWarnings(t)

	body := makeEPSSGzip(t, []string{
		"CVE-2024-0001,0.1,0.9",
		"CVE-2024-0002,0.2,0.9",
		",0.5,0.5",
		"CVE-2024-0003,0.3,0.9",
		"CVE-2024-0004,not-a-number,0.9",
		"CVE-2024-0005,0.5,0.9",
		"CVE-2024-0006,0.6,0.9",
		"CVE-2024-0007,0,0.9",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(body) //nolint:errcheck,gosec // test helper
	}))
	defer srv.Close()

	var batches [][]scoreRow
	adapter := &Adapter{
		client:      feed.WrapClientWithUA(&http.Client{Transport: &redirectTransport{target: srv.URL}}),
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
		batchSize:   3,
		applyBatchFn: func(_ context.Context, _ *sql.DB, rows []scoreRow, _ time.Time) error {
			// Apply reuses the batch slice, so keep a copy.
			batches = append(batches, append([]scoreRow(nil), rows...))
			return nil
		},
		applyRowFn: func(_ context.Context, _ *sql.DB, cveID string, _ float64, _ time.Time) error {
			t.Errorf("row %s applied one at a time, want only batches", cveID)
			return nil
		},
	}

	if _, err := adapter.Apply(context.Background(), nil, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	want := [][]scoreRow{
		{{"CVE-2024-0001", 0.1}, {"CVE-2024-0002", 0.2}, {"CVE-2024-0003", 0.3}},
		{{"CVE-2024-0005", 0.5}, {"CVE-2024-0006", 0.6}, {"CVE-2024-0007", 0}},
	}
	if fmt.Sprint(batches) != fmt.Sprint(want) {
		t.Errorf("batches = %v, want %v", batches, want)
	}
	if !strings.Contains(logBuf.String(), "skip row with unparseable score") {
		t.Errorf("expected warning about the unparseable score, got: %s", logBuf.String())
	}
}

// A file whose row count is not a multiple of batchSize ends with a short batch.
func TestApply_AppliesFinalShortBatch(t *testing.T) {
	t.Parallel()

	body := makeEPSSGzip(t, []string{
		"CVE-2024-0001,0.1,0.9",
		"CVE-2024-0002,0.2,0.9",
		"CVE-2024-0003,0.3,0.9",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(body) //nolint:errcheck,gosec // test helper
	}))
	defer srv.Close()

	var sizes []int
	adapter := &Adapter{
		client:      feed.WrapClientWithUA(&http.Client{Transport: &redirectTransport{target: srv.URL}}),
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
		batchSize:   2,
		applyBatchFn: func(_ context.Context, _ *sql.DB, rows []scoreRow, _ time.Time) error {
			sizes = append(sizes, len(rows))
			return nil
		},
	}

	if _, err := adapter.Apply(context.Background(), nil, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if fmt.Sprint(sizes) != "[2 1]" {
		t.Errorf("batch sizes = %v, want [2 1]", sizes)
	}
}

// The feed client's timeout covers reading the response body. Applying rows
// must not count against it, or a slow apply fails the download partway
// through the file.
func TestApply_SlowApplyDoesNotHitClientTimeout(t *testing.T) {
	t.Parallel()

	// Enough distinct rows that the compressed body is far larger than the
	// buffers between the socket and the CSV reader.
	rows := make([]string, 20000)
	for i := range rows {
		rows[i] = fmt.Sprintf("CVE-2024-%d,0.%05d,0.5", 10000+i, (i*7919)%100000)
	}
	body := makeEPSSGzip(t, rows)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(body) //nolint:errcheck,gosec // test helper
	}))
	defer srv.Close()

	const clientTimeout = 300 * time.Millisecond
	applied := 0
	slept := false
	adapter := &Adapter{
		client: feed.WrapClientWithUA(&http.Client{
			Transport: &redirectTransport{target: srv.URL},
			Timeout:   clientTimeout,
		}),
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
		batchSize:   100,
		applyBatchFn: func(_ context.Context, _ *sql.DB, rows []scoreRow, _ time.Time) error {
			if !slept {
				slept = true
				time.Sleep(2 * clientTimeout)
			}
			applied += len(rows)
			return nil
		},
	}

	if _, err := adapter.Apply(context.Background(), nil, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if applied != len(rows) {
		t.Errorf("applied %d rows, want %d", applied, len(rows))
	}
}

// latestScores keeps one score per CVE ID, the last one in the batch, which is
// the score that applying the rows one at a time in file order ends with.
func TestLatestScores_KeepsLastScorePerCVE(t *testing.T) {
	t.Parallel()

	ids, scores := latestScores([]scoreRow{
		{"CVE-2024-0001", 0.1},
		{"CVE-2024-0002", 0.2},
		{"CVE-2024-0001", 0.3},
		{"CVE-2024-0003", 0},
	})

	got := map[string]float64{}
	for i, id := range ids {
		if _, dup := got[id]; dup {
			t.Errorf("CVE %s appears twice in %v", id, ids)
		}
		got[id] = scores[i]
	}
	want := map[string]float64{"CVE-2024-0001": 0.3, "CVE-2024-0002": 0.2, "CVE-2024-0003": 0}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("latestScores = %v, want %v", got, want)
	}
	if len(ids) != len(scores) {
		t.Errorf("len(ids) = %d, len(scores) = %d, want equal", len(ids), len(scores))
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
