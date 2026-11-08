package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/jackc/pgx/v5/pgconn"
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
				return fmt.Errorf("upsert epss staging: %w", &pgconn.PgError{Code: "22021"})
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

// elapseLimiterTime moves the limiter's clock forward by d, so a test can observe
// a call made after d without sleeping. Reserving zero tokens at a future time
// credits the refill for d and spends nothing.
func elapseLimiterTime(l *rate.Limiter, d time.Duration) {
	l.AllowN(time.Now().Add(d), 0)
}

// A failed run keeps the cursor unchanged, so the file still has to be applied.
// The job's later attempts and the scheduler's later runs must be able to do that
// in the same process on the same day; otherwise one transient failure loses a
// day of scores.
func TestApply_FailedRunSucceedsOnLaterAttempt(t *testing.T) {
	t.Parallel()

	body := makeEPSSGzip(t, []string{"CVE-2024-0001,0.5,0.9"})

	tests := []struct {
		name string
		// failDownload makes the first request return HTTP 500. Otherwise the
		// download succeeds and the job context ends while rows are applied.
		failDownload bool
		wantFirstErr string
	}{
		{name: "upstream error during the download", failDownload: true, wantFirstErr: "HTTP 500"},
		{name: "job context ends after the download", failDownload: false, wantFirstErr: "apply interrupted"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if requests.Add(1) == 1 && tc.failDownload {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Write(body) //nolint:errcheck,gosec // test helper
			}))
			defer srv.Close()

			firstRunCtx, endFirstRun := context.WithCancel(context.Background())
			defer endFirstRun()

			interruptNextApply := !tc.failDownload
			var applied []string
			adapter := New(&http.Client{Transport: &redirectTransport{target: srv.URL}})
			adapter.applyBatchFn = func(_ context.Context, _ *sql.DB, rows []scoreRow, _ time.Time) error {
				if interruptNextApply {
					interruptNextApply = false
					endFirstRun()
					return context.Canceled
				}
				for _, r := range rows {
					applied = append(applied, r.cveID)
				}
				return nil
			}

			_, err := adapter.Apply(firstRunCtx, nil, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantFirstErr) {
				t.Fatalf("first Apply error = %v, want one containing %q", err, tc.wantFirstErr)
			}

			elapseLimiterTime(adapter.rateLimiter, minDownloadInterval)

			cursor, err := adapter.Apply(context.Background(), nil, nil)
			if err != nil {
				t.Fatalf("second Apply: %v", err)
			}
			if len(cursor) == 0 {
				t.Error("second Apply returned an empty cursor")
			}
			if len(applied) != 1 || applied[0] != "CVE-2024-0001" {
				t.Errorf("applied = %v, want [CVE-2024-0001]", applied)
			}
			if got := requests.Load(); got != 2 {
				t.Errorf("server received %d requests, want 2", got)
			}
		})
	}
}

// A malformed CVE ID never reaches the database, because a row the database cannot
// store would otherwise stop every retry of the file at that row.
func TestApply_SkipsRowsWithMalformedCVEID(t *testing.T) {
	logs := captureWarnings(t)

	oversized := "CVE-2024-" + strings.Repeat("9", 6400)
	body := makeEPSSGzip(t, []string{
		"CVE-2024-0001,0.1,0.9",
		"not-a-cve-id,0.2,0.9",
		oversized + ",0.3,0.9",
		"CVE-2024-\xff,0.4,0.9",
		"CVE-2024-0002,0.5,0.9",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(body) //nolint:errcheck,gosec // test helper
	}))
	defer srv.Close()

	var applied []string
	adapter := New(&http.Client{Transport: &redirectTransport{target: srv.URL}})
	adapter.applyBatchFn = func(_ context.Context, _ *sql.DB, rows []scoreRow, _ time.Time) error {
		for _, r := range rows {
			applied = append(applied, r.cveID)
		}
		return nil
	}

	cursor, err := adapter.Apply(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(cursor) == 0 {
		t.Error("Apply returned an empty cursor")
	}
	if fmt.Sprint(applied) != fmt.Sprint([]string{"CVE-2024-0001", "CVE-2024-0002"}) {
		t.Errorf("applied %d IDs, want only the two well-formed ones: %.100q", len(applied), applied)
	}
	if got := strings.Count(logs.String(), "skip row with malformed CVE ID"); got != 3 {
		t.Errorf("logged %d malformed-row warnings, want 3: %.300s", got, logs.String())
	}
	if strings.Contains(logs.String(), oversized) {
		t.Error("the warning logged the whole oversized ID")
	}
}

// An EPSS score is a probability. NaN and infinity pass strconv.ParseFloat and
// float8 accepts them, but the API cannot marshal them to JSON and Postgres orders
// NaN above every number, so they must not reach the database.
func TestApply_SkipsRowsWithScoreOutsideProbabilityRange(t *testing.T) {
	logs := captureWarnings(t)

	body := makeEPSSGzip(t, []string{
		"CVE-2024-0001,0,0.9",
		"CVE-2024-0002,NaN,0.9",
		"CVE-2024-0003,Inf,0.9",
		"CVE-2024-0004,-Inf,0.9",
		"CVE-2024-0005,-0.1,0.9",
		"CVE-2024-0006,1.5,0.9",
		"CVE-2024-0007,1,0.9",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(body) //nolint:errcheck,gosec // test helper
	}))
	defer srv.Close()

	var applied []scoreRow
	adapter := New(&http.Client{Transport: &redirectTransport{target: srv.URL}})
	adapter.applyBatchFn = func(_ context.Context, _ *sql.DB, rows []scoreRow, _ time.Time) error {
		applied = append(applied, rows...)
		return nil
	}

	if _, err := adapter.Apply(context.Background(), nil, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := []scoreRow{{"CVE-2024-0001", 0}, {"CVE-2024-0007", 1}}
	if fmt.Sprint(applied) != fmt.Sprint(want) {
		t.Errorf("applied = %v, want %v", applied, want)
	}
	if got := strings.Count(logs.String(), "skip row with score outside 0 to 1"); got != 5 {
		t.Errorf("logged %d out-of-range warnings, want 5: %s", got, logs.String())
	}
}

// Only a data exception costs just that row. Every other failure,
// including an error that is not from Postgres at all, must stop the run.
func TestIsRowRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"invalid byte sequence", &pgconn.PgError{Code: "22021"}, true},
		{"numeric out of range", &pgconn.PgError{Code: "22003"}, true},
		{"check constraint", &pgconn.PgError{Code: "23514"}, false},
		{"not-null constraint", &pgconn.PgError{Code: "23502"}, false},
		{"index key too large", &pgconn.PgError{Code: "54000"}, false},
		{"wrapped rejection", fmt.Errorf("update cve epss: %w", &pgconn.PgError{Code: "22021"}), true},
		{"admin shutdown", &pgconn.PgError{Code: "57P01"}, false},
		{"too many connections", &pgconn.PgError{Code: "53300"}, false},
		{"read-only transaction", &pgconn.PgError{Code: "25006"}, false},
		{"permission denied", &pgconn.PgError{Code: "42501"}, false},
		{"deadlock", &pgconn.PgError{Code: "40P01"}, false},
		{"not a Postgres error", errors.New("connection refused"), false},
		{"bad connection", driver.ErrBadConn, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isRowRejected(tc.err); got != tc.want {
				t.Errorf("isRowRejected(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// A database outage must fail the run. Reporting it as a success would advance the
// cursor past a file with no rows applied, and the same-day cursor check would then
// skip that file. The run stops at the first failing row, because each row after it
// would wait on the same outage, and a later attempt can apply the file.
func TestApply_DatabaseOutage_FailsRunAndLaterAttemptSucceeds(t *testing.T) {
	logs := captureWarnings(t)

	body := makeEPSSGzip(t, []string{
		"CVE-2024-0001,0.5,0.9",
		"CVE-2024-0002,0.3,0.7",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(body) //nolint:errcheck,gosec // test helper
	}))
	defer srv.Close()

	errConnLost := errors.New("connection lost")
	outage := true
	var attemptedDuringOutage []string
	var applied []string

	adapter := New(&http.Client{Transport: &redirectTransport{target: srv.URL}})
	adapter.applyBatchFn = func(_ context.Context, _ *sql.DB, rows []scoreRow, _ time.Time) error {
		if outage {
			return errConnLost
		}
		for _, r := range rows {
			applied = append(applied, r.cveID)
		}
		return nil
	}
	adapter.applyRowFn = func(_ context.Context, _ *sql.DB, cveID string, _ float64, _ time.Time) error {
		attemptedDuringOutage = append(attemptedDuringOutage, cveID)
		return errConnLost
	}

	cursor, err := adapter.Apply(context.Background(), nil, nil)
	if !errors.Is(err, errConnLost) {
		t.Fatalf("Apply during the outage: error = %v, want %v", err, errConnLost)
	}
	if cursor != nil {
		t.Errorf("Apply during the outage returned cursor %s, want nil", cursor)
	}
	if len(attemptedDuringOutage) != 1 {
		t.Errorf("rows attempted during the outage = %v, want the run to stop at the first", attemptedDuringOutage)
	}
	if !strings.Contains(logs.String(), "batch failed") {
		t.Errorf("expected a warning about the failed batch, got: %s", logs.String())
	}

	outage = false
	elapseLimiterTime(adapter.rateLimiter, minDownloadInterval)

	cursor, err = adapter.Apply(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("Apply after the outage: %v", err)
	}
	if len(cursor) == 0 {
		t.Error("Apply after the outage returned an empty cursor")
	}
	if len(applied) != 2 {
		t.Errorf("applied after the outage = %v, want both rows", applied)
	}
}

// The job queue retries a failed run within seconds. Such a retry must not fetch
// the file again until minDownloadInterval has passed.
func TestApply_RetrySoonerThanDownloadInterval_DoesNotDownload(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	adapter := New(&http.Client{Transport: &redirectTransport{target: srv.URL}})

	if _, err := adapter.Apply(context.Background(), nil, nil); err == nil {
		t.Fatal("first Apply: expected the HTTP 500 to fail the run")
	}

	// A deadline shorter than the interval makes the limiter refuse at once.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := adapter.Apply(ctx, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("second Apply error = %v, want a rate limit error", err)
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("server received %d requests, want 1", got)
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
