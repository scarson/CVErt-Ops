// ABOUTME: Integration tests for the batched EPSS apply against a real Postgres database.
// ABOUTME: Covers the two-statement write, staging of unknown CVEs, and the merge advisory lock.
package epss_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/epss"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// applyFile serves rows as an EPSS file dated the day before and applies it
// with a new adapter, so the adapter's rate limit never delays a call.
// It fails on any logged warning: a batch that fails is retried row by row and
// reaches the same scores, so the warning is the only sign that batching broke.
func applyFile(t *testing.T, db *sql.DB, rows ...string) {
	t.Helper()
	warnings := epss.CaptureWarnings(t)
	if _, err := fileAdapter(t, rows...).Apply(context.Background(), db, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if warnings.Len() != 0 {
		t.Errorf("Apply logged warnings: %s", warnings.String())
	}
}

// fileAdapter returns a new adapter whose download serves rows as an EPSS file
// dated the day before.
func fileAdapter(t *testing.T, rows ...string) *epss.Adapter {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	yesterday := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	fmt.Fprintf(gz, "#model_version:v2025.03.14,score_date:%s\n", yesterday) //nolint:errcheck // test helper
	fmt.Fprintln(gz, "cve,epss,percentile")                                  //nolint:errcheck // test helper
	fmt.Fprintln(gz, strings.Join(rows, "\n"))                               //nolint:errcheck // test helper
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	body := buf.Bytes()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: testutil.NewURLRewriteTransport(
		"https://epss.empiricalsecurity.com", srv.URL, http.DefaultTransport)}
	return epss.New(client)
}

func seedCVE(t *testing.T, db *testutil.TestDB, cveID string) {
	t.Helper()
	if err := merge.Ingest(context.Background(), db.Store, feed.CanonicalPatch{
		CVEID:  cveID,
		Status: "published",
	}, "nvd"); err != nil {
		t.Fatalf("merge.Ingest %s: %v", cveID, err)
	}
}

type epssState struct {
	score   sql.NullFloat64
	updated sql.NullTime
}

func cveEPSS(t *testing.T, db *sql.DB, cveID string) epssState {
	t.Helper()
	var s epssState
	if err := db.QueryRowContext(context.Background(),
		"SELECT epss_score, date_epss_updated FROM cves WHERE cve_id = $1", cveID,
	).Scan(&s.score, &s.updated); err != nil {
		t.Fatalf("read %s: %v", cveID, err)
	}
	return s
}

func stagedScores(t *testing.T, db *sql.DB) map[string]float64 {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), "SELECT cve_id, epss_score FROM epss_staging")
	if err != nil {
		t.Fatalf("read staging: %v", err)
	}
	defer rows.Close() //nolint:errcheck
	got := map[string]float64{}
	for rows.Next() {
		var id string
		var score float64
		if err := rows.Scan(&id, &score); err != nil {
			t.Fatalf("scan staging: %v", err)
		}
		got[id] = score
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("staging rows: %v", err)
	}
	return got
}

// Scores for known CVEs land on cves, scores for unknown CVEs land in
// epss_staging and nowhere else, and a CVE listed twice keeps its later score.
func TestApply_WritesKnownCVEsAndStagesUnknownCVEs(t *testing.T) {
	if testing.Short() {
		t.Skip("requires testcontainer")
	}
	db := testutil.NewTestDB(t)
	seedCVE(t, db, "CVE-2024-1001")
	seedCVE(t, db, "CVE-2024-1002")

	applyFile(t, db.DB(),
		"CVE-2024-1001,0.5,0.9",
		"CVE-2024-1002,0,0.1",
		"CVE-2024-9001,0.7,0.95",
		"CVE-2024-1001,0.6,0.92",
	)

	if got := cveEPSS(t, db.DB(), "CVE-2024-1001"); !got.score.Valid || got.score.Float64 != 0.6 {
		t.Errorf("CVE-2024-1001 epss_score = %v, want 0.6 (the later row)", got.score)
	}
	if got := cveEPSS(t, db.DB(), "CVE-2024-1002"); !got.score.Valid || got.score.Float64 != 0 {
		t.Errorf("CVE-2024-1002 epss_score = %v, want 0 (not NULL)", got.score)
	}
	staged := stagedScores(t, db.DB())
	if fmt.Sprint(staged) != fmt.Sprint(map[string]float64{"CVE-2024-9001": 0.7}) {
		t.Errorf("epss_staging = %v, want only CVE-2024-9001 = 0.7", staged)
	}
}

// date_epss_updated moves only when a CVE's score changes, so the EPSS alert
// evaluator does not re-evaluate CVEs whose scores are the same as yesterday.
func TestApply_UnchangedScoreKeepsUpdateTime(t *testing.T) {
	if testing.Short() {
		t.Skip("requires testcontainer")
	}
	db := testutil.NewTestDB(t)
	seedCVE(t, db, "CVE-2024-1001")
	seedCVE(t, db, "CVE-2024-1002")

	applyFile(t, db.DB(), "CVE-2024-1001,0.5,0.9", "CVE-2024-1002,0.3,0.5",
		"CVE-2024-9001,0.7,0.9", "CVE-2024-9002,0.2,0.4")
	firstSame := cveEPSS(t, db.DB(), "CVE-2024-1001")
	firstChanged := cveEPSS(t, db.DB(), "CVE-2024-1002")

	// Backdate the staged row whose score stays the same, so that any write to
	// it shows in its dates.
	backdated := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := db.DB().ExecContext(context.Background(),
		"UPDATE epss_staging SET as_of_date = $1::timestamptz::date, ingested_at = $1::timestamptz WHERE cve_id = 'CVE-2024-9002'", backdated); err != nil {
		t.Fatalf("backdate staging row: %v", err)
	}

	applyFile(t, db.DB(), "CVE-2024-1001,0.5,0.9", "CVE-2024-1002,0.4,0.6",
		"CVE-2024-9001,0.8,0.9", "CVE-2024-9002,0.2,0.4")

	if got := cveEPSS(t, db.DB(), "CVE-2024-1001"); !got.updated.Time.Equal(firstSame.updated.Time) {
		t.Errorf("unchanged score moved date_epss_updated from %v to %v", firstSame.updated.Time, got.updated.Time)
	}
	got := cveEPSS(t, db.DB(), "CVE-2024-1002")
	if got.score.Float64 != 0.4 || !got.updated.Time.After(firstChanged.updated.Time) {
		t.Errorf("changed score: got %v at %v, want 0.4 after %v", got.score, got.updated.Time, firstChanged.updated.Time)
	}
	if staged := stagedScores(t, db.DB()); staged["CVE-2024-9001"] != 0.8 {
		t.Errorf("epss_staging = %v, want CVE-2024-9001 updated to 0.8", staged)
	}

	var asOf, ingested time.Time
	if err := db.DB().QueryRowContext(context.Background(),
		"SELECT as_of_date, ingested_at FROM epss_staging WHERE cve_id = 'CVE-2024-9002'",
	).Scan(&asOf, &ingested); err != nil {
		t.Fatalf("read staging row: %v", err)
	}
	if !asOf.Equal(backdated) || !ingested.Equal(backdated) {
		t.Errorf("unchanged staged score was rewritten: as_of_date %v, ingested_at %v, want both %v", asOf, ingested, backdated)
	}
}

// A file longer than one batch is applied across several transactions, and
// every batch writes known CVEs to cves and stages unknown ones. applyFile fails
// if any batch had to fall back to row-by-row writes.
func TestApply_FileLongerThanOneBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("requires testcontainer")
	}
	db := testutil.NewTestDB(t)

	const n = 1201
	known := map[int]bool{0: true, 600: true, 1200: true}
	rows := make([]string, n)
	for i := range rows {
		id := fmt.Sprintf("CVE-2024-%d", 30000+i)
		if known[i] {
			seedCVE(t, db, id)
		}
		rows[i] = fmt.Sprintf("%s,0.%04d,0.5", id, i+1)
	}

	applyFile(t, db.DB(), rows...)

	for i := range known {
		id := fmt.Sprintf("CVE-2024-%d", 30000+i)
		want := float64(i+1) / 10000
		if got := cveEPSS(t, db.DB(), id); !got.score.Valid || got.score.Float64 != want {
			t.Errorf("%s epss_score = %v, want %v", id, got.score, want)
		}
	}
	staged := stagedScores(t, db.DB())
	if len(staged) != n-len(known) {
		t.Errorf("staged %d rows, want %d", len(staged), n-len(known))
	}
	if got, want := staged["CVE-2024-31199"], float64(1200)/10000; got != want {
		t.Errorf("staged score in the last batch = %v, want %v", got, want)
	}
}

// A row the database rejects aborts its whole batch. The other rows of that
// batch still land through the row-by-row path, and only the rejected row is lost.
func TestApply_RowRejectedByDatabaseCostsOnlyThatRow(t *testing.T) {
	if testing.Short() {
		t.Skip("requires testcontainer")
	}
	db := testutil.NewTestDB(t)
	seedCVE(t, db, "CVE-2024-1001")
	seedCVE(t, db, "CVE-2024-1002")
	warnings := epss.CaptureWarnings(t)

	if _, err := db.DB().ExecContext(context.Background(),
		"ALTER TABLE epss_staging ADD CONSTRAINT rejects_one_cve CHECK (cve_id <> 'CVE-2024-9002')"); err != nil {
		t.Fatalf("add constraint: %v", err)
	}

	adapter := fileAdapter(t,
		"CVE-2024-1001,0.5,0.9",
		"CVE-2024-9002,0.6,0.9",
		"CVE-2024-1002,0.7,0.9",
		"CVE-2024-9001,0.8,0.9",
	)
	if _, err := adapter.Apply(context.Background(), db.DB(), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := cveEPSS(t, db.DB(), "CVE-2024-1001"); got.score.Float64 != 0.5 {
		t.Errorf("CVE-2024-1001 epss_score = %v, want 0.5", got.score)
	}
	if got := cveEPSS(t, db.DB(), "CVE-2024-1002"); got.score.Float64 != 0.7 {
		t.Errorf("CVE-2024-1002 epss_score = %v, want 0.7", got.score)
	}
	staged := stagedScores(t, db.DB())
	if fmt.Sprint(staged) != fmt.Sprint(map[string]float64{"CVE-2024-9001": 0.8}) {
		t.Errorf("epss_staging = %v, want only CVE-2024-9001 = 0.8", staged)
	}
	for _, want := range []string{"batch failed; applying its rows one at a time", "skipping row with DB error"} {
		if !strings.Contains(warnings.String(), want) {
			t.Errorf("expected warning %q, got: %s", want, warnings.String())
		}
	}
}

// When the first ingest of a CVE runs at the same time as an EPSS apply that
// scores it, the score ends on the cves row and no staging row is left, whichever
// transaction goes first (PLAN.md §5.3), and neither side fails.
//
// The race the shared advisory lock prevents (an ingest committing between the
// apply's two statements, so the update finds no cves row and the staging insert
// then finds one) has a window too narrow for this test to hit reliably.
// TestApply_WaitsForMergeAdvisoryLock is the test that fails without the lock.
func TestApply_ConcurrentFirstIngestKeepsScore(t *testing.T) {
	if testing.Short() {
		t.Skip("requires testcontainer")
	}
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	const n = 200
	ids := make([]string, n)
	rows := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("CVE-2024-%d", 20000+i)
		rows[i] = fmt.Sprintf("%s,0.%03d,0.5", ids[i], i+1)
	}
	adapter := fileAdapter(t, rows...)

	var applyErr, ingestErr error
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		_, applyErr = adapter.Apply(ctx, db.DB(), nil)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		for _, id := range ids {
			if err := merge.Ingest(ctx, db.Store, feed.CanonicalPatch{CVEID: id, Status: "published"}, "nvd"); err != nil {
				ingestErr = fmt.Errorf("merge.Ingest %s: %w", id, err)
				return
			}
		}
	}()
	<-done
	<-done
	if applyErr != nil {
		t.Fatalf("Apply: %v", applyErr)
	}
	if ingestErr != nil {
		t.Fatal(ingestErr)
	}

	for i, id := range ids {
		want := float64(i+1) / 1000
		if got := cveEPSS(t, db.DB(), id); !got.score.Valid || got.score.Float64 != want {
			t.Errorf("%s epss_score = %v, want %v", id, got.score, want)
		}
	}
	if staged := stagedScores(t, db.DB()); len(staged) != 0 {
		t.Errorf("epss_staging = %v, want empty once every CVE is ingested", staged)
	}
}

// The apply takes the merge pipeline's per-CVE advisory lock (PLAN.md §5.3),
// so it waits while a merge of that CVE is in progress and writes after it.
func TestApply_WaitsForMergeAdvisoryLock(t *testing.T) {
	if testing.Short() {
		t.Skip("requires testcontainer")
	}
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	seedCVE(t, db, "CVE-2024-1001")

	// Stand-in for a merge in progress: hold the merge lock for the CVE.
	mergeTx, err := db.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = mergeTx.Rollback() }()
	if _, err := mergeTx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)",
		merge.CVEAdvisoryKey("CVE-2024-1001")); err != nil {
		t.Fatalf("lock: %v", err)
	}

	adapter := fileAdapter(t, "CVE-2024-1001,0.5,0.9")
	var applyErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, applyErr = adapter.Apply(ctx, db.DB(), nil)
	}()

	// Wait until the apply is blocked on an advisory lock.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := db.DB().QueryRowContext(ctx,
			"SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted").Scan(&waiting); err != nil {
			t.Fatalf("read pg_locks: %v", err)
		}
		if waiting > 0 {
			break
		}
		select {
		case <-done:
			t.Fatal("Apply finished while the merge lock was held")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("Apply never waited on an advisory lock")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := cveEPSS(t, db.DB(), "CVE-2024-1001"); got.score.Valid {
		t.Errorf("epss_score = %v while the merge lock was held, want NULL", got.score)
	}

	if err := mergeTx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	<-done
	if applyErr != nil {
		t.Fatalf("Apply: %v", applyErr)
	}
	if got := cveEPSS(t, db.DB(), "CVE-2024-1001"); got.score.Float64 != 0.5 {
		t.Errorf("epss_score = %v after the merge lock was released, want 0.5", got.score)
	}
}
