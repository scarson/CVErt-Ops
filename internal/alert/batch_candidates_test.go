// ABOUTME: Integration tests for the batch and EPSS candidate scans, which page each change date by (date, cve_id).
// ABOUTME: Covers page boundaries, date ties, CVEs found by two scans, the upper bound and rows that move mid-scan.
package alert

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// Fixed dates, so no comparison depends on the order of two clock readings.
var (
	scanSince = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	scanUntil = scanSince.Add(7 * 24 * time.Hour)
)

// candidateScanFixture ingests one CVE through the merge pipeline and then sets its
// change dates, which the merge stamps from the clock.
type candidateScanFixture struct {
	id            string
	status        string
	modified      time.Time
	inputsChanged sql.NullTime
	epssUpdated   sql.NullTime
}

func seedCandidateScanCorpus(t *testing.T, ctx context.Context, tdb *testutil.TestDB, corpus []candidateScanFixture) {
	t.Helper()
	for _, c := range corpus {
		desc := "candidate scan fixture"
		status := c.status
		if status == "" {
			status = "Published"
		}
		if err := merge.Ingest(ctx, tdb.Store, feed.CanonicalPatch{
			CVEID: c.id, SourceID: c.id, Status: status, DescriptionPrimary: &desc,
		}, "nvd"); err != nil {
			t.Fatalf("merge.Ingest(%s): %v", c.id, err)
		}
		var score sql.NullFloat64
		if c.epssUpdated.Valid {
			score = sql.NullFloat64{Float64: 0.5, Valid: true}
		}
		if _, err := tdb.DB().ExecContext(ctx,
			`UPDATE cves SET date_modified_canonical = $2, date_match_inputs_changed = $3,
			        epss_score = $4, date_epss_updated = $5
			 WHERE cve_id = $1`,
			c.id, c.modified, c.inputsChanged, score, c.epssUpdated); err != nil {
			t.Fatalf("set change dates of %s: %v", c.id, err)
		}
	}
}

func newCandidateScanEvaluator(tdb *testutil.TestDB) *Evaluator {
	return New(tdb.AppStore.DB(), tdb.AppStore, NewRuleCache(),
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), 0)
}

func at(d time.Time) sql.NullTime { return sql.NullTime{Time: d, Valid: true} }

func TestBatchCandidates_PagesBothChangeDatesByDate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := testutil.NewTestDB(t)

	recent := scanSince.Add(24 * time.Hour)
	later := scanSince.Add(48 * time.Hour)
	old := scanSince.Add(-24 * time.Hour)
	future := scanUntil.Add(time.Second)

	// With a page size of 2, the five CVEs modified at `recent` and the five whose
	// inputs changed at `recent` tie across page boundaries in their own scans.
	corpus := []candidateScanFixture{
		{id: "CVE-2026-91000", modified: old, inputsChanged: at(old)},             // neither
		{id: "CVE-2026-91010", modified: recent, inputsChanged: at(old)},          // modified
		{id: "CVE-2026-91020", modified: old, inputsChanged: at(recent)},          // inputs
		{id: "CVE-2026-91030", modified: recent, inputsChanged: at(recent)},       // both
		{id: "CVE-2026-91040", modified: old, inputsChanged: at(recent)},          // inputs
		{id: "CVE-2026-91050", modified: old},                                     // neither, never re-checked
		{id: "CVE-2026-91060", modified: recent, inputsChanged: at(old)},          // modified
		{id: "CVE-2026-91070", modified: recent, inputsChanged: at(recent)},       // both
		{id: "CVE-2026-91080", modified: later, inputsChanged: at(recent)},        // both, different dates
		{id: "CVE-2026-91090", modified: recent},                                  // modified
		{id: "CVE-2026-91100", modified: old, inputsChanged: at(old)},             // neither
		{id: "CVE-2026-91110", modified: scanSince, inputsChanged: at(scanSince)}, // neither: since is exclusive
		{id: "CVE-2026-91120", modified: scanUntil, inputsChanged: at(old)},       // modified: until is inclusive
		{id: "CVE-2026-91130", modified: future, inputsChanged: at(future)},       // neither: after until
		{id: "CVE-2026-91140", modified: old, inputsChanged: at(later)},           // inputs
	}
	seedCandidateScanCorpus(t, ctx, tdb, corpus)
	want := []string{
		"CVE-2026-91010", "CVE-2026-91020", "CVE-2026-91030", "CVE-2026-91040",
		"CVE-2026-91060", "CVE-2026-91070", "CVE-2026-91080", "CVE-2026-91090",
		"CVE-2026-91120", "CVE-2026-91140",
	}

	e := newCandidateScanEvaluator(tdb)
	got, err := e.getCVEsModifiedSince(ctx, scanSince, scanUntil, 2)
	if err != nil {
		t.Fatalf("getCVEsModifiedSince: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("candidates = %v, want each eligible CVE once in ID order: %v", got, want)
	}

	// With no cursor every CVE is a candidate, whatever its dates.
	all, err := e.getCVEsModifiedSince(ctx, time.Time{}, scanUntil, 2)
	if err != nil {
		t.Fatalf("getCVEsModifiedSince(zero since): %v", err)
	}
	var wantAll []string
	for _, c := range corpus {
		wantAll = append(wantAll, c.id)
	}
	if !slices.Equal(all, wantAll) {
		t.Errorf("zero-since candidates = %v, want every CVE in ID order: %v", all, wantAll)
	}
}

func TestBatchCandidates_RowsMovedDuringScan(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := testutil.NewTestDB(t)

	day := func(n int) time.Time { return scanSince.Add(time.Duration(n) * 24 * time.Hour) }
	// IDs in reverse date order, so the scan order differs from the ID order.
	corpus := []candidateScanFixture{
		{id: "CVE-2026-92060", modified: day(1)},
		{id: "CVE-2026-92050", modified: day(2)},
		{id: "CVE-2026-92040", modified: day(3)},
		{id: "CVE-2026-92030", modified: day(4)},
		{id: "CVE-2026-92020", modified: day(5)},
		{id: "CVE-2026-92010", modified: day(6)},
	}
	seedCandidateScanCorpus(t, ctx, tdb, corpus)
	e := newCandidateScanEvaluator(tdb)

	// After the first page (day 1 and day 2), three merges stamp new dates:
	//   - CVE-2026-92060, already read, moves to just before until: it is read again.
	//   - CVE-2026-92040, not yet read, moves forward within the window: it is read once, at its new date.
	//   - CVE-2026-92030, not yet read, moves past until: this scan does not read it. The next run's
	//     scan starts at until minus cursorRescanWindow, so that run reads it.
	page := e.changePage(modifiedScan, scanSince, scanUntil, 2)
	pages := 0
	moved := func(ctx context.Context, after *changeKey) ([]changeKey, error) {
		keys, err := page(ctx, after)
		pages++
		if pages == 1 {
			for id, d := range map[string]time.Time{
				"CVE-2026-92060": scanUntil.Add(-time.Hour),
				"CVE-2026-92040": day(6).Add(time.Hour),
				"CVE-2026-92030": scanUntil.Add(time.Hour),
			} {
				if _, uerr := tdb.DB().ExecContext(ctx,
					`UPDATE cves SET date_modified_canonical = $2 WHERE cve_id = $1`, id, d); uerr != nil {
					t.Fatalf("move %s: %v", id, uerr)
				}
			}
		}
		return keys, err
	}
	got, err := collectChanges(ctx, 2, moved)
	if err != nil {
		t.Fatalf("collectChanges: %v", err)
	}
	want := []string{
		"CVE-2026-92060", "CVE-2026-92050", // first page
		"CVE-2026-92020", "CVE-2026-92010", // days 5 and 6
		"CVE-2026-92040", "CVE-2026-92060", // moved forward, in their new date order
	}
	if !slices.Equal(got, want) {
		t.Errorf("scan order = %v, want %v", got, want)
	}

	// The candidate set holds each CVE once.
	ids, err := e.getCVEsModifiedSince(ctx, scanSince, scanUntil, 2)
	if err != nil {
		t.Fatalf("getCVEsModifiedSince: %v", err)
	}
	wantIDs := []string{"CVE-2026-92010", "CVE-2026-92020", "CVE-2026-92040", "CVE-2026-92050", "CVE-2026-92060"}
	if !slices.Equal(ids, wantIDs) {
		t.Errorf("candidates after the moves = %v, want %v", ids, wantIDs)
	}
}

func TestEPSSCandidates_PagesScoreAndRetractionDatesByDate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := testutil.NewTestDB(t)

	recent := scanSince.Add(24 * time.Hour)
	old := scanSince.Add(-24 * time.Hour)
	future := scanUntil.Add(time.Second)

	// An EPSS batch stamps every row it changes with one now(), so date_epss_updated
	// ties are the normal case: four scores tie at `recent` across pages of 2.
	corpus := []candidateScanFixture{
		{id: "CVE-2026-93000", modified: old, epssUpdated: at(recent)},                        // score
		{id: "CVE-2026-93010", modified: old, epssUpdated: at(old)},                           // neither
		{id: "CVE-2026-93020", modified: recent, epssUpdated: at(old)},                        // neither: not retracted
		{id: "CVE-2026-93030", modified: old, epssUpdated: at(recent)},                        // score
		{id: "CVE-2026-93040", status: "Rejected", modified: recent},                          // retracted
		{id: "CVE-2026-93050", status: "Rejected", modified: old},                             // neither
		{id: "CVE-2026-93060", status: "Rejected", modified: recent, epssUpdated: at(recent)}, // both
		{id: "CVE-2026-93070", modified: old, epssUpdated: at(recent)},                        // score
		{id: "CVE-2026-93080", modified: old, epssUpdated: at(future)},                        // neither: after until
		{id: "CVE-2026-93090", modified: old},                                                 // neither, never scored
		{id: "CVE-2026-93100", status: "Rejected", modified: recent.Add(time.Hour)},           // retracted
	}
	seedCandidateScanCorpus(t, ctx, tdb, corpus)
	e := newCandidateScanEvaluator(tdb)

	got, err := e.getCVEsEPSSUpdatedSince(ctx, scanSince, scanUntil, 2)
	if err != nil {
		t.Fatalf("getCVEsEPSSUpdatedSince: %v", err)
	}
	want := []string{"CVE-2026-93000", "CVE-2026-93030", "CVE-2026-93040", "CVE-2026-93060", "CVE-2026-93070", "CVE-2026-93100"}
	if !slices.Equal(got, want) {
		t.Errorf("candidates = %v, want each eligible CVE once in ID order: %v", got, want)
	}

	// With no cursor the candidates are every scored or retracted CVE.
	all, err := e.getCVEsEPSSUpdatedSince(ctx, time.Time{}, scanUntil, 2)
	if err != nil {
		t.Fatalf("getCVEsEPSSUpdatedSince(zero since): %v", err)
	}
	wantAll := []string{
		"CVE-2026-93000", "CVE-2026-93010", "CVE-2026-93020", "CVE-2026-93030", "CVE-2026-93040",
		"CVE-2026-93050", "CVE-2026-93060", "CVE-2026-93070", "CVE-2026-93080", "CVE-2026-93100",
	}
	if !slices.Equal(all, wantAll) {
		t.Errorf("zero-since candidates = %v, want %v", all, wantAll)
	}
}
