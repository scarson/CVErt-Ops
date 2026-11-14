// ABOUTME: Integration test for the batch candidate scan, which unions CVEs by two change dates.
// ABOUTME: Pages through CVEs eligible by date_modified_canonical, date_match_inputs_changed or both.
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

func TestBatchCandidates_UnionPagesThroughBothChangeDates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := testutil.NewTestDB(t)

	// Fixed dates, so no comparison depends on the order of two clock readings.
	since := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := since.Add(24 * time.Hour)
	old := since.Add(-24 * time.Hour)
	type dates struct {
		modified      time.Time
		inputsChanged sql.NullTime
		eligible      bool
	}
	byModified := dates{recent, sql.NullTime{Time: old, Valid: true}, true}
	byInputs := dates{old, sql.NullTime{Time: recent, Valid: true}, true}
	byBoth := dates{recent, sql.NullTime{Time: recent, Valid: true}, true}
	neither := dates{old, sql.NullTime{Time: old, Valid: true}, false}
	neitherNull := dates{old, sql.NullTime{}, false}

	// Interleaved by ID: 3 eligible by date_modified_canonical only, 3 by
	// date_match_inputs_changed only, 2 by both, and 3 by neither.
	corpus := []struct {
		id string
		d  dates
	}{
		{"CVE-2026-91000", neither},
		{"CVE-2026-91010", byModified},
		{"CVE-2026-91020", byInputs},
		{"CVE-2026-91030", byBoth},
		{"CVE-2026-91040", byInputs},
		{"CVE-2026-91050", neitherNull},
		{"CVE-2026-91060", byModified},
		{"CVE-2026-91070", byBoth},
		{"CVE-2026-91080", byInputs},
		{"CVE-2026-91090", byModified},
		{"CVE-2026-91100", neither},
	}
	var want []string
	for _, c := range corpus {
		desc := "batch candidate scan fixture"
		if err := merge.Ingest(ctx, tdb.Store, feed.CanonicalPatch{
			CVEID: c.id, Status: "Published", DescriptionPrimary: &desc,
		}, "nvd"); err != nil {
			t.Fatalf("merge.Ingest(%s): %v", c.id, err)
		}
		if _, err := tdb.DB().ExecContext(ctx,
			`UPDATE cves SET date_modified_canonical = $2, date_match_inputs_changed = $3 WHERE cve_id = $1`,
			c.id, c.d.modified, c.d.inputsChanged); err != nil {
			t.Fatalf("set change dates of %s: %v", c.id, err)
		}
		if c.d.eligible {
			want = append(want, c.id)
		}
	}
	if len(want) != 8 {
		t.Fatalf("fixture has %d eligible CVEs, want 8", len(want))
	}

	e := New(tdb.AppStore.DB(), tdb.AppStore, NewRuleCache(),
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), 0)

	// Page the way evaluateBatchPath does, with a page size of 2.
	const pageSize = 2
	var got []string
	afterID := ""
	for range len(corpus) + 1 {
		page, err := e.getCVEsModifiedSince(ctx, since, afterID, pageSize)
		if err != nil {
			t.Fatalf("getCVEsModifiedSince(after %q): %v", afterID, err)
		}
		if len(page) > pageSize {
			t.Fatalf("page after %q has %d IDs, want at most %d", afterID, len(page), pageSize)
		}
		got = append(got, page...)
		if len(page) < pageSize {
			break
		}
		afterID = page[len(page)-1]
	}
	if !slices.Equal(got, want) {
		t.Errorf("paged candidates = %v, want each eligible CVE once in ID order: %v", got, want)
	}
}
