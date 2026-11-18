// ABOUTME: Integration test for what CPE watchlist items match in NVD configurations, using real golden CVEs.
// ABOUTME: Pins that items match vulnerable: false platform CPEs, so a hardware watchlist still sees its firmware CVEs.
package alert_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/store"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// NVD marks hardware as vulnerable: false when the flaw is in its firmware
// (CVE-2017-12542), and an operating system as vulnerable: false when an
// application running on it is affected (CVE-2026-3909). CPE watchlist items
// match both. Dropping the first kind would silently stop alerts for a device
// someone is watching, which is worse than the noise from the second kind.
func TestEvaluatorRealtime_CPEWatchlistMatchesRunningOnPlatforms(t *testing.T) {
	tests := []struct {
		name      string
		cveID     string
		watched   string
		wantMatch bool
	}{
		{"hardware named for its firmware", "CVE-2017-12542", "cpe:2.3:h:hp:integrated_lights-out_4", true},
		{"firmware itself", "CVE-2017-12542", "cpe:2.3:o:hp:integrated_lights-out_4_firmware", true},
		{"platform an application runs on", "CVE-2026-3909", "cpe:2.3:o:microsoft:windows", true},
		{"unrelated product", "CVE-2017-12542", "cpe:2.3:a:nodejs:node.js", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tdb := testutil.NewTestDB(t)
			ev := newTestEvaluator(t, tdb)
			ctx := context.Background()
			orgID := createTestOrg(t, tdb.DB())

			if err := merge.Ingest(ctx, tdb.Store, testutil.GoldenPatch(t, "nvd", tc.cveID), "nvd"); err != nil {
				t.Fatalf("Ingest: %v", err)
			}
			watchlist, err := tdb.CreateWatchlist(ctx, orgID, uuid.NullUUID{}, "platforms", sql.NullString{})
			if err != nil {
				t.Fatalf("CreateWatchlist: %v", err)
			}
			watched := tc.watched
			if _, err := tdb.CreateWatchlistItem(ctx, orgID, watchlist.ID, store.CreateWatchlistItemParams{
				ItemType:      generated.WatchlistItemTypeCpe,
				CpeNormalized: &watched,
			}); err != nil {
				t.Fatalf("CreateWatchlistItem: %v", err)
			}
			rule := mustRule(t, ctx, tdb.Store, orgID, "and",
				`[{"field":"cvss_v3_score","operator":"gte","value":0}]`, []uuid.UUID{watchlist.ID})
			activateRule(t, ctx, tdb.Store, orgID, rule.ID)

			if err := ev.EvaluateRealtime(ctx, tc.cveID); err != nil {
				t.Fatalf("EvaluateRealtime: %v", err)
			}

			got := countAlertEvents(t, tdb.DB(), rule.ID, tc.cveID) == 1
			if got != tc.wantMatch {
				t.Errorf("matched = %v, want %v", got, tc.wantMatch)
			}
		})
	}
}
