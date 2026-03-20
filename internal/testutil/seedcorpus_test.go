// ABOUTME: Integration test for the SeedCorpus helper.
// ABOUTME: Verifies that golden fixtures can be ingested through the merge pipeline into a test DB.
package testutil_test

import (
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestSeedCorpus(t *testing.T) {
	if testing.Short() {
		t.Skip("requires testcontainer")
	}

	db := testutil.NewTestDB(t)

	stats := testutil.SeedCorpus(t, db)

	if stats.TotalCVEs == 0 {
		t.Fatal("SeedCorpus produced 0 CVEs")
	}

	// At minimum: NVD, MITRE, OSV, KEV, MSRC, Red Hat should produce patches.
	// GHSA may produce 0 due to known adapter parsing issue.
	// EPSS is applied separately and may not match any seeded CVEs.
	minFeeds := 6 // NVD, MITRE, OSV, KEV, MSRC, Red Hat
	if stats.FeedsSeeded < minFeeds {
		t.Errorf("SeedCorpus seeded %d feeds, want at least %d (got %v)", stats.FeedsSeeded, minFeeds, stats.FeedNames)
	}

	t.Logf("seeded %d CVEs from %d feeds (%v)", stats.TotalCVEs, stats.FeedsSeeded, stats.FeedNames)
}
