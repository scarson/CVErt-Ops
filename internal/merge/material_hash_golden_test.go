// ABOUTME: Pins the material_hash of every CVE in the golden corpus, computed through the real merge pipeline.
// ABOUTME: A hash change makes alert_events insert a new row per matching rule, so it must be a deliberate decision.
package merge_test

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// goldenHashPinsPath holds cve_id -> material_hash for the golden corpus. A
// production CVE whose hash inputs equal a pinned CVE's hashes the same way, so
// a moved pin means deployed CVEs re-fire alerts when they are next merged.
var goldenHashPinsPath = filepath.Join("testdata", "golden_material_hashes.json")

// goldenCorpusHashes seeds a database from every adapter's golden fixtures and
// returns the material_hash the merge pipeline stored for each CVE.
func goldenCorpusHashes(t *testing.T) map[string]string {
	t.Helper()
	db := testutil.NewTestDB(t)
	testutil.SeedCorpus(t, db)

	rows, err := db.DB().QueryContext(context.Background(), "SELECT cve_id, material_hash FROM cves")
	if err != nil {
		t.Fatalf("query hashes: %v", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query in a test

	hashes := make(map[string]string)
	for rows.Next() {
		var id, hash string
		if err := rows.Scan(&id, &hash); err != nil {
			t.Fatalf("scan hash: %v", err)
		}
		hashes[id] = hash
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate hashes: %v", err)
	}
	return hashes
}

func TestMaterialHash_GoldenCorpusMatchesPins(t *testing.T) {
	raw, err := os.ReadFile(goldenHashPinsPath)
	if err != nil {
		t.Fatalf("read pins: %v", err)
	}
	var pins map[string]string
	if err := json.Unmarshal(raw, &pins); err != nil {
		t.Fatalf("parse pins: %v", err)
	}

	got := goldenCorpusHashes(t)

	// UPDATE_GOLDEN_HASHES=1 rewrites the pins, for a change that means to move them.
	if os.Getenv("UPDATE_GOLDEN_HASHES") == "1" {
		updated, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatalf("marshal pins: %v", err)
		}
		if err := os.WriteFile(goldenHashPinsPath, append(updated, '\n'), 0o600); err != nil {
			t.Fatalf("write pins: %v", err)
		}
		return
	}

	if len(pins) == 0 {
		t.Fatal("no pinned hashes")
	}
	for _, id := range slices.Sorted(maps.Keys(pins)) {
		gotHash, ok := got[id]
		if !ok {
			t.Errorf("%s: pinned but missing from the seeded corpus", id)
			continue
		}
		if gotHash != pins[id] {
			t.Errorf("%s: material_hash = %s, pinned %s", id, gotHash, pins[id])
		}
	}
	for _, id := range slices.Sorted(maps.Keys(got)) {
		if _, ok := pins[id]; !ok {
			t.Errorf("%s: in the seeded corpus but not pinned", id)
		}
	}
}
