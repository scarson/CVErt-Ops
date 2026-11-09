// ABOUTME: Integration tests for an advisory that moves between CVEs or loses its CVE alias.
// ABOUTME: Only the advisory's own row may move unless it is the old CVE's only source.
package merge_test

import (
	"context"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func withPackage(cveID, sourceID, name string) feed.CanonicalPatch {
	return feed.CanonicalPatch{CVEID: cveID, SourceID: sourceID, AffectedPackages: []feed.AffectedPackage{
		{Ecosystem: "npm", PackageName: name, Introduced: "0", Fixed: "1.0.0"},
	}}
}

func sourceCount(t *testing.T, s *testutil.TestDB, cveID, sourceName, sourceID string) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRowContext(context.Background(),
		"SELECT count(*) FROM cve_sources WHERE cve_id = $1 AND source_name = $2 AND source_id = $3",
		cveID, sourceName, sourceID).Scan(&n); err != nil {
		t.Fatalf("count source rows: %v", err)
	}
	return n
}

func TestIngest_AdvisoryMovesBetweenCVEs_KeepsOtherSources(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	const cveA, cveB = "CVE-2026-30001", "CVE-2026-30002"
	mustIngest(t, s, feed.CanonicalPatch{CVEID: cveA, SourceID: cveA, Status: "Analyzed"}, "nvd")
	mustIngest(t, s, withPackage(cveA, "GHSA-x", "moved"), "osv")
	mustIngest(t, s, withPackage(cveB, "GHSA-x", "moved"), "osv")

	if sourceCount(t, s, cveA, "nvd", cveA) != 1 {
		t.Error("CVE-A lost its NVD row")
	}
	if n := countRows(t, s, "cve_affected_packages", cveA); n != 0 {
		t.Errorf("CVE-A has %d package rows, want 0", n)
	}
	if n := countRows(t, s, "cve_affected_packages", cveB); n != 1 {
		t.Errorf("CVE-B has %d package rows, want 1", n)
	}
	if sourceCount(t, s, cveA, "osv", "GHSA-x") != 0 || sourceCount(t, s, cveB, "osv", "GHSA-x") != 1 {
		t.Error("the advisory row is not under CVE-B alone")
	}
}

func TestIngest_AdvisoryLosesAlias_MovesToNativeID(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	const cveA, native = "CVE-2026-30003", "GHSA-y"
	mustIngest(t, s, feed.CanonicalPatch{CVEID: cveA, SourceID: cveA, Status: "Analyzed"}, "nvd")
	mustIngest(t, s, withPackage(cveA, native, "unaliased"), "osv")
	mustIngest(t, s, withPackage(native, native, "unaliased"), "osv")

	if sourceCount(t, s, cveA, "nvd", cveA) != 1 {
		t.Error("CVE-A lost its NVD row")
	}
	if n := countRows(t, s, "cve_affected_packages", cveA); n != 0 {
		t.Errorf("CVE-A has %d package rows, want 0", n)
	}
	if sourceCount(t, s, native, "osv", native) != 1 {
		t.Error("the advisory row is not under its native ID")
	}
}

func TestIngest_SoleAdvisoryMove_RenamesRecord(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	const cveA, cveB = "CVE-2026-30004", "CVE-2026-30005"
	mustIngest(t, s, withPackage(cveA, "GHSA-z", "renamed"), "osv")
	before, err := s.GetCVE(ctx, cveA)
	if err != nil || before == nil {
		t.Fatalf("GetCVE(A) = %v, %v", before, err)
	}
	mustIngest(t, s, withPackage(cveB, "GHSA-z", "renamed"), "osv")

	gone, err := s.GetCVE(ctx, cveA)
	if err != nil {
		t.Fatalf("GetCVE(A): %v", err)
	}
	if gone != nil {
		t.Error("CVE-A still exists")
	}
	after, err := s.GetCVE(ctx, cveB)
	if err != nil || after == nil {
		t.Fatalf("GetCVE(B) = %v, %v", after, err)
	}
	if !after.DateFirstSeen.Equal(before.DateFirstSeen) {
		t.Errorf("date_first_seen = %v, want %v", after.DateFirstSeen, before.DateFirstSeen)
	}
}

func TestIngest_NativeRecordSplit_DoesNotDependOnOrder(t *testing.T) {
	t.Parallel()
	const native, cve = "GHSA-split", "CVE-2026-30006"
	seed := func(s *testutil.TestDB) {
		mustIngest(t, s, withPackage(native, native, "split"), "ghsa")
		mustIngest(t, s, withPackage(native, native, "split"), "osv")
	}
	osvUpdate := withPackage(native, native, "split-updated")
	ghsaGainsCVE := withPackage(cve, native, "split")
	check := func(s *testutil.TestDB, label string) {
		if sourceCount(t, s, cve, "ghsa", native) != 1 {
			t.Errorf("%s: the ghsa row is not under the CVE", label)
		}
		if sourceCount(t, s, native, "osv", native) != 1 {
			t.Errorf("%s: the osv row is not under the native ID", label)
		}
	}

	a := testutil.NewTestDB(t)
	seed(a)
	mustIngest(t, a, osvUpdate, "osv")
	mustIngest(t, a, ghsaGainsCVE, "ghsa")
	check(a, "osv first")

	b := testutil.NewTestDB(t)
	seed(b)
	mustIngest(t, b, ghsaGainsCVE, "ghsa")
	mustIngest(t, b, osvUpdate, "osv")
	check(b, "ghsa first")
}

func TestIngest_MigrateCVEPK_TargetExists_KeepsDistinctAdvisoriesOfOneSource(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	const native, cve = "GHSA-distinct", "CVE-2026-30007"
	mustIngest(t, s, withPackage(cve, "PYSEC-y", "existing"), "osv")
	mustIngest(t, s, withPackage(native, native, "promoted"), "osv")
	mustIngest(t, s, withPackage(cve, native, "promoted"), "osv")

	if sourceCount(t, s, cve, "osv", "PYSEC-y") != 1 || sourceCount(t, s, cve, "osv", native) != 1 {
		t.Error("the target CVE should hold both OSV advisories")
	}
}

func TestIngest_AdvisoryMove_TargetAlreadyHasRow(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	const cveA, cveB = "CVE-2026-30008", "CVE-2026-30009"
	mustIngest(t, s, feed.CanonicalPatch{CVEID: cveA, SourceID: cveA, Status: "Analyzed"}, "nvd")
	mustIngest(t, s, withPackage(cveA, "GHSA-dup", "first"), "osv")
	// A row for the same advisory under the target, which the key allows.
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO cve_sources (cve_id, source_name, source_id, normalized_json) VALUES ($1, 'osv', 'GHSA-dup', '{}')`, cveB); err != nil {
		t.Fatalf("insert row: %v", err)
	}
	mustIngest(t, s, withPackage(cveB, "GHSA-dup", "first"), "osv")

	if sourceCount(t, s, cveA, "osv", "GHSA-dup") != 0 {
		t.Error("the old row is still present")
	}
	if n := countRows(t, s, "cve_affected_packages", cveB); n != 1 {
		t.Errorf("CVE-B has %d package rows, want 1 from the upserted row", n)
	}
}

func TestIngest_FeedWithCVESourceIDDoesNotMove(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	const cve = "CVE-2026-30010"
	for range 2 {
		mustIngest(t, s, feed.CanonicalPatch{CVEID: cve, SourceID: cve, Status: "Analyzed"}, "nvd")
	}
	if sourceCount(t, s, cve, "nvd", cve) != 1 {
		t.Error("want exactly one row")
	}
}

// TestIngest_TakesSourceLockBeforeCVELock holds the advisory's lock and confirms a
// merge waits on it before taking any CVE lock.
func TestIngest_TakesSourceLockBeforeCVELock(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const cve, advisory = "CVE-2026-30011", "GHSA-locked"
	sourceKey := merge.SourceAdvisoryKey("osv", advisory)
	cveKey := merge.CVEAdvisoryKey(cve)

	conn, err := s.DB().Conn(ctx)
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test connection
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", sourceKey); err != nil {
		t.Fatalf("hold source lock: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- merge.Ingest(ctx, s.Store, withPackage(cve, advisory, "locked"), "osv") }()

	lockRows := func(key int64, granted bool) int {
		t.Helper()
		var n int
		if err := s.DB().QueryRowContext(ctx, `SELECT count(*) FROM pg_locks
			WHERE locktype = 'advisory' AND objsubid = 1 AND granted = $1
			  AND classid::bigint = $2 AND objid::bigint = $3`,
			granted, int64(uint64(key)>>32), int64(uint64(key)&0xffffffff)).Scan(&n); err != nil { //nolint:gosec // G115: lock key bits
			t.Fatalf("read pg_locks: %v", err)
		}
		return n
	}

	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for lockRows(sourceKey, false) == 0 {
		select {
		case <-ctx.Done():
			t.Fatal("the merge never waited on the source lock")
		case <-ticker.C:
		}
	}
	if n := lockRows(cveKey, true); n != 0 {
		t.Errorf("%d CVE locks granted while waiting on the source lock", n)
	}

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", sourceKey); err != nil {
		t.Fatalf("release source lock: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if sourceCount(t, s, cve, "osv", advisory) != 1 {
		t.Error("the row was not written after the lock was released")
	}
}
