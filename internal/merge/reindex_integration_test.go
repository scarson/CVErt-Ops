// ABOUTME: Integration tests for RebuildSearchIndex against a real Postgres corpus.
// ABOUTME: Verifies missing and stale cve_search_index rows are rebuilt to match merge output.
package merge_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// ingestForReindex merges three CVEs with descriptions, CWEs and affected
// packages (unsorted, with a duplicate) and returns the fts_document text the
// merge pipeline wrote for each.
func ingestForReindex(t *testing.T, s *testutil.TestDB) map[string]string {
	t.Helper()
	ctx := context.Background()

	descs := map[string]string{
		"CVE-2024-99950": "Heap overflow in image decoder",
		"CVE-2024-99951": "SQL injection in admin console",
		"CVE-2024-99952": "Path traversal in archive extraction",
	}
	for id, desc := range descs {
		patch := feed.CanonicalPatch{
			CVEID:              id,
			Status:             "published",
			DescriptionPrimary: &desc,
			CWEIDs:             []string{"CWE-89", "CWE-22"},
			AffectedPackages: []feed.AffectedPackage{
				{Ecosystem: "pip", PackageName: "zlib-wrapper"},
				{Ecosystem: "npm", PackageName: "archiver"},
				{Ecosystem: "npm", PackageName: "zlib-wrapper"},
			},
		}
		if err := merge.Ingest(ctx, s.Store, patch, "nvd"); err != nil {
			t.Fatalf("Ingest %s: %v", id, err)
		}
	}

	want := make(map[string]string, len(descs))
	for id := range descs {
		want[id] = readFTSDocument(t, s, id)
	}
	return want
}

func readFTSDocument(t *testing.T, s *testutil.TestDB, cveID string) string {
	t.Helper()
	var doc string
	if err := s.DB().QueryRowContext(context.Background(),
		"SELECT fts_document::text FROM cve_search_index WHERE cve_id = $1", cveID,
	).Scan(&doc); err != nil {
		t.Fatalf("read fts_document for %s: %v", cveID, err)
	}
	return doc
}

func TestRebuildSearchIndex_RestoresMissingAndStaleRows(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	want := ingestForReindex(t, s)

	// One row lost entirely, one row holding a tsvector that no longer
	// matches the CVE's text.
	if _, err := s.DB().ExecContext(ctx,
		"DELETE FROM cve_search_index WHERE cve_id = 'CVE-2024-99950'"); err != nil {
		t.Fatalf("delete index row: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx,
		"UPDATE cve_search_index SET fts_document = to_tsvector('english', 'stale') WHERE cve_id = 'CVE-2024-99951'"); err != nil {
		t.Fatalf("corrupt index row: %v", err)
	}

	// Batch size 2 forces the three CVEs across a batch boundary.
	n, err := merge.RebuildSearchIndex(ctx, s.Store, 2)
	if err != nil {
		t.Fatalf("RebuildSearchIndex: %v", err)
	}
	if n != len(want) {
		t.Errorf("RebuildSearchIndex processed %d CVEs, want %d", n, len(want))
	}

	for id, doc := range want {
		if got := readFTSDocument(t, s, id); got != doc {
			t.Errorf("%s fts_document after rebuild:\n got  %s\n want %s", id, got, doc)
		}
	}
}

// TestRebuildSearchIndex_PackageOrderIgnoresCollation verifies the rebuild
// orders package names the way merge does (bytewise), not by the database
// collation. Under a linguistic collation "alpha" sorts before "Zebra";
// bytewise, "Zebra" comes first.
func TestRebuildSearchIndex_PackageOrderIgnoresCollation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	if _, err := s.DB().ExecContext(ctx,
		`ALTER TABLE cve_affected_packages ALTER COLUMN package_name TYPE text COLLATE "en-US-x-icu"`); err != nil {
		t.Fatalf("set package_name collation: %v", err)
	}

	cveID := "CVE-2024-99953"
	desc := "Prototype pollution in object merge helper"
	if err := merge.Ingest(ctx, s.Store, feed.CanonicalPatch{
		CVEID:              cveID,
		Status:             "published",
		DescriptionPrimary: &desc,
		AffectedPackages: []feed.AffectedPackage{
			{Ecosystem: "npm", PackageName: "alpha"},
			{Ecosystem: "npm", PackageName: "Zebra"},
		},
	}, "nvd"); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	want := readFTSDocument(t, s, cveID)

	if _, err := merge.RebuildSearchIndex(ctx, s.Store, 100); err != nil {
		t.Fatalf("RebuildSearchIndex: %v", err)
	}
	if got := readFTSDocument(t, s, cveID); got != want {
		t.Errorf("fts_document changed by rebuild under en-US collation:\n got  %s\n want %s", got, want)
	}
}

// TestRebuildSearchIndex_RetriesBatchAfterDeadlock reproduces the lock cycle a
// late-binding PK migration can form with a rebuild batch: merge holds the
// destination CVE's lock and then asks for the source ID's lock, while the
// batch holds the source's lock and waits for the destination's. Postgres
// aborts the rebuild's transaction; the rebuild must retry the batch rather
// than fail the whole job.
func TestRebuildSearchIndex_RetriesBatchAfterDeadlock(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	want := ingestForReindex(t, s)

	// The batch takes locks in ascending key order, so it takes lowID first.
	lowID, highID := "CVE-2024-99950", "CVE-2024-99951"
	if merge.CVEAdvisoryKey(lowID) > merge.CVEAdvisoryKey(highID) {
		lowID, highID = highID, lowID
	}

	// This session plays the merge transaction: destination lock first.
	conn, err := s.DB().Conn(ctx)
	if err != nil {
		t.Fatalf("open conn: %v", err)
	}
	defer conn.Close() //nolint:errcheck
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", merge.CVEAdvisoryKey(highID)); err != nil {
		t.Fatalf("lock %s: %v", highID, err)
	}

	rebuildErr := make(chan error, 1)
	go func() {
		_, err := merge.RebuildSearchIndex(ctx, s.Store, 100)
		rebuildErr <- err
	}()

	// Wait until the rebuild holds lowID and is blocked on highID. pg_locks
	// covers the whole cluster, which other tests' databases share.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := s.DB().QueryRowContext(ctx, `
			SELECT count(*) FROM pg_locks
			WHERE locktype = 'advisory' AND NOT granted
			  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`,
		).Scan(&waiting); err != nil {
			t.Fatalf("read pg_locks: %v", err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("rebuild never blocked on the held advisory lock")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Close the cycle. The rebuild has waited longer, so its deadlock check
	// fires first and Postgres aborts its transaction, granting this lock.
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", merge.CVEAdvisoryKey(lowID)); err != nil {
		t.Fatalf("setup: expected the rebuild to be the deadlock victim, but this session was: %v", err)
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_unlock_all()"); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	select {
	case err := <-rebuildErr:
		if err != nil {
			t.Fatalf("RebuildSearchIndex after deadlock: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("RebuildSearchIndex did not finish after the locks were released")
	}
	for id, doc := range want {
		if got := readFTSDocument(t, s, id); got != doc {
			t.Errorf("%s fts_document after retried rebuild:\n got  %s\n want %s", id, got, doc)
		}
	}
}

func TestRebuildSearchIndex_EmptyCorpus(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)

	n, err := merge.RebuildSearchIndex(context.Background(), s.Store, 100)
	if err != nil {
		t.Fatalf("RebuildSearchIndex: %v", err)
	}
	if n != 0 {
		t.Errorf("RebuildSearchIndex processed %d CVEs on an empty corpus, want 0", n)
	}
}

// TestRebuildSearchIndex_WaitsForMergeLock verifies the rebuild takes the same
// per-CVE advisory lock as the merge pipeline, so it cannot interleave with an
// in-flight merge and write a tsvector built from pre-merge text.
func TestRebuildSearchIndex_WaitsForMergeLock(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	ingestForReindex(t, s)

	// Hold the merge lock for one CVE on a separate session.
	conn, err := s.DB().Conn(ctx)
	if err != nil {
		t.Fatalf("open conn: %v", err)
	}
	defer conn.Close() //nolint:errcheck
	key := merge.CVEAdvisoryKey("CVE-2024-99951")
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
		t.Fatalf("acquire advisory lock: %v", err)
	}

	blockedCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	if _, err := merge.RebuildSearchIndex(blockedCtx, s.Store, 100); err == nil {
		t.Fatal("RebuildSearchIndex completed while the merge lock was held; want it to block")
	} else if !errors.Is(blockedCtx.Err(), context.DeadlineExceeded) {
		t.Fatalf("RebuildSearchIndex failed before the deadline: %v", err)
	}

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", key); err != nil {
		t.Fatalf("release advisory lock: %v", err)
	}
	if _, err := merge.RebuildSearchIndex(ctx, s.Store, 100); err != nil {
		t.Fatalf("RebuildSearchIndex after lock release: %v", err)
	}
}
