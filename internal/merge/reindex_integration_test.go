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
