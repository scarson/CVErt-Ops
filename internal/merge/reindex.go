// ABOUTME: Full rebuild of cve_search_index from the canonical cves rows and their packages.
// ABOUTME: Runs as the system_reindex job behind POST /api/v1/admin/reindex.
package merge

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// SearchReindexQueue is the job_queue queue name for search index rebuilds.
// The admin API enqueues on it and the worker pool consumes it.
const SearchReindexQueue = "system_reindex"

// RebuildSearchIndex recomputes every cve_search_index row from the canonical
// cves row and its affected packages, using the same tsvector recipe as merge
// step 10 (UpsertCVESearchIndex). It walks the corpus in cve_id order, in
// batches of batchSize, and returns the number of CVEs it rebuilt.
//
// Each batch is one transaction that takes the per-CVE merge advisory lock
// for every CVE in the batch before reading them. Under READ COMMITTED the read
// then sees every merge that committed before the locks were granted, and
// merges that start later wait for this commit, so the rebuild never writes a
// tsvector built from pre-merge text. Merge's late-binding PK migration takes
// a second lock out of key order, so a batch that holds a migration's source
// ID while waiting for its destination can deadlock with it. Postgres aborts
// one of the two transactions; when the batch is the one aborted, it is rolled
// back whole and retried up to maxBatchAttempts times.
func RebuildSearchIndex(ctx context.Context, s Store, batchSize int32) (int, error) {
	if batchSize <= 0 {
		return 0, errors.New("rebuild search index: batch size must be positive")
	}

	total := 0
	after := ""
	for {
		ids, err := generated.New(s.DB()).ListCVEIDsAfter(ctx, generated.ListCVEIDsAfterParams{
			AfterCveID: after,
			BatchSize:  batchSize,
		})
		if err != nil {
			return total, fmt.Errorf("rebuild search index: list CVE IDs after %q: %w", after, err)
		}
		if len(ids) == 0 {
			return total, nil
		}

		var n int
		for attempt := 1; ; attempt++ {
			n, err = rebuildSearchIndexBatch(ctx, s, ids)
			if err == nil || !isDeadlock(err) || attempt == maxBatchAttempts {
				break
			}
		}
		if err != nil {
			return total, fmt.Errorf("rebuild search index: batch after %q: %w", after, err)
		}
		total += n
		after = ids[len(ids)-1]
	}
}

// maxBatchAttempts bounds how many times one rebuild batch is retried after
// Postgres aborts it to break a deadlock.
const maxBatchAttempts = 3

// isDeadlock reports whether err is Postgres's deadlock_detected (40P01).
func isDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}

// rebuildSearchIndexBatch rebuilds the cve_search_index rows for ids under the
// merge advisory locks. CVEs deleted since ids was listed are skipped.
func rebuildSearchIndexBatch(ctx context.Context, s Store, ids []string) (int, error) {
	tx, err := s.DB().BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	// Rollback is a no-op after Commit; always safe to defer.
	defer func() { _ = tx.Rollback() }()

	q := generated.New(tx)

	keys := make([]int64, len(ids))
	for i, id := range ids {
		keys[i] = CVEAdvisoryKey(id)
	}
	if err := q.LockCVEAdvisoryKeys(ctx, keys); err != nil {
		return 0, fmt.Errorf("advisory locks: %w", err)
	}

	rows, err := q.ListSearchIndexInputs(ctx, ids)
	if err != nil {
		return 0, fmt.Errorf("read search index inputs: %w", err)
	}
	for _, r := range rows {
		if err := q.UpsertCVESearchIndex(ctx, generated.UpsertCVESearchIndexParams{
			CveID:        r.CveID,
			Description:  r.DescriptionPrimary.String,
			CweNames:     strings.Join(r.CweIds, " "),
			PackageNames: strings.Join(ftsPackageNames(r.PackageNames), " "),
		}); err != nil {
			return 0, fmt.Errorf("upsert search index for %s: %w", r.CveID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return len(rows), nil
}
