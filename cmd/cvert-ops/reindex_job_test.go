// ABOUTME: End-to-end test of the system_reindex job: queued job → worker pool → rebuilt search index.
// ABOUTME: Proves the queue the admin API enqueues on has a consuming handler that completes.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/testutil"
	"github.com/scarson/cvert-ops/internal/worker"
)

func TestSearchReindexJob_RunsAndRebuildsIndex(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	cveID := "CVE-2024-99960"
	desc := "Deserialization flaw in message broker"
	if err := merge.Ingest(ctx, tdb.Store, feed.CanonicalPatch{
		CVEID:              cveID,
		Status:             "published",
		DescriptionPrimary: &desc,
		AffectedPackages:   []feed.AffectedPackage{{Ecosystem: "maven", PackageName: "broker-core"}},
	}, "nvd"); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	var want string
	if err := tdb.DB().QueryRowContext(ctx,
		"SELECT fts_document::text FROM cve_search_index WHERE cve_id = $1", cveID,
	).Scan(&want); err != nil {
		t.Fatalf("read fts_document: %v", err)
	}
	if _, err := tdb.DB().ExecContext(ctx, "DELETE FROM cve_search_index WHERE cve_id = $1", cveID); err != nil {
		t.Fatalf("delete index row: %v", err)
	}

	// Enqueue exactly as POST /api/v1/admin/reindex does.
	lockKey := "system:reindex"
	jobID, err := tdb.EnqueueJob(ctx, merge.SearchReindexQueue, 0, json.RawMessage(`{}`), &lockKey, 1, nil)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	pool := worker.New(tdb.Store)
	pool.Register(merge.SearchReindexQueue, searchReindexHandler(tdb.Store))
	poolCtx, stopPool := context.WithCancel(ctx)
	poolDone := make(chan struct{})
	go func() {
		pool.Start(poolCtx)
		close(poolDone)
	}()
	t.Cleanup(func() {
		stopPool()
		<-poolDone
	})

	deadline := time.Now().Add(30 * time.Second)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var status string
	for {
		if err := tdb.DB().QueryRowContext(ctx,
			"SELECT status FROM job_queue WHERE id = $1", jobID,
		).Scan(&status); err != nil {
			t.Fatalf("read job status: %v", err)
		}
		if status != "pending" && status != "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job still %q after 30s", status)
		}
		<-ticker.C
	}
	if status != "succeeded" {
		t.Fatalf("job status = %q, want succeeded", status)
	}

	var got string
	err = tdb.DB().QueryRowContext(ctx,
		"SELECT fts_document::text FROM cve_search_index WHERE cve_id = $1", cveID,
	).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		t.Fatal("search index row not rebuilt")
	}
	if err != nil {
		t.Fatalf("read rebuilt fts_document: %v", err)
	}
	if got != want {
		t.Errorf("rebuilt fts_document:\n got  %s\n want %s", got, want)
	}
}
