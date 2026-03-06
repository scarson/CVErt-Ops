// ABOUTME: Integration tests for job queue store methods against real Postgres.
// ABOUTME: Validates enqueue, claim, complete, fail (backoff + dead), recover stale, and dedup check.
package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// ── EnqueueJob tests ──────────────────────────────────────────────────────────

func TestEnqueueJob_Basic(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	payload := json.RawMessage(`{"feed":"nvd"}`)
	id, err := db.EnqueueJob(ctx, "feed_ingest", 0, payload, nil, 3, nil)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}
	if id == uuid.Nil {
		t.Error("EnqueueJob should return a non-nil UUID")
	}
}

func TestEnqueueJob_WithLockKey(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	payload := json.RawMessage(`{"feed":"mitre"}`)
	lk := "feed:mitre"
	id, err := db.EnqueueJob(ctx, "feed_ingest", 0, payload, &lk, 3, nil)
	if err != nil {
		t.Fatalf("EnqueueJob(lockKey): %v", err)
	}
	if id == uuid.Nil {
		t.Error("EnqueueJob should return a non-nil UUID")
	}
}

func TestEnqueueJob_WithRunAfter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	payload := json.RawMessage(`{"feed":"epss"}`)
	future := time.Now().Add(1 * time.Hour)
	id, err := db.EnqueueJob(ctx, "feed_ingest", 0, payload, nil, 3, &future)
	if err != nil {
		t.Fatalf("EnqueueJob(runAfter): %v", err)
	}
	if id == uuid.Nil {
		t.Error("EnqueueJob should return a non-nil UUID")
	}

	// Claiming should return nil because run_after is in the future.
	job, err := db.ClaimJob(ctx, "feed_ingest", "worker-1")
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}
	if job != nil {
		t.Error("ClaimJob should return nil for future run_after job")
	}
}

// ── ClaimJob tests ────────────────────────────────────────────────────────────

func TestClaimJob_HappyPath(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	payload := json.RawMessage(`{"cve":"CVE-2024-0001"}`)
	_, err := db.EnqueueJob(ctx, "alert_eval", 0, payload, nil, 3, nil)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	job, err := db.ClaimJob(ctx, "alert_eval", "worker-1")
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}
	if job == nil {
		t.Fatal("ClaimJob returned nil, expected a job")
	}
	if job.Queue != "alert_eval" {
		t.Errorf("Queue = %q, want alert_eval", job.Queue)
	}
	if job.Attempts != 1 {
		t.Errorf("Attempts = %d, want 1 (incremented by claim)", job.Attempts)
	}
}

func TestClaimJob_NoPendingJobs(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// No jobs enqueued.
	job, err := db.ClaimJob(ctx, "empty_queue", "worker-1")
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}
	if job != nil {
		t.Error("ClaimJob should return nil when no pending jobs exist")
	}
}

func TestClaimJob_SkipsRunningJobs(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	payload := json.RawMessage(`{"task":"only-one"}`)
	_, err := db.EnqueueJob(ctx, "single_task", 0, payload, nil, 3, nil)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	// First claim succeeds.
	job1, err := db.ClaimJob(ctx, "single_task", "worker-1")
	if err != nil {
		t.Fatalf("ClaimJob(1): %v", err)
	}
	if job1 == nil {
		t.Fatal("first claim should succeed")
	}

	// Second claim returns nil — the only job is now running.
	job2, err := db.ClaimJob(ctx, "single_task", "worker-2")
	if err != nil {
		t.Fatalf("ClaimJob(2): %v", err)
	}
	if job2 != nil {
		t.Error("second claim should return nil (job already running)")
	}
}

// ── CompleteJob tests ─────────────────────────────────────────────────────────

func TestCompleteJob_HappyPath(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	payload := json.RawMessage(`{"task":"complete-me"}`)
	id, err := db.EnqueueJob(ctx, "completable", 0, payload, nil, 3, nil)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	// Claim first.
	_, err = db.ClaimJob(ctx, "completable", "worker-1")
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}

	// Complete.
	if err := db.CompleteJob(ctx, id); err != nil {
		t.Fatalf("CompleteJob: %v", err)
	}

	// Verify job is no longer claimable (status = 'succeeded').
	job, err := db.ClaimJob(ctx, "completable", "worker-2")
	if err != nil {
		t.Fatalf("ClaimJob after complete: %v", err)
	}
	if job != nil {
		t.Error("completed job should not be claimable")
	}
}

func TestCompleteJob_NonexistentID(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Completing a non-existent job should not error (UPDATE ... WHERE id = $1 affects 0 rows).
	if err := db.CompleteJob(ctx, uuid.New()); err != nil {
		t.Fatalf("CompleteJob(nonexistent): %v", err)
	}
}

// ── FailJob tests ─────────────────────────────────────────────────────────────

func TestFailJob_BackoffRetry(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	payload := json.RawMessage(`{"task":"fail-retry"}`)
	id, err := db.EnqueueJob(ctx, "failable", 0, payload, nil, 3, nil)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	// Claim and fail.
	_, err = db.ClaimJob(ctx, "failable", "worker-1")
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}

	if err := db.FailJob(ctx, id, "temporary error"); err != nil {
		t.Fatalf("FailJob: %v", err)
	}

	// The job should be back to 'pending' with a future run_after (backoff).
	// Since run_after is in the future, immediate claim should return nil.
	job, err := db.ClaimJob(ctx, "failable", "worker-2")
	if err != nil {
		t.Fatalf("ClaimJob after fail: %v", err)
	}
	if job != nil {
		t.Error("failed job should have backoff run_after in the future")
	}
}

func TestFailJob_MaxAttemptsExhausted(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	payload := json.RawMessage(`{"task":"die"}`)
	id, err := db.EnqueueJob(ctx, "mortal", 0, payload, nil, 1, nil) // max_attempts = 1
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	// Claim increments attempts to 1 (= max_attempts).
	_, err = db.ClaimJob(ctx, "mortal", "worker-1")
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}

	if err := db.FailJob(ctx, id, "fatal error"); err != nil {
		t.Fatalf("FailJob: %v", err)
	}

	// Job should be 'dead' — verify by checking it's not claimable.
	job, err := db.ClaimJob(ctx, "mortal", "worker-2")
	if err != nil {
		t.Fatalf("ClaimJob after dead: %v", err)
	}
	if job != nil {
		t.Error("dead job should not be claimable")
	}

	// Verify the status is 'dead' via direct query.
	var status string
	if err := db.DB().QueryRowContext(ctx,
		"SELECT status FROM job_queue WHERE id = $1", id,
	).Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "dead" {
		t.Errorf("status = %q, want dead", status)
	}
}

// ── RecoverStaleJobs tests ────────────────────────────────────────────────────

func TestRecoverStaleJobs_RecoversStuck(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	payload := json.RawMessage(`{"task":"stuck"}`)
	id, err := db.EnqueueJob(ctx, "recoverable", 0, payload, nil, 3, nil)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	// Claim the job.
	_, err = db.ClaimJob(ctx, "recoverable", "worker-1")
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}

	// Manually backdate locked_at to simulate a stuck job.
	_, err = db.DB().ExecContext(ctx,
		"UPDATE job_queue SET locked_at = $1 WHERE id = $2",
		time.Now().Add(-10*time.Minute), id,
	)
	if err != nil {
		t.Fatalf("backdate locked_at: %v", err)
	}

	// Recover jobs stuck for > 5 minutes.
	n, err := db.RecoverStaleJobs(ctx, 5*time.Minute)
	if err != nil {
		t.Fatalf("RecoverStaleJobs: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 recovered job, got %d", n)
	}

	// The recovered job should be claimable again.
	job, err := db.ClaimJob(ctx, "recoverable", "worker-2")
	if err != nil {
		t.Fatalf("ClaimJob after recovery: %v", err)
	}
	if job == nil {
		t.Error("recovered job should be claimable")
	}
}

func TestRecoverStaleJobs_NoStaleJobs(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// No jobs at all.
	n, err := db.RecoverStaleJobs(ctx, 5*time.Minute)
	if err != nil {
		t.Fatalf("RecoverStaleJobs: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 recovered jobs, got %d", n)
	}
}

func TestRecoverStaleJobs_RecentRunningNotRecovered(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	payload := json.RawMessage(`{"task":"not-stuck"}`)
	_, err := db.EnqueueJob(ctx, "fresh", 0, payload, nil, 3, nil)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	// Claim the job — locked_at is now().
	_, err = db.ClaimJob(ctx, "fresh", "worker-1")
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}

	// Recover with 5-minute threshold — recently claimed job should not be recovered.
	n, err := db.RecoverStaleJobs(ctx, 5*time.Minute)
	if err != nil {
		t.Fatalf("RecoverStaleJobs: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 recovered (job is recent), got %d", n)
	}
}

// ── HasPendingOrRunningJob tests ──────────────────────────────────────────────

func TestHasPendingOrRunningJob_Pending(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	lk := "feed:nvd"
	_, err := db.EnqueueJob(ctx, "feed_ingest", 0, json.RawMessage(`{}`), &lk, 3, nil)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	has, err := db.HasPendingOrRunningJob(ctx, "feed:nvd")
	if err != nil {
		t.Fatalf("HasPendingOrRunningJob: %v", err)
	}
	if !has {
		t.Error("should return true for pending job with matching lock_key")
	}
}

func TestHasPendingOrRunningJob_Running(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	lk := "feed:mitre"
	_, err := db.EnqueueJob(ctx, "feed_ingest", 0, json.RawMessage(`{}`), &lk, 3, nil)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	// Claim to move to 'running'.
	_, err = db.ClaimJob(ctx, "feed_ingest", "worker-1")
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}

	has, err := db.HasPendingOrRunningJob(ctx, "feed:mitre")
	if err != nil {
		t.Fatalf("HasPendingOrRunningJob: %v", err)
	}
	if !has {
		t.Error("should return true for running job with matching lock_key")
	}
}

func TestHasPendingOrRunningJob_Succeeded(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	lk := "feed:kev"
	id, err := db.EnqueueJob(ctx, "feed_ingest", 0, json.RawMessage(`{}`), &lk, 3, nil)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	_, _ = db.ClaimJob(ctx, "feed_ingest", "worker-1")
	_ = db.CompleteJob(ctx, id)

	has, err := db.HasPendingOrRunningJob(ctx, "feed:kev")
	if err != nil {
		t.Fatalf("HasPendingOrRunningJob: %v", err)
	}
	if has {
		t.Error("should return false for succeeded job")
	}
}

func TestHasPendingOrRunningJob_Dead(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	lk := "feed:epss"
	id, err := db.EnqueueJob(ctx, "feed_ingest", 0, json.RawMessage(`{}`), &lk, 1, nil) // max 1 attempt
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	_, _ = db.ClaimJob(ctx, "feed_ingest", "worker-1")
	_ = db.FailJob(ctx, id, "fatal")

	has, err := db.HasPendingOrRunningJob(ctx, "feed:epss")
	if err != nil {
		t.Fatalf("HasPendingOrRunningJob: %v", err)
	}
	if has {
		t.Error("should return false for dead job")
	}
}

func TestHasPendingOrRunningJob_NoMatch(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	has, err := db.HasPendingOrRunningJob(ctx, "nonexistent:key")
	if err != nil {
		t.Fatalf("HasPendingOrRunningJob: %v", err)
	}
	if has {
		t.Error("should return false for non-existent lock_key")
	}
}

func TestClaimJob_PriorityOrdering(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Enqueue low priority first, high priority second.
	_, err := db.EnqueueJob(ctx, "priority_q", 1, json.RawMessage(`{"p":"low"}`), nil, 3, nil)
	if err != nil {
		t.Fatalf("EnqueueJob low: %v", err)
	}
	_, err = db.EnqueueJob(ctx, "priority_q", 10, json.RawMessage(`{"p":"high"}`), nil, 3, nil)
	if err != nil {
		t.Fatalf("EnqueueJob high: %v", err)
	}

	// Claim should return the higher priority job first.
	job, err := db.ClaimJob(ctx, "priority_q", "worker-1")
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}
	if job == nil {
		t.Fatal("ClaimJob returned nil")
	}

	var p struct {
		P string `json:"p"`
	}
	if err := json.Unmarshal(job.Payload, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if p.P != "high" {
		t.Errorf("expected high-priority job first, got %q", p.P)
	}
}
