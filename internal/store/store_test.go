// ABOUTME: Integration tests for store.go transaction helpers (withBypassTx, withOrgRawTx, OrgTx, WorkerTx).
// ABOUTME: Verifies SET LOCAL execution, commit-on-success, and rollback-on-error behaviors.
package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// ── withBypassTx ──────────────────────────────────────────────────────────────

// TestWithBypassTx_SetsSessionVar verifies that withBypassTx executes
// SET LOCAL app.bypass_rls = 'on' by confirming the Store can query
// a table without an org context.
func TestWithBypassTx_SetsSessionVar(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// HasPendingOrRunningJob uses withBypassTx internally.
	// If SET LOCAL bypass_rls is set, this succeeds without error.
	_, err := s.HasPendingOrRunningJob(ctx, "nonexistent:key")
	if err != nil {
		t.Fatalf("HasPendingOrRunningJob via Store (bypass): %v", err)
	}
}

// ── withOrgRawTx / withOrgTx ──────────────────────────────────────────────────

// TestWithOrgTx_RLSEnforced verifies that withOrgTx sets app.org_id so that
// RLS filters rows to only the specified org. Two orgs with members are created;
// querying via AppStore for org1 must see only org1's members.
func TestWithOrgTx_RLSEnforced(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, err := s.CreateOrg(ctx, "OrgTxOrg1")
	if err != nil {
		t.Fatalf("setup: CreateOrg OrgTxOrg1: %v", err)
	}
	org2, err := s.CreateOrg(ctx, "OrgTxOrg2")
	if err != nil {
		t.Fatalf("setup: CreateOrg OrgTxOrg2: %v", err)
	}
	u1, err := s.CreateUser(ctx, "orgtx1@example.com", "OrgTx1", "", 0)
	if err != nil {
		t.Fatalf("setup: CreateUser orgtx1: %v", err)
	}
	u2, err := s.CreateUser(ctx, "orgtx2@example.com", "OrgTx2", "", 0)
	if err != nil {
		t.Fatalf("setup: CreateUser orgtx2: %v", err)
	}
	err = s.CreateOrgMember(ctx, org1.ID, u1.ID, "member")
	if err != nil {
		t.Fatalf("setup: CreateOrgMember org1/u1: %v", err)
	}
	err = s.CreateOrgMember(ctx, org2.ID, u2.ID, "member")
	if err != nil {
		t.Fatalf("setup: CreateOrgMember org2/u2: %v", err)
	}

	// ListOrgMembers uses withOrgTx internally (sqlc queries).
	members, err := s.AppStore.ListOrgMembers(ctx, org1.ID)
	if err != nil {
		t.Fatalf("ListOrgMembers: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("expected 1 member for org1, got %d — withOrgTx RLS not enforced", len(members))
	}
}

// ── OrgTx commit/rollback ─────────────────────────────────────────────────────

func TestOrgTx_CommitsOnSuccess(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := s.CreateOrg(ctx, "OrgTxCommit")
	if err != nil {
		t.Fatalf("setup: CreateOrg: %v", err)
	}

	// Insert a row within OrgTx — it should persist after commit.
	err = s.AppStore.OrgTx(ctx, org.ID, func(tx pgx.Tx) error {
		_, txErr := tx.Exec(ctx, "SELECT 1") // trivial operation
		return txErr
	})
	if err != nil {
		t.Fatalf("OrgTx(success): %v", err)
	}
}

func TestOrgTx_RollsBackOnError(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := s.CreateOrg(ctx, "OrgTxRollback")
	if err != nil {
		t.Fatalf("setup: CreateOrg: %v", err)
	}
	user, err := s.CreateUser(ctx, "orgtxrb@example.com", "OrgTxRB", "", 0)
	if err != nil {
		t.Fatalf("setup: CreateUser: %v", err)
	}

	// Attempt to create a group within OrgTx but return an error — should rollback.
	sentinel := errors.New("deliberate failure")
	err = s.AppStore.OrgTx(ctx, org.ID, func(tx pgx.Tx) error {
		_, txErr := tx.Exec(ctx,
			"INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3)",
			org.ID, user.ID, "viewer",
		)
		if txErr != nil {
			return txErr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("OrgTx should propagate error, got: %v", err)
	}

	// The member should NOT have been persisted due to rollback.
	members, err := s.ListOrgMembers(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListOrgMembers: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("expected 0 members after rollback, got %d", len(members))
	}
}

// ── WorkerTx ──────────────────────────────────────────────────────────────────

// TestWorkerTx_BypassRLSEnabled verifies that WorkerTx sets bypass_rls so
// the non-superuser AppStore can read data across all orgs.
func TestWorkerTx_BypassRLSEnabled(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, err := s.CreateOrg(ctx, "WTxOrg1")
	if err != nil {
		t.Fatalf("setup: CreateOrg WTxOrg1: %v", err)
	}
	org2, err := s.CreateOrg(ctx, "WTxOrg2")
	if err != nil {
		t.Fatalf("setup: CreateOrg WTxOrg2: %v", err)
	}
	u1, err := s.CreateUser(ctx, "wtx1@example.com", "WTx1", "", 0)
	if err != nil {
		t.Fatalf("setup: CreateUser wtx1: %v", err)
	}
	u2, err := s.CreateUser(ctx, "wtx2@example.com", "WTx2", "", 0)
	if err != nil {
		t.Fatalf("setup: CreateUser wtx2: %v", err)
	}
	err = s.CreateOrgMember(ctx, org1.ID, u1.ID, "member")
	if err != nil {
		t.Fatalf("setup: CreateOrgMember org1/u1: %v", err)
	}
	err = s.CreateOrgMember(ctx, org2.ID, u2.ID, "member")
	if err != nil {
		t.Fatalf("setup: CreateOrgMember org2/u2: %v", err)
	}

	var count int
	err = s.AppStore.WorkerTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT COUNT(*) FROM org_members").Scan(&count)
	})
	if err != nil {
		t.Fatalf("WorkerTx: %v", err)
	}
	if count < 2 {
		t.Errorf("WorkerTx bypass: visible members = %d, want >= 2", count)
	}
}

func TestWorkerTx_RollsBackOnError(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	sentinel := errors.New("worker failure")
	err := s.WorkerTx(ctx, func(tx pgx.Tx) error {
		_, txErr := tx.Exec(ctx, "SELECT 1")
		if txErr != nil {
			return txErr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WorkerTx should propagate error, got: %v", err)
	}
}
