// ABOUTME: Integration tests for OrgTx and WorkerTx helpers in store/store.go.
// ABOUTME: Verifies SET LOCAL app.org_id enforcement and RLS fail-closed guarantee.
package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// TestOrgTx_SetsOrgID verifies that OrgTx sets app.org_id for the duration of
// the transaction and that RLS applies (org_members for other org are invisible).
// Uses AppStore (cvert_ops_app, NOBYPASSRLS) to enforce RLS policies.
func TestOrgTx_SetsOrgID(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create two orgs and one member each using the superuser store (bypasses RLS).
	org1, _ := s.CreateOrg(ctx, "RLSOrg1a")
	org2, _ := s.CreateOrg(ctx, "RLSOrg1b")
	user1, _ := s.CreateUser(ctx, "rlsuser1a@example.com", "RLSUser1a", "", 0)
	user2, _ := s.CreateUser(ctx, "rlsuser1b@example.com", "RLSUser1b", "", 0)
	_ = s.CreateOrgMember(ctx, org1.ID, user1.ID, "member")
	_ = s.CreateOrgMember(ctx, org2.ID, user2.ID, "member")

	// Open OrgTx for org1 using the app-role store — RLS is enforced.
	var visibleCount int
	err := s.AppStore.OrgTx(ctx, org1.ID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT COUNT(*) FROM org_members").Scan(&visibleCount)
	})
	if err != nil {
		t.Fatalf("OrgTx: %v", err)
	}
	// With app.org_id = org1.ID, only org1's member is visible.
	if visibleCount != 1 {
		t.Errorf("OrgTx: visible members = %d, want 1 (RLS should filter org2's member)", visibleCount)
	}
}

// TestOrgTx_FailClosed verifies that a raw query with NO app.org_id set returns
// 0 rows — not an error. This is the RLS fail-closed guarantee.
// CRITICAL: if this test fails, the dual-layer isolation is broken.
func TestOrgTx_FailClosed(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Insert an org + member using the superuser store (bypasses RLS for setup).
	org, _ := s.CreateOrg(ctx, "RLSOrg2")
	user, _ := s.CreateUser(ctx, "rlsuser2@example.com", "RLSUser2", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user.ID, "owner")

	// Acquire a raw connection from the app-role pool with no SET LOCAL app.org_id.
	conn, err := s.AppStore.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire app pool conn: %v", err)
	}
	defer conn.Release()

	// Query org_members with no org context — must return 0 rows (fail-closed).
	var count int
	if err := conn.QueryRow(ctx, "SELECT COUNT(*) FROM org_members").Scan(&count); err != nil {
		t.Fatalf("fail-closed query: %v", err)
	}
	if count != 0 {
		t.Errorf("fail-closed: expected 0 rows with no app.org_id, got %d — RLS isolation broken", count)
	}
}

// TestWorkerTx_BypassRLS verifies that WorkerTx with app.bypass_rls = 'on'
// can read rows from all orgs. Uses AppStore to confirm the bypass is effective
// for non-superuser connections.
func TestWorkerTx_BypassRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create two orgs with one member each using superuser store.
	org1, _ := s.CreateOrg(ctx, "RLSOrg3a")
	org2, _ := s.CreateOrg(ctx, "RLSOrg3b")
	user1, _ := s.CreateUser(ctx, "rlsuser3a@example.com", "RLSUser3a", "", 0)
	user2, _ := s.CreateUser(ctx, "rlsuser3b@example.com", "RLSUser3b", "", 0)
	_ = s.CreateOrgMember(ctx, org1.ID, user1.ID, "member")
	_ = s.CreateOrgMember(ctx, org2.ID, user2.ID, "member")

	// WorkerTx on the app-role store sets bypass_rls = 'on' — should see all rows.
	var count int
	err := s.AppStore.WorkerTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT COUNT(*) FROM org_members").Scan(&count)
	})
	if err != nil {
		t.Fatalf("WorkerTx: %v", err)
	}
	if count != 2 {
		t.Errorf("WorkerTx bypass: visible members = %d, want 2 (should see both orgs)", count)
	}
}
