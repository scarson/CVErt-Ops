// ABOUTME: Integration test for the settings the evaluator applies before a rule's candidate query.
// ABOUTME: Checks JIT is off inside the transaction and back to the server default after it ends.
package alert

import (
	"context"
	"database/sql"
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// showJIT returns the jit setting as conn or tx sees it.
func showJIT(ctx context.Context, t *testing.T, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) string {
	t.Helper()
	var jit string
	if err := q.QueryRowContext(ctx, "SHOW jit").Scan(&jit); err != nil {
		t.Fatalf("SHOW jit: %v", err)
	}
	return jit
}

func TestPrepareCandidateTx_TurnsJITOffForTheTransaction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := testutil.NewTestDB(t)
	conn, err := tdb.DB().Conn(ctx)
	if err != nil {
		t.Fatalf("Conn: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	if before := showJIT(ctx, t, conn); before != "on" {
		t.Fatalf("server jit = %q; the test needs the default, on, to show the change", before)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := prepareCandidateTx(ctx, tx); err != nil {
		t.Fatalf("prepareCandidateTx: %v", err)
	}
	if got := showJIT(ctx, t, tx); got != "off" {
		t.Errorf("jit in the transaction = %q, want off", got)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	// SET LOCAL ends with the transaction, so a pooled connection keeps the default.
	if after := showJIT(ctx, t, conn); after != "on" {
		t.Errorf("jit after the transaction = %q, want on", after)
	}
}
