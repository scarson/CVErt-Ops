// ABOUTME: Integration test for the settings the evaluator applies before a rule's candidate query.
// ABOUTME: Checks JIT and parallel query are off inside the transaction and back to the server defaults after it ends.
package alert

import (
	"context"
	"database/sql"
	"testing"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// show returns a setting as conn or tx sees it.
func show(ctx context.Context, t *testing.T, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, setting string) string {
	t.Helper()
	var v string
	if err := q.QueryRowContext(ctx, "SHOW "+setting).Scan(&v); err != nil {
		t.Fatalf("SHOW %s: %v", setting, err)
	}
	return v
}

func TestPrepareRuleQueryTx_TurnsJITAndParallelQueryOffForTheTransaction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := testutil.NewTestDB(t)
	conn, err := tdb.DB().Conn(ctx)
	if err != nil {
		t.Fatalf("Conn: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	settings := []struct{ name, inTx string }{
		{"jit", "off"},
		{"max_parallel_workers_per_gather", "0"},
	}
	defaults := map[string]string{}
	for _, s := range settings {
		defaults[s.name] = show(ctx, t, conn, s.name)
		if defaults[s.name] == s.inTx {
			t.Fatalf("server %s = %q; the test needs a default other than %q to show the change", s.name, defaults[s.name], s.inTx)
		}
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := dsl.PrepareRuleQueryTx(ctx, tx); err != nil {
		t.Fatalf("PrepareRuleQueryTx: %v", err)
	}
	for _, s := range settings {
		if got := show(ctx, t, tx, s.name); got != s.inTx {
			t.Errorf("%s in the transaction = %q, want %q", s.name, got, s.inTx)
		}
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	// SET LOCAL ends with the transaction, so a pooled connection keeps the defaults.
	for _, s := range settings {
		if got := show(ctx, t, conn, s.name); got != defaults[s.name] {
			t.Errorf("%s after the transaction = %q, want the default %q", s.name, got, defaults[s.name])
		}
	}
}
