// ABOUTME: Tests for transaction-scoped statement timeout override.
// ABOUTME: Verifies SetStatementTimeout cancels slow queries within a transaction.
package store_test

import (
	"context"
	"testing"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestSetStatementTimeout_CancelsSlowQuery(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	tx, err := tdb.DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback() //nolint:errcheck

	// Set a very short timeout (1ms)
	require.NoError(t, store.SetStatementTimeout(ctx, tx, 1))

	// This 1-second sleep should be cancelled by the 1ms timeout
	_, err = tx.ExecContext(ctx, "SELECT pg_sleep(1)")
	require.Error(t, err)
	require.Contains(t, err.Error(), "canceling statement due to statement timeout")
}
