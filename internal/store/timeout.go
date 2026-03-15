// ABOUTME: Transaction-scoped statement timeout override for long-running operations.
// ABOUTME: Use SetStatementTimeout within a transaction to override the connection-level default.
package store

import (
	"context"
	"database/sql"
	"fmt"
)

// SetStatementTimeout overrides the connection-level statement_timeout for the
// current transaction. The timeout resets automatically when the transaction
// ends. Use for operations expected to exceed the default 14s timeout
// (activation scans, complex DSL queries).
func SetStatementTimeout(ctx context.Context, tx *sql.Tx, ms int) error {
	_, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", ms))
	return err
}
