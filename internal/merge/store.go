// ABOUTME: Interface for the store dependency used by the merge pipeline.
// ABOUTME: Decouples merge from the concrete store.Store for testability.
package merge

import "database/sql"

// Store defines the database access the merge pipeline requires.
// *store.Store satisfies this interface implicitly.
type Store interface {
	DB() *sql.DB
}
