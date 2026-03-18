// ABOUTME: Shared database/sql nullable type conversion helpers.
// ABOUTME: Eliminates duplication across store, merge, and other packages.
package dbutil

import (
	"database/sql"
)

// NullString converts a Go string to sql.NullString. An empty string is treated
// as NULL (Valid=false). Use NullStringPtr when empty strings should be preserved
// as distinct from NULL.
func NullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// NullStringPtr converts a *string to sql.NullString; nil maps to NULL.
func NullStringPtr(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}
