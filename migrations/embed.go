// Package migrations embeds the SQL migration files so that the compiled
// binary carries its own schema management without requiring files on disk.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
