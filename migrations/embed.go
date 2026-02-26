// Package migrations embeds the SQL migration files so that the compiled
// binary carries its own schema management without requiring files on disk.
package migrations

import "embed"

//go:embed *.sql
// FS holds all migration SQL files embedded in the binary at compile time.
var FS embed.FS
