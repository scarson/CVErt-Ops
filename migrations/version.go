// ABOUTME: Reports the highest migration version embedded in the binary.
// ABOUTME: Parses file names with golang-migrate's iofs driver, the same parser `cvert-ops migrate` uses.
package migrations

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// LatestVersion returns the highest migration version in FS. The binary
// requires the database schema to be at exactly this version.
func LatestVersion() (int, error) {
	return latestVersion(FS)
}

func latestVersion(fsys fs.FS) (int, error) {
	src, err := iofs.New(fsys, ".")
	if err != nil {
		return 0, fmt.Errorf("open migrations: %w", err)
	}
	defer src.Close() //nolint:errcheck // read-only fs.FS source; Close has nothing to release

	version, err := src.First()
	if err != nil {
		return 0, fmt.Errorf("first migration: %w", err)
	}
	for {
		next, err := src.Next(version)
		if errors.Is(err, fs.ErrNotExist) {
			return int(version), nil //nolint:gosec // G115: migration versions are six-digit file prefixes
		}
		if err != nil {
			return 0, fmt.Errorf("migration after %d: %w", version, err)
		}
		version = next
	}
}
