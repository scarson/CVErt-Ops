// ABOUTME: Tests for LatestVersion, which reports the highest embedded migration version.
// ABOUTME: Uses in-memory filesystems for parsing cases and the real embedded FS as a smoke check.
package migrations

import (
	"testing"
	"testing/fstest"
)

func TestLatestVersion_ReturnsHighestVersion(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"000001_init.up.sql":     {Data: []byte("SELECT 1;")},
		"000001_init.down.sql":   {Data: []byte("SELECT 1;")},
		"000010_tenth.up.sql":    {Data: []byte("SELECT 1;")},
		"000010_tenth.down.sql":  {Data: []byte("SELECT 1;")},
		"000002_second.up.sql":   {Data: []byte("SELECT 1;")},
		"000002_second.down.sql": {Data: []byte("SELECT 1;")},
	}
	got, err := latestVersion(fsys)
	if err != nil {
		t.Fatalf("latestVersion: %v", err)
	}
	if got != 10 {
		t.Errorf("latestVersion = %d, want 10", got)
	}
}

func TestLatestVersion_NoMigrations_Error(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{"README.txt": {Data: []byte("not a migration")}}
	if _, err := latestVersion(fsys); err == nil {
		t.Error("latestVersion on a filesystem without migrations: got nil error, want error")
	}
}

func TestLatestVersion_EmbeddedFS(t *testing.T) {
	t.Parallel()
	got, err := LatestVersion()
	if err != nil {
		t.Fatalf("LatestVersion: %v", err)
	}
	// 45 is the version of the newest migration when this test was written;
	// the embedded set only grows.
	if got < 45 {
		t.Errorf("LatestVersion = %d, want >= 45", got)
	}
}
