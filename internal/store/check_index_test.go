// ABOUTME: Pins the version check package index to the expression ecosystem.FoldedNameSQL builds.
// ABOUTME: The check query is built from that function, so the index is used only while the two match.
package store_test

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/ecosystem"
	"github.com/scarson/cvert-ops/migrations"
)

func TestCheckPackageIndexMatchesFoldedName(t *testing.T) {
	t.Parallel()
	names, err := fs.Glob(migrations.FS, "*_check_lookups.up.sql")
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	if len(names) != 1 {
		t.Fatalf("found %d check_lookups up migrations, want 1: %v", len(names), names)
	}
	body, err := fs.ReadFile(migrations.FS, names[0])
	if err != nil {
		t.Fatalf("read %s: %v", names[0], err)
	}
	want := ecosystem.FoldedNameSQL("ecosystem", "package_name")
	if !strings.Contains(string(body), want) {
		t.Errorf("%s does not contain the folded name expression %q", names[0], want)
	}
}
