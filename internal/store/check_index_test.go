// ABOUTME: Pins the version check indexes to the expressions the check statements compare.
// ABOUTME: Each statement's predicate is built from the same function, so an index is used only while the two match.
package store_test

import (
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/ecosystem"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/migrations"
)

// checkLookupsMigration returns the body of the up migration that creates the
// version check indexes.
func checkLookupsMigration(t *testing.T) string {
	t.Helper()
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
	return string(body)
}

func TestCheckPackageIndexMatchesFoldedName(t *testing.T) {
	t.Parallel()
	want := ecosystem.FoldedNameSQL("ecosystem", "package_name")
	if !strings.Contains(checkLookupsMigration(t), want) {
		t.Errorf("check_lookups migration does not contain the folded name expression %q", want)
	}
}

// latestIndexMigration returns the body of the last up migration, in migration
// order, that creates the index name, since a later migration may rebuild it.
func latestIndexMigration(t *testing.T, name string) string {
	t.Helper()
	names, err := fs.Glob(migrations.FS, "*.up.sql")
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	creates := regexp.MustCompile(`CREATE INDEX CONCURRENTLY IF NOT EXISTS ` + regexp.QuoteMeta(name) + `\s`)
	slices.Sort(names)
	for _, n := range slices.Backward(names) {
		body, err := fs.ReadFile(migrations.FS, n)
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		if creates.Match(body) {
			return string(body)
		}
	}
	t.Fatalf("no up migration creates %s", name)
	return ""
}

func TestCheckCPEIndexMatchesQuery(t *testing.T) {
	t.Parallel()
	want := "ON cve_cpe_matches ((" + store.CPEIndexExpr("cpe_normalized") + "))"
	if !strings.Contains(latestIndexMigration(t, "cve_cpe_matches_check_idx"), want) {
		t.Errorf("the last migration that creates cve_cpe_matches_check_idx does not index the CPE expression: want %q", want)
	}
}

func TestCheckCNAIndexMatchesQuery(t *testing.T) {
	t.Parallel()
	want := "ON cve_cna_affected ((" + store.CNANameIndexExpr("vendor") + "), (" + store.CNANameIndexExpr("product") + "))"
	if !strings.Contains(checkLookupsMigration(t), want) {
		t.Errorf("check_lookups migration does not index the CNA name expressions: want %q", want)
	}
}
