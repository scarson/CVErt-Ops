// ABOUTME: Applies migration 000065 on real Postgres, down then up then down.
// ABOUTME: Checks the change-date indexes on cves pair each date with cve_id after up and are single-column after down.
package migrations_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// readChangeDateIndexes returns the definition of each named index on cves that
// exists, with " (invalid)" appended to an index Postgres marks invalid.
func readChangeDateIndexes(t *testing.T, ctx context.Context, db *sql.DB, names []string) map[string]string {
	t.Helper()
	got := map[string]string{}
	for _, name := range names {
		var def string
		var valid bool
		err := db.QueryRowContext(ctx, `SELECT pg_get_indexdef(i.indexrelid), i.indisvalid
			FROM pg_index i
			JOIN pg_class c ON c.oid = i.indexrelid
			WHERE c.relname = $1 AND c.relnamespace = to_regnamespace(current_schema())`, name).Scan(&def, &valid)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			t.Fatalf("read index %s: %v", name, err)
		}
		if !valid {
			def += " (invalid)"
		}
		got[name] = def
	}
	return got
}

func TestChangeDateKeysetIndexesMigration(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	db := tdb.DB()

	var schema string
	if err := db.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatalf("current schema: %v", err)
	}
	def := func(name, rest string) string {
		return fmt.Sprintf("CREATE INDEX %s ON %s.cves USING btree %s", name, schema, rest)
	}
	singleColumn := map[string]string{
		"cves_date_modified_canonical_idx":   def("cves_date_modified_canonical_idx", "(date_modified_canonical DESC)"),
		"cves_date_epss_updated_idx":         def("cves_date_epss_updated_idx", "(date_epss_updated)"),
		"cves_date_match_inputs_changed_idx": def("cves_date_match_inputs_changed_idx", "(date_match_inputs_changed) WHERE (date_match_inputs_changed IS NOT NULL)"),
	}
	keyset := map[string]string{
		"cves_date_modified_canonical_cve_id_idx":   def("cves_date_modified_canonical_cve_id_idx", "(date_modified_canonical, cve_id)"),
		"cves_date_epss_updated_cve_id_idx":         def("cves_date_epss_updated_cve_id_idx", "(date_epss_updated, cve_id)"),
		"cves_date_match_inputs_changed_cve_id_idx": def("cves_date_match_inputs_changed_cve_id_idx", "(date_match_inputs_changed, cve_id) WHERE (date_match_inputs_changed IS NOT NULL)"),
	}
	var names []string
	for name := range maps.Keys(singleColumn) {
		names = append(names, name)
	}
	for name := range maps.Keys(keyset) {
		names = append(names, name)
	}

	check := func(stage string, want map[string]string) {
		t.Helper()
		got := readChangeDateIndexes(t, ctx, db, names)
		if !maps.Equal(got, want) {
			t.Errorf("%s: change-date indexes on cves =\n%v\nwant\n%v", stage, got, want)
		}
	}

	runMigrationFile(t, ctx, db, "000065_change_date_keyset_indexes.down.sql")
	check("after down", singleColumn)

	runMigrationFile(t, ctx, db, "000065_change_date_keyset_indexes.up.sql")
	check("after up", keyset)

	// The up file is safe to run again, as a retried deploy would.
	runMigrationFile(t, ctx, db, "000065_change_date_keyset_indexes.up.sql")
	check("after second up", keyset)

	runMigrationFile(t, ctx, db, "000065_change_date_keyset_indexes.down.sql")
	check("after second down", singleColumn)
}
