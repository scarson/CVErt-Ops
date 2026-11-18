// ABOUTME: Applies migration 000063 on real Postgres, down then up then down.
// ABOUTME: Checks the two re-check columns on cves are nullable with no default and their index is partial.
package migrations_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// matchInputsColumn is one re-check column as information_schema reports it.
type matchInputsColumn struct {
	dataType  string
	nullable  string
	defaulted bool
}

// readMatchInputsColumns returns the re-check columns cves has, by name.
func readMatchInputsColumns(t *testing.T, ctx context.Context, db *sql.DB) map[string]matchInputsColumn {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT column_name, data_type, is_nullable, column_default IS NOT NULL
		FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'cves'
		  AND column_name IN ('match_inputs_hash', 'date_match_inputs_changed')`)
	if err != nil {
		t.Fatalf("read columns: %v", err)
	}
	defer rows.Close() //nolint:errcheck
	got := map[string]matchInputsColumn{}
	for rows.Next() {
		var name string
		var c matchInputsColumn
		if err := rows.Scan(&name, &c.dataType, &c.nullable, &c.defaulted); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		got[name] = c
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("columns: %v", err)
	}
	return got
}

// readMatchInputsIndex returns the re-check index's indexed column, its partial
// predicate and whether it is valid. found is false when the index does not exist.
func readMatchInputsIndex(t *testing.T, ctx context.Context, db *sql.DB) (column, predicate string, valid, found bool) {
	t.Helper()
	err := db.QueryRowContext(ctx, `SELECT a.attname, coalesce(pg_get_expr(i.indpred, i.indrelid), ''), i.indisvalid
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
		WHERE c.relname = 'cves_date_match_inputs_changed_idx'
		  AND i.indrelid = 'cves'::regclass AND i.indnatts = 1`).Scan(&column, &predicate, &valid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, false
	}
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	return column, predicate, valid, true
}

func assertMatchInputsSchemaAbsent(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	if cols := readMatchInputsColumns(t, ctx, db); len(cols) != 0 {
		t.Errorf("after down: columns %v remain, want none", cols)
	}
	if _, _, _, found := readMatchInputsIndex(t, ctx, db); found {
		t.Error("after down: cves_date_match_inputs_changed_idx remains, want it dropped")
	}
}

func TestMatchInputsRecheckMigration(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	db := tdb.DB()

	runMigrationFile(t, ctx, db, "000063_match_inputs_recheck.down.sql")
	assertMatchInputsSchemaAbsent(t, ctx, db)

	runMigrationFile(t, ctx, db, "000063_match_inputs_recheck.up.sql")

	cols := readMatchInputsColumns(t, ctx, db)
	want := map[string]matchInputsColumn{
		"match_inputs_hash":         {dataType: "text", nullable: "YES"},
		"date_match_inputs_changed": {dataType: "timestamp with time zone", nullable: "YES"},
	}
	for name, w := range want {
		got, ok := cols[name]
		if !ok {
			t.Errorf("after up: column %s missing", name)
			continue
		}
		if got != w {
			t.Errorf("after up: column %s = %+v, want %+v (nullable, no default: adding it rewrites no rows)", name, got, w)
		}
	}

	column, predicate, valid, found := readMatchInputsIndex(t, ctx, db)
	if !found {
		t.Fatal("after up: cves_date_match_inputs_changed_idx missing")
	}
	if column != "date_match_inputs_changed" || predicate != "(date_match_inputs_changed IS NOT NULL)" || !valid {
		t.Errorf("after up: index on %q where %q, valid = %v; want date_match_inputs_changed where (date_match_inputs_changed IS NOT NULL), valid",
			column, predicate, valid)
	}

	// The up file is safe to run again, as a retried deploy would.
	runMigrationFile(t, ctx, db, "000063_match_inputs_recheck.up.sql")

	runMigrationFile(t, ctx, db, "000063_match_inputs_recheck.down.sql")
	assertMatchInputsSchemaAbsent(t, ctx, db)
}
