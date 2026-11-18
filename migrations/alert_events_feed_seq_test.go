// ABOUTME: Applies migration 000062 to existing alert events on real Postgres, down then up.
// ABOUTME: Checks history gets negative feed positions in fire order, new events follow, and the column's constraints.
package migrations_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/golang-migrate/migrate/v4/database/multistmt"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
	"github.com/scarson/cvert-ops/migrations"
)

// runMigrationFile runs a migration file one statement at a time, split by
// golang-migrate's parser, as the migrate command does.
func runMigrationFile(t *testing.T, ctx context.Context, db *sql.DB, name string) {
	t.Helper()
	script, err := migrations.FS.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var execErr error
	parseErr := multistmt.Parse(bytes.NewReader(script), []byte(";"), 1<<20, func(stmt []byte) bool {
		if len(bytes.TrimSpace(stmt)) == 0 {
			return true
		}
		if _, execErr = db.ExecContext(ctx, string(stmt)); execErr != nil {
			t.Errorf("%s: statement %q: %v", name, stmt, execErr)
			return false
		}
		return true
	})
	if parseErr != nil && !errors.Is(parseErr, io.EOF) {
		t.Fatalf("parse %s: %v", name, parseErr)
	}
	if execErr != nil {
		t.FailNow()
	}
}

func TestAlertEventsFeedSeqMigration(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	db := tdb.DB()

	runMigrationFile(t, ctx, db, "000062_alert_events_feed_seq.down.sql")

	org, err := tdb.CreateOrg(ctx, "Feed Migration Org")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	rule, err := tdb.CreateAlertRule(ctx, org.ID, store.CreateAlertRuleParams{
		Name: "r", Logic: "and", Conditions: json.RawMessage(`[{"field":"severity","operator":"eq","value":"high"}]`), Status: "active",
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	// Inserted out of fire order: the backfill orders by first fire.
	if _, err := db.ExecContext(ctx, `INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash, first_fired_at) VALUES
		($1, $2, 'CVE-2024-3', 'h', now() - interval '1 day'),
		($1, $2, 'CVE-2024-1', 'h', now() - interval '3 days'),
		($1, $2, 'CVE-2024-2', 'h', now() - interval '2 days')`, org.ID, rule.ID); err != nil {
		t.Fatalf("insert events: %v", err)
	}

	runMigrationFile(t, ctx, db, "000062_alert_events_feed_seq.up.sql")

	if _, err := tdb.InsertAlertEvent(ctx, org.ID, rule.ID, "CVE-2024-4", "h", false); err != nil {
		t.Fatalf("insert event after migration: %v", err)
	}

	rows, err := db.QueryContext(ctx, `SELECT cve_id, feed_seq FROM alert_events WHERE org_id = $1 ORDER BY feed_seq`, org.ID)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close() //nolint:errcheck
	var order []string
	var seqs []int64
	for rows.Next() {
		var cve string
		var seq int64
		if err := rows.Scan(&cve, &seq); err != nil {
			t.Fatalf("scan: %v", err)
		}
		order = append(order, cve)
		seqs = append(seqs, seq)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	want := []string{"CVE-2024-1", "CVE-2024-2", "CVE-2024-3", "CVE-2024-4"}
	if len(order) != len(want) {
		t.Fatalf("feed order = %v (positions %v), want %v", order, seqs, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("feed order = %v (positions %v), want %v: history by first fire, then the new event", order, seqs, want)
		}
	}
	if seqs[0] != -3 || seqs[1] != -2 || seqs[2] != -1 || seqs[3] < 1 {
		t.Errorf("positions = %v, want -3, -2, -1, then 1 or more", seqs)
	}

	// An insert that draws no position is refused rather than given an unordered one.
	if _, err := db.ExecContext(ctx, `INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash)
		VALUES ($1, $2, 'CVE-2024-5', 'h')`, org.ID, rule.ID); err == nil {
		t.Error("insert without feed_seq succeeded, want a NOT NULL violation")
	}

	var unique, valid bool
	if err := db.QueryRowContext(ctx, `SELECT i.indisunique, i.indisvalid FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = 'alert_events_feed_seq_uq'`).Scan(&unique, &valid); err != nil {
		t.Fatalf("read index: %v", err)
	}
	var owned bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_depend d
		JOIN pg_class s ON s.oid = d.objid AND s.relname = 'alert_event_feed_seq'
		WHERE d.refobjid = 'alert_events'::regclass AND d.deptype = 'a')`).Scan(&owned); err != nil {
		t.Fatalf("read sequence owner: %v", err)
	}
	if !unique || !valid || !owned {
		t.Errorf("index unique = %v, valid = %v; sequence owned by the column = %v; want all true", unique, valid, owned)
	}
}
