//go:build keptingest

// ABOUTME: Times a full activation scan of the limit rule on a disposable restored copy (design section 13, M8).
// ABOUTME: Runs only with -tags keptingest and KEPT_INGEST_COPY_DATABASE_URL; it migrates and writes to that copy only.
package alert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/migrations"
)

// keptIngestCopyMarker names the variable that must hold the disposable copy's container
// name before this test runs, so it cannot be pointed at another database by mistake.
const keptIngestCopyMarker = "KEPT_INGEST_COPY_CONFIRM"

// TestKeptIngestActivation migrates the copy to this branch's head, creates an
// organisation and the limit rule under "or" with status activating, and times
// EvaluateActivation as the worker runs it (the long statement timeout of 120 s).
func TestKeptIngestActivation(t *testing.T) {
	ctx := context.Background()
	if os.Getenv(keptIngestCopyMarker) != "cvert-match2-activation-copy" {
		t.Skipf("%s must name the disposable copy", keptIngestCopyMarker)
	}
	db := openMeasuredDB(t, "KEPT_INGEST_COPY_DATABASE_URL", "KEPT_INGEST_COPY_USER", "KEPT_INGEST_COPY_PASSWORD")
	dir := resultsDir(t)

	migrateCopy(ctx, t)

	raw, err := os.ReadFile(filepath.Join(dir, "inputs.json"))
	if err != nil {
		t.Fatalf("read inputs from the read-only run: %v", err)
	}
	var in keptInputs
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("parse inputs: %v", err)
	}
	var conds []dsl.Condition
	for _, p := range in.Products {
		conds = append(conds, condition(t, "affected.cpe_product", "eq", p))
	}
	for _, n := range in.Packages {
		conds = append(conds, condition(t, "affected.package", "eq", n))
	}
	compileMeasured(t, dsl.LogicOr, conds...) // the rule must pass validation, as the API requires
	condJSON, err := json.Marshal(conds)
	if err != nil {
		t.Fatalf("marshal conditions: %v", err)
	}

	pool := copyPool(ctx, t)
	st := store.New(pool)
	orgID := uuid.New()
	if _, err := db.ExecContext(ctx, `INSERT INTO organizations (id, name) VALUES ($1, $2)`, orgID, "M8 activation "+orgID.String()[:8]); err != nil {
		t.Fatalf("create organisation: %v", err)
	}
	rule, err := st.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:       "M8 limit rule, or",
		Logic:      string(dsl.LogicOr),
		Conditions: condJSON,
		Status:     "activating",
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}

	e := New(db, st, NewRuleCache(), slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), 120000)
	start := time.Now()
	actErr := e.EvaluateActivation(ctx, rule.ID, orgID)
	elapsed := time.Since(start)

	var events int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM alert_events WHERE rule_id = $1`, rule.ID).Scan(&events); err != nil {
		t.Fatalf("count events: %v", err)
	}
	after, err := st.GetAlertRule(ctx, orgID, rule.ID)
	if err != nil || after == nil {
		t.Fatalf("read rule after activation: %v", err)
	}
	line := fmt.Sprintf("M8 full activation (disposable copy): %s wall clock, %d events, rule status %s, threshold 7 min, %s.\n",
		elapsed.Round(time.Second), events, after.Status, map[bool]string{true: "pass", false: "FAIL"}[actErr == nil && elapsed <= 7*time.Minute])
	if actErr != nil {
		line = strings.TrimSuffix(line, ".\n") + fmt.Sprintf(" (activation error class %s).\n", errorClass(actErr))
	}
	if err := os.WriteFile(filepath.Join(dir, "m8-activation.md"), []byte(line), 0o600); err != nil {
		t.Fatalf("write result: %v", err)
	}
	t.Log(line)
	if actErr != nil || elapsed > 7*time.Minute {
		t.Errorf("M8 fails: %s", line)
	}
}

// copyPool opens a pgx pool on the copy for the store, credentials from their own variables.
func copyPool(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(os.Getenv("KEPT_INGEST_COPY_DATABASE_URL"))
	if err != nil {
		t.Fatalf("copy URL does not parse (%T)", err)
	}
	cfg.ConnConfig.User = os.Getenv("KEPT_INGEST_COPY_USER")
	cfg.ConnConfig.Password = os.Getenv("KEPT_INGEST_COPY_PASSWORD")
	cfg.ConnConfig.DefaultQueryExecMode = store.DefaultQueryExecMode
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("copy pool (%s)", errorClass(err))
	}
	t.Cleanup(pool.Close)
	return pool
}

// migrateCopy runs the embedded migrations up on the copy, as internal/testutil does.
// The restore skipped privileges, so the app role the migrations grant to is created
// first, without login.
func migrateCopy(ctx context.Context, t *testing.T) {
	t.Helper()
	cfg, err := pgx.ParseConfig(os.Getenv("KEPT_INGEST_COPY_DATABASE_URL"))
	if err != nil {
		t.Fatalf("copy URL does not parse (%T)", err)
	}
	cfg.User = os.Getenv("KEPT_INGEST_COPY_USER")
	cfg.Password = os.Getenv("KEPT_INGEST_COPY_PASSWORD")
	// Simple protocol runs each statement of a migration file in its own autocommit,
	// which CREATE INDEX CONCURRENTLY requires.
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	db := stdlib.OpenDB(*cfg)
	defer db.Close() //nolint:errcheck
	if _, err := db.ExecContext(ctx, `DO $$ BEGIN
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cvert_ops_app') THEN
			CREATE ROLE cvert_ops_app NOLOGIN NOBYPASSRLS;
		END IF;
	END $$`); err != nil {
		t.Fatalf("create app role: %s", errorClass(err))
	}
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		t.Fatalf("migration source: %v", err)
	}
	driver, err := migratepg.WithInstance(db, &migratepg.Config{MultiStatementEnabled: true})
	if err != nil {
		t.Fatalf("migration driver: %s", errorClass(err))
	}
	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil {
		t.Fatalf("migrate init: %s", errorClass(err))
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("migrate up: %v", err)
	}
	v, dirty, _ := m.Version()
	t.Logf("copy migrated to version %d (dirty %v)", v, dirty)
}
