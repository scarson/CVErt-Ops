// ABOUTME: Test helper that starts a Postgres testcontainer with all migrations applied.
// ABOUTME: Use NewTestDB(t) in integration tests that need a real database.
package testutil

import (
	"context"
	"errors"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/migrations"
)

// TestDB wraps a Store with helpers for RLS integration tests.
// It embeds *store.Store so all store methods are directly callable,
// keeping all existing tests working without modification.
type TestDB struct {
	*store.Store // superuser store — bypasses RLS (for data setup)
	// AppStore connects as cvert_ops_app (NOBYPASSRLS) — use for RLS isolation tests.
	AppStore *store.Store
}

// NewTestDB starts a Postgres testcontainer, runs all migrations, and returns
// a TestDB backed by the test DB. The container and pools are cleaned up via t.Cleanup.
func NewTestDB(t *testing.T) *TestDB {
	t.Helper()
	ctx := context.Background()

	pgCtr, err := tcpostgres.Run(ctx,
		"postgres:18-alpine",
		tcpostgres.WithDatabase("cvert_ops_test"),
		tcpostgres.WithUsername("cvert_ops_test"),
		tcpostgres.WithPassword("testpassword"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() {
		if err := pgCtr.Terminate(ctx); err != nil {
			t.Logf("terminate postgres container: %v", err)
		}
	})

	connStr, err := pgCtr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	// Run migrations using the same pattern as cmd/cvert-ops/main.go runMigrate.
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		t.Fatalf("migration source: %v", err)
	}

	connCfg, err := pgx.ParseConfig(connStr)
	if err != nil {
		t.Fatalf("parse db url: %v", err)
	}
	// Simple query protocol lets postgres execute multi-statement migration files
	// natively — each statement runs in its own autocommit. Extended protocol
	// wraps the whole file in an implicit transaction, rejecting CREATE INDEX CONCURRENTLY.
	connCfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	db := stdlib.OpenDB(*connCfg)
	defer db.Close() //nolint:errcheck

	// Migrations reference cvert_ops_app in GRANT statements — create the role
	// before running migrations. In production this is done by docker/init.sql.
	// A known password is set so RLS integration tests can connect as this role.
	if _, err := db.ExecContext(ctx, `
		DO $$ BEGIN
			IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cvert_ops_app') THEN
				CREATE ROLE cvert_ops_app LOGIN NOBYPASSRLS PASSWORD 'apptestpw';
			ELSE
				ALTER ROLE cvert_ops_app WITH LOGIN NOBYPASSRLS PASSWORD 'apptestpw';
			END IF;
		END $$`); err != nil {
		t.Fatalf("create cvert_ops_app role: %v", err)
	}

	driver, err := migratepg.WithInstance(db, &migratepg.Config{MultiStatementEnabled: true})
	if err != nil {
		t.Fatalf("migration driver: %v", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil {
		t.Fatalf("migrate init: %v", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("migrate up: %v", err)
	}

	// Superuser pool for data setup (bypasses RLS).
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	t.Cleanup(pool.Close)

	// App-role pool connecting as cvert_ops_app (subject to RLS).
	appPoolCfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		t.Fatalf("parse app pool config: %v", err)
	}
	appPoolCfg.ConnConfig.User = "cvert_ops_app"
	appPoolCfg.ConnConfig.Password = "apptestpw"
	appPool, err := pgxpool.NewWithConfig(ctx, appPoolCfg)
	if err != nil {
		t.Fatalf("pgxpool (cvert_ops_app): %v", err)
	}
	t.Cleanup(appPool.Close)

	return &TestDB{
		Store:    store.New(pool),
		AppStore: store.New(appPool),
	}
}
