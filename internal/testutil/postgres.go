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

// NewTestDB starts a Postgres testcontainer, runs all migrations, and returns
// a Store backed by the test DB. The container and pool are cleaned up via t.Cleanup.
func NewTestDB(t *testing.T) *store.Store {
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
	if _, err := db.ExecContext(ctx, `
		DO $$ BEGIN
			IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cvert_ops_app') THEN
				CREATE ROLE cvert_ops_app LOGIN NOBYPASSRLS;
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

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	t.Cleanup(pool.Close)

	return store.New(pool)
}
