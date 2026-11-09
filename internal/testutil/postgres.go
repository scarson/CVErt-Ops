// ABOUTME: Test helper that gives each test its own migrated Postgres database.
// ABOUTME: One container per test binary holds a migrated template; NewTestDB clones it per test.
package testutil

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/migrations"
)

func init() {
	// On Windows, testcontainers-go discovers Docker by calling os.Stat on the
	// named pipe. Under concurrent test load, os.Stat fails with "All pipe
	// instances are busy," causing a panic. Setting DOCKER_HOST bypasses the
	// stat-based discovery entirely.
	// See dev/research-findings/testcontainers-go-windows-panic.md
	if runtime.GOOS == "windows" && os.Getenv("DOCKER_HOST") == "" {
		os.Setenv("DOCKER_HOST", client.DefaultDockerHost) //nolint:errcheck,gosec // best-effort; no recovery path
	}

	// Ryuk runs in a Linux container and needs the daemon's Unix socket bound in.
	// testcontainers-go chooses that path only when the daemon's OperatingSystem
	// is exactly "Docker Desktop". A daemon reporting "Docker Desktop
	// (containerized)" gets the client's named pipe path instead, which mounts as
	// an empty directory, and Ryuk exits as soon as it starts.
	// See dev/research-findings/ryuk-named-pipe-socket-bind.md
	if runtime.GOOS == "windows" && os.Getenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE") == "" {
		os.Setenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", "//var/run/docker.sock") //nolint:errcheck,gosec // best-effort; no recovery path
	}
}

// templateDBName is the migrated database every test database is cloned from.
const templateDBName = "cvert_ops_template"

// cluster is the Postgres container shared by all NewTestDB calls in one test
// binary.
type cluster struct {
	ctr *tcpostgres.PostgresContainer
	// url is a superuser connection URL; NewTestDB swaps in each test's database.
	url url.URL
	// admin is connected to the "postgres" maintenance database, which CREATE
	// DATABASE and DROP DATABASE run from (a template cannot have connections).
	admin *sql.DB
}

var (
	// runActive is set by Run. NewTestDB refuses to start a container without
	// it, because nothing else would terminate the container.
	runActive atomic.Bool

	clusterOnce sync.Once
	shared      *cluster
	sharedErr   error
)

// Run runs the package's tests and then terminates the shared Postgres
// container, if any test started one. Every package that calls NewTestDB needs
//
//	func TestMain(m *testing.M) { os.Exit(testutil.Run(m)) }
func Run(m *testing.M) int {
	runActive.Store(true)
	code := m.Run()
	if shared != nil {
		shared.close()
	}
	return code
}

// checkRunner reports whether the test binary's TestMain called Run.
func checkRunner() error {
	if !runActive.Load() {
		return errors.New("testutil.NewTestDB needs the package's TestMain to call testutil.Run, " +
			"which terminates the shared Postgres container: " +
			"func TestMain(m *testing.M) { os.Exit(testutil.Run(m)) }")
	}
	return nil
}

// TestDB wraps a Store with helpers for RLS integration tests.
// It embeds *store.Store so all store methods are directly callable,
// keeping all existing tests working without modification.
type TestDB struct {
	*store.Store // superuser store — bypasses RLS (for data setup)
	// AppStore connects as cvert_ops_app (NOBYPASSRLS) — use for RLS isolation tests.
	AppStore *store.Store
	// URL is the superuser connection string for this test's database.
	URL string
	// AppURL connects to the same database as cvert_ops_app.
	AppURL string
}

// NewTestDB returns a TestDB backed by a new database cloned from the test
// binary's migrated template. The first call in a binary starts the shared
// container and migrates the template. The database and pools are cleaned up
// via t.Cleanup; the container is terminated by Run.
func NewTestDB(t *testing.T) *TestDB {
	t.Helper()
	ctx := context.Background()

	if err := checkRunner(); err != nil {
		t.Fatal(err)
	}
	clusterOnce.Do(func() { shared, sharedErr = startCluster(ctx) })
	if sharedErr != nil {
		t.Fatalf("start shared postgres: %v", sharedErr)
	}

	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("database name: %v", err)
	}
	name := "test_" + hex.EncodeToString(suffix)
	if _, err := shared.admin.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s",
		pgx.Identifier{name}.Sanitize(), pgx.Identifier{templateDBName}.Sanitize())); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	// Registered before the pools, so it runs after they close (cleanups run
	// last-in first-out). FORCE ends any connection a test leaked.
	t.Cleanup(func() {
		if _, err := shared.admin.ExecContext(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)",
			pgx.Identifier{name}.Sanitize())); err != nil {
			t.Logf("drop test database %s: %v", name, err)
		}
	})

	dbURL := shared.url
	dbURL.Path = "/" + name

	// Superuser pool for data setup (bypasses RLS). Both pools use the query mode
	// a deployment runs, so tests encode parameters the way production does.
	poolCfg, err := pgxpool.ParseConfig(dbURL.String())
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	poolCfg.ConnConfig.DefaultQueryExecMode = store.DefaultQueryExecMode
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	t.Cleanup(pool.Close)

	// App-role pool connecting as cvert_ops_app (subject to RLS).
	appPoolCfg, err := pgxpool.ParseConfig(dbURL.String())
	if err != nil {
		t.Fatalf("parse app pool config: %v", err)
	}
	appPoolCfg.ConnConfig.User = "cvert_ops_app"
	appPoolCfg.ConnConfig.Password = "apptestpw"
	appPoolCfg.ConnConfig.DefaultQueryExecMode = store.DefaultQueryExecMode
	appPool, err := pgxpool.NewWithConfig(ctx, appPoolCfg)
	if err != nil {
		t.Fatalf("pgxpool (cvert_ops_app): %v", err)
	}
	t.Cleanup(appPool.Close)

	appURL := dbURL
	appURL.User = url.UserPassword(appPoolCfg.ConnConfig.User, appPoolCfg.ConnConfig.Password)

	return &TestDB{
		Store:    store.New(pool),
		AppStore: store.New(appPool),
		URL:      dbURL.String(),
		AppURL:   appURL.String(),
	}
}

// startCluster starts the Postgres container, creates the cvert_ops_app role,
// and runs all migrations into the template database. opts are applied after
// the defaults.
func startCluster(ctx context.Context, opts ...testcontainers.ContainerCustomizer) (*cluster, error) {
	owner, err := OwnerOption()
	if err != nil {
		return nil, fmt.Errorf("owner labels: %w", err)
	}
	pgCtr, err := tcpostgres.Run(ctx,
		"postgres:18-alpine",
		append([]testcontainers.ContainerCustomizer{
			tcpostgres.WithDatabase(templateDBName),
			tcpostgres.WithUsername("cvert_ops_test"),
			tcpostgres.WithPassword("testpassword"),
			tcpostgres.BasicWaitStrategies(),
			// Lets a later test binary remove this container if this one is
			// killed before Run terminates it.
			owner,
			// Every parallel test in the binary connects to this one server.
			// The module already sets fsync=off; durability is irrelevant for tests.
			testcontainers.WithCmdArgs(
				"-c", "max_connections=1000",
				"-c", "synchronous_commit=off",
				"-c", "full_page_writes=off",
			),
		}, opts...)...,
	)
	if err != nil {
		// Run returns a container that was created but never became ready
		// together with the error; nothing else would remove it.
		if pgCtr != nil {
			if termErr := pgCtr.Terminate(ctx); termErr != nil {
				fmt.Fprintf(os.Stderr, "testutil: terminate postgres container that failed to start: %v\n", termErr)
			}
		}
		return nil, fmt.Errorf("start postgres container: %w", err)
	}
	c := &cluster{ctr: pgCtr}
	if err := c.prepare(ctx); err != nil {
		c.close()
		return nil, err
	}
	return c, nil
}

// prepare migrates the template database and opens the maintenance connection.
func (c *cluster) prepare(ctx context.Context) error {
	connStr, err := c.ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return fmt.Errorf("connection string: %w", err)
	}
	u, err := url.Parse(connStr)
	if err != nil {
		return fmt.Errorf("parse connection string: %w", err)
	}
	c.url = *u

	if err := migrateTemplate(ctx, connStr); err != nil {
		return err
	}

	adminCfg, err := pgx.ParseConfig(connStr)
	if err != nil {
		return fmt.Errorf("parse db url: %w", err)
	}
	adminCfg.Database = "postgres"
	c.admin = stdlib.OpenDB(*adminCfg)
	return nil
}

// migrateTemplate creates the cvert_ops_app role and applies all migrations to
// the database connStr names. It closes its connections before returning,
// because CREATE DATABASE ... TEMPLATE fails while the template has any.
func migrateTemplate(ctx context.Context, connStr string) error {
	// Run migrations using the same pattern as cmd/cvert-ops/main.go runMigrate.
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("migration source: %w", err)
	}

	connCfg, err := pgx.ParseConfig(connStr)
	if err != nil {
		return fmt.Errorf("parse db url: %w", err)
	}
	// Simple query protocol lets postgres execute multi-statement migration files
	// natively — each statement runs in its own autocommit. Extended protocol
	// wraps the whole file in an implicit transaction, rejecting CREATE INDEX CONCURRENTLY.
	connCfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	db := stdlib.OpenDB(*connCfg)
	defer db.Close() //nolint:errcheck

	// Migrations reference cvert_ops_app in GRANT statements — create the role
	// before running migrations. In production this is done by docker/init-app-role.sh.
	// A known password is set so RLS integration tests can connect as this role.
	if _, err := db.ExecContext(ctx, `
		DO $$ BEGIN
			IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cvert_ops_app') THEN
				CREATE ROLE cvert_ops_app LOGIN NOBYPASSRLS PASSWORD 'apptestpw';
			ELSE
				ALTER ROLE cvert_ops_app WITH LOGIN NOBYPASSRLS PASSWORD 'apptestpw';
			END IF;
		END $$`); err != nil {
		return fmt.Errorf("create cvert_ops_app role: %w", err)
	}

	driver, err := migratepg.WithInstance(db, &migratepg.Config{MultiStatementEnabled: true})
	if err != nil {
		return fmt.Errorf("migration driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil {
		return fmt.Errorf("migrate init: %w", err)
	}
	defer m.Close() //nolint:errcheck

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// close releases the maintenance connection and terminates the container.
func (c *cluster) close() {
	if c.admin != nil {
		_ = c.admin.Close()
	}
	if err := c.ctr.Terminate(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "testutil: terminate postgres container: %v\n", err)
	}
}
