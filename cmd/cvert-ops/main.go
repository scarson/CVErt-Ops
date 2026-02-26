// Command cvert-ops is the CVErt Ops server binary.
//
// Subcommands:
//
//	serve        — HTTP server + embedded worker pool (default for production)
//	worker       — standalone worker pool only (SaaS scaled deployments)
//	migrate      — run pending database migrations and exit
//	import-bulk  — import a bulk data file for a given feed source
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	// Embeds the IANA timezone database in the binary so that
	// time.LoadLocation works inside distroless containers that have no
	// /usr/share/zoneinfo (PLAN.md §18.3).
	_ "time/tzdata"

	// Automatically sets GOMEMLIMIT from the cgroup memory limit so that
	// the Go GC triggers before the OOM killer fires in containers
	// (PLAN.md §18.3).
	_ "github.com/KimMachineGun/automemlimit"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/spf13/cobra"

	"github.com/scarson/cvert-ops/internal/api"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/worker"
	"github.com/scarson/cvert-ops/migrations"
)

func main() {
	root := &cobra.Command{
		Use:   "cvert-ops",
		Short: "CVErt Ops — vulnerability intelligence and alerting",
		// Silence default error printing; we print it ourselves with slog.
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	root.AddCommand(
		serveCmd(),
		workerCmd(),
		migrateCmd(),
		importBulkCmd(),
	)

	if err := root.Execute(); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

// ── serve ─────────────────────────────────────────────────────────────────────

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the HTTP server and embedded worker pool",
		RunE:  runServe,
	}
}

func runServe(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	logger := newLogger(cfg)
	slog.SetDefault(logger)

	db, err := newPool(cmd.Context(), cfg)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer db.Close()

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	st := store.New(db)

	// Start embedded worker pool. Runs until ctx is cancelled, at which point
	// in-flight jobs complete and the goroutines exit. The goroutine is
	// intentionally fire-and-forget here; the pool drains on ctx cancellation
	// which happens before or alongside HTTP server shutdown.
	workerPool := worker.New(st)
	workerPool.Register("feed_ingest", feedIngestHandler)
	go workerPool.Start(ctx) //nolint:contextcheck // ctx is the process-lifetime context

	handler := api.NewRouter(st)

	// PLAN.md §18.3: explicit timeouts required to prevent Slowloris attacks.
	// WriteTimeout intentionally omitted — applied per-handler via http.TimeoutHandler
	// for non-streaming endpoints; streaming endpoints need unbounded write time.
	srv := &http.Server{ //nolint:exhaustruct // WriteTimeout intentionally omitted per PLAN.md §18.3
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("server started", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	select {
	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	case <-ctx.Done():
		stop() // release signal notification
	}

	slog.Info("shutting down", "timeout_seconds", cfg.ShutdownTimeoutSeconds)
	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(cfg.ShutdownTimeoutSeconds)*time.Second,
	)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	slog.Info("server stopped")
	return nil
}

// ── worker ────────────────────────────────────────────────────────────────────

func workerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "worker",
		Short: "Start the standalone worker pool (no HTTP server)",
		RunE:  runWorker,
	}
}

func runWorker(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	logger := newLogger(cfg)
	slog.SetDefault(logger)

	db, err := newPool(cmd.Context(), cfg)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer db.Close()

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	workerPool := worker.New(store.New(db))
	workerPool.Register("feed_ingest", feedIngestHandler)

	slog.Info("worker started")
	workerPool.Start(ctx) // blocks until ctx cancelled, then drains in-flight jobs
	return nil
}

// feedIngestHandler is a stub for the feed ingestion job handler.
// Replaced with the real implementation in Phase 1 commits 4–8 when the
// FeedAdapter interface and individual adapters are wired in.
func feedIngestHandler(_ context.Context, payload json.RawMessage) error {
	slog.Info("feed ingest job received — handler wired in commits 4–8",
		"payload_len", len(payload))
	return nil
}

// ── migrate ───────────────────────────────────────────────────────────────────

func migrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Run pending database migrations and exit",
		RunE:  runMigrate,
	}
}

func runMigrate(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	slog.Info("running migrations")

	// Source: embedded SQL files from the migrations package.
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("migration source: %w", err)
	}

	// golang-migrate requires a *sql.DB. Use pgx's stdlib adapter so the same
	// driver is used project-wide. No pooling needed here — this is a one-shot
	// migration run.
	migrateURL := cfg.DatabaseURL
	if cfg.DatabaseURLMigrate != "" {
		migrateURL = cfg.DatabaseURLMigrate
	}
	connCfg, err := pgx.ParseConfig(migrateURL)
	if err != nil {
		return fmt.Errorf("parse db url: %w", err)
	}
	db := stdlib.OpenDB(*connCfg)
	defer db.Close() //nolint:errcheck

	driver, err := migratepg.WithInstance(db, &migratepg.Config{})
	if err != nil {
		return fmt.Errorf("migration driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil {
		return fmt.Errorf("migrate init: %w", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}

	version, _, _ := m.Version() //nolint:errcheck
	slog.Info("migrations complete", "version", version)
	return nil
}

// ── import-bulk ───────────────────────────────────────────────────────────────

func importBulkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import-bulk",
		Short: "Import a local bulk data file for a feed source (Phase 2)",
		RunE: func(_ *cobra.Command, _ []string) error {
			slog.Info("import-bulk not yet implemented — coming in Phase 2")
			return nil
		},
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// newPool creates and validates a pgxpool with all required settings from
// PLAN.md §18.3 and §19.2 (PgBouncer compatibility, statement timeout, pool
// sizing).
//
// Retries up to 10 times with linear backoff to handle Docker Compose startup
// race where Postgres is not immediately ready (PLAN.md §18.3).
func newPool(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// PgBouncer transaction-pooling compatibility (PLAN.md §19.2).
	if cfg.DBQueryExecMode == "simple_protocol" {
		poolCfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	}

	// Global per-query statement timeout prevents runaway queries from holding
	// connections indefinitely (PLAN.md §19.2).
	poolCfg.ConnConfig.RuntimeParams["statement_timeout"] = strconv.Itoa(cfg.DBStatementTimeoutMS)

	// Pool sizing — prevents connection multiplication across instances
	// (PLAN.md §19.2: DB_MAX_CONNS × instances < postgres_max_connections − 10).
	poolCfg.MaxConns = cfg.DBMaxConns
	poolCfg.MaxConnIdleTime = cfg.DBMaxConnIdleTime

	var (
		db      *pgxpool.Pool
		connErr error
	)
	for attempt := 1; attempt <= 10; attempt++ {
		db, connErr = pgxpool.NewWithConfig(ctx, poolCfg)
		if connErr == nil {
			if connErr = db.Ping(ctx); connErr == nil {
				break
			}
			db.Close()
		}
		slog.Warn("database not ready, retrying",
			"attempt", attempt,
			"error", connErr,
		)
		// time.NewTimer (not time.After) to avoid leaking the timer if ctx
		// is cancelled before the timer fires (pitfalls §timer-leak).
		timer := time.NewTimer(time.Duration(attempt) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if connErr != nil {
		return nil, fmt.Errorf("database unavailable after retries: %w", connErr)
	}

	// PLAN.md §19.2: warn if DB_MAX_CONNS is dangerously close to Postgres's
	// server-side max_connections limit. This prevents connection exhaustion
	// when multiple instances share the same Postgres server.
	var pgMaxConnsStr string
	if err := db.QueryRow(ctx, "SHOW max_connections").Scan(&pgMaxConnsStr); err == nil {
		if pgMaxConns, err := strconv.Atoi(pgMaxConnsStr); err == nil {
			if int(cfg.DBMaxConns) > int(float64(pgMaxConns)*0.8) {
				slog.Warn("DB_MAX_CONNS exceeds 80% of Postgres max_connections",
					"db_max_conns", cfg.DBMaxConns,
					"postgres_max_connections", pgMaxConns,
				)
			}
		}
	}

	// Advisory schema version check: warn if the applied schema version does
	// not match the version the binary was compiled for. This catches
	// misconfigured deployments where migrations haven't been applied yet
	// (PLAN.md §18 advisory item).
	var schemaVersion int
	err = db.QueryRow(ctx,
		"SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1",
	).Scan(&schemaVersion)
	if err == nil && schemaVersion != expectedSchemaVersion {
		slog.Warn("schema version mismatch — run `cvert-ops migrate`",
			"applied_version", schemaVersion,
			"expected_version", expectedSchemaVersion,
		)
	}

	return db, nil
}

// expectedSchemaVersion is the database migration version this binary requires.
// Update this constant when new migrations are added.
const expectedSchemaVersion = 3

// newLogger creates a slog.Logger based on the configured log level and format.
func newLogger(cfg *config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "text" || cfg.IsDevelopment() {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}
