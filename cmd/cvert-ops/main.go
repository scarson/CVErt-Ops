// ABOUTME: CVErt Ops server binary with cobra subcommands: serve, worker, migrate, import-bulk.
// ABOUTME: Single static binary combining HTTP server, worker pool, and database migrations.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
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
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/scarson/cvert-ops/internal/ai"
	"github.com/scarson/cvert-ops/internal/alert"
	"github.com/scarson/cvert-ops/internal/api"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/feed/epss"
	"github.com/scarson/cvert-ops/internal/feed/generic"
	"github.com/scarson/cvert-ops/internal/ingest"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/metrics"
	"github.com/scarson/cvert-ops/internal/notify"
	"github.com/scarson/cvert-ops/internal/retention"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/worker"
	"github.com/scarson/cvert-ops/migrations"
)

// Build metadata — set via ldflags at compile time:
//
//	go build -ldflags "-X main.version=v1.0.0 -X main.commit=abc123 -X main.buildTime=2026-03-10T00:00:00Z"
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
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
		quotaCmd(),
		validateFeedsCmd(),
	)

	if err := root.Execute(); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

// ── serve ─────────────────────────────────────────────────────────────────────

func serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the HTTP server and embedded worker pool",
		RunE:  runServe,
	}
	cmd.Flags().Bool("skip-auto-migrate", false, "Skip automatic database migrations on startup")
	return cmd
}

func runServe(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}

	logger := newLogger(cfg)
	slog.SetDefault(logger)

	db, err := newPool(cmd.Context(), cfg)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer db.Close()

	// Register DB pool metrics collector so Prometheus can scrape pool utilization.
	prometheus.MustRegister(metrics.NewDBPoolCollector(poolStatter{db}))

	// Auto-migrate: run pending migrations before starting the server.
	// Skippable for operators who run migrations via a separate init container.
	skipMigrate, _ := cmd.Flags().GetBool("skip-auto-migrate")
	if !skipMigrate {
		slog.Info("auto-migrate: running pending migrations")
		if err := autoMigrate(cmd.Context(), cfg); err != nil {
			return fmt.Errorf("auto-migrate: %w", err)
		}
	} else {
		slog.Info("auto-migrate: skipped (--skip-auto-migrate)")
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	st := store.New(db)

	// Start embedded worker pool. Runs until ctx is cancelled, at which point
	// in-flight jobs complete and the goroutines exit. The goroutine is
	// intentionally fire-and-forget here; the pool drains on ctx cancellation
	// which happens before or alongside HTTP server shutdown.
	// Load generic feed configs from CVERTOPS_FEEDS_DIR (if set).
	var genericConfigs []generic.Config
	if cfg.FeedsDir != "" {
		configs, errs := generic.LoadDir(cfg.FeedsDir)
		for _, e := range errs {
			slog.Warn("invalid feed config", "error", e)
		}
		genericConfigs = configs
		slog.Info("loaded generic feed configs", "count", len(genericConfigs), "dir", cfg.FeedsDir)
	}

	feedClient := &http.Client{Timeout: 5 * time.Minute}
	workerPool := worker.New(st)
	if len(genericConfigs) > 0 {
		factory := generic.AdapterFactory(genericConfigs)
		workerPool.Register("feed_ingest", ingest.HandlerWithFactory(st, feedClient, merge.Ingest, factory))
	} else {
		workerPool.Register("feed_ingest", ingest.Handler(st, feedClient, merge.Ingest))
	}
	epssClient := &http.Client{Timeout: 300 * time.Second} // EPSS downloads ~15MB gzip; allow generous timeout
	workerPool.Register("epss_ingest", ingest.EPSSHandler(st, epss.New(epssClient).Apply))

	// Construct AI/LLM client based on configuration. MockClient is used for
	// development and testing; GeminiClient for production.
	var llm ai.LLMClient
	if cfg.GeminiMock {
		llm = ai.NewMockClient()
		slog.Info("using mock LLM client")
	} else if cfg.GeminiAPIKey != "" {
		llm, err = ai.NewGeminiClient(cfg.GeminiAPIKey, cfg.GeminiModel, cfg.GeminiTimeout)
		if err != nil {
			return fmt.Errorf("creating Gemini client: %w", err)
		}
		slog.Info("using Gemini LLM client", "model", cfg.GeminiModel)
	}

	apiSrv, err := api.NewServer(st, cfg)
	if err != nil {
		return fmt.Errorf("api server init: %w", err)
	}
	apiSrv.SetExpectedSchemaVersion(expectedSchemaVersion)
	apiSrv.SetVersionInfo(api.VersionInfo{
		Version:   version,
		Commit:    commit,
		BuildTime: buildTime,
	})

	// Wire alert evaluation dependencies. The cache and evaluator are used by
	// the dry-run endpoint; the batch/EPSS/activation workers run via the pool.
	alertCache := alert.NewRuleCache()
	alertEval := alert.New(stdlib.OpenDBFromPool(db), st, alertCache, slog.Default())
	apiSrv.SetAlertDeps(alertCache, alertEval)

	// Wire AI/LLM dependencies for NL search and summarization handlers.
	if llm != nil {
		apiSrv.SetAIDeps(llm)
	}

	// Wire notification delivery: dispatcher fans out alert events to delivery rows;
	// worker polls delivery rows and executes outbound webhook calls.
	deliveryClient, err := notify.BuildSafeClient()
	if err != nil {
		return fmt.Errorf("build delivery HTTP client: %w", err)
	}
	dispatcher := notify.NewDispatcher(st, cfg.NotifyDebounceSeconds)
	alertEval.SetDispatcher(dispatcher)
	smtpCfg := notify.SmtpConfig{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		From:     cfg.SMTPFrom,
		Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword,
		TLS:      cfg.SMTPTLS,
	}
	deliveryWorker := notify.NewWorker(st, deliveryClient, notify.WorkerConfig{
		ClaimBatchSize:      cfg.NotifyClaimBatchSize,
		MaxAttempts:         cfg.NotifyMaxAttempts,
		BackoffBaseSeconds:  cfg.NotifyBackoffBaseSeconds,
		MaxConcurrentPerOrg: cfg.NotifyMaxConcurrentPerOrg,
		RetentionEnabled:    cfg.RetentionCleanupEnabled,
	}, smtpCfg, cfg.ExternalURL)
	deliveryWorker.SetDispatcher(dispatcher)
	go deliveryWorker.Start(ctx) //nolint:contextcheck // ctx is the process-lifetime context

	workerPool.Register("alert_activation", activationHandler(alertEval))
	workerPool.Register("retention_cleanup", retentionHandler(st, cfg))
	if cfg.FeedSchedulerEnabled {
		feedScheduler := ingest.NewScheduler(st)
		if len(genericConfigs) > 0 {
			feedScheduler.AddEntries(generic.ScheduleEntries(genericConfigs))
		}
		go feedScheduler.Start(ctx) //nolint:contextcheck // ctx is the process-lifetime context
	}
	go workerPool.Start(ctx) //nolint:contextcheck // ctx is the process-lifetime context

	handler := apiSrv.Handler()

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

	// Metrics endpoint on a separate port so operators can restrict access
	// without exposing it on the public API port.
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsSrv := &http.Server{ //nolint:exhaustruct // minimal metrics server
		Addr:              ":" + cfg.MetricsPort,
		Handler:           metricsMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		slog.Info("metrics server started", "addr", metricsSrv.Addr)
		if err := metricsSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			slog.Error("metrics server error", "error", err)
		}
	}()

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

	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		slog.Error("metrics server shutdown error", "error", err)
	}
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
	if err := validateConfig(cfg); err != nil {
		return err
	}

	logger := newLogger(cfg)
	slog.SetDefault(logger)

	db, err := newPool(cmd.Context(), cfg)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer db.Close()

	// Register DB pool metrics collector so Prometheus can scrape pool utilization.
	prometheus.MustRegister(metrics.NewDBPoolCollector(poolStatter{db}))

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	st := store.New(db)

	// Load generic feed configs from CVERTOPS_FEEDS_DIR (if set).
	var genericConfigs []generic.Config
	if cfg.FeedsDir != "" {
		configs, errs := generic.LoadDir(cfg.FeedsDir)
		for _, e := range errs {
			slog.Warn("invalid feed config", "error", e)
		}
		genericConfigs = configs
		slog.Info("loaded generic feed configs", "count", len(genericConfigs), "dir", cfg.FeedsDir)
	}

	alertCache := alert.NewRuleCache()
	alertEval := alert.New(stdlib.OpenDBFromPool(db), st, alertCache, slog.Default())

	feedClient := &http.Client{Timeout: 5 * time.Minute}
	workerPool := worker.New(st)
	if len(genericConfigs) > 0 {
		factory := generic.AdapterFactory(genericConfigs)
		workerPool.Register("feed_ingest", ingest.HandlerWithFactory(st, feedClient, merge.Ingest, factory))
	} else {
		workerPool.Register("feed_ingest", ingest.Handler(st, feedClient, merge.Ingest))
	}
	epssClient := &http.Client{Timeout: 300 * time.Second}
	workerPool.Register("epss_ingest", ingest.EPSSHandler(st, epss.New(epssClient).Apply))
	workerPool.Register("alert_activation", activationHandler(alertEval))

	// Start notification delivery worker alongside the job queue worker pool.
	deliveryClient, err := notify.BuildSafeClient()
	if err != nil {
		return fmt.Errorf("build delivery HTTP client: %w", err)
	}
	dispatcher := notify.NewDispatcher(st, cfg.NotifyDebounceSeconds)
	smtpCfg := notify.SmtpConfig{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		From:     cfg.SMTPFrom,
		Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword,
		TLS:      cfg.SMTPTLS,
	}
	deliveryWorker := notify.NewWorker(st, deliveryClient, notify.WorkerConfig{
		ClaimBatchSize:      cfg.NotifyClaimBatchSize,
		MaxAttempts:         cfg.NotifyMaxAttempts,
		BackoffBaseSeconds:  cfg.NotifyBackoffBaseSeconds,
		MaxConcurrentPerOrg: cfg.NotifyMaxConcurrentPerOrg,
		RetentionEnabled:    cfg.RetentionCleanupEnabled,
	}, smtpCfg, cfg.ExternalURL)
	deliveryWorker.SetDispatcher(dispatcher)
	go deliveryWorker.Start(ctx) //nolint:contextcheck // ctx is the process-lifetime context

	workerPool.Register("retention_cleanup", retentionHandler(st, cfg))
	if cfg.FeedSchedulerEnabled {
		feedScheduler := ingest.NewScheduler(st)
		if len(genericConfigs) > 0 {
			feedScheduler.AddEntries(generic.ScheduleEntries(genericConfigs))
		}
		go feedScheduler.Start(ctx) //nolint:contextcheck // ctx is the process-lifetime context
	}

	// Metrics endpoint so Prometheus can scrape the standalone worker.
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsSrv := &http.Server{ //nolint:exhaustruct // minimal metrics server
		Addr:              ":" + cfg.MetricsPort,
		Handler:           metricsMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		slog.Info("metrics server started", "addr", metricsSrv.Addr)
		if err := metricsSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			slog.Error("metrics server error", "error", err)
		}
	}()

	slog.Info("worker started")
	workerPool.Start(ctx) // blocks until ctx cancelled, then drains in-flight jobs

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		slog.Error("metrics server shutdown error", "error", err)
	}
	return nil
}

// activationHandler returns a worker.Handler that runs the activation scan for
// a newly created or re-enabled alert rule.
func activationHandler(eval *alert.Evaluator) worker.Handler {
	return func(ctx context.Context, payload json.RawMessage) error {
		var p struct {
			RuleID string `json:"rule_id"`
			OrgID  string `json:"org_id"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal activation payload: %w", err)
		}
		ruleID, err := uuid.Parse(p.RuleID)
		if err != nil {
			return fmt.Errorf("parse rule_id: %w", err)
		}
		orgID, err := uuid.Parse(p.OrgID)
		if err != nil {
			return fmt.Errorf("parse org_id: %w", err)
		}
		return eval.EvaluateActivation(ctx, ruleID, orgID)
	}
}

// retentionHandler returns a worker.Handler that runs the retention cleanup runner.
func retentionHandler(st *store.Store, cfg *config.Config) worker.Handler {
	return func(ctx context.Context, _ json.RawMessage) error {
		r := retention.NewRunner(st, retention.Config{
			Enabled:           cfg.RetentionCleanupEnabled,
			BatchSize:         cfg.RetentionCleanupBatchSize,
			MaxRuntimeSeconds: cfg.RetentionMaxRuntimeSeconds,
			RawPayloadDays:    cfg.RetentionRawPayloadDays,
			FeedFetchLogDays:  cfg.RetentionFeedFetchLogDays,
			JobQueueHours:     cfg.RetentionJobQueueHours,
			AILogDays:         cfg.AILogRetentionDays,
			AlertEventsDays:   cfg.RetentionAlertEventsDays,
			NotifDelivDays:    cfg.RetentionNotifDeliveriesDays,
			AuditLogDays:      cfg.RetentionAuditLogDays,
		}, slog.Default())
		return r.Run(ctx)
	}
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

	db, err := openMigrateDB(cfg)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck

	return migrateUp(db)
}

// autoMigrate acquires a Postgres advisory lock and runs pending migrations.
// The advisory lock prevents concurrent migration runs when multiple instances
// start simultaneously (e.g., Kubernetes rolling update). The lock is released
// on return via defer.
//
// The lock and migrations share the same *sql.DB connection — this is critical
// because pg_advisory_lock is session-scoped and must protect the same session
// that executes the DDL.
func autoMigrate(ctx context.Context, cfg *config.Config) error {
	db, err := openMigrateDB(cfg)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck

	// Force single connection so the advisory lock and migration DDL share
	// the same Postgres session. Without this, the pool could route the lock
	// and the DDL to different backend connections.
	db.SetMaxOpenConns(1)

	// Verify connectivity before acquiring lock.
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping: %w", err)
	}

	// Acquire advisory lock — blocks until available, released on disconnect
	// or explicit unlock. hashtext('cvertops-migrate') returns a stable int32.
	if _, err := db.ExecContext(ctx, "SELECT pg_advisory_lock(hashtext('cvertops-migrate'))"); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		if _, unlockErr := db.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock(hashtext('cvertops-migrate'))"); unlockErr != nil {
			slog.Error("auto-migrate: failed to release advisory lock", "error", unlockErr)
		}
	}()

	return migrateUp(db)
}

// openMigrateDB opens a database/sql connection for running migrations.
// golang-migrate requires *sql.DB; this uses pgx's stdlib adapter.
// Uses DATABASE_URL_MIGRATE if set, otherwise falls back to DATABASE_URL.
func openMigrateDB(cfg *config.Config) (*sql.DB, error) {
	migrateURL := cfg.DatabaseURL
	if cfg.DatabaseURLMigrate != "" {
		migrateURL = cfg.DatabaseURLMigrate
	}
	connCfg, err := pgx.ParseConfig(migrateURL)
	if err != nil {
		return nil, fmt.Errorf("parse db url: %w", err)
	}
	// Simple query protocol + MultiStatementEnabled: each statement in the migration
	// file runs as its own ExecContext call in autocommit, allowing CREATE INDEX CONCURRENTLY.
	connCfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	return stdlib.OpenDB(*connCfg), nil
}

// migrateUp applies all pending migrations on the given database connection.
func migrateUp(db *sql.DB) error {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("migration source: %w", err)
	}

	driver, err := migratepg.WithInstance(db, &migratepg.Config{MultiStatementEnabled: true})
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

	ver, _, _ := m.Version() //nolint:errcheck
	slog.Info("migrations complete", "version", ver)
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

// validateConfig enforces startup invariants that environment parsing cannot express:
// JWT_SECRET minimum length and HTTPS requirement for EXTERNAL_URL outside development.
func validateConfig(cfg *config.Config) error {
	if len(cfg.JWTSecret) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 bytes (got %d)", len(cfg.JWTSecret))
	}
	if !cfg.IsDevelopment() && !strings.HasPrefix(cfg.ExternalURL, "https://") {
		return fmt.Errorf("EXTERNAL_URL must use https:// in non-development environments (got %q)", cfg.ExternalURL)
	}
	return nil
}

// expectedSchemaVersion is the database migration version this binary requires.
// Update this constant when new migrations are added.
const expectedSchemaVersion = 34

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

// poolStatter adapts *pgxpool.Pool to the metrics.PoolStatter interface.
type poolStatter struct{ pool *pgxpool.Pool }

func (p poolStatter) PoolStats() metrics.PoolStats {
	s := p.pool.Stat()
	return metrics.PoolStats{
		AcquiredConns: s.AcquiredConns(),
		IdleConns:     s.IdleConns(),
		MaxConns:      s.MaxConns(),
		TotalConns:    s.TotalConns(),
	}
}
