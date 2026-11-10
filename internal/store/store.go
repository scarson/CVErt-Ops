// ABOUTME: Central data access layer with dual-layer tenant isolation (orgID param + RLS).
// ABOUTME: Provides transaction helpers: withOrgTx (API), withBypassTx (auth), WorkerTx (background).
package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// DefaultQueryExecMode is how a deployment sends queries unless DB_QUERY_EXEC_MODE
// says otherwise. pgx learns each statement's parameter types once per connection,
// so a []byte reaches a jsonb column as JSON and a bytea column as bytes. Every
// execution re-sends the SQL as an unnamed statement, so no statement outlives a
// PgBouncer transaction-mode server assignment.
const DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe

// ParseQueryExecMode returns the pgx mode a DB_QUERY_EXEC_MODE value names.
func ParseQueryExecMode(name string) (pgx.QueryExecMode, error) {
	switch name {
	case "cache_describe":
		return pgx.QueryExecModeCacheDescribe, nil
	case "extended_protocol":
		return pgx.QueryExecModeCacheStatement, nil
	default:
		return 0, fmt.Errorf("DB_QUERY_EXEC_MODE %q: must be cache_describe or extended_protocol", name)
	}
}

// Store is the central data access object. Callers should use the domain
// methods on the embedded sub-types (CVEStore, FeedStore, JobStore) rather
// than the raw queries or pool directly.
type Store struct {
	pool *pgxpool.Pool
	db   *sql.DB
	q    *generated.Queries
}

// New creates a Store backed by pool. The same pool is used for both
// sqlc-generated queries (via stdlib adapter) and direct pgx transactions.
func New(pool *pgxpool.Pool) *Store {
	db := stdlib.OpenDBFromPool(pool)
	return &Store{
		pool: pool,
		db:   db,
		q:    generated.New(db),
	}
}

// Pool returns the underlying pgxpool for callers that need pgx native
// operations (e.g., merge pipeline advisory locks, worker SKIP LOCKED).
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// DB returns the stdlib-wrapped *sql.DB for use with sqlc Queries.WithTx.
func (s *Store) DB() *sql.DB { return s.db }

// withBypassTx runs fn inside a database/sql transaction with RLS bypass enabled.
// Use for auth-path queries (e.g., LookupAPIKey) that must execute without an
// org context — the application enforces org membership separately.
// NEVER call from org-scoped handler code paths.
func (s *Store) withBypassTx(ctx context.Context, fn func(*generated.Queries) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin bypass tx: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if _, err := tx.ExecContext(ctx, "SET LOCAL app.bypass_rls = 'on'"); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("set bypass_rls: %w", err)
	}
	if err := fn(s.q.WithTx(tx)); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// withBypassRawTx runs fn inside a database/sql transaction with RLS bypass enabled.
// Use for admin/cross-org squirrel queries that need a raw *sql.Tx rather than
// sqlc-generated Queries.
func (s *Store) withBypassRawTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin bypass raw tx: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if _, err := tx.ExecContext(ctx, "SET LOCAL app.bypass_rls = 'on'"); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("set bypass_rls: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// withOrgRawTx runs fn inside a database/sql transaction with app.org_id set
// to orgID. Use this for squirrel/dynamic-SQL queries that need a raw *sql.Tx
// rather than sqlc-generated Queries. SET LOCAL resets on commit or rollback —
// safe for pooled connections. NOTE: SET LOCAL does not accept parameterized
// values; formatting is safe because orgID is a typed uuid.UUID, not
// user-supplied text.
func (s *Store) withOrgRawTx(ctx context.Context, orgID uuid.UUID, fn func(*sql.Tx) error) error {
	return s.withOrgRawTxOptions(ctx, orgID, nil, fn)
}

// withOrgSnapshotTx is withOrgRawTx in one read-only REPEATABLE READ snapshot, for
// reads that must not mix states from before and after a concurrent merge.
//
// JIT compilation is off inside it. Its statements are the version check
// lookups, whose estimated cost passes PostgreSQL's JIT thresholds once a
// request has a few keys, and compiling them costs more than it saves: 30 to
// 50 ms for a statement of one key, and over a second with five (design
// section 9 of dev/plans/2026-11-08-version-check-endpoint-design.md).
func (s *Store) withOrgSnapshotTx(ctx context.Context, orgID uuid.UUID, fn func(*sql.Tx) error) error {
	opts := &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}
	return s.withOrgRawTxOptions(ctx, orgID, opts, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "SET LOCAL jit = off"); err != nil {
			return fmt.Errorf("set jit off: %w", err)
		}
		return fn(tx)
	})
}

// withOrgRawTxOptions is withOrgRawTx with the transaction begun with opts; nil
// gives the default isolation level, read-write.
func (s *Store) withOrgRawTxOptions(ctx context.Context, orgID uuid.UUID, opts *sql.TxOptions, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("begin org tx: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL app.org_id = '%s'", orgID)); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("set org_id: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// withOrgTx runs fn inside a database/sql transaction with app.org_id set to
// orgID. Implements Layer 2 tenant isolation (PLAN.md §6.2) for store-level
// org-scoped methods that use sqlc-generated Queries.
func (s *Store) withOrgTx(ctx context.Context, orgID uuid.UUID, fn func(*generated.Queries) error) error {
	return s.withOrgRawTx(ctx, orgID, func(tx *sql.Tx) error {
		return fn(s.q.WithTx(tx))
	})
}

// OrgTx opens a pgx native transaction and sets app.org_id = orgID for the
// duration of the transaction (PLAN.md §6.2). RLS policies on org-scoped tables
// use this setting to filter rows to the specified org. Safe for connection
// pooling: SET LOCAL resets on commit or rollback.
//
// Use this for all org-scoped write operations from HTTP handlers.
func (s *Store) OrgTx(ctx context.Context, orgID uuid.UUID, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on panic or fn error
	// SET LOCAL does not accept parameterized values in PostgreSQL; formatting
	// is safe here because orgID is a typed uuid.UUID, not user-supplied text.
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL app.org_id = '%s'", orgID)); err != nil {
		return fmt.Errorf("set org_id: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// clampInt32 clamps v to [lo, hi] and returns it as int32.
func clampInt32(v, lo, hi int32) int32 {
	return min(max(v, lo), hi)
}

// WorkerTx opens a pgx native transaction with RLS bypass enabled.
// ONLY for background worker goroutines (batch evaluator, EPSS, retention).
// NEVER call from HTTP handler code paths — see PLAN.md §6.2.
func (s *Store) WorkerTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin worker tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, "SET LOCAL app.bypass_rls = 'on'"); err != nil {
		return fmt.Errorf("set bypass_rls: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
