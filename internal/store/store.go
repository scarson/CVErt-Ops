// Package store provides the data access layer. Simple CRUD queries use
// sqlc-generated code backed by a *sql.DB (wrapping pgxpool via stdlib).
// Complex transactional operations (merge pipeline, SKIP LOCKED worker)
// use *pgxpool.Pool directly for pgx native transactions and advisory locks.
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

// withTx runs fn inside a database/sql transaction. The transaction is
// committed if fn returns nil, rolled back otherwise.
func (s *Store) withTx(ctx context.Context, fn func(*generated.Queries) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if err := fn(s.q.WithTx(tx)); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
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
