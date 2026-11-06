// ABOUTME: Tests RLS policies on a pooled session that has already served an org-scoped transaction.
// ABOUTME: Runs as the restricted app role on a single connection, as production pool reuse does.
package store_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// newSingleConnAppStore returns a store whose every transaction shares one
// session, as the app role, so session state from one reaches the next.
func newSingleConnAppStore(t *testing.T, db *testutil.TestDB) (*store.Store, *pgxpool.Pool) {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(db.AppURL)
	if err != nil {
		t.Fatalf("parse app url: %v", err)
	}
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("app pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return store.New(pool), pool
}

// TestRLS_BypassWorksAfterOrgTransactionOnSameSession covers API key auth: the
// lookup runs with RLS bypass on a connection an org request may just have used.
func TestRLS_BypassWorksAfterOrgTransactionOnSameSession(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := testutil.NewTestDB(t)
	org := db.MustCreateOrg(t, ctx, "Session Org")
	user := db.MustCreateUser(t, ctx, "session@example.test", "Session", "hash", 2)
	const keyHash = "session-key-hash"
	if _, err := db.CreateAPIKey(ctx, org.ID, user.ID, keyHash, "session", "member", sql.NullTime{}); err != nil {
		t.Fatalf("create key: %v", err)
	}

	app, _ := newSingleConnAppStore(t, db)
	keys, err := app.ListOrgAPIKeys(ctx, org.ID)
	if err != nil {
		t.Fatalf("org-scoped list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("org-scoped list returned %d keys, want 1", len(keys))
	}

	key, err := app.LookupAPIKey(ctx, keyHash)
	if err != nil {
		t.Fatalf("bypass lookup on a session that served an org transaction: %v", err)
	}
	if key == nil {
		t.Fatal("bypass lookup found no key")
	}
}

// TestRLS_EveryPolicyFailsClosedOnSessionWithEmptyOrgSetting sweeps every table
// with RLS, so a table added later with the bare cast fails here. With no org
// context a query must return no rows, not raise an error.
func TestRLS_EveryPolicyFailsClosedOnSessionWithEmptyOrgSetting(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := testutil.NewTestDB(t)
	org := db.MustCreateOrg(t, ctx, "Sweep Org")
	user := db.MustCreateUser(t, ctx, "sweep@example.test", "Sweep", "hash", 2)
	if _, err := db.CreateAPIKey(ctx, org.ID, user.ID, "sweep-key-hash", "sweep", "member", sql.NullTime{}); err != nil {
		t.Fatalf("create key: %v", err)
	}

	_, pool := newSingleConnAppStore(t, db)
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

	rows, err := conn.Query(ctx, `
		SELECT c.relname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity
		ORDER BY c.relname`)
	if err != nil {
		t.Fatalf("list RLS tables: %v", err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("collect RLS tables: %v", err)
	}
	if len(tables) == 0 {
		t.Fatal("found no tables with RLS")
	}

	runTx := func(setup string, fn func(pgx.Tx) error) error {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(context.Background()) //nolint:errcheck // no-op after commit
		if setup != "" {
			if _, err := tx.Exec(ctx, setup); err != nil {
				return err
			}
		}
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	// An org transaction leaves app.org_id as an empty string on this session.
	if err := runTx("SET LOCAL app.org_id = '"+org.ID.String()+"'", func(pgx.Tx) error { return nil }); err != nil {
		t.Fatalf("org transaction: %v", err)
	}

	for _, table := range tables {
		query := "SELECT count(*) FROM " + pgx.Identifier{table}.Sanitize()
		var noContext, bypassed int
		err := runTx("", func(tx pgx.Tx) error { return tx.QueryRow(ctx, query).Scan(&noContext) })
		if err != nil {
			t.Errorf("%s with no org context: %v", table, err)
			continue
		}
		if noContext != 0 {
			t.Errorf("%s with no org context returned %d rows, want 0", table, noContext)
		}
		err = runTx("SET LOCAL app.bypass_rls = 'on'", func(tx pgx.Tx) error { return tx.QueryRow(ctx, query).Scan(&bypassed) })
		if err != nil {
			t.Errorf("%s with bypass: %v", table, err)
		}
		if table == "api_keys" && bypassed != 1 {
			t.Errorf("api_keys with bypass returned %d rows, want 1", bypassed)
		}
	}
}

// TestQueryExecMode_DefaultMatchesConfig keeps the test pools on the mode a
// deployment runs by default.
func TestQueryExecMode_DefaultMatchesConfig(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test:test@localhost/test")
	t.Setenv("JWT_SECRET", "test-secret-for-query-exec-mode")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	mode, err := store.ParseQueryExecMode(cfg.DBQueryExecMode)
	if err != nil {
		t.Fatalf("parse configured default: %v", err)
	}
	if mode != store.DefaultQueryExecMode {
		t.Errorf("configured default = %v, store default = %v", mode, store.DefaultQueryExecMode)
	}
}

func TestParseQueryExecMode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		want    pgx.QueryExecMode
		wantErr bool
	}{
		{name: "cache_describe", want: pgx.QueryExecModeCacheDescribe},
		{name: "extended_protocol", want: pgx.QueryExecModeCacheStatement},
		// Sends []byte as bytea, which jsonb columns reject.
		{name: "simple_protocol", wantErr: true},
		{name: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := store.ParseQueryExecMode(tt.name)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseQueryExecMode(%q) returned %v, want an error", tt.name, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseQueryExecMode(%q): %v", tt.name, err)
			}
			if got != tt.want {
				t.Errorf("ParseQueryExecMode(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
