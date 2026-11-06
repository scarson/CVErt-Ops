// ABOUTME: Tests for auto-migrate on startup — advisory lock, flag skip, error handling.
// ABOUTME: Unit tests for flag parsing; integration tests require testcontainers (Docker).
package main

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestAutoMigrate_InvalidURL_ReturnsError(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		DatabaseURL: "postgres://invalid:5432/nonexistent?connect_timeout=1",
	}
	err := autoMigrate(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for invalid database URL, got nil")
	}
}

// TestAutoMigrate_ReturnsAndReleasesItsLock covers the path every server start
// takes: serve cannot begin listening until autoMigrate returns.
func TestAutoMigrate_ReturnsAndReleasesItsLock(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	cfg := &config.Config{DatabaseURL: db.URL}

	done := make(chan error, 1)
	go func() { done <- autoMigrate(context.Background(), cfg) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("autoMigrate: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("autoMigrate did not return within 30s")
	}

	ctx := t.Context()
	conn, err := pgx.Connect(ctx, db.URL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(context.Background()) //nolint:errcheck
	var acquired bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtext('cvertops-migrate'))").Scan(&acquired); err != nil {
		t.Fatalf("try lock: %v", err)
	}
	if !acquired {
		t.Error("autoMigrate returned while still holding the migration lock")
	}
}

func TestServeCmd_HasSkipAutoMigrateFlag(t *testing.T) {
	t.Parallel()
	cmd := serveCmd()
	f := cmd.Flags().Lookup("skip-auto-migrate")
	if f == nil {
		t.Fatal("serveCmd should have --skip-auto-migrate flag")
	}
	if f.DefValue != "false" {
		t.Errorf("--skip-auto-migrate default = %q, want %q", f.DefValue, "false")
	}
}
