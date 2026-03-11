// ABOUTME: Tests for auto-migrate on startup — advisory lock, flag skip, error handling.
// ABOUTME: Unit tests for flag parsing; integration tests require testcontainers (Docker).
package main

import (
	"context"
	"testing"

	"github.com/scarson/cvert-ops/internal/config"
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
