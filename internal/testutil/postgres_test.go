// ABOUTME: Tests for NewTestDB: per-test databases cloned from one migrated template per test binary.
// ABOUTME: Covers isolation, shared cluster, migration state, cleanup, and the testutil.Run precondition.
package testutil

import (
	"context"
	"strings"
	"testing"
)

func TestNewTestDB_IsolatedDatabasesShareOneCluster(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := NewTestDB(t)
	b := NewTestDB(t)

	var sysA, sysB int64
	var nameA, nameB string
	if err := a.DB().QueryRowContext(ctx,
		"SELECT system_identifier, current_database() FROM pg_control_system()",
	).Scan(&sysA, &nameA); err != nil {
		t.Fatalf("read cluster identity (a): %v", err)
	}
	if err := b.DB().QueryRowContext(ctx,
		"SELECT system_identifier, current_database() FROM pg_control_system()",
	).Scan(&sysB, &nameB); err != nil {
		t.Fatalf("read cluster identity (b): %v", err)
	}
	if sysA != sysB {
		t.Errorf("NewTestDB calls used different clusters (%d, %d); want one container per test binary", sysA, sysB)
	}
	if nameA == nameB {
		t.Fatalf("NewTestDB calls share database %q; want one database per test", nameA)
	}

	if _, err := a.CreateOrg(ctx, "visible-only-in-a"); err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	var orgsInB int
	if err := b.DB().QueryRowContext(ctx, "SELECT count(*) FROM organizations").Scan(&orgsInB); err != nil {
		t.Fatalf("count orgs in b: %v", err)
	}
	if orgsInB != 0 {
		t.Errorf("database b sees %d orgs written to database a; want 0", orgsInB)
	}

	// Both databases carry the fully migrated schema.
	for name, db := range map[string]*TestDB{"a": a, "b": b} {
		var version int64
		var dirty bool
		if err := db.DB().QueryRowContext(ctx,
			"SELECT version, dirty FROM schema_migrations",
		).Scan(&version, &dirty); err != nil {
			t.Fatalf("read schema_migrations (%s): %v", name, err)
		}
		if dirty || version == 0 {
			t.Errorf("database %s schema_migrations = (%d, dirty=%v); want latest clean version", name, version, dirty)
		}
	}
}

func TestNewTestDB_DropsDatabaseAtCleanup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var name string
	t.Run("owner", func(t *testing.T) {
		db := NewTestDB(t)
		if err := db.DB().QueryRowContext(ctx, "SELECT current_database()").Scan(&name); err != nil {
			t.Fatalf("read database name: %v", err)
		}
	})

	probe := NewTestDB(t)
	var exists bool
	if err := probe.DB().QueryRowContext(ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", name,
	).Scan(&exists); err != nil {
		t.Fatalf("look up database %q: %v", name, err)
	}
	if exists {
		t.Errorf("database %q still exists after its test finished; want it dropped", name)
	}
}

// TestCheckRunner_RequiresRun verifies NewTestDB refuses to start a container
// in a test binary whose TestMain does not call Run, because nothing would
// terminate that container.
func TestCheckRunner_RequiresRun(t *testing.T) {
	prev := runActive.Load()
	runActive.Store(false)
	t.Cleanup(func() { runActive.Store(prev) })

	err := checkRunner()
	if err == nil {
		t.Fatal("checkRunner() = nil without testutil.Run; want an error")
	}
	if !strings.Contains(err.Error(), "testutil.Run") {
		t.Errorf("checkRunner() error %q does not tell the reader to call testutil.Run", err)
	}

	runActive.Store(true)
	if err := checkRunner(); err != nil {
		t.Errorf("checkRunner() under testutil.Run = %v; want nil", err)
	}
}
