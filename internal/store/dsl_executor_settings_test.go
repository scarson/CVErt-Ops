// ABOUTME: Integration test for the transaction settings ExecuteDSLQuery runs a rule's SQL under.
// ABOUTME: Checks read-only, JIT off, parallel query off and RLS bypass inside the statement, and the defaults after it.
package store_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestExecuteDSLQuery_RunsUnderRuleQuerySettings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := testutil.NewTestDB(t)
	tdb.SeedTestCVE(t, "CVE-2024-0001", "critical", nil)

	// One connection, so the SHOW after a query sees the connection that ran it.
	s := tdb.AppStore
	s.DB().SetMaxOpenConns(1)

	defaults := map[string]string{}
	for _, name := range []string{"jit", "max_parallel_workers_per_gather"} {
		var v string
		if err := s.DB().QueryRowContext(ctx, "SHOW "+name).Scan(&v); err != nil {
			t.Fatalf("SHOW %s: %v", name, err)
		}
		defaults[name] = v
	}
	if defaults["jit"] == "off" || defaults["max_parallel_workers_per_gather"] == "0" {
		t.Fatalf("server defaults %v; the test needs JIT and parallel query on to show the change", defaults)
	}

	rule := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "severity", Op: "eq", Value: json.RawMessage(`"critical"`)},
		},
	}
	// Each check is a join that keeps the CVE only when the condition holds in
	// the statement, so a missing setting returns no rows.
	checks := []struct {
		name         string
		hasWatchlist bool
		condition    string
	}{
		{"read only", false, "current_setting('transaction_read_only') = 'on'"},
		{"jit off", false, "current_setting('jit') = 'off'"},
		{"parallel query off", false, "current_setting('max_parallel_workers_per_gather') = '0'"},
		{"no RLS bypass without watchlists", false, "current_setting('app.bypass_rls', true) IS DISTINCT FROM 'on'"},
		{"watchlist rule read only", true, "current_setting('transaction_read_only') = 'on'"},
		{"watchlist rule jit off", true, "current_setting('jit') = 'off'"},
		{"watchlist rule parallel query off", true, "current_setting('max_parallel_workers_per_gather') = '0'"},
		{"watchlist rule bypasses RLS", true, "current_setting('app.bypass_rls', true) = 'on'"},
	}
	for _, c := range checks {
		compiled, err := dsl.Compile(rule, uuid.Nil, 0, uuid.Nil, nil)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		compiled.HasWatchlist = c.hasWatchlist
		compiled.Joins = append(compiled.Joins, "(SELECT 1) AS settings_check ON "+c.condition)

		results, _, err := s.ExecuteDSLQuery(ctx, compiled, "", 25)
		if err != nil {
			t.Fatalf("%s: ExecuteDSLQuery: %v", c.name, err)
		}
		if len(results) != 1 {
			t.Errorf("%s: got %d rows, want 1: %s does not hold in the statement", c.name, len(results), c.condition)
		}
	}

	// SET LOCAL ends with the transaction, so the pooled connection keeps the defaults.
	for name, want := range defaults {
		var got string
		if err := s.DB().QueryRowContext(ctx, "SHOW "+name).Scan(&got); err != nil {
			t.Fatalf("SHOW %s: %v", name, err)
		}
		if got != want {
			t.Errorf("%s after ExecuteDSLQuery = %q, want the default %q", name, got, want)
		}
	}
}
