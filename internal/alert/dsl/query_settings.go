// ABOUTME: Transaction settings every compiled rule statement runs under.
// ABOUTME: Shared by the alert evaluator's candidate queries and saved and AI search execution.
package dsl

import (
	"context"
	"database/sql"
	"fmt"
)

// RuleQuerySettings are the settings a compiled rule's statement runs under, in
// the order PrepareRuleQueryTx applies them, each for the rest of the
// transaction (dev/plans/2026-11-13-product-match-rules-measurements.md):
//
//   - JIT off. A rule statement over a large corpus has a high estimated cost,
//     so PostgreSQL JIT-compiles it: about 4 s of a 50-product dry run on a full
//     ingest.
//   - Parallel query off. On a full ingest PostgreSQL planned a parallel plan
//     for one realtime CVE (about 20 ms of 26 ms), and an activation page's
//     parallel hashes exhausted the container's 64 MB of shared memory.
var RuleQuerySettings = []string{
	"SET LOCAL jit = off",
	"SET LOCAL max_parallel_workers_per_gather = 0",
}

// PrepareRuleQueryTx applies RuleQuerySettings to tx. They end with the
// transaction.
func PrepareRuleQueryTx(ctx context.Context, tx *sql.Tx) error {
	for _, s := range RuleQuerySettings {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("prepare rule query transaction (%s): %w", s, err)
		}
	}
	return nil
}
