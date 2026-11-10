// ABOUTME: Exposes unexported store internals to this package's external (store_test) tests.
// ABOUTME: Compiled only with tests, so nothing here is part of the package's API.
package store

import (
	"context"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/check"
)

// CheckLimits is checkLimits, for tests that lower the version check read limits.
type CheckLimits = checkLimits

// DefaultCheckLimits is the limits ReadCheckCandidates applies.
var DefaultCheckLimits = defaultCheckLimits

// CPEIndexExpr and CNANameIndexExpr build the indexed expressions the version
// check statements compare, for the tests that pin them to migration 000059.
var (
	CPEIndexExpr     = cpeIndexExpr
	CNANameIndexExpr = cnaNameIndexExpr
)

// ReadCheckCandidatesWith is readCheckCandidates: ReadCheckCandidates with the
// given limits, calling afterStatement after each statement it runs.
func (s *Store) ReadCheckCandidatesWith(ctx context.Context, orgID uuid.UUID, keys check.Keys, limits CheckLimits,
	afterStatement func(name string)) (check.Candidates, map[string]check.CVEEnrichment, []check.FeedRow, error) {
	return s.readCheckCandidates(ctx, orgID, keys, limits, afterStatement)
}
