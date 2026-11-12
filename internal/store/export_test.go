// ABOUTME: Exposes unexported store internals to this package's external (store_test) tests.
// ABOUTME: Compiled only with tests, so nothing here is part of the package's API.
package store

import (
	"context"
	"database/sql"
	"errors"

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

// WithOrgSnapshotTx is withOrgSnapshotTx, for the test that pins its
// transaction's isolation level and read-only mode.
func (s *Store) WithOrgSnapshotTx(ctx context.Context, orgID uuid.UUID, fn func(*sql.Tx) error) error {
	return s.withOrgSnapshotTx(ctx, orgID, fn)
}

// ErrScanFailed is the error ReadKeyRowsFailingScan's scan returns.
var ErrScanFailed = errors.New("scan failed")

// ReadKeyRowsFailingScan runs query through readKeyRows in a version check
// snapshot, as the lookup of one key whose scan returns ErrScanFailed on the
// first row. No version check statement can fail to scan its own rows, so the
// test of what readKeyRows does on a scan error uses this.
func (s *Store) ReadKeyRowsFailingScan(ctx context.Context, orgID uuid.UUID, query string) error {
	return s.withOrgSnapshotTx(ctx, orgID, func(tx *sql.Tx) error {
		r := &checkRead{tx: tx, limits: defaultCheckLimits, advisories: map[string]bool{}}
		return readKeyRows(ctx, r, "failing_scan", query, nil, make([]check.KeyRows[struct{}], 1),
			func(*sql.Rows) (scanned[struct{}], error) { return scanned[struct{}]{}, ErrScanFailed })
	})
}
