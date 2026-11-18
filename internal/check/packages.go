// ABOUTME: Decides one advisory's verdict for a package version from its cve_affected_packages rows.
// ABOUTME: Applies design section 4.1's row rules and combining rule; anything uncertain is cannot evaluate.
package check

import (
	"github.com/scarson/cvert-ops/internal/ecosystem"
	"github.com/scarson/cvert-ops/internal/version"
)

// Stored range types with their own handling. Other values ("ECOSYSTEM",
// "VERSIONS", none) are compared in the ecosystem's native order.
const (
	rangeTypeGit    = "GIT"
	rangeTypeSemver = "SEMVER"
)

// evidencePackageRange is the API's evidence value for a cve_affected_packages range.
const evidencePackageRange = "package_range"

// PackageRow is one cve_affected_packages row. Status is its CVE's cves.status.
type PackageRow struct {
	CVEID, Ecosystem, PackageName, RangeType, Introduced, Fixed, LastAffected string
	Status                                                                    string
}

// EvaluatePackageRows decides one advisory's verdict for version ver of a package
// in ecosystem, from that advisory's rows for the package. GIT rows hold commit
// hashes and are skipped when the advisory has any other row; with only GIT rows
// the advisory cannot be evaluated. The advisory is Affected if any row contains
// the version, NotAffected only if some row excludes it and no row could not be
// compared, and CannotEvaluate otherwise, with the reason of its first row that
// could not be compared.
//
// It calls m.Tick once per row compared and returns as soon as Tick refuses; the
// caller then discards the outcome and reports m.Err.
func EvaluatePackageRows(m *workMeter, ecosystem, ver string, rows []PackageRow) Outcome {
	compared := comparedRows(rows)
	if len(rows) > 0 && len(compared) == 0 {
		return Outcome{Verdict: CannotEvaluate, Reason: ReasonCommitRangesOnly}
	}

	var verdicts rowVerdicts
	for _, row := range compared {
		if !m.Tick() {
			return Outcome{}
		}
		verdicts.compare(ver, Bound{
			Range: version.Range{Introduced: row.Introduced, Fixed: row.Fixed, LastAffected: row.LastAffected},
			Check: rowCheck(ecosystem, row.RangeType),
		}, Matched{Evidence: evidencePackageRange, Ecosystem: row.Ecosystem})
	}
	return verdicts.outcome()
}

// comparedRows returns the rows to compare: every row except GIT rows, which
// have no version order.
func comparedRows(rows []PackageRow) []PackageRow {
	var compared []PackageRow
	for _, row := range rows {
		if row.RangeType != rangeTypeGit {
			compared = append(compared, row)
		}
	}
	return compared
}

// rowCheck returns the check for a row. A SEMVER range in an ecosystem whose
// native order is not SemVer is read as SemVer, as the OSV schema defines it,
// and also in the ecosystem's native order when it has one, because PLAN.md
// section 9.2 compares versions by the ecosystem's own rules and the two orders
// can disagree (2.0.0-1 is a SemVer prerelease below 2.0.0 and a Debian
// revision above it). Every other range is read in the ecosystem's native order.
func rowCheck(eco, rangeType string) func(string, version.Range) (version.Status, error) {
	native := func(v string, r version.Range) (version.Status, error) {
		return version.Check(eco, v, r)
	}
	if rangeType != rangeTypeSemver || ecosystem.OrdersBySemver(eco) {
		return native
	}
	if !version.Supported(eco) {
		return version.CheckSemver
	}
	return func(v string, r version.Range) (version.Status, error) {
		return checkBothOrders(v, r, native)
	}
}

// checkBothOrders reads v against r as SemVer and in the native order. It is
// Affected if either order contains v, NotAffected only if both exclude it, and
// CannotEvaluate otherwise, with the error of an order that could not evaluate:
// the native order's when both could not.
func checkBothOrders(v string, r version.Range,
	native func(string, version.Range) (version.Status, error)) (version.Status, error) {
	semverStatus, semverErr := version.CheckSemver(v, r)
	nativeStatus, nativeErr := native(v, r)
	switch {
	case semverStatus == version.Affected || nativeStatus == version.Affected:
		return version.Affected, nil
	case semverStatus == version.NotAffected && nativeStatus == version.NotAffected:
		return version.NotAffected, nil
	case nativeErr != nil:
		return version.CannotEvaluate, nativeErr
	default:
		return version.CannotEvaluate, semverErr
	}
}
