// ABOUTME: Tests one advisory's verdict from its cve_affected_packages rows for one package version.
// ABOUTME: Covers each row rule of design section 4.1, the combining rule, fix candidates and the work meter.
package check

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/version"
)

// Commit hashes as GIT ranges store them.
const (
	commitA = "0123456789abcdef0123456789abcdef01234567"
	commitB = "89abcdef0123456789abcdef0123456789abcdef"
)

// pkgRow builds one stored row with the range type as the OSV and GHSA adapters
// write it: "ECOSYSTEM", "SEMVER" or "GIT" as OSV sends it, "ECOSYSTEM" from GHSA,
// and "VERSIONS" for rows built from an OSV versions list.
func pkgRow(rangeType, introduced, fixed, lastAffected string) PackageRow {
	return PackageRow{
		CVEID: "CVE-2026-0001", PackageName: "pkg", RangeType: rangeType,
		Introduced: introduced, Fixed: fixed, LastAffected: lastAffected,
	}
}

func matchedRow(introduced, fixed, lastAffected string) Matched {
	return Matched{Evidence: "package_range", Introduced: introduced, Fixed: fixed, LastAffected: lastAffected}
}

// boundRanges lists the ranges of an outcome's bounds, nil when there are none.
func boundRanges(bounds []Bound) []version.Range {
	var ranges []version.Range
	for _, b := range bounds {
		ranges = append(ranges, b.Range)
	}
	return ranges
}

func evaluate(t *testing.T, ecosystem, ver string, rows []PackageRow) Outcome {
	t.Helper()
	for i := range rows {
		rows[i].Ecosystem = ecosystem
	}
	m := newWorkMeter(context.Background())
	got := EvaluatePackageRows(m, ecosystem, ver, rows)
	if err := m.Err(); err != nil {
		t.Fatalf("meter error after evaluation: %v", err)
	}
	return got
}

func TestEvaluatePackageRows(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		ecosystem  string
		version    string
		rows       []PackageRow
		want       Outcome // Ranges is compared through wantRanges
		wantRanges []version.Range
	}{
		// Design 4.1, row "anything else": version.Check in the ecosystem's order.
		{
			name: "ecosystem range contains the version", ecosystem: "npm", version: "4.17.20",
			rows: []PackageRow{pkgRow("ECOSYSTEM", "0", "4.17.21", "")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("0", "4.17.21", "")}, Candidates: []string{"4.17.21"}},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "4.17.21"}},
		},
		{
			name: "ecosystem range does not contain the version", ecosystem: "npm", version: "4.17.21",
			rows:       []PackageRow{pkgRow("ECOSYSTEM", "0", "4.17.21", "")},
			want:       Outcome{Verdict: NotAffected, Comparable: true},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "4.17.21"}},
		},
		{
			name: "ecosystem order is native: PyPI release candidate sorts before the release", ecosystem: "PyPI", version: "1.1rc1",
			rows: []PackageRow{pkgRow("ECOSYSTEM", "1.0", "1.1", "")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("1.0", "1.1", "")}, Candidates: []string{"1.1"}},
			wantRanges: []version.Range{{Introduced: "1.0", Fixed: "1.1"}},
		},
		{
			name: "range with no upper bound is affected from introduced on", ecosystem: "npm", version: "9.0.0",
			rows: []PackageRow{pkgRow("ECOSYSTEM", "1.0.0", "", "")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("1.0.0", "", "")}},
			wantRanges: []version.Range{{Introduced: "1.0.0"}},
		},
		{
			name: "listed version row matches its exact version", ecosystem: "npm", version: "1.2.3",
			rows: []PackageRow{pkgRow("VERSIONS", "1.2.3", "", "1.2.3")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("1.2.3", "", "1.2.3")}},
			wantRanges: []version.Range{{Introduced: "1.2.3", LastAffected: "1.2.3"}},
		},
		{
			name: "listed version row does not match another version", ecosystem: "npm", version: "1.2.4",
			rows:       []PackageRow{pkgRow("VERSIONS", "1.2.3", "", "1.2.3")},
			want:       Outcome{Verdict: NotAffected, Comparable: true},
			wantRanges: []version.Range{{Introduced: "1.2.3", LastAffected: "1.2.3"}},
		},
		{
			name: "range type with no stored value is compared in the ecosystem's order", ecosystem: "npm", version: "1.0.0",
			rows: []PackageRow{pkgRow("", "0", "2.0.0", "")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("0", "2.0.0", "")}, Candidates: []string{"2.0.0"}},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "2.0.0"}},
		},
		{
			name: "version the ecosystem cannot read is invalid_version", ecosystem: "npm", version: "banana",
			rows:       []PackageRow{pkgRow("ECOSYSTEM", "0", "4.17.21", "")},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidVersion, InvalidVersion: true},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "4.17.21"}},
		},

		// Design 4.1, row "last_affected": an inclusive upper bound, never a fix candidate (design 7).
		{
			name: "last_affected contains its own version and is not a candidate", ecosystem: "npm", version: "1.5.0",
			rows: []PackageRow{pkgRow("ECOSYSTEM", "0", "", "1.5.0")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("0", "", "1.5.0")}},
			wantRanges: []version.Range{{Introduced: "0", LastAffected: "1.5.0"}},
		},
		{
			name: "last_affected excludes the next version", ecosystem: "npm", version: "1.5.1",
			rows:       []PackageRow{pkgRow("ECOSYSTEM", "0", "", "1.5.0")},
			want:       Outcome{Verdict: NotAffected, Comparable: true},
			wantRanges: []version.Range{{Introduced: "0", LastAffected: "1.5.0"}},
		},

		// Design 4.1, row "GIT".
		{
			name: "only GIT rows is commit_ranges_only", ecosystem: "npm", version: "1.0.0",
			rows: []PackageRow{pkgRow("GIT", commitA, commitB, ""), pkgRow("GIT", commitB, "", "")},
			want: Outcome{Verdict: CannotEvaluate, Reason: ReasonCommitRangesOnly},
		},
		{
			name: "GIT row ignored beside an affected row", ecosystem: "npm", version: "1.0.0",
			rows: []PackageRow{pkgRow("GIT", commitA, commitB, ""), pkgRow("ECOSYSTEM", "0", "2.0.0", "")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("0", "2.0.0", "")}, Candidates: []string{"2.0.0"}},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "2.0.0"}},
		},
		{
			name: "GIT row ignored beside a not affected row, so it does not block not affected", ecosystem: "npm", version: "3.0.0",
			rows:       []PackageRow{pkgRow("ECOSYSTEM", "0", "2.0.0", ""), pkgRow("GIT", commitA, commitB, "")},
			want:       Outcome{Verdict: NotAffected, Comparable: true},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "2.0.0"}},
		},
		{
			name: "GIT row ignored beside a row that cannot be evaluated", ecosystem: "npm", version: "1.0.0",
			rows:       []PackageRow{pkgRow("GIT", commitA, commitB, ""), pkgRow("VERSIONS", "", "", "")},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidRange},
			wantRanges: []version.Range{{}},
		},

		// Design 4.1, row "SEMVER type in an ecosystem whose native order is not SemVer",
		// with PLAN.md 9.2's rule that versions compare by the ecosystem's native order:
		// where the ecosystem has a comparator the row is read in both orders, Affected
		// if either contains the version and NotAffected only if both exclude it.
		// 2.0.0-1 is a SemVer prerelease below 2.0.0, and a Debian revision above it.
		{
			name: "SEMVER range in Debian is affected when SemVer order contains the version", ecosystem: "Debian:13", version: "2.0.0-1",
			rows: []PackageRow{pkgRow("SEMVER", "0", "2.0.0", "")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("0", "2.0.0", "")}, Candidates: []string{"2.0.0"}},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "2.0.0"}},
		},
		{
			name: "SEMVER range in Debian is affected when dpkg order contains the version", ecosystem: "Debian:13", version: "2.0.0-1",
			rows: []PackageRow{pkgRow("SEMVER", "2.0.0", "3.0.0", "")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("2.0.0", "3.0.0", "")}, Candidates: []string{"3.0.0"}},
			wantRanges: []version.Range{{Introduced: "2.0.0", Fixed: "3.0.0"}},
		},
		// 1.0-sp is a Maven service pack after 1.0, and a SemVer prerelease before it.
		{
			name: "SEMVER range in Maven is affected when Maven order contains the version", ecosystem: "Maven", version: "1.0-sp",
			rows: []PackageRow{pkgRow("SEMVER", "1.0", "2.0", "")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("1.0", "2.0", "")}, Candidates: []string{"2.0"}},
			wantRanges: []version.Range{{Introduced: "1.0", Fixed: "2.0"}},
		},
		{
			name: "SEMVER range in Debian is not affected when both orders exclude the version", ecosystem: "Debian:13", version: "1.0.0",
			rows:       []PackageRow{pkgRow("SEMVER", "2.0.0", "3.0.0", "")},
			want:       Outcome{Verdict: NotAffected, Comparable: true},
			wantRanges: []version.Range{{Introduced: "2.0.0", Fixed: "3.0.0"}},
		},
		{
			name: "ECOSYSTEM range in Debian with the same bounds is read in dpkg order", ecosystem: "Debian:13", version: "2.0.0-1",
			rows:       []PackageRow{pkgRow("ECOSYSTEM", "0", "2.0.0", "")},
			want:       Outcome{Verdict: NotAffected, Comparable: true},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "2.0.0"}},
		},
		// 1:2.0.0 has a Debian epoch, which SemVer cannot read; dpkg sorts it above 3.0.0.
		{
			name: "SEMVER range in Debian that dpkg excludes and SemVer cannot read is invalid_version", ecosystem: "Debian:13", version: "1:2.0.0",
			rows:       []PackageRow{pkgRow("SEMVER", "0", "3.0.0", "")},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidVersion, InvalidVersion: true},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "3.0.0"}},
		},
		// 2.5.0_rc1 is an Alpine version SemVer cannot read, and 2.0.0-1 a SemVer
		// version Alpine cannot read.
		{
			name: "SEMVER range in Alpine that SemVer excludes and Alpine cannot read is invalid_version", ecosystem: "Alpine:v3.20", version: "2.0.0-1",
			rows:       []PackageRow{pkgRow("SEMVER", "2.0.0", "3.0.0", "")},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidVersion, InvalidVersion: true},
			wantRanges: []version.Range{{Introduced: "2.0.0", Fixed: "3.0.0"}},
		},
		{
			name: "SEMVER range in Alpine that SemVer contains and Alpine cannot read is affected", ecosystem: "Alpine:v3.20", version: "2.5.0-beta",
			rows: []PackageRow{pkgRow("SEMVER", "2.0.0", "3.0.0", "")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("2.0.0", "3.0.0", "")}, Candidates: []string{"3.0.0"}},
			wantRanges: []version.Range{{Introduced: "2.0.0", Fixed: "3.0.0"}},
		},
		{
			name: "SEMVER range in Alpine that Alpine contains and SemVer cannot read is affected", ecosystem: "Alpine:v3.20", version: "2.5.0_rc1",
			rows: []PackageRow{pkgRow("SEMVER", "2.0.0", "3.0.0", "")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("2.0.0", "3.0.0", "")}, Candidates: []string{"3.0.0"}},
			wantRanges: []version.Range{{Introduced: "2.0.0", Fixed: "3.0.0"}},
		},
		{
			name: "SEMVER range neither order can evaluate takes the native order's reason", ecosystem: "Alpine:v3.20", version: "2.5.0_rc1",
			rows:       []PackageRow{pkgRow("SEMVER", "2.0.0-1", "3.0.0", "")},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidRange},
			wantRanges: []version.Range{{Introduced: "2.0.0-1", Fixed: "3.0.0"}},
		},
		{
			name: "SEMVER range in a SemVer ecosystem", ecosystem: "npm", version: "1.0.0",
			rows: []PackageRow{pkgRow("SEMVER", "0", "2.0.0", "")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("0", "2.0.0", "")}, Candidates: []string{"2.0.0"}},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "2.0.0"}},
		},
		{
			name: "SEMVER range in an ecosystem with no comparator is read as SemVer", ecosystem: "Root:x", version: "1.0.0",
			rows: []PackageRow{pkgRow("SEMVER", "0", "2.0.0", "")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("0", "2.0.0", "")}, Candidates: []string{"2.0.0"}},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "2.0.0"}},
		},

		// Design 4.1, row "ecosystem with no comparator".
		{
			name: "Root ecosystem is unknown_version_scheme", ecosystem: "Root:x", version: "1.0.0",
			rows:       []PackageRow{pkgRow("ECOSYSTEM", "0", "2.0.0", "")},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonUnknownVersionScheme, UnknownVersionScheme: true},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "2.0.0"}},
		},
		{
			name: "GitHub Actions is unknown_version_scheme", ecosystem: "GitHub Actions", version: "1.0.0",
			rows:       []PackageRow{pkgRow("ECOSYSTEM", "0", "2.0.0", "")},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonUnknownVersionScheme, UnknownVersionScheme: true},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "2.0.0"}},
		},

		// Design 4.1, row "no bounds, or empty introduced".
		{
			name: "row with no bounds is invalid_range", ecosystem: "npm", version: "1.0.0",
			rows:       []PackageRow{pkgRow("VERSIONS", "", "", "")},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidRange},
			wantRanges: []version.Range{{}},
		},
		{
			name: "row with an empty introduced is invalid_range", ecosystem: "npm", version: "1.0.0",
			rows:       []PackageRow{pkgRow("ECOSYSTEM", "", "2.0.0", "")},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidRange},
			wantRanges: []version.Range{{Fixed: "2.0.0"}},
		},
		{
			name: "row with both fixed and last_affected is invalid_range", ecosystem: "npm", version: "1.0.0",
			rows:       []PackageRow{pkgRow("ECOSYSTEM", "0", "2.0.0", "1.9.0")},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidRange},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "2.0.0", LastAffected: "1.9.0"}},
		},

		// Combining rows for one advisory.
		{
			name: "affected wins over not affected", ecosystem: "npm", version: "1.5.0",
			rows: []PackageRow{pkgRow("ECOSYSTEM", "2.0.0", "3.0.0", ""), pkgRow("ECOSYSTEM", "1.0.0", "1.6.0", "")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("1.0.0", "1.6.0", "")}, Candidates: []string{"1.6.0"}},
			wantRanges: []version.Range{{Introduced: "2.0.0", Fixed: "3.0.0"}, {Introduced: "1.0.0", Fixed: "1.6.0"}},
		},
		{
			name: "affected wins over cannot evaluate", ecosystem: "npm", version: "1.5.0",
			rows: []PackageRow{pkgRow("ECOSYSTEM", "", "9.0.0", ""), pkgRow("ECOSYSTEM", "1.0.0", "1.6.0", "")},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedRow("1.0.0", "1.6.0", "")}, Candidates: []string{"1.6.0"}},
			wantRanges: []version.Range{{Fixed: "9.0.0"}, {Introduced: "1.0.0", Fixed: "1.6.0"}},
		},
		{
			name: "every row not affected is not affected", ecosystem: "npm", version: "5.0.0",
			rows:       []PackageRow{pkgRow("ECOSYSTEM", "0", "1.0.0", ""), pkgRow("ECOSYSTEM", "2.0.0", "3.0.0", "")},
			want:       Outcome{Verdict: NotAffected, Comparable: true},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "1.0.0"}, {Introduced: "2.0.0", Fixed: "3.0.0"}},
		},
		{
			name: "not affected beside cannot evaluate is cannot evaluate", ecosystem: "npm", version: "5.0.0",
			rows:       []PackageRow{pkgRow("ECOSYSTEM", "0", "1.0.0", ""), pkgRow("VERSIONS", "", "", "")},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidRange, Comparable: true},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "1.0.0"}, {}},
		},
		// 1:5.0 is a valid Debian version with an epoch, which SemVer cannot read.
		{
			name: "reason is the first cannot evaluate row's: invalid_version first", ecosystem: "Debian:13", version: "1:5.0",
			rows: []PackageRow{
				pkgRow("ECOSYSTEM", "0", "1.0", ""),
				pkgRow("SEMVER", "0", "2.0.0", ""),
				pkgRow("VERSIONS", "", "", ""),
			},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidVersion, Comparable: true, InvalidVersion: true},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "1.0"}, {Introduced: "0", Fixed: "2.0.0"}, {}},
		},
		{
			name: "reason is the first cannot evaluate row's: invalid_range first", ecosystem: "Debian:13", version: "1:5.0",
			rows: []PackageRow{
				pkgRow("VERSIONS", "", "", ""),
				pkgRow("ECOSYSTEM", "0", "1.0", ""),
				pkgRow("SEMVER", "0", "2.0.0", ""),
			},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidRange, Comparable: true, InvalidVersion: true},
			wantRanges: []version.Range{{}, {Introduced: "0", Fixed: "1.0"}, {Introduced: "0", Fixed: "2.0.0"}},
		},
		{
			name: "every affected row is matched and its fix is a candidate", ecosystem: "npm", version: "1.2.0",
			rows: []PackageRow{
				pkgRow("ECOSYSTEM", "1.0.0", "1.2.3", ""),
				pkgRow("ECOSYSTEM", "1.1.0", "1.2.4", ""),
				pkgRow("ECOSYSTEM", "0", "", "1.3.0"),
			},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{
					matchedRow("1.0.0", "1.2.3", ""),
					matchedRow("1.1.0", "1.2.4", ""),
					matchedRow("0", "", "1.3.0"),
				},
				Candidates: []string{"1.2.3", "1.2.4"}},
			wantRanges: []version.Range{
				{Introduced: "1.0.0", Fixed: "1.2.3"},
				{Introduced: "1.1.0", Fixed: "1.2.4"},
				{Introduced: "0", LastAffected: "1.3.0"},
			},
		},
		{
			name: "no rows cannot be evaluated", ecosystem: "npm", version: "1.0.0",
			want: Outcome{Verdict: CannotEvaluate},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := evaluate(t, tt.ecosystem, tt.version, tt.rows)
			gotRanges := boundRanges(got.Ranges)
			for i, b := range got.Ranges {
				if b.Check == nil {
					t.Errorf("Ranges[%d].Check is nil", i)
				}
			}
			got.Ranges = nil
			// Each matched range names the stored row's ecosystem.
			want := tt.want
			want.Matched = slices.Clone(tt.want.Matched)
			for i := range want.Matched {
				want.Matched[i].Ecosystem = tt.ecosystem
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("EvaluatePackageRows(%q, %q) =\n  %+v\nwant\n  %+v", tt.ecosystem, tt.version, got, want)
			}
			if !reflect.DeepEqual(gotRanges, tt.wantRanges) {
				t.Errorf("Ranges = %+v, want %+v", gotRanges, tt.wantRanges)
			}
		})
	}
}

// TestEvaluatePackageRowsBoundOrder checks that each Bound carries the order its
// row was compared with, because fix reporting re-checks candidates through it.
// A SEMVER row in Debian reads both orders, so it contains 2.0.0-1 under SemVer
// and 2.0.0-1 against [2.0.0, 3.0.0) under dpkg.
func TestEvaluatePackageRowsBoundOrder(t *testing.T) {
	t.Parallel()
	got := evaluate(t, "Debian:13", "1.0.0", []PackageRow{
		pkgRow("SEMVER", "0", "2.0.0", ""),
		pkgRow("ECOSYSTEM", "0", "2.0.0", ""),
		pkgRow("SEMVER", "2.0.0", "3.0.0", ""),
	})
	if len(got.Ranges) != 3 {
		t.Fatalf("len(Ranges) = %d, want 3", len(got.Ranges))
	}
	semverBound, dpkgBound, upperSemverBound := got.Ranges[0], got.Ranges[1], got.Ranges[2]
	if s, err := semverBound.Check("2.0.0-1", semverBound.Range); s != version.Affected || err != nil {
		t.Errorf("SEMVER bound Check(2.0.0-1) = %v, %v; want affected under SemVer order", s, err)
	}
	if s, err := upperSemverBound.Check("2.0.0-1", upperSemverBound.Range); s != version.Affected || err != nil {
		t.Errorf("SEMVER [2.0.0, 3.0.0) bound Check(2.0.0-1) = %v, %v; want affected under dpkg order", s, err)
	}
	if s, err := dpkgBound.Check("2.0.0-1", dpkgBound.Range); s != version.NotAffected || err != nil {
		t.Errorf("ECOSYSTEM bound Check(2.0.0-1) = %v, %v; want not affected under dpkg order", s, err)
	}
}

// TestEvaluatePackageRowsSeveralFixesUnderOneIntroduced documents design 4.1's
// shape [{introduced: 0}, {fixed: A}, {fixed: B}], stored as (0, A) and ("", B).
// Below A the advisory is Affected with candidate A, and A is then rejected by
// fix reporting because the ("", B) bound cannot evaluate it, so no fix is
// claimed. At or above A the advisory cannot be evaluated.
func TestEvaluatePackageRowsSeveralFixesUnderOneIntroduced(t *testing.T) {
	t.Parallel()
	rows := func() []PackageRow {
		return []PackageRow{pkgRow("ECOSYSTEM", "0", "1.5.0", ""), pkgRow("ECOSYSTEM", "", "2.0.0", "")}
	}

	below := evaluate(t, "npm", "1.0.0", rows())
	if below.Verdict != Affected || !reflect.DeepEqual(below.Candidates, []string{"1.5.0"}) {
		t.Fatalf("below A: verdict %v, candidates %v; want Affected with candidate 1.5.0", below.Verdict, below.Candidates)
	}
	if len(below.Ranges) != 2 {
		t.Fatalf("below A: len(Ranges) = %d, want 2", len(below.Ranges))
	}
	b := below.Ranges[1]
	if s, err := b.Check("1.5.0", b.Range); s != version.CannotEvaluate || !errors.Is(err, version.ErrInvalidRange) {
		t.Errorf("candidate 1.5.0 against the (\"\", 2.0.0) bound = %v, %v; want cannot evaluate, invalid range", s, err)
	}

	for _, ver := range []string{"1.5.0", "1.7.0"} {
		got := evaluate(t, "npm", ver, rows())
		if got.Verdict != CannotEvaluate || got.Reason != ReasonInvalidRange {
			t.Errorf("version %s: verdict %v, reason %q; want cannot evaluate, invalid_range", ver, got.Verdict, got.Reason)
		}
	}
}

func TestReasonValues(t *testing.T) {
	t.Parallel()
	// The API's reason enumeration, design section 11.
	want := []string{
		"unknown_version_scheme", "invalid_version", "invalid_range", "commit_ranges_only",
		"no_version_bounds", "cna_cannot_clear", "cna_indeterminate", "cna_name_uncertain",
		"cna_product_not_mapped", "data_incomplete", "distro_package_not_found",
		"too_many_candidates", "too_many_ranges", "evaluation_failed", "sdk_version_not_comparable",
		"distro_stream_incomplete", "distro_lists_fixes_only",
	}
	got := []Reason{
		ReasonUnknownVersionScheme, ReasonInvalidVersion, ReasonInvalidRange, ReasonCommitRangesOnly,
		ReasonNoVersionBounds, ReasonCNACannotClear, ReasonCNAIndeterminate, ReasonCNANameUncertain,
		ReasonCNAProductNotMapped, ReasonDataIncomplete, ReasonDistroPackageNotFound,
		ReasonTooManyCandidates, ReasonTooManyRanges, ReasonEvaluationFailed, ReasonSDKVersionNotComparable,
		ReasonDistroStreamIncomplete, ReasonDistroListsFixesOnly,
	}
	if len(got) != len(want) {
		t.Fatalf("%d reasons, want %d", len(got), len(want))
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Errorf("reason %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestVerdictZeroValueIsCannotEvaluate(t *testing.T) {
	t.Parallel()
	var v Verdict
	if v != CannotEvaluate {
		t.Errorf("zero Verdict = %v, want CannotEvaluate", v)
	}
	if (Outcome{}).Verdict != CannotEvaluate {
		t.Error("zero Outcome's verdict is not CannotEvaluate")
	}
}

// affectedRows returns n rows that each contain 1.0.0.
func affectedRows(n int) []PackageRow {
	rows := make([]PackageRow, n)
	for i := range rows {
		rows[i] = pkgRow("ECOSYSTEM", "0", "2.0.0", "")
		rows[i].Ecosystem = "npm"
	}
	return rows
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// TestEvaluatePackageRowsMeter checks that Tick reads the context only on every
// 1,000th call, so a cancelled request still evaluates fewer rows than that, and
// that evaluation stops at the 1,000th row once the context has ended.
func TestEvaluatePackageRowsMeter(t *testing.T) {
	t.Parallel()

	t.Run("one tick per compared row", func(t *testing.T) {
		t.Parallel()
		m := newWorkMeter(context.Background())
		ticks := 0
		m.onTick = func() { ticks++ }
		rows := append(affectedRows(3), pkgRow("GIT", commitA, commitB, ""))
		got := EvaluatePackageRows(m, "npm", "1.0.0", rows)
		if ticks != 3 {
			t.Errorf("ticks = %d, want 3 (GIT rows are not compared)", ticks)
		}
		if got.Verdict != Affected {
			t.Errorf("verdict = %v, want Affected", got.Verdict)
		}
	})

	t.Run("cancelled context below 1,000 rows completes", func(t *testing.T) {
		t.Parallel()
		m := newWorkMeter(cancelledContext())
		ticks := 0
		m.onTick = func() { ticks++ }
		got := EvaluatePackageRows(m, "npm", "1.0.0", affectedRows(999))
		if ticks != 999 {
			t.Errorf("ticks = %d, want 999", ticks)
		}
		if got.Verdict != Affected || len(got.Matched) != 999 {
			t.Errorf("verdict %v with %d matched, want Affected with 999", got.Verdict, len(got.Matched))
		}
		if !errors.Is(m.Err(), context.Canceled) {
			t.Errorf("Err() = %v, want context.Canceled", m.Err())
		}
	})

	t.Run("cancelled context stops at the 1,000th row", func(t *testing.T) {
		t.Parallel()
		m := newWorkMeter(cancelledContext())
		ticks := 0
		m.onTick = func() { ticks++ }
		EvaluatePackageRows(m, "npm", "1.0.0", affectedRows(2500))
		if ticks != 1000 {
			t.Errorf("ticks = %d, want 1000", ticks)
		}
		if !errors.Is(m.Err(), context.Canceled) {
			t.Errorf("Err() = %v, want context.Canceled", m.Err())
		}
		if m.Tick() {
			t.Error("Tick() after the context ended = true, want false")
		}
		if ticks != 1000 {
			t.Errorf("ticks after a refused Tick = %d, want 1000", ticks)
		}
	})

	t.Run("live context evaluates every row", func(t *testing.T) {
		t.Parallel()
		m := newWorkMeter(context.Background())
		got := EvaluatePackageRows(m, "npm", "1.0.0", affectedRows(2500))
		if len(got.Matched) != 2500 || m.Err() != nil {
			t.Errorf("matched %d, Err() = %v; want 2500 and nil", len(got.Matched), m.Err())
		}
	})

	t.Run("Err reports cancellation before any tick", func(t *testing.T) {
		t.Parallel()
		m := newWorkMeter(cancelledContext())
		if !errors.Is(m.Err(), context.Canceled) {
			t.Errorf("Err() = %v, want context.Canceled", m.Err())
		}
	})
}

// TestEvaluatePackageRowsMatchedEvidence pins the evidence value the API reports.
func TestEvaluatePackageRowsMatchedEvidence(t *testing.T) {
	t.Parallel()
	got := evaluate(t, "npm", "1.0.0", []PackageRow{pkgRow("ECOSYSTEM", "0", "2.0.0", "")})
	if len(got.Matched) != 1 || got.Matched[0].Evidence != "package_range" || got.Matched[0].CPE != "" {
		t.Errorf("Matched = %+v, want one package_range entry with no CPE", got.Matched)
	}
	if strings.TrimSpace(string(got.Reason)) != "" {
		t.Errorf("Reason = %q for an affected advisory, want empty", got.Reason)
	}
}
