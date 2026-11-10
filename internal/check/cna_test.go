// ABOUTME: Tests how CNA affected[].versions entries are read for one version, as segments.
// ABOUTME: Covers every row of the plan's Task 3.5 table and design section 4.3, strongest-wins, range counts and the work meter.
package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed"
)

// Entries from the plan's Task 3.5 table. Real CNA values where the table names a CVE.
var (
	// {1.0, lt 2.0, affected, semver}
	cnaSemver10To20 = CNAVersion{Version: "1.0", LessThan: "2.0", Status: "affected", VersionType: "semver"}

	// CVE-2024-7347 (F5, nginx): {1.25.0, lt 1.27.1, affected}, changes to
	// unaffected at 1.26.2 and 1.27.1.
	cnaNginx7347 = CNAVersion{
		Version: "1.25.0", LessThan: "1.27.1", Status: "affected", VersionType: "semver",
		Changes: []CNAChange{{At: "1.26.2", Status: "unaffected"}, {At: "1.27.1", Status: "unaffected"}},
	}

	// CVE-2021-44228 as the MITRE golden archive holds it.
	cnaLog4j44228 = CNAVersion{
		Version: "2.0-beta9", LessThan: "log4j-core*", Status: "affected", VersionType: "custom",
		Changes: []CNAChange{
			{At: "2.3.1", Status: "unaffected"},
			{At: "2.4", Status: "affected"},
			{At: "2.12.2", Status: "unaffected"},
			{At: "2.13.0", Status: "affected"},
			{At: "2.15.0", Status: "unaffected"},
		},
	}

	// {1.0, lt 3.0, unknown}, change to affected at 2.0.
	cnaUnknownThenAffected = CNAVersion{
		Version: "1.0", LessThan: "3.0", Status: "unknown",
		Changes: []CNAChange{{At: "2.0", Status: "affected"}},
	}

	// {1.0, lt 3.0, unaffected}, change to affected at 2.0, to unaffected at 2.5.
	cnaUnaffectedAffectedUnaffected = CNAVersion{
		Version: "1.0", LessThan: "3.0", Status: "unaffected",
		Changes: []CNAChange{{At: "2.0", Status: "affected"}, {At: "2.5", Status: "unaffected"}},
	}

	// {1, lt *, affected}, change to unaffected at 2.
	cnaStarWithChange = CNAVersion{
		Version: "1", LessThan: "*", Status: "affected",
		Changes: []CNAChange{{At: "2", Status: "unaffected"}},
	}

	// CVE-2024-27980 (Node.js): {12.0, lt 12.*, affected, semver}.
	cnaNode27980 = CNAVersion{Version: "12.0", LessThan: "12.*", Status: "affected", VersionType: "semver"}

	// {1.0.0, lt 2.*, affected, semver}
	cnaWildcardLine2 = CNAVersion{Version: "1.0.0", LessThan: "2.*", Status: "affected", VersionType: "semver"}

	// {1.0rc1, lte 2.0, affected, custom}
	cnaUnreadableLowerInclusive = CNAVersion{Version: "1.0rc1", LessThanOrEqual: "2.0", Status: "affected", VersionType: "custom"}

	// {>= 1.0.0, affected, custom}
	cnaFreeTextOpen = CNAVersion{Version: ">= 1.0.0", Status: "affected", VersionType: "custom"}

	// {1.0, lt 3.0, affected}, changes to affected and to unaffected, both at 2.0.
	cnaConflictAt2 = CNAVersion{
		Version: "1.0", LessThan: "3.0", Status: "affected",
		Changes: []CNAChange{{At: "2.0", Status: "affected"}, {At: "2.0", Status: "unaffected"}},
	}

	// {1.0, lt 2.x, affected, maven}: Maven reads 2.x as a version.
	cnaMavenLt2x = CNAVersion{Version: "1.0", LessThan: "2.x", Status: "affected", VersionType: "maven"}

	// {1.0, lt 3.0, affected, maven}, change to unaffected at 2.x.
	cnaMavenChangeAt2x = CNAVersion{
		Version: "1.0", LessThan: "3.0", Status: "affected", VersionType: "maven",
		Changes: []CNAChange{{At: "2.x", Status: "unaffected"}},
	}

	// {2.0, lt 1.0, affected}: the upper bound is below the lower.
	cnaInverted = CNAVersion{Version: "2.0", LessThan: "1.0", Status: "affected"}

	// {1.0, lt 2.0, unaffected}, change to affected at 3.0, above the upper bound.
	cnaAffectedChangeAboveUpper = CNAVersion{
		Version: "1.0", LessThan: "2.0", Status: "unaffected",
		Changes: []CNAChange{{At: "3.0", Status: "affected"}},
	}

	// {*, lte 1.4.4, affected, semver}
	cnaStarLower = CNAVersion{Version: "*", LessThanOrEqual: "1.4.4", Status: "affected", VersionType: "semver"}

	// {1.0, lte 2.*, affected, semver}
	cnaInclusiveWildcardLine2 = CNAVersion{Version: "1.0", LessThanOrEqual: "2.*", Status: "affected", VersionType: "semver"}
)

// reversed returns e with its changes in reverse order.
func reversed(e CNAVersion) CNAVersion {
	changes := make([]CNAChange, len(e.Changes))
	for i, c := range e.Changes {
		changes[len(changes)-1-i] = c
	}
	e.Changes = changes
	return e
}

func cnaMatched(introduced, fixed, lastAffected string) []Matched {
	return []Matched{{Evidence: "cna", Introduced: introduced, Fixed: fixed, LastAffected: lastAffected}}
}

func readCNA(t *testing.T, ver string, rows []CNARow) CNAResult {
	t.Helper()
	m := newWorkMeter(context.Background())
	got := ReadCNAEntries(m, ver, rows)
	if err := m.Err(); err != nil {
		t.Fatalf("meter error after reading: %v", err)
	}
	return got
}

func oneEntry(e CNAVersion) []CNARow {
	return []CNARow{{CVEID: "CVE-2026-0001", Vendor: "vendor", Product: "product", Versions: []CNAVersion{e}}}
}

// TestReadCNAEntry has one case for each version of each row of the plan's
// Task 3.5 table, named "plan: <row> / <version>", then one case for each row of
// design section 4.3's result table and supporting rule the plan rows do not
// already exercise, named "design: ...".
func TestReadCNAEntry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		entry   CNAVersion
		version string
		want    CNAResult
	}{
		// Plan: {1.0, lt 2.0, affected, semver}.
		{
			name: "plan: {1.0, lt 2.0, affected, semver} / 1.5", entry: cnaSemver10To20, version: "1.5",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"2.0"}, Matched: cnaMatched("1.0", "2.0", "")},
		},
		{name: "plan: same / 2.0", entry: cnaSemver10To20, version: "2.0", want: CNAResult{Reading: NoStatement}},
		{name: "plan: same / 0.9", entry: cnaSemver10To20, version: "0.9", want: CNAResult{Reading: NoStatement}},

		// Plan: the shape of CVE-2024-7347.
		{
			name: "plan: CVE-2024-7347 shape / 1.26.0", entry: cnaNginx7347, version: "1.26.0",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"1.26.2"}, Matched: cnaMatched("1.25.0", "1.26.2", "")},
		},
		{name: "plan: CVE-2024-7347 shape / 1.26.2", entry: cnaNginx7347, version: "1.26.2", want: CNAResult{Reading: NoStatement}},
		{name: "plan: CVE-2024-7347 shape / 1.26.5", entry: cnaNginx7347, version: "1.26.5", want: CNAResult{Reading: Indeterminate}},

		// Plan: CVE-2021-44228 values.
		{
			name: "plan: CVE-2021-44228 values / 2.14.0", entry: cnaLog4j44228, version: "2.14.0",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"2.15.0"}, Matched: cnaMatched("2.13.0", "2.15.0", "")},
		},
		{name: "plan: CVE-2021-44228 values / 2.0.1", entry: cnaLog4j44228, version: "2.0.1", want: CNAResult{Reading: Indeterminate}},
		{name: "plan: CVE-2021-44228 values / 2.17.0", entry: cnaLog4j44228, version: "2.17.0", want: CNAResult{Reading: Indeterminate}},

		// Plan: {1.0, lt 3.0, unknown}, change to affected at 2.0.
		{name: "plan: {1.0, lt 3.0, unknown} with affected at 2.0 / 1.5", entry: cnaUnknownThenAffected, version: "1.5", want: CNAResult{Reading: Indeterminate}},
		{
			name: "plan: {1.0, lt 3.0, unknown} with affected at 2.0 / 2.5", entry: cnaUnknownThenAffected, version: "2.5",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"3.0"}, Matched: cnaMatched("2.0", "3.0", "")},
		},

		// Plan: {1.0, lt 3.0, unaffected}, change to affected at 2.0, to unaffected at 2.5.
		{name: "plan: {1.0, lt 3.0, unaffected} affected at 2.0 unaffected at 2.5 / 1.5", entry: cnaUnaffectedAffectedUnaffected, version: "1.5", want: CNAResult{Reading: NoStatement}},
		{
			name: "plan: {1.0, lt 3.0, unaffected} affected at 2.0 unaffected at 2.5 / 2.2", entry: cnaUnaffectedAffectedUnaffected, version: "2.2",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"2.5"}, Matched: cnaMatched("2.0", "2.5", "")},
		},
		{name: "plan: {1.0, lt 3.0, unaffected} affected at 2.0 unaffected at 2.5 / 2.7", entry: cnaUnaffectedAffectedUnaffected, version: "2.7", want: CNAResult{Reading: Indeterminate}},

		// Plan: changes given in reverse order give the same result as sorted. The
		// two multi-change entries above, with their changes reversed.
		{
			name: "plan: changes given in reverse order / CVE-2024-7347 shape 1.26.0", entry: reversed(cnaNginx7347), version: "1.26.0",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"1.26.2"}, Matched: cnaMatched("1.25.0", "1.26.2", "")},
		},
		{name: "plan: changes given in reverse order / CVE-2024-7347 shape 1.26.2", entry: reversed(cnaNginx7347), version: "1.26.2", want: CNAResult{Reading: NoStatement}},
		{name: "plan: changes given in reverse order / CVE-2024-7347 shape 1.26.5", entry: reversed(cnaNginx7347), version: "1.26.5", want: CNAResult{Reading: Indeterminate}},
		{name: "plan: changes given in reverse order / unaffected affected unaffected 1.5", entry: reversed(cnaUnaffectedAffectedUnaffected), version: "1.5", want: CNAResult{Reading: NoStatement}},
		{
			name: "plan: changes given in reverse order / unaffected affected unaffected 2.2", entry: reversed(cnaUnaffectedAffectedUnaffected), version: "2.2",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"2.5"}, Matched: cnaMatched("2.0", "2.5", "")},
		},
		{name: "plan: changes given in reverse order / unaffected affected unaffected 2.7", entry: reversed(cnaUnaffectedAffectedUnaffected), version: "2.7", want: CNAResult{Reading: Indeterminate}},
		{
			name: "plan: changes given in reverse order / CVE-2021-44228 values 2.14.0", entry: reversed(cnaLog4j44228), version: "2.14.0",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"2.15.0"}, Matched: cnaMatched("2.13.0", "2.15.0", "")},
		},

		// Plan: a change whose at the comparator cannot read, version above the
		// lower bound. Entry {1.0, lt 3.0, affected, custom}, change to unaffected
		// at 2.0rc1, which CheckNumeric cannot read.
		{
			name:  "plan: a change whose at the comparator cannot read / 1.5 above the lower bound",
			entry: CNAVersion{Version: "1.0", LessThan: "3.0", Status: "affected", VersionType: "custom", Changes: []CNAChange{{At: "2.0rc1", Status: "unaffected"}}}, version: "1.5",
			want: CNAResult{Reading: Indeterminate},
		},

		// Plan: {1, lt *, affected}, change to unaffected at 2.
		{
			name: "plan: {1, lt *, affected} unaffected at 2 / 1.5", entry: cnaStarWithChange, version: "1.5",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"2"}, Matched: cnaMatched("1", "2", "")},
		},
		{name: "plan: {1, lt *, affected} unaffected at 2 / 2", entry: cnaStarWithChange, version: "2", want: CNAResult{Reading: NoStatement}},
		{name: "plan: {1, lt *, affected} unaffected at 2 / 2.5", entry: cnaStarWithChange, version: "2.5", want: CNAResult{Reading: Indeterminate}},

		// Plan: {12.0, lt 12.*, affected, semver}, CVE-2024-27980's shape.
		{name: "plan: {12.0, lt 12.*, affected, semver} / 12.22.12", entry: cnaNode27980, version: "12.22.12", want: CNAResult{Reading: Indeterminate}},
		{name: "plan: same / 13.0.0", entry: cnaNode27980, version: "13.0.0", want: CNAResult{Reading: NoStatement}},

		// Plan: {1.0.0, lt 2.*, affected, semver}.
		{name: "plan: {1.0.0, lt 2.*, affected, semver} / 1.5.0", entry: cnaWildcardLine2, version: "1.5.0", want: CNAResult{Reading: Indeterminate}},
		{name: "plan: {1.0.0, lt 2.*, affected, semver} / 2.9.0", entry: cnaWildcardLine2, version: "2.9.0", want: CNAResult{Reading: Indeterminate}},
		{name: "plan: {1.0.0, lt 2.*, affected, semver} / 3.0.0", entry: cnaWildcardLine2, version: "3.0.0", want: CNAResult{Reading: NoStatement}},

		// Plan: wholly unaffected entries.
		{
			name:  "plan: {6.6.1, lte 6.6.*, unaffected, semver} / 6.6.5",
			entry: CNAVersion{Version: "6.6.1", LessThanOrEqual: "6.6.*", Status: "unaffected", VersionType: "semver"}, version: "6.6.5",
			want: CNAResult{Reading: NoStatement},
		},
		{
			name:  "plan: {1.0rc1, lt 2.0, unaffected, custom} / 1.5",
			entry: CNAVersion{Version: "1.0rc1", LessThan: "2.0", Status: "unaffected", VersionType: "custom"}, version: "1.5",
			want: CNAResult{Reading: NoStatement},
		},
		{
			name:  "plan: {1.0, lt 2.0, unaffected, custom} / 1.1rc1 the comparator cannot read",
			entry: CNAVersion{Version: "1.0", LessThan: "2.0", Status: "unaffected", VersionType: "custom"}, version: "1.1rc1",
			want: CNAResult{Reading: NoStatement},
		},
		{
			name:  "plan: {1.0, lt 2.0, unaffected, versionType deb} / 1.5",
			entry: CNAVersion{Version: "1.0", LessThan: "2.0", Status: "unaffected", VersionType: "deb"}, version: "1.5",
			want: CNAResult{Reading: NoStatement},
		},

		// Plan: unreadable lower bounds.
		{
			name:  "plan: {1.0rc1, lt 2.0, affected, custom} / 1.5",
			entry: CNAVersion{Version: "1.0rc1", LessThan: "2.0", Status: "affected", VersionType: "custom"}, version: "1.5",
			want: CNAResult{Reading: Indeterminate},
		},
		{name: "plan: {1.0rc1, lte 2.0, affected, custom} / 2.0", entry: cnaUnreadableLowerInclusive, version: "2.0", want: CNAResult{Reading: Indeterminate}},
		{name: "plan: {1.0rc1, lte 2.0, affected, custom} / 2.1", entry: cnaUnreadableLowerInclusive, version: "2.1", want: CNAResult{Reading: NoStatement}},

		// Plan: both upper bounds set.
		{
			name:  "plan: {1, lt 2, lte 3, affected} both upper bounds / 2.5",
			entry: CNAVersion{Version: "1", LessThan: "2", LessThanOrEqual: "3", Status: "affected"}, version: "2.5",
			want: CNAResult{Reading: Indeterminate},
		},

		// Plan: a sentinel lower bound with a change.
		{
			name:  "plan: {unspecified, affected} affected at 2 / 3",
			entry: CNAVersion{Version: "unspecified", Status: "affected", Changes: []CNAChange{{At: "2", Status: "affected"}}}, version: "3",
			want: CNAResult{Reading: Indeterminate},
		},

		// Plan: free text.
		{
			name:  "plan: {0.5.6 - 1.13.2, affected} CVE-2017-7529 / 1.0.0",
			entry: CNAVersion{Version: "0.5.6 - 1.13.2", Status: "affected"}, version: "1.0.0",
			want: CNAResult{Reading: Indeterminate},
		},
		{
			name:  "plan: {>= 20.0.0, <= 20.10.27, affected} CVE-2024-41110 / 20.5.0",
			entry: CNAVersion{Version: ">= 20.0.0, <= 20.10.27", Status: "affected"}, version: "20.5.0",
			want: CNAResult{Reading: AffectedReading, Matched: cnaMatched("20.0.0", "", "20.10.27")},
		},
		{
			name: "plan: {>= 1.0.0, affected, custom} / 1.5.0", entry: cnaFreeTextOpen, version: "1.5.0",
			want: CNAResult{Reading: AffectedReading, Matched: cnaMatched("1.0.0", "", "")},
		},
		{name: "plan: {>= 1.0.0, affected, custom} / 0.9.0", entry: cnaFreeTextOpen, version: "0.9.0", want: CNAResult{Reading: NoStatement}},

		// Plan: {1.0, lte 2.*, affected, semver}.
		{name: "plan: {1.0, lte 2.*, affected, semver} / 2.9.0", entry: cnaInclusiveWildcardLine2, version: "2.9.0", want: CNAResult{Reading: Indeterminate}},
		{name: "plan: {1.0, lte 2.*, affected, semver} / 3.0.0", entry: cnaInclusiveWildcardLine2, version: "3.0.0", want: CNAResult{Reading: NoStatement}},

		// Plan: no version information.
		{name: "plan: {unspecified, affected} / any", entry: CNAVersion{Version: "unspecified", Status: "affected"}, version: "1.0", want: CNAResult{Reading: NoVersionInfo}},
		{name: "plan: {n/a, affected} / any", entry: CNAVersion{Version: "n/a", Status: "affected"}, version: "1.0", want: CNAResult{Reading: NoVersionInfo}},
		{name: "plan: {*, affected} / any", entry: CNAVersion{Version: "*", Status: "affected"}, version: "1.0", want: CNAResult{Reading: NoVersionInfo}},
		{name: `plan: {"", affected} / any`, entry: CNAVersion{Version: "", Status: "affected"}, version: "1.0", want: CNAResult{Reading: NoVersionInfo}},
		{
			name:  "plan: {<commit>, lt <commit>, affected, git} / any",
			entry: CNAVersion{Version: commitA, LessThan: commitB, Status: "affected", VersionType: "git"}, version: "1.0",
			want: CNAResult{Reading: NoVersionInfo},
		},

		// Plan: a type with no comparator.
		{
			name:  "plan: {1.0, lt 2.0, affected, versionType deb} / 1.5",
			entry: CNAVersion{Version: "1.0", LessThan: "2.0", Status: "affected", VersionType: "deb"}, version: "1.5",
			want: CNAResult{Reading: Indeterminate},
		},

		// Plan: CVE-2026-56847 as the MITRE golden archive holds it.
		{
			name:  "plan: {26.5.0, lte 26.5.0, affected} CVE-2026-56847 / 26.4.0",
			entry: CNAVersion{Version: "26.5.0", LessThanOrEqual: "26.5.0", Status: "affected", VersionType: "semver"}, version: "26.4.0",
			want: CNAResult{Reading: NoStatement},
		},

		// Plan: a single version.
		{
			name: "plan: {1.2.3, affected} / 1.2.3", entry: CNAVersion{Version: "1.2.3", Status: "affected"}, version: "1.2.3",
			want: CNAResult{Reading: AffectedReading, Matched: cnaMatched("1.2.3", "", "1.2.3")},
		},

		// Plan: a "0" lower bound.
		{
			name:  "plan: {0, lt 2.0, affected, semver} / 0.0.1-alpha",
			entry: CNAVersion{Version: "0", LessThan: "2.0", Status: "affected", VersionType: "semver"}, version: "0.0.1-alpha",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"2.0"}, Matched: cnaMatched("0", "2.0", "")},
		},

		// Design 4.3 result table, "Inside a first segment whose status is
		// unaffected", when that segment's lower bound cannot be read.
		{
			name:  "design: inside a first unaffected segment with an unreadable lower bound / 1.5",
			entry: CNAVersion{Version: "1.0rc1", LessThan: "3.0", Status: "unaffected", VersionType: "custom", Changes: []CNAChange{{At: "2.0", Status: "affected"}}}, version: "1.5",
			want: CNAResult{Reading: NoStatement},
		},
		{
			name:  "design: first unaffected segment with an unreadable lower bound, later affected segment / 2.5",
			entry: CNAVersion{Version: "1.0rc1", LessThan: "3.0", Status: "unaffected", VersionType: "custom", Changes: []CNAChange{{At: "2.0", Status: "affected"}}}, version: "2.5",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"3.0"}, Matched: cnaMatched("2.0", "3.0", "")},
		},
		// Design 4.3 segments: an unreadable at leaves the entry Indeterminate only
		// at or above its lower bound, or everywhere when that cannot be read either.
		{
			name:  "design: a change whose at the comparator cannot read / 0.5 below the lower bound",
			entry: CNAVersion{Version: "1.0", LessThan: "3.0", Status: "affected", VersionType: "custom", Changes: []CNAChange{{At: "2.0rc1", Status: "unaffected"}}}, version: "0.5",
			want: CNAResult{Reading: NoStatement},
		},
		{
			name:  "design: a change whose at the comparator cannot read / 1.0 at the lower bound",
			entry: CNAVersion{Version: "1.0", LessThan: "3.0", Status: "affected", VersionType: "custom", Changes: []CNAChange{{At: "2.0rc1", Status: "unaffected"}}}, version: "1.0",
			want: CNAResult{Reading: Indeterminate},
		},
		{
			name:  "design: unreadable at and unreadable lower bound / 0.5",
			entry: CNAVersion{Version: "1.0rc1", LessThan: "3.0", Status: "affected", VersionType: "custom", Changes: []CNAChange{{At: "2.0rc1", Status: "unaffected"}}}, version: "0.5",
			want: CNAResult{Reading: Indeterminate},
		},
		// Design 4.3 "No version information": unknown is a sentinel too, in any case.
		{name: "design: {unknown, affected} / any", entry: CNAVersion{Version: "unknown", Status: "affected"}, version: "1.0", want: CNAResult{Reading: NoVersionInfo}},
		{name: "design: {Unspecified, affected} / any", entry: CNAVersion{Version: "Unspecified", Status: "affected"}, version: "1.0", want: CNAResult{Reading: NoVersionInfo}},
		// Design 4.3 normalisation: a wildcard lower bound 8.1.* becomes 8.1.
		{
			name:  "design: wildcard lower bound {8.1.*, lt 8.3, affected} / 8.1.5",
			entry: CNAVersion{Version: "8.1.*", LessThan: "8.3", Status: "affected"}, version: "8.1.5",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"8.3"}, Matched: cnaMatched("8.1", "8.3", "")},
		},
		{
			name:  "design: wildcard lower bound {8.1.*, lt 8.3, affected} / 8.0.9",
			entry: CNAVersion{Version: "8.1.*", LessThan: "8.3", Status: "affected"}, version: "8.0.9",
			want: CNAResult{Reading: NoStatement},
		},
		// A single-version entry 8.1.* names the whole 8.1 line: the segment from 8.1
		// to the wildcard end 8.2, which design 4.3's wildcard row reads as
		// Indeterminate inside the line and no statement past it.
		{
			name:  "design: single wildcard version {8.1.*, affected} is the 8.1 line, wildcard row / 8.1.5",
			entry: CNAVersion{Version: "8.1.*", Status: "affected"}, version: "8.1.5",
			want: CNAResult{Reading: Indeterminate},
		},
		{
			name:  "design: single wildcard version {8.1.*, affected} is the 8.1 line, below it / 8.0.9",
			entry: CNAVersion{Version: "8.1.*", Status: "affected"}, version: "8.0.9",
			want: CNAResult{Reading: NoStatement},
		},
		{
			name:  "design: single wildcard version {8.1.*, affected} is the 8.1 line, past its end / 8.2.0",
			entry: CNAVersion{Version: "8.1.*", Status: "affected"}, version: "8.2.0",
			want: CNAResult{Reading: NoStatement},
		},
		{
			name:  "design: single wildcard version {8.1.*, affected} is the 8.1 line, past its end / 9.0",
			entry: CNAVersion{Version: "8.1.*", Status: "affected"}, version: "9.0",
			want: CNAResult{Reading: NoStatement},
		},
		{
			name:  "design: single x wildcard version {8.1.x, affected, maven} is the 8.1 line / 8.1.5",
			entry: CNAVersion{Version: "8.1.x", Status: "affected", VersionType: "maven"}, version: "8.1.5",
			want: CNAResult{Reading: Indeterminate},
		},
		{
			name:  "design: single x wildcard version {8.1.x, affected, maven} is the 8.1 line / 8.2.0",
			entry: CNAVersion{Version: "8.1.x", Status: "affected", VersionType: "maven"}, version: "8.2.0",
			want: CNAResult{Reading: NoStatement},
		},
		// Line wildcards ending in .x or .X, which Maven and RPM would otherwise read
		// as versions, end the line as .* does.
		{name: "design: x wildcard upper bound {1.0, lt 2.x, affected, maven} / 1.5", entry: cnaMavenLt2x, version: "1.5", want: CNAResult{Reading: Indeterminate}},
		{name: "design: x wildcard upper bound {1.0, lt 2.x, affected, maven} / 2.1", entry: cnaMavenLt2x, version: "2.1", want: CNAResult{Reading: Indeterminate}},
		{name: "design: x wildcard upper bound {1.0, lt 2.x, affected, maven} / 2.5", entry: cnaMavenLt2x, version: "2.5", want: CNAResult{Reading: Indeterminate}},
		{name: "design: x wildcard upper bound {1.0, lt 2.x, affected, maven} / 3.0", entry: cnaMavenLt2x, version: "3.0", want: CNAResult{Reading: NoStatement}},
		{
			name:  "design: x wildcard upper bound {2.4.0, lte 2.4.x, affected, maven} / 2.4.5",
			entry: CNAVersion{Version: "2.4.0", LessThanOrEqual: "2.4.x", Status: "affected", VersionType: "maven"}, version: "2.4.5",
			want: CNAResult{Reading: Indeterminate},
		},
		{
			name:  "design: x wildcard upper bound {2.4.0, lte 2.4.x, affected, maven} / 2.5.0",
			entry: CNAVersion{Version: "2.4.0", LessThanOrEqual: "2.4.x", Status: "affected", VersionType: "maven"}, version: "2.5.0",
			want: CNAResult{Reading: NoStatement},
		},
		{
			name:  "design: X wildcard upper bound {1.0, lt 2.X, affected, rpm} / 2.5",
			entry: CNAVersion{Version: "1.0", LessThan: "2.X", Status: "affected", VersionType: "rpm"}, version: "2.5",
			want: CNAResult{Reading: Indeterminate},
		},
		{
			name:  "design: X wildcard upper bound {1.0, lt 2.X, affected, rpm} / 3.0",
			entry: CNAVersion{Version: "1.0", LessThan: "2.X", Status: "affected", VersionType: "rpm"}, version: "3.0",
			want: CNAResult{Reading: NoStatement},
		},
		{
			name:  "design: x wildcard upper bound {1.0.0, lt 2.x, affected, semver} / 2.5.0",
			entry: CNAVersion{Version: "1.0.0", LessThan: "2.x", Status: "affected", VersionType: "semver"}, version: "2.5.0",
			want: CNAResult{Reading: Indeterminate},
		},
		{
			name:  "design: x wildcard upper bound {1.0.0, lt 2.x, affected, semver} / 3.0.0",
			entry: CNAVersion{Version: "1.0.0", LessThan: "2.x", Status: "affected", VersionType: "semver"}, version: "3.0.0",
			want: CNAResult{Reading: NoStatement},
		},
		{
			name:  "design: x wildcard lower bound {2.x, lt 4.0, affected, maven} becomes 2 / 2.5",
			entry: CNAVersion{Version: "2.x", LessThan: "4.0", Status: "affected", VersionType: "maven"}, version: "2.5",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"4.0"}, Matched: cnaMatched("2", "4.0", "")},
		},
		{
			name:  "design: x wildcard lower bound {2.x, lt 4.0, affected, maven} becomes 2 / 1.5",
			entry: CNAVersion{Version: "2.x", LessThan: "4.0", Status: "affected", VersionType: "maven"}, version: "1.5",
			want: CNAResult{Reading: NoStatement},
		},
		// A change at a line wildcard has no single position, so the entry is unsortable.
		{name: "design: change at an x wildcard is unsortable {1.0, lt 3.0, affected, maven} unaffected at 2.x / 1.5", entry: cnaMavenChangeAt2x, version: "1.5", want: CNAResult{Reading: Indeterminate}},
		{name: "design: change at an x wildcard is unsortable {1.0, lt 3.0, affected, maven} unaffected at 2.x / 2.5", entry: cnaMavenChangeAt2x, version: "2.5", want: CNAResult{Reading: Indeterminate}},
		{name: "design: change at an x wildcard is unsortable {1.0, lt 3.0, affected, maven} unaffected at 2.x / 0.5", entry: cnaMavenChangeAt2x, version: "0.5", want: CNAResult{Reading: NoStatement}},
		{
			name:  "design: change at a * wildcard is unsortable {1.0, lt 3.0, affected, semver} unaffected at 2.* / 2.5.0",
			entry: CNAVersion{Version: "1.0", LessThan: "3.0", Status: "affected", VersionType: "semver", Changes: []CNAChange{{At: "2.*", Status: "unaffected"}}}, version: "2.5.0",
			want: CNAResult{Reading: Indeterminate},
		},
		// An inverted segment that is not unaffected has no known meaning, so the
		// entry is Indeterminate for every version.
		{name: "design: inverted entry {2.0, lt 1.0, affected} / 0.5", entry: cnaInverted, version: "0.5", want: CNAResult{Reading: Indeterminate}},
		{name: "design: inverted entry {2.0, lt 1.0, affected} / 1.5", entry: cnaInverted, version: "1.5", want: CNAResult{Reading: Indeterminate}},
		{name: "design: inverted entry {2.0, lt 1.0, affected} / 2.5", entry: cnaInverted, version: "2.5", want: CNAResult{Reading: Indeterminate}},
		{
			name:  "design: inverted entry {2.10, lte 2.9, affected, semver} / 2.9.5",
			entry: CNAVersion{Version: "2.10", LessThanOrEqual: "2.9", Status: "affected", VersionType: "semver"}, version: "2.9.5",
			want: CNAResult{Reading: Indeterminate},
		},
		{
			name:  "design: inverted entry {2.10, lte 2.9, affected, semver} / 2.10.0",
			entry: CNAVersion{Version: "2.10", LessThanOrEqual: "2.9", Status: "affected", VersionType: "semver"}, version: "2.10.0",
			want: CNAResult{Reading: Indeterminate},
		},
		{
			name:  "design: empty entry {1.2.3, lt 1.2.3, affected, semver} / 1.2.3",
			entry: CNAVersion{Version: "1.2.3", LessThan: "1.2.3", Status: "affected", VersionType: "semver"}, version: "1.2.3",
			want: CNAResult{Reading: Indeterminate},
		},
		{name: "design: affected change above the upper bound {1.0, lt 2.0, unaffected} affected at 3.0 / 3.0", entry: cnaAffectedChangeAboveUpper, version: "3.0", want: CNAResult{Reading: Indeterminate}},
		{name: "design: affected change above the upper bound {1.0, lt 2.0, unaffected} affected at 3.0 / 3.5", entry: cnaAffectedChangeAboveUpper, version: "3.5", want: CNAResult{Reading: Indeterminate}},
		// An inverted unaffected segment is left alone: it condemns nothing.
		{
			name:  "design: unaffected change above the upper bound {1.0, lt 2.0, affected} unaffected at 3.0 / 1.5",
			entry: CNAVersion{Version: "1.0", LessThan: "2.0", Status: "affected", Changes: []CNAChange{{At: "3.0", Status: "unaffected"}}}, version: "1.5",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"3.0"}, Matched: cnaMatched("1.0", "3.0", "")},
		},
		// "0" sorts below every version, as version.Check reads introduced "0".
		{
			name:  "design: lower bound 0 is below every version {0, lt 2.0, affected, semver} / 0.0.0-alpha",
			entry: CNAVersion{Version: "0", LessThan: "2.0", Status: "affected", VersionType: "semver"}, version: "0.0.0-alpha",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"2.0"}, Matched: cnaMatched("0", "2.0", "")},
		},
		// A change with no status starts an unknown segment.
		{
			name:  "design: a change with an empty status is unknown / 2.5",
			entry: CNAVersion{Version: "1.0", LessThan: "3.0", Status: "affected", Changes: []CNAChange{{At: "2.0", Status: ""}}}, version: "2.5",
			want: CNAResult{Reading: Indeterminate},
		},
		// An affected segment followed by an affected one names no fix.
		{
			name:  "design: affected segment followed by an affected segment has no candidate / 1.5",
			entry: CNAVersion{Version: "1.0", LessThan: "3.0", Status: "affected", Changes: []CNAChange{{At: "2.0", Status: "affected"}}}, version: "1.5",
			want: CNAResult{Reading: AffectedReading, Matched: cnaMatched("1.0", "2.0", "")},
		},
		// Two changes at one version with different statuses collapse to one change
		// with status unknown, in either input order. The segment before it is still
		// read; it names no fix, because the next segment is not unaffected.
		{
			name: "design: conflicting changes at one version collapse to unknown, affected first / 1.5", entry: cnaConflictAt2, version: "1.5",
			want: CNAResult{Reading: AffectedReading, Matched: cnaMatched("1.0", "2.0", "")},
		},
		{name: "design: conflicting changes at one version collapse to unknown, affected first / 2.0", entry: cnaConflictAt2, version: "2.0", want: CNAResult{Reading: Indeterminate}},
		{name: "design: conflicting changes at one version collapse to unknown, affected first / 2.5", entry: cnaConflictAt2, version: "2.5", want: CNAResult{Reading: Indeterminate}},
		{name: "design: conflicting changes at one version collapse to unknown, affected first / 0.5", entry: cnaConflictAt2, version: "0.5", want: CNAResult{Reading: NoStatement}},
		{
			name: "design: conflicting changes at one version collapse to unknown, unaffected first / 1.5", entry: reversed(cnaConflictAt2), version: "1.5",
			want: CNAResult{Reading: AffectedReading, Matched: cnaMatched("1.0", "2.0", "")},
		},
		{name: "design: conflicting changes at one version collapse to unknown, unaffected first / 2.0", entry: reversed(cnaConflictAt2), version: "2.0", want: CNAResult{Reading: Indeterminate}},
		{name: "design: conflicting changes at one version collapse to unknown, unaffected first / 2.5", entry: reversed(cnaConflictAt2), version: "2.5", want: CNAResult{Reading: Indeterminate}},
		{name: "design: conflicting changes at one version collapse to unknown, unaffected first / 0.5", entry: reversed(cnaConflictAt2), version: "0.5", want: CNAResult{Reading: NoStatement}},
		// Repeated affected changes collapse before inverted segments are looked
		// for, so they leave no empty affected segment.
		{
			name:  "design: repeated affected change at one version collapses, no empty segment / 2.5",
			entry: CNAVersion{Version: "1.0", LessThan: "3.0", Status: "affected", Changes: []CNAChange{{At: "2.0", Status: "affected"}, {At: "2.0", Status: "affected"}}}, version: "2.5",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"3.0"}, Matched: cnaMatched("2.0", "3.0", "")},
		},
		// Two changes at one version with the same status still read as segments.
		{
			name:  "design: repeated change with the same status at one version / 1.5",
			entry: CNAVersion{Version: "1.0", LessThan: "3.0", Status: "affected", Changes: []CNAChange{{At: "2.0", Status: "unaffected"}, {At: "2.0", Status: "unaffected"}}}, version: "1.5",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"2.0"}, Matched: cnaMatched("1.0", "2.0", "")},
		},
		{
			name:  "design: repeated change with the same status at one version / 2.0",
			entry: CNAVersion{Version: "1.0", LessThan: "3.0", Status: "affected", Changes: []CNAChange{{At: "2.0", Status: "unaffected"}, {At: "2.0", Status: "unaffected"}}}, version: "2.0",
			want: CNAResult{Reading: NoStatement},
		},
		// The version the comparator cannot read: Indeterminate unless the entry is
		// wholly unaffected.
		{
			name:  "design: version the comparator cannot read, affected entry / 1.1rc1",
			entry: CNAVersion{Version: "1.0", LessThan: "2.0", Status: "affected", VersionType: "custom"}, version: "1.1rc1",
			want: CNAResult{Reading: Indeterminate},
		},
		// The other typed comparators of design 4.3.
		{
			name:  "design: versionType python reads PEP 440 / 1.5rc1",
			entry: CNAVersion{Version: "1.0", LessThan: "2.0", Status: "affected", VersionType: "python"}, version: "1.5rc1",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"2.0"}, Matched: cnaMatched("1.0", "2.0", "")},
		},
		{
			name:  "design: versionType maven reads Maven / 1.5-SNAPSHOT",
			entry: CNAVersion{Version: "1.0", LessThan: "2.0", Status: "affected", VersionType: "maven"}, version: "1.5-SNAPSHOT",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"2.0"}, Matched: cnaMatched("1.0", "2.0", "")},
		},
		{
			name:  "design: versionType rpm reads RPM / 1.5-1.el9",
			entry: CNAVersion{Version: "1.0", LessThan: "2.0", Status: "affected", VersionType: "rpm"}, version: "1.5-1.el9",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"2.0"}, Matched: cnaMatched("1.0", "2.0", "")},
		},
		{
			name:  "design: free text the range grammar cannot read stays unreadable / 1.5",
			entry: CNAVersion{Version: ">= 1.0 || < 0.5", Status: "affected"}, version: "1.5",
			want: CNAResult{Reading: Indeterminate},
		},
		// isBelow treats "0" as below every version, so a wildcard-ended segment from
		// "0" still holds a version SemVer sorts below 0.
		{
			name:  "design: isBelow reads 0 as below every version {0, lt 2.*, affected, semver} / 0.0.0-alpha",
			entry: CNAVersion{Version: "0", LessThan: "2.*", Status: "affected", VersionType: "semver"}, version: "0.0.0-alpha",
			want: CNAResult{Reading: Indeterminate},
		},
		// Free-text forms the range grammar reads.
		{
			name:  "design: free text < 2.0 / 1.5",
			entry: CNAVersion{Version: "< 2.0", Status: "affected"}, version: "1.5",
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"2.0"}, Matched: cnaMatched("0", "2.0", "")},
		},
		{name: "design: free text < 2.0 / 2.0", entry: CNAVersion{Version: "< 2.0", Status: "affected"}, version: "2.0", want: CNAResult{Reading: NoStatement}},
		{
			name:  "design: free text > 1.0 is read inclusively / 1.0",
			entry: CNAVersion{Version: "> 1.0", Status: "affected"}, version: "1.0",
			want: CNAResult{Reading: AffectedReading, Matched: cnaMatched("1.0", "", "")},
		},
		{
			name:  "design: free text <= 2 / 2",
			entry: CNAVersion{Version: "<= 2", Status: "affected"}, version: "2",
			want: CNAResult{Reading: AffectedReading, Matched: cnaMatched("0", "", "2")},
		},
		{name: "design: free text <= 2 / 2.1", entry: CNAVersion{Version: "<= 2", Status: "affected"}, version: "2.1", want: CNAResult{Reading: NoStatement}},
		{
			name:  "design: free text = 1.0 is 1.0 only / 1.0",
			entry: CNAVersion{Version: "= 1.0", Status: "affected"}, version: "1.0",
			want: CNAResult{Reading: AffectedReading, Matched: cnaMatched("1.0", "", "1.0")},
		},
		{name: "design: free text = 1.0 is 1.0 only / 1.1", entry: CNAVersion{Version: "= 1.0", Status: "affected"}, version: "1.1", want: CNAResult{Reading: NoStatement}},
		{name: "design: free text = 1.0 is 1.0 only / 0.9", entry: CNAVersion{Version: "= 1.0", Status: "affected"}, version: "0.9", want: CNAResult{Reading: NoStatement}},
		// An upper bound of * with no changes is unlimited and never read outright.
		{name: "design: {1.0, lt *, affected} with no changes / 1.5", entry: CNAVersion{Version: "1.0", LessThan: "*", Status: "affected"}, version: "1.5", want: CNAResult{Reading: Indeterminate}},
		{name: "design: {1.0, lt *, affected} with no changes / 0.5", entry: CNAVersion{Version: "1.0", LessThan: "*", Status: "affected"}, version: "0.5", want: CNAResult{Reading: NoStatement}},
		// Status and versionType values are matched as the CVE schema spells them.
		{
			name:  "design: mis-cased status Affected is not affected or unaffected / 1.5",
			entry: CNAVersion{Version: "1.0", LessThan: "2.0", Status: "Affected"}, version: "1.5",
			want: CNAResult{Reading: Indeterminate},
		},
		{
			name:  "design: mis-cased versionType SemVer has no comparator / 1.5.0",
			entry: CNAVersion{Version: "1.0.0", LessThan: "2.0.0", Status: "affected", VersionType: "SemVer"}, version: "1.5.0",
			want: CNAResult{Reading: Indeterminate},
		},
		// A * lower bound with an upper bound is today an unreadable start, not 0;
		// whether it should read as 0 is open with Sam.
		{name: "design: * lower bound is unreadable, not 0 (open with Sam) {*, lte 1.4.4, affected, semver} / 1.0.0", entry: cnaStarLower, version: "1.0.0", want: CNAResult{Reading: Indeterminate}},
		{name: "design: * lower bound is unreadable, not 0 (open with Sam) {*, lte 1.4.4, affected, semver} / 1.4.4", entry: cnaStarLower, version: "1.4.4", want: CNAResult{Reading: Indeterminate}},
		{name: "design: * lower bound is unreadable, not 0 (open with Sam) {*, lte 1.4.4, affected, semver} / 1.4.5", entry: cnaStarLower, version: "1.4.5", want: CNAResult{Reading: NoStatement}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := readCNA(t, tt.version, oneEntry(tt.entry))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReadCNAEntries(%q, %+v) = %+v, want %+v", tt.version, tt.entry, got, tt.want)
			}
		})
	}
}

// Entries whose reading of version 1.5 is each Reading in turn.
var (
	cnaReadsNoStatement   = CNAVersion{Version: "2.0", LessThan: "3.0", Status: "affected", VersionType: "custom"}
	cnaReadsNoVersionInfo = CNAVersion{Version: "unspecified", Status: "affected"}
	cnaReadsIndeterminate = CNAVersion{Version: "1.0rc1", LessThan: "2.0", Status: "affected", VersionType: "custom"}
	cnaReadsAffected      = CNAVersion{Version: "1.0", LessThan: "2.0", Status: "affected", VersionType: "custom"}
)

// TestReadCNAEntries checks that the strongest reading wins across entries and
// rows (Affected, then Indeterminate, then NoVersionInfo, then NoStatement), and
// that candidates and matched ranges come only from Affected entries.
func TestReadCNAEntries(t *testing.T) {
	t.Parallel()
	row := func(versions ...CNAVersion) CNARow {
		return CNARow{CVEID: "CVE-2026-0001", Vendor: "vendor", Product: "product", Versions: versions}
	}
	tests := []struct {
		name string
		rows []CNARow
		want CNAResult
	}{
		{name: "no rows is no statement", want: CNAResult{Reading: NoStatement}},
		{name: "a row with no versions is no statement", rows: []CNARow{row()}, want: CNAResult{Reading: NoStatement}},
		{
			name: "affected wins over indeterminate, no version info and no statement in another row",
			rows: []CNARow{row(cnaReadsNoStatement, cnaReadsNoVersionInfo, cnaReadsIndeterminate), row(cnaReadsAffected)},
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"2.0"}, Matched: cnaMatched("1.0", "2.0", "")},
		},
		{
			name: "affected wins when it comes first",
			rows: []CNARow{row(cnaReadsAffected, cnaReadsIndeterminate, cnaReadsNoVersionInfo, cnaReadsNoStatement)},
			want: CNAResult{Reading: AffectedReading, Candidates: []string{"2.0"}, Matched: cnaMatched("1.0", "2.0", "")},
		},
		{
			name: "indeterminate wins over no version info and no statement",
			rows: []CNARow{row(cnaReadsNoVersionInfo), row(cnaReadsIndeterminate, cnaReadsNoStatement)},
			want: CNAResult{Reading: Indeterminate},
		},
		{
			name: "no version info wins over no statement",
			rows: []CNARow{row(cnaReadsNoStatement), row(cnaReadsNoVersionInfo, cnaReadsNoStatement)},
			want: CNAResult{Reading: NoVersionInfo},
		},
		{
			name: "only no statement entries",
			rows: []CNARow{row(cnaReadsNoStatement), row(cnaReadsNoStatement)},
			want: CNAResult{Reading: NoStatement},
		},
		{
			name: "every affected entry adds its candidate and matched range; one with no fix adds no candidate",
			rows: []CNARow{
				row(cnaReadsAffected, CNAVersion{Version: "1.5", Status: "affected"}),
				row(cnaReadsIndeterminate, CNAVersion{Version: "1.2", LessThan: "1.7", Status: "affected"}),
			},
			want: CNAResult{
				Reading:    AffectedReading,
				Candidates: []string{"2.0", "1.7"},
				Matched: []Matched{
					{Evidence: "cna", Introduced: "1.0", Fixed: "2.0"},
					{Evidence: "cna", Introduced: "1.5", LastAffected: "1.5"},
					{Evidence: "cna", Introduced: "1.2", Fixed: "1.7"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := readCNA(t, "1.5", tt.rows)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReadCNAEntries = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestCNARangeCount checks 2 plus the number of changes for each versions element.
func TestCNARangeCount(t *testing.T) {
	t.Parallel()
	threeChanges := CNAVersion{Version: "1", Changes: make([]CNAChange, 3)}
	oneChange := CNAVersion{Version: "1", Changes: make([]CNAChange, 1)}
	tests := []struct {
		name string
		rows []CNARow
		want int
	}{
		{name: "no rows", want: 0},
		{name: "a row with no versions", rows: []CNARow{{}}, want: 0},
		{name: "one element without changes", rows: []CNARow{{Versions: []CNAVersion{{Version: "1"}}}}, want: 2},
		{
			name: "elements across rows",
			rows: []CNARow{{Versions: []CNAVersion{{Version: "1"}, threeChanges}}, {Versions: []CNAVersion{oneChange}}},
			want: 2 + 5 + 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := CNARangeCount(tt.rows); got != tt.want {
				t.Errorf("CNARangeCount = %d, want %d", got, tt.want)
			}
		})
	}
}

// manyChanges returns an affected entry with n changes, each readable by
// CheckNumeric, so reading it needs more than n comparisons.
func manyChanges(n int) CNAVersion {
	e := CNAVersion{Version: "1", LessThan: "2", Status: "affected", VersionType: "custom"}
	for i := range n {
		e.Changes = append(e.Changes, CNAChange{At: fmt.Sprintf("1.%d", n-i), Status: "affected"})
	}
	return e
}

// TestReadCNAEntriesMeter checks that every comparison ticks the meter, and that
// reading stops with the zero result once the context has ended.
func TestReadCNAEntriesMeter(t *testing.T) {
	t.Parallel()

	t.Run("every comparison ticks", func(t *testing.T) {
		t.Parallel()
		m := newWorkMeter(context.Background())
		ticks := 0
		m.onTick = func() { ticks++ }
		got := ReadCNAEntries(m, "1.5", oneEntry(manyChanges(3000)))
		if ticks <= 3000 {
			t.Errorf("ticks = %d, want more than 3000", ticks)
		}
		if got.Reading != AffectedReading {
			t.Errorf("reading = %v, want AffectedReading", got.Reading)
		}
	})

	t.Run("context cancelled while reading stops at the next 1,000th tick", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m := newWorkMeter(ctx)
		ticks := 0
		m.onTick = func() {
			ticks++
			if ticks == 10 {
				cancel()
			}
		}
		rows := []CNARow{
			{CVEID: "CVE-2026-0001", Versions: []CNAVersion{manyChanges(5000), manyChanges(5000)}},
			{CVEID: "CVE-2026-0002", Versions: []CNAVersion{manyChanges(5000)}},
		}
		got := ReadCNAEntries(m, "1.5", rows)
		if ticks != 1000 {
			t.Errorf("ticks = %d, want 1000", ticks)
		}
		if !reflect.DeepEqual(got, CNAResult{}) {
			t.Errorf("result after cancellation = %+v, want the zero CNAResult", got)
		}
		if !errors.Is(m.Err(), context.Canceled) {
			t.Errorf("Err() = %v, want context.Canceled", m.Err())
		}
	})

	t.Run("context cancelled before reading reads nothing", func(t *testing.T) {
		t.Parallel()
		m := newWorkMeter(cancelledContext())
		ticks := 0
		m.onTick = func() { ticks++ }
		got := ReadCNAEntries(m, "1.5", oneEntry(cnaReadsAffected))
		if ticks != 0 {
			t.Errorf("ticks = %d, want 0", ticks)
		}
		if !reflect.DeepEqual(got, CNAResult{}) {
			t.Errorf("result = %+v, want the zero CNAResult", got)
		}
		if !errors.Is(m.Err(), context.Canceled) {
			t.Errorf("Err() = %v, want context.Canceled", m.Err())
		}
	})
}

// TestCNAVersionDecodesStoredJSON checks that a cve_cna_affected.versions array,
// as the feed adapters marshal it, decodes into CNAVersion with every field.
func TestCNAVersionDecodesStoredJSON(t *testing.T) {
	t.Parallel()
	want := []CNAVersion{
		{
			Version: "2.0-beta9", LessThan: "log4j-core*", Status: "affected", VersionType: "custom",
			Changes: []CNAChange{{At: "2.3.1", Status: "unaffected"}},
		},
		{Version: "26.5.0", LessThanOrEqual: "26.5.0", Status: "affected", VersionType: "semver"},
	}

	t.Run("marshalled feed.CNAVersion", func(t *testing.T) {
		t.Parallel()
		stored, err := json.Marshal([]feed.CNAVersion{
			{
				Version: "2.0-beta9", LessThan: "log4j-core*", Status: "affected", VersionType: "custom",
				Changes: []feed.CNAVersionChange{{At: "2.3.1", Status: "unaffected"}},
			},
			{Version: "26.5.0", LessThanOrEqual: "26.5.0", Status: "affected", VersionType: "semver"},
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got []CNAVersion
		if err := json.Unmarshal(stored, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", stored, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("decoded %s as %+v, want %+v", stored, got, want)
		}
	})

	t.Run("literal stored JSON", func(t *testing.T) {
		t.Parallel()
		stored := `[{"version":"2.0-beta9","less_than":"log4j-core*","status":"affected","version_type":"custom","changes":[{"at":"2.3.1","status":"unaffected"}]},` +
			`{"version":"26.5.0","less_than_or_equal":"26.5.0","status":"affected","version_type":"semver"}]`
		var got []CNAVersion
		if err := json.Unmarshal([]byte(stored), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("decoded as %+v, want %+v", got, want)
		}
	})
}
