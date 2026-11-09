// ABOUTME: Tests collapsing several rows of one source and the union of version ranges.
// ABOUTME: Each result must not depend on the order rows or sources arrive in.
package merge

import (
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed"
)

func row(name, id string, p feed.CanonicalPatch) sourceRow {
	return sourceRow{name: name, id: id, patch: p}
}

func TestCollapse_ScalarsComeFromLowestSourceID(t *testing.T) {
	t.Parallel()
	a, b := "from-a", "from-b"
	patches, allWithdrawn := collapseSources([]sourceRow{
		row(SourceOSV, "PYSEC-2", feed.CanonicalPatch{DescriptionPrimary: &b}),
		row(SourceOSV, "GHSA-1", feed.CanonicalPatch{DescriptionPrimary: &a}),
	})
	if allWithdrawn {
		t.Fatal("allWithdrawn = true")
	}
	if got := *patches[SourceOSV].DescriptionPrimary; got != a {
		t.Errorf("description = %q, want %q", got, a)
	}
}

func TestCollapse_CVSSScoreAndVectorComeFromOneRow(t *testing.T) {
	t.Parallel()
	score, vecA, vecB := 7.5, "CVSS:3.1/AV:N", "CVSS:3.1/AV:L"
	patches, _ := collapseSources([]sourceRow{
		row(SourceGHSA, "A", feed.CanonicalPatch{CVSSv3Vector: &vecA}),
		row(SourceGHSA, "B", feed.CanonicalPatch{CVSSv3Score: &score, CVSSv3Vector: &vecB}),
	})
	p := patches[SourceGHSA]
	if p.CVSSv3Score == nil || *p.CVSSv3Score != score || *p.CVSSv3Vector != vecB {
		t.Errorf("score %v vector %v, want the pair from row B", p.CVSSv3Score, p.CVSSv3Vector)
	}
}

func TestCollapse_FlagsAreTrueIfAnyRowIs(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	patches, _ := collapseSources([]sourceRow{
		row(SourceOSV, "A", feed.CanonicalPatch{ExploitAvailable: &no, InCISAKEV: &no}),
		row(SourceOSV, "B", feed.CanonicalPatch{ExploitAvailable: &yes, InCISAKEV: &yes}),
	})
	p := patches[SourceOSV]
	if !*p.ExploitAvailable || !*p.InCISAKEV {
		t.Errorf("flags = %v, %v, want true", *p.ExploitAvailable, *p.InCISAKEV)
	}
}

func TestCollapse_WithdrawnAdvisoryContributesNothing(t *testing.T) {
	t.Parallel()
	patches, allWithdrawn := collapseSources([]sourceRow{
		row(SourceOSV, "A", feed.CanonicalPatch{IsWithdrawn: true, Status: "withdrawn",
			AffectedPackages: []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "gone"}}}),
		row(SourceOSV, "B", feed.CanonicalPatch{AffectedPackages: []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "kept"}}}),
		row(SourceGHSA, "C", feed.CanonicalPatch{IsWithdrawn: true, Status: "withdrawn"}),
		row(SourceNVD, "D", feed.CanonicalPatch{}),
	})
	if allWithdrawn {
		t.Fatal("allWithdrawn = true")
	}
	if _, ok := patches[SourceGHSA]; ok {
		t.Error("a source whose rows are all withdrawn is still present")
	}
	p := patches[SourceOSV]
	if p.IsWithdrawn || p.Status != "" || len(p.AffectedPackages) != 1 || p.AffectedPackages[0].PackageName != "kept" {
		t.Errorf("osv patch = %+v", p)
	}
}

func TestCollapse_StatusAuthorityKeepsWithdrawnRow(t *testing.T) {
	t.Parallel()
	patches, allWithdrawn := collapseSources([]sourceRow{
		row(SourceMITRE, "CVE-1", feed.CanonicalPatch{IsWithdrawn: true, Status: "REJECTED"}),
		row(SourceGHSA, "A", feed.CanonicalPatch{}),
	})
	if allWithdrawn {
		t.Fatal("allWithdrawn = true")
	}
	if !patches[SourceMITRE].IsWithdrawn {
		t.Error("mitre row was dropped or cleared")
	}
}

func TestCollapse_EveryRowWithdrawn(t *testing.T) {
	t.Parallel()
	patches, allWithdrawn := collapseSources([]sourceRow{
		row(SourceGHSA, "A", feed.CanonicalPatch{IsWithdrawn: true, Status: "withdrawn"}),
		row(SourceOSV, "B", feed.CanonicalPatch{IsWithdrawn: true, Status: "withdrawn"}),
	})
	if !allWithdrawn {
		t.Fatal("allWithdrawn = false")
	}
	if len(patches) != 2 {
		t.Errorf("patches = %v, want both sources", patches)
	}
}

func TestUnionPackages_KeepsEachBranch(t *testing.T) {
	t.Parallel()
	got := unionPackages(map[string]feed.CanonicalPatch{SourceGHSA: {AffectedPackages: []feed.AffectedPackage{
		{Ecosystem: "npm", PackageName: "node", Introduced: "22.0.0", Fixed: "22.23.4"},
		{Ecosystem: "npm", PackageName: "node", Introduced: "24.0.0", Fixed: "24.22.1"},
		{Ecosystem: "npm", PackageName: "node", Introduced: "26.0.0", Fixed: "26.12.1"},
	}}})
	if len(got) != 3 {
		t.Fatalf("got %d ranges, want 3: %+v", len(got), got)
	}
}

func TestUnionPackages_TiedIntroducedKeepsBothFixes(t *testing.T) {
	t.Parallel()
	got := unionPackages(map[string]feed.CanonicalPatch{
		SourceOSV:  {AffectedPackages: []feed.AffectedPackage{{Ecosystem: "PyPI", PackageName: "requests", Introduced: "2.0.0", Fixed: "2.28.0"}}},
		SourceGHSA: {AffectedPackages: []feed.AffectedPackage{{Ecosystem: "PyPI", PackageName: "requests", Introduced: "2.0.0", Fixed: "2.27.0"}}},
	})
	if len(got) != 2 {
		t.Fatalf("got %d ranges, want 2: %+v", len(got), got)
	}
}

func TestUnionPackages_DuplicateKeepsHighestPrecedenceRow(t *testing.T) {
	t.Parallel()
	got := unionPackages(map[string]feed.CanonicalPatch{
		SourceGHSA: {AffectedPackages: []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "Foo", RangeType: "ECOSYSTEM", Introduced: "1.3.0", LastAffected: "1.3.1"}}},
		SourceOSV:  {AffectedPackages: []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "foo", RangeType: "SEMVER", Introduced: "1.3.0", LastAffected: "1.3.1"}}},
	})
	if len(got) != 1 {
		t.Fatalf("got %d ranges, want 1: %+v", len(got), got)
	}
	if got[0].PackageName != "foo" || got[0].RangeType != "SEMVER" {
		t.Errorf("kept %+v, want the OSV row", got[0])
	}
}

func TestUnionPackages_PyPISpellingsAreOneRange(t *testing.T) {
	t.Parallel()
	got := unionPackages(map[string]feed.CanonicalPatch{
		SourceGHSA: {AffectedPackages: []feed.AffectedPackage{{Ecosystem: "PyPI", PackageName: "Foo_Bar", RangeType: "ECOSYSTEM", Introduced: "0", Fixed: "1.0"}}},
		SourceOSV:  {AffectedPackages: []feed.AffectedPackage{{Ecosystem: "PyPI", PackageName: "foo-bar", RangeType: "ECOSYSTEM", Introduced: "0", Fixed: "1.0"}}},
	})
	if len(got) != 1 || got[0].PackageName != "foo-bar" {
		t.Fatalf("got %+v, want one row spelled as OSV spelled it", got)
	}
}

func TestUnionPackages_SemverIsSeparateWhereTheOrderDiffers(t *testing.T) {
	t.Parallel()
	got := unionPackages(map[string]feed.CanonicalPatch{SourceOSV: {AffectedPackages: []feed.AffectedPackage{
		{Ecosystem: "PyPI", PackageName: "x", RangeType: "SEMVER", Introduced: "0", Fixed: "1.0.0"},
		{Ecosystem: "PyPI", PackageName: "x", RangeType: "ECOSYSTEM", Introduced: "0", Fixed: "1.0.0"},
	}}})
	if len(got) != 2 {
		t.Fatalf("got %d ranges, want 2", len(got))
	}
}

func TestUnionPackages_ListedVersionMatchesExactRange(t *testing.T) {
	t.Parallel()
	got := unionPackages(map[string]feed.CanonicalPatch{
		SourceOSV:  {AffectedPackages: []feed.AffectedPackage{{Ecosystem: "RubyGems", PackageName: "sprout", RangeType: "VERSIONS", Introduced: "0.7.246", LastAffected: "0.7.246"}}},
		SourceGHSA: {AffectedPackages: []feed.AffectedPackage{{Ecosystem: "RubyGems", PackageName: "sprout", RangeType: "ECOSYSTEM", Introduced: "0.7.246", LastAffected: "0.7.246"}}},
	})
	if len(got) != 1 {
		t.Fatalf("got %d ranges, want 1", len(got))
	}
}

func TestUnionPackages_GitRangeIsSeparate(t *testing.T) {
	t.Parallel()
	got := unionPackages(map[string]feed.CanonicalPatch{SourceOSV: {AffectedPackages: []feed.AffectedPackage{
		{Ecosystem: "npm", PackageName: "x", RangeType: "GIT", Introduced: "0"},
		{Ecosystem: "npm", PackageName: "x", RangeType: "SEMVER", Introduced: "0"},
	}}})
	if len(got) != 2 {
		t.Fatalf("got %d ranges, want 2", len(got))
	}
}

func TestUnionPackages_WithdrawnPatchContributesNothing(t *testing.T) {
	t.Parallel()
	got := unionPackages(map[string]feed.CanonicalPatch{SourceMITRE: {IsWithdrawn: true,
		AffectedPackages: []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "x", Introduced: "0"}}}})
	if len(got) != 0 {
		t.Errorf("got %+v", got)
	}
}

func TestCollapseAndUnion_IndependentOfRowOrder(t *testing.T) {
	t.Parallel()
	rows := []sourceRow{
		row(SourceOSV, "GHSA-1", feed.CanonicalPatch{AffectedPackages: []feed.AffectedPackage{{Ecosystem: "PyPI", PackageName: "a", Introduced: "0", Fixed: "1"}}}),
		row(SourceOSV, "PYSEC-2", feed.CanonicalPatch{AffectedPackages: []feed.AffectedPackage{{Ecosystem: "PyPI", PackageName: "a", Introduced: "0", Fixed: "2"}}}),
		row(SourceOSV, "CVE-1", feed.CanonicalPatch{}),
		row(SourceGHSA, "GHSA-1", feed.CanonicalPatch{AffectedPackages: []feed.AffectedPackage{{Ecosystem: "PyPI", PackageName: "A", Introduced: "0", Fixed: "1"}}}),
	}
	first, _ := collapseSources(slices.Clone(rows))
	want := unionPackages(first)
	for range 50 {
		shuffled := slices.Clone(rows)
		rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] }) //nolint:gosec // G404: test input order only
		patches, _ := collapseSources(shuffled)
		if got := unionPackages(patches); !reflect.DeepEqual(got, want) {
			t.Fatalf("order changed the result:\n got %+v\nwant %+v", got, want)
		}
	}
}
