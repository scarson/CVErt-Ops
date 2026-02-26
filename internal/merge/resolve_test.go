package merge

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// makeSource serialises patch into the NormalizedJson of a CveSource row.
func makeSource(sourceName string, patch feed.CanonicalPatch) generated.CveSource {
	b, _ := json.Marshal(patch)
	return generated.CveSource{
		CveID:          patch.CVEID,
		SourceName:     sourceName,
		NormalizedJson: json.RawMessage(b),
	}
}

// makeSourceWithDate adds a SourceDateModified to makeSource.
func makeSourceWithDate(sourceName string, patch feed.CanonicalPatch, t time.Time) generated.CveSource {
	s := makeSource(sourceName, patch)
	s.SourceDateModified = sql.NullTime{Time: t, Valid: true}
	return s
}

// strPtr is a convenience helper for *string literals in test data.
func strPtr(s string) *string { return &s }

// f64Ptr is a convenience helper for *float64 literals in test data.
func f64Ptr(f float64) *float64 { return &f }

// boolPtr is a convenience helper for *bool literals in test data.
func boolPtr(b bool) *bool { return &b }

// ── Status + IsWithdrawn ──────────────────────────────────────────────────────

func TestResolveStatusMITREWinsOverNVD(t *testing.T) {
	t.Parallel()

	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1", Status: "Active"}),
		makeSource(SourceMITRE, feed.CanonicalPatch{CVEID: "CVE-1", Status: "Published"}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.Status != "Published" {
		t.Errorf("status = %q, want %q (MITRE should win over NVD)", r.Status, "Published")
	}
}

func TestResolveStatusFallsBackToNVD(t *testing.T) {
	t.Parallel()

	// MITRE absent; NVD should win.
	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1", Status: "Active"}),
		makeSource(SourceGHSA, feed.CanonicalPatch{CVEID: "CVE-1", Status: "Reviewed"}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.Status != "Active" {
		t.Errorf("status = %q, want %q (NVD should win over GHSA)", r.Status, "Active")
	}
}

func TestResolveIsWithdrawnFromPrimarySource(t *testing.T) {
	t.Parallel()

	// MITRE says withdrawn — should propagate via primary-source path.
	sources := []generated.CveSource{
		makeSource(SourceMITRE, feed.CanonicalPatch{CVEID: "CVE-1", Status: "REJECTED", IsWithdrawn: true}),
		makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1", Status: "Rejected", IsWithdrawn: false}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !r.IsWithdrawn {
		t.Error("IsWithdrawn should be true when primary status source says withdrawn")
	}
}

func TestResolveIsWithdrawnORLogic(t *testing.T) {
	t.Parallel()

	// MITRE (primary) says NOT withdrawn; GHSA says withdrawn.
	// OR logic should still set IsWithdrawn.
	sources := []generated.CveSource{
		makeSource(SourceMITRE, feed.CanonicalPatch{CVEID: "CVE-1", Status: "Published", IsWithdrawn: false}),
		makeSource(SourceGHSA, feed.CanonicalPatch{CVEID: "CVE-1", IsWithdrawn: true}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !r.IsWithdrawn {
		t.Error("IsWithdrawn should be true when any source marks withdrawal (OR logic)")
	}
}

// ── Description ──────────────────────────────────────────────────────────────

func TestResolveDescriptionMITREWins(t *testing.T) {
	t.Parallel()

	mitreDesc := "MITRE description"
	nvdDesc := "NVD description"
	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1", DescriptionPrimary: &nvdDesc}),
		makeSource(SourceMITRE, feed.CanonicalPatch{CVEID: "CVE-1", DescriptionPrimary: &mitreDesc}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.DescriptionPrimary == nil || *r.DescriptionPrimary != mitreDesc {
		t.Errorf("description = %v, want %q (MITRE wins)", r.DescriptionPrimary, mitreDesc)
	}
}

// ── DatePublished ─────────────────────────────────────────────────────────────

func TestResolveDatePublishedEarliest(t *testing.T) {
	t.Parallel()

	early := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1", DatePublished: &late}),
		makeSource(SourceMITRE, feed.CanonicalPatch{CVEID: "CVE-1", DatePublished: &early}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.DatePublished == nil || !r.DatePublished.Equal(early) {
		t.Errorf("DatePublished = %v, want %v (earliest)", r.DatePublished, early)
	}
}

func TestResolveDatePublishedNilWhenNoneProvided(t *testing.T) {
	t.Parallel()

	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1", Status: "Active"}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.DatePublished != nil {
		t.Errorf("DatePublished = %v, want nil", *r.DatePublished)
	}
}

// ── CVSS ──────────────────────────────────────────────────────────────────────

func TestResolveCVSSv3NVDWinsOverGHSA(t *testing.T) {
	t.Parallel()

	sources := []generated.CveSource{
		makeSource(SourceGHSA, feed.CanonicalPatch{CVEID: "CVE-1", CVSSv3Score: f64Ptr(7.0)}),
		makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1", CVSSv3Score: f64Ptr(9.0)}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.CVSSv3Score == nil || *r.CVSSv3Score != 9.0 {
		t.Errorf("CVSSv3Score = %v, want 9.0 (NVD wins)", r.CVSSv3Score)
	}
	if r.CVSSv3Source != SourceNVD {
		t.Errorf("CVSSv3Source = %q, want %q", r.CVSSv3Source, SourceNVD)
	}
}

func TestResolveCVSSv3VectorCaptured(t *testing.T) {
	t.Parallel()

	vec := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{
			CVEID:        "CVE-1",
			CVSSv3Score:  f64Ptr(9.8),
			CVSSv3Vector: &vec,
		}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.CVSSv3Vector != vec {
		t.Errorf("CVSSv3Vector = %q, want %q", r.CVSSv3Vector, vec)
	}
}

// ── CVSSScoreDiverges ─────────────────────────────────────────────────────────

func TestResolveScoreDivergesTrue(t *testing.T) {
	t.Parallel()

	// NVD = 9.0, MITRE = 5.0 → diff = 4.0 ≥ 2.0
	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1", CVSSv3Score: f64Ptr(9.0)}),
		makeSource(SourceMITRE, feed.CanonicalPatch{CVEID: "CVE-1", CVSSv3Score: f64Ptr(5.0)}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !r.CVSSScoreDiverges {
		t.Error("CVSSScoreDiverges should be true when scores differ by ≥2.0")
	}
}

func TestResolveScoreDivergesFalse(t *testing.T) {
	t.Parallel()

	// NVD = 7.5, OSV = 7.0 → diff = 0.5 < 2.0
	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1", CVSSv3Score: f64Ptr(7.5)}),
		makeSource(SourceOSV, feed.CanonicalPatch{CVEID: "CVE-1", CVSSv3Score: f64Ptr(7.0)}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.CVSSScoreDiverges {
		t.Error("CVSSScoreDiverges should be false when scores differ by <2.0")
	}
}

func TestResolveScoreDivergesNoScores(t *testing.T) {
	t.Parallel()

	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1", Status: "Active"}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.CVSSScoreDiverges {
		t.Error("CVSSScoreDiverges should be false when no CVSSv3 scores present")
	}
}

// ── CWE IDs ───────────────────────────────────────────────────────────────────

func TestResolveCWEUnionSortedDeduped(t *testing.T) {
	t.Parallel()

	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1", CWEIDs: []string{"CWE-89", "CWE-79"}}),
		makeSource(SourceMITRE, feed.CanonicalPatch{CVEID: "CVE-1", CWEIDs: []string{"CWE-79", "CWE-94"}}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want := []string{"CWE-79", "CWE-89", "CWE-94"}
	if len(r.CWEIDs) != len(want) {
		t.Fatalf("CWEIDs = %v, want %v", r.CWEIDs, want)
	}
	for i, id := range want {
		if r.CWEIDs[i] != id {
			t.Errorf("CWEIDs[%d] = %q, want %q", i, r.CWEIDs[i], id)
		}
	}
}

func TestResolveCWEEmptyWhenNoneProvided(t *testing.T) {
	t.Parallel()

	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1", Status: "Active"}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(r.CWEIDs) != 0 {
		t.Errorf("CWEIDs = %v, want empty", r.CWEIDs)
	}
}

// ── CISA KEV + ExploitAvailable ───────────────────────────────────────────────

func TestResolveInCISAKEVAnySource(t *testing.T) {
	t.Parallel()

	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1", InCISAKEV: boolPtr(false)}),
		makeSource(SourceKEV, feed.CanonicalPatch{CVEID: "CVE-1", InCISAKEV: boolPtr(true)}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !r.InCISAKEV {
		t.Error("InCISAKEV should be true when any source asserts it")
	}
}

func TestResolveExploitAvailableAnySource(t *testing.T) {
	t.Parallel()

	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1", ExploitAvailable: boolPtr(false)}),
		makeSource(SourceGHSA, feed.CanonicalPatch{CVEID: "CVE-1", ExploitAvailable: boolPtr(true)}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !r.ExploitAvailable {
		t.Error("ExploitAvailable should be true when any source asserts it")
	}
}

// ── References ────────────────────────────────────────────────────────────────

func TestResolveRefDeduplicatedByCanonicalURL(t *testing.T) {
	t.Parallel()

	// Same URL (one with trailing slash, one without) from two sources.
	url1 := "https://example.com/advisory"
	url2 := "https://example.com/advisory/"
	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{
			CVEID:      "CVE-1",
			References: []feed.ReferenceEntry{{URL: url1}},
		}),
		makeSource(SourceMITRE, feed.CanonicalPatch{
			CVEID:      "CVE-1",
			References: []feed.ReferenceEntry{{URL: url2}},
		}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(r.References) != 1 {
		t.Errorf("References count = %d, want 1 (deduped by canonical URL)", len(r.References))
	}
}

func TestResolveRefDistinctURLsKept(t *testing.T) {
	t.Parallel()

	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{
			CVEID:      "CVE-1",
			References: []feed.ReferenceEntry{{URL: "https://nvd.nist.gov/1"}, {URL: "https://example.com/2"}},
		}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(r.References) != 2 {
		t.Errorf("References count = %d, want 2", len(r.References))
	}
}

// ── Affected packages ─────────────────────────────────────────────────────────

func TestResolvePkgOSVWinsOverGHSA(t *testing.T) {
	t.Parallel()

	// Same ecosystem+package+introduced from two sources: OSV entry should win.
	osvPkg := feed.AffectedPackage{
		Ecosystem: "PyPI", PackageName: "requests", Introduced: "2.0.0", Fixed: "2.28.0",
	}
	ghsaPkg := feed.AffectedPackage{
		Ecosystem: "PyPI", PackageName: "requests", Introduced: "2.0.0", Fixed: "2.27.0",
	}
	sources := []generated.CveSource{
		makeSource(SourceGHSA, feed.CanonicalPatch{CVEID: "CVE-1", AffectedPackages: []feed.AffectedPackage{ghsaPkg}}),
		makeSource(SourceOSV, feed.CanonicalPatch{CVEID: "CVE-1", AffectedPackages: []feed.AffectedPackage{osvPkg}}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(r.AffectedPackages) != 1 {
		t.Fatalf("AffectedPackages count = %d, want 1 (deduped)", len(r.AffectedPackages))
	}
	if r.AffectedPackages[0].Fixed != "2.28.0" {
		t.Errorf("AffectedPackages[0].Fixed = %q, want %q (OSV wins over GHSA)", r.AffectedPackages[0].Fixed, "2.28.0")
	}
}

// ── DateModifiedSourceMax ────────────────────────────────────────────────────

func TestResolveDateModifiedSourceMaxIsLatest(t *testing.T) {
	t.Parallel()

	early := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	sources := []generated.CveSource{
		makeSourceWithDate(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1"}, early),
		makeSourceWithDate(SourceMITRE, feed.CanonicalPatch{CVEID: "CVE-1"}, late),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.DateModifiedSourceMax == nil || !r.DateModifiedSourceMax.Equal(late) {
		t.Errorf("DateModifiedSourceMax = %v, want %v (latest)", r.DateModifiedSourceMax, late)
	}
}

// ── Malformed JSON ────────────────────────────────────────────────────────────

func TestResolveMalformedSourceSkipped(t *testing.T) {
	t.Parallel()

	// One source has invalid JSON; the other is well-formed. resolve continues.
	good := makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-1", Status: "Active"})
	bad := generated.CveSource{
		CveID:          "CVE-1",
		SourceName:     SourceMITRE,
		NormalizedJson: json.RawMessage(`{not valid json}`),
	}
	r, err := resolve([]generated.CveSource{bad, good})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.Status != "Active" {
		t.Errorf("status = %q, want %q (malformed source skipped, well-formed source used)", r.Status, "Active")
	}
}
