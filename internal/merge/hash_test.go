package merge

import (
	"testing"
)

// ── ComputeMaterialHash ───────────────────────────────────────────────────────

func TestComputeMaterialHashDeterminism(t *testing.T) {
	t.Parallel()

	f := MaterialFields{
		Status:    "published",
		Severity:  "HIGH",
		CWEIDs:    []string{"CWE-79", "CWE-89"},
		InCISAKEV: true,
	}
	h1 := ComputeMaterialHash(f)
	h2 := ComputeMaterialHash(f)
	if h1 == "" {
		t.Fatal("hash is empty")
	}
	if h1 != h2 {
		t.Errorf("hash not deterministic: %q != %q", h1, h2)
	}
}

func TestComputeMaterialHashFieldSensitivity(t *testing.T) {
	t.Parallel()

	base := MaterialFields{Status: "published", Severity: "HIGH"}
	changed := MaterialFields{Status: "published", Severity: "CRITICAL"}
	if ComputeMaterialHash(base) == ComputeMaterialHash(changed) {
		t.Error("severity change should produce a different hash")
	}
}

func TestComputeMaterialHashInCISAKEVSensitivity(t *testing.T) {
	t.Parallel()

	f1 := MaterialFields{InCISAKEV: false}
	f2 := MaterialFields{InCISAKEV: true}
	if ComputeMaterialHash(f1) == ComputeMaterialHash(f2) {
		t.Error("in_cisa_kev change should produce a different hash")
	}
}

func TestComputeMaterialHashCWEOrder(t *testing.T) {
	t.Parallel()

	// CWE IDs in different order should hash identically (sorted before hashing).
	f1 := MaterialFields{CWEIDs: []string{"CWE-89", "CWE-79"}}
	f2 := MaterialFields{CWEIDs: []string{"CWE-79", "CWE-89"}}
	if ComputeMaterialHash(f1) != ComputeMaterialHash(f2) {
		t.Error("CWE IDs in different order should produce the same hash")
	}
}

func TestComputeMaterialHashNilSlicesEqualEmpty(t *testing.T) {
	t.Parallel()

	// nil slices must not serialise as JSON null (would differ from []).
	fNil := MaterialFields{}
	fEmpty := MaterialFields{
		CWEIDs:       []string{},
		AffectedCPEs: []string{},
		AffectedPkgs: []affectedPkgKey{},
	}
	if ComputeMaterialHash(fNil) != ComputeMaterialHash(fEmpty) {
		t.Error("nil slices should hash identically to empty slices")
	}
}

func TestComputeMaterialHashPkgOrder(t *testing.T) {
	t.Parallel()

	// Affected packages in different insertion order should hash identically.
	f1 := MaterialFields{
		AffectedPkgs: []affectedPkgKey{
			{Ecosystem: "npm", PackageName: "lodash", Introduced: "4.0.0"},
			{Ecosystem: "npm", PackageName: "axios", Introduced: "0.1.0"},
		},
	}
	f2 := MaterialFields{
		AffectedPkgs: []affectedPkgKey{
			{Ecosystem: "npm", PackageName: "axios", Introduced: "0.1.0"},
			{Ecosystem: "npm", PackageName: "lodash", Introduced: "4.0.0"},
		},
	}
	if ComputeMaterialHash(f1) != ComputeMaterialHash(f2) {
		t.Error("affected packages in different order should produce the same hash")
	}
}

func TestComputeMaterialHashCPEOrder(t *testing.T) {
	t.Parallel()

	f1 := MaterialFields{AffectedCPEs: []string{"cpe:2.3:a:foo:bar:1.0:*", "cpe:2.3:a:foo:baz:2.0:*"}}
	f2 := MaterialFields{AffectedCPEs: []string{"cpe:2.3:a:foo:baz:2.0:*", "cpe:2.3:a:foo:bar:1.0:*"}}
	if ComputeMaterialHash(f1) != ComputeMaterialHash(f2) {
		t.Error("CPEs in different order should produce the same hash")
	}
}

func TestComputeMaterialHashCVSSVectorNormalized(t *testing.T) {
	t.Parallel()

	// The same CVSS v3 metrics in different order should produce the same hash.
	score := 9.8
	f1 := MaterialFields{CVSSv3Score: &score, CVSSv3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
	f2 := MaterialFields{CVSSv3Score: &score, CVSSv3Vector: "CVSS:3.1/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N/S:U"}
	if ComputeMaterialHash(f1) != ComputeMaterialHash(f2) {
		t.Error("CVSS vectors with same metrics in different order should produce the same hash")
	}
}

// ── normalizeCVSSVector ───────────────────────────────────────────────────────

func TestNormalizeCVSSVectorEmpty(t *testing.T) {
	t.Parallel()
	if got := normalizeCVSSVector(""); got != "" {
		t.Errorf("normalizeCVSSVector(\"\") = %q, want %q", got, "")
	}
}

func TestNormalizeCVSSVectorReordersMetrics(t *testing.T) {
	t.Parallel()

	v1 := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	v2 := "CVSS:3.1/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N/S:U"
	n1 := normalizeCVSSVector(v1)
	n2 := normalizeCVSSVector(v2)
	if n1 != n2 {
		t.Errorf("same metrics in different order should normalize identically:\n  got  %q\n  got  %q", n1, n2)
	}
}

func TestNormalizeCVSSVectorPreservesPrefix(t *testing.T) {
	t.Parallel()

	v := "CVSS:3.1/AV:N/AC:L"
	got := normalizeCVSSVector(v)
	if len(got) < 7 || got[:7] != "CVSS:3." {
		t.Errorf("normalizeCVSSVector(%q) = %q: should preserve CVSS version prefix", v, got)
	}
}

func TestNormalizeCVSSVectorSingleSegmentUnchanged(t *testing.T) {
	t.Parallel()

	// A string with no '/' at all: len(parts) < 2, returned unchanged.
	v := "NOPREFIX"
	if got := normalizeCVSSVector(v); got != v {
		t.Errorf("normalizeCVSSVector(%q) = %q, want %q", v, got, v)
	}
}

func TestNormalizeCVSSVectorIdempotent(t *testing.T) {
	t.Parallel()

	v := "CVSS:3.1/A:H/AC:L/AV:N/C:H/I:H/PR:N/S:U/UI:N"
	if normalizeCVSSVector(v) != normalizeCVSSVector(normalizeCVSSVector(v)) {
		t.Error("normalizeCVSSVector should be idempotent")
	}
}
