// ABOUTME: Regression tests for OSV adapter multi-event range data loss bug.
// ABOUTME: Validates that extractPackageRange produces one AffectedPackage per introduced/fixed pair.
package osv

import (
	"encoding/json"
	"testing"
)

func TestExtractPackageRange_MultipleEventPairs(t *testing.T) {
	t.Parallel()

	// OSV ranges can contain multiple introduced/fixed event pairs.
	// Each pair must produce a separate AffectedPackage entry.
	events := json.RawMessage(`[
		{"introduced": "1.0.0"},
		{"fixed": "1.5.0"},
		{"introduced": "2.0.0"},
		{"fixed": "2.3.0"}
	]`)

	rng := osvRange{
		Type:   "SEMVER",
		Events: events,
	}

	packages := extractPackageRanges("Go", "example.com/pkg", rng)
	if len(packages) != 2 {
		t.Fatalf("extractPackageRanges returned %d packages, want 2", len(packages))
	}

	if packages[0].Introduced != "1.0.0" || packages[0].Fixed != "1.5.0" {
		t.Errorf("pkg[0]: introduced=%q fixed=%q, want 1.0.0/1.5.0",
			packages[0].Introduced, packages[0].Fixed)
	}
	if packages[1].Introduced != "2.0.0" || packages[1].Fixed != "2.3.0" {
		t.Errorf("pkg[1]: introduced=%q fixed=%q, want 2.0.0/2.3.0",
			packages[1].Introduced, packages[1].Fixed)
	}
}

func TestExtractPackageRange_SingleEventPair(t *testing.T) {
	t.Parallel()

	events := json.RawMessage(`[
		{"introduced": "0"},
		{"fixed": "1.2.3"}
	]`)

	rng := osvRange{
		Type:   "ECOSYSTEM",
		Events: events,
	}

	packages := extractPackageRanges("npm", "lodash", rng)
	if len(packages) != 1 {
		t.Fatalf("extractPackageRanges returned %d packages, want 1", len(packages))
	}
	if packages[0].Introduced != "0" || packages[0].Fixed != "1.2.3" {
		t.Errorf("pkg[0]: introduced=%q fixed=%q, want 0/1.2.3",
			packages[0].Introduced, packages[0].Fixed)
	}
	if packages[0].Ecosystem != "npm" || packages[0].PackageName != "lodash" {
		t.Errorf("pkg[0]: ecosystem=%q pkg=%q, want npm/lodash",
			packages[0].Ecosystem, packages[0].PackageName)
	}
}

func TestExtractPackageRange_LastAffected(t *testing.T) {
	t.Parallel()

	events := json.RawMessage(`[
		{"introduced": "1.0.0"},
		{"last_affected": "1.9.9"}
	]`)

	rng := osvRange{
		Type:   "SEMVER",
		Events: events,
	}

	packages := extractPackageRanges("Go", "example.com/pkg", rng)
	if len(packages) != 1 {
		t.Fatalf("extractPackageRanges returned %d packages, want 1", len(packages))
	}
	if packages[0].Introduced != "1.0.0" || packages[0].LastAffected != "1.9.9" {
		t.Errorf("pkg[0]: introduced=%q last_affected=%q, want 1.0.0/1.9.9",
			packages[0].Introduced, packages[0].LastAffected)
	}
}

func TestExtractPackageRange_EmptyEvents(t *testing.T) {
	t.Parallel()

	rng := osvRange{
		Type:   "SEMVER",
		Events: json.RawMessage(`[]`),
	}

	packages := extractPackageRanges("Go", "example.com/pkg", rng)
	if len(packages) != 0 {
		t.Errorf("extractPackageRanges returned %d packages for empty events, want 0", len(packages))
	}
}
