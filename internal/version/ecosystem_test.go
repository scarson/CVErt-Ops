// ABOUTME: Tests SemVer checks for ranges typed SEMVER and the orderings chosen by name.
// ABOUTME: Pins that a version an ordering cannot read is an error, never a guessed order.
package version

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckSemver(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, version string
		r             Range
		want          Status
	}{
		{"inside", "1.2.3", Range{Introduced: "1.0.0", Fixed: "2.0.0"}, Affected},
		{"below", "0.9.0", Range{Introduced: "1.0.0", Fixed: "2.0.0"}, NotAffected},
		{"at fixed", "2.0.0", Range{Introduced: "1.0.0", Fixed: "2.0.0"}, NotAffected},
		// A distro-style suffix reads as a SemVer prerelease, which sorts below its release.
		{"distro suffix is a prerelease", "1.2.3-1ubuntu1", Range{Introduced: "1.0.0", Fixed: "1.2.3"}, Affected},
		{"prerelease below release", "2.0.0-rc1", Range{Introduced: "1.0.0", Fixed: "2.0.0"}, Affected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := CheckSemver(tt.version, tt.r)
			if err != nil || got != tt.want {
				t.Errorf("CheckSemver(%q, %+v) = (%s, %v), want %s", tt.version, tt.r, got, err, tt.want)
			}
		})
	}
}

func TestCheckSemver_UnreadableCannotEvaluate(t *testing.T) {
	t.Parallel()
	r := Range{Introduced: "1.0.0", Fixed: "2.0.0"}
	for _, value := range []string{
		"banana",
		"",
		"1.2.3.4",
		"1.2rc1",
		strings.Repeat("1", 40),
		"1.0.0-" + strings.Repeat("a", maxVersionLen),
	} {
		got, err := CheckSemver(value, r)
		if got != CannotEvaluate || !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("CheckSemver(%q) = (%s, %v), want (%s, ErrInvalidVersion)", value, got, err, CannotEvaluate)
		}
	}
	got, err := CheckSemver("1.5.0", Range{Introduced: "1.0.0", Fixed: "banana"})
	if got != CannotEvaluate || !errors.Is(err, ErrInvalidRange) {
		t.Errorf("malformed bound = (%s, %v), want (%s, ErrInvalidRange)", got, err, CannotEvaluate)
	}
	got, err = CheckSemver("1.5.0", Range{Introduced: "2.0.0", Fixed: "1.0.0"})
	if got != CannotEvaluate || !errors.Is(err, ErrInvalidRange) {
		t.Errorf("inverted range = (%s, %v), want (%s, ErrInvalidRange)", got, err, CannotEvaluate)
	}
}

// sign reduces a comparison result to -1, 0 or 1.
func sign(c int) int {
	switch {
	case c < 0:
		return -1
	case c > 0:
		return 1
	default:
		return 0
	}
}

func TestSemverOrder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.10.0", "1.9.0", 1},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3-1ubuntu1", "1.2.3", -1},
	}
	for _, tt := range tests {
		got, err := SemverOrder(tt.a, tt.b)
		if err != nil || sign(got) != tt.want {
			t.Errorf("SemverOrder(%q, %q) = (%d, %v), want sign %d", tt.a, tt.b, got, err, tt.want)
		}
	}
	for _, pair := range [][2]string{
		{"banana", "1.0.0"},
		{"1.0.0", "banana"},
		{"1.2rc1", "1.2.0"},
		{strings.Repeat("1", 40), "1.0.0"},
		{"1.0.0", "1.0.0-" + strings.Repeat("a", maxVersionLen)},
	} {
		if _, err := SemverOrder(pair[0], pair[1]); !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("SemverOrder(%q, %q) err = %v, want ErrInvalidVersion", pair[0], pair[1], err)
		}
	}
}

func TestEcosystemOrder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ecosystem, a, b string
		want            int
	}{
		{"PyPI", "1.1rc1", "1.1", -1},
		{"Debian:13", "1:1.0-1", "2.0-1", 1},
		{"Maven", "1.0", "1.0.0", 0},
	}
	for _, tt := range tests {
		order := EcosystemOrder(tt.ecosystem)
		if order == nil {
			t.Fatalf("EcosystemOrder(%q) = nil", tt.ecosystem)
		}
		got, err := order(tt.a, tt.b)
		if err != nil || sign(got) != tt.want {
			t.Errorf("EcosystemOrder(%q)(%q, %q) = (%d, %v), want sign %d", tt.ecosystem, tt.a, tt.b, got, err, tt.want)
		}
	}

	order := EcosystemOrder("PyPI")
	for _, pair := range [][2]string{{"banana", "1.1"}, {"1.1", "banana"}} {
		if _, err := order(pair[0], pair[1]); !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("PyPI order(%q, %q) err = %v, want ErrInvalidVersion", pair[0], pair[1], err)
		}
	}
}

func TestEcosystemOrder_NoComparatorIsNil(t *testing.T) {
	t.Parallel()
	for _, ecosystem := range []string{"Root:x", "GitHub Actions", "", "pip", "npm:1", "Debian:"} {
		if EcosystemOrder(ecosystem) != nil {
			t.Errorf("EcosystemOrder(%q) is not nil", ecosystem)
		}
	}
}
