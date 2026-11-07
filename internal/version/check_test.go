// ABOUTME: Tests that version checks follow each ecosystem's native ordering.
// ABOUTME: Also pins that anything not reliably comparable is never reported as "not affected".
package version

import (
	"errors"
	"strings"
	"testing"
)

// allEcosystems holds one stored spelling of every supported ecosystem.
var allEcosystems = []string{
	"npm", "Go", "crates.io", "Hex", "Pub", "NuGet", "PyPI", "Maven", "RubyGems",
	"Packagist", "Debian:13", "Ubuntu:26.04:LTS", "Alpine:v3.20", "Red Hat:rhel_aus:8.4::appstream",
}

func TestCheck_NativeOrdering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		ecosystem string
		version   string
		r         Range
		want      Status
	}{
		// String comparison sorts 2.10.0 below 2.9.0.
		{"2.9.0 is below fix 2.10.0", "npm", "2.9.0", Range{Introduced: "0", Fixed: "2.10.0"}, Affected},
		{"2.10.0 reaches fix 2.10.0", "npm", "2.10.0", Range{Introduced: "0", Fixed: "2.10.0"}, NotAffected},
		{"2.10.0 is above last affected 2.9.0", "npm", "2.10.0", Range{Introduced: "0", LastAffected: "2.9.0"}, NotAffected},

		{"node 24.22.0 is below fix", "npm", "24.22.0", Range{Introduced: "24.0.0", Fixed: "24.22.1"}, Affected},
		{"node 24.22.1 reaches fix", "npm", "24.22.1", Range{Introduced: "24.0.0", Fixed: "24.22.1"}, NotAffected},

		{"dpkg revision below fix", "Ubuntu:26.04:LTS", "8.5.4-0ubuntu1.4", Range{Introduced: "0", Fixed: "8.5.4-0ubuntu1.5"}, Affected},
		{"dpkg revision reaches fix", "Ubuntu:26.04:LTS", "8.5.4-0ubuntu1.5", Range{Introduced: "0", Fixed: "8.5.4-0ubuntu1.5"}, NotAffected},
		{"dpkg revision compares numerically", "Ubuntu:26.04:LTS", "8.5.4-0ubuntu1.10", Range{Introduced: "0", Fixed: "8.5.4-0ubuntu1.5"}, NotAffected},

		// An absent epoch is epoch 0, so 2.0-1 sorts below 1:1.0-1.
		{"debian epoch outranks upstream", "Debian:13", "2.0-1", Range{Introduced: "0", Fixed: "1:1.0-1"}, Affected},
		{"debian epoch reaches fix", "Debian:13", "1:1.0-1", Range{Introduced: "0", Fixed: "1:1.0-1"}, NotAffected},
		// A tilde sorts below the empty string, so 1.0~rc1 precedes 1.0.
		{"debian tilde sorts before release", "Debian:13", "1.0~rc1-1", Range{Introduced: "0", Fixed: "1.0-1"}, Affected},
		{"debian tilde is below introduced release", "Debian:13", "1.0~rc1-1", Range{Introduced: "1.0-1", Fixed: "2.0-1"}, NotAffected},

		// Semver reads every hyphenless suffix as invalid or as a pre-release.
		{"pep440 post release is above release", "PyPI", "1.0.post1", Range{Introduced: "0", Fixed: "1.0"}, NotAffected},
		{"pep440 release is below its post release", "PyPI", "1.0", Range{Introduced: "0", Fixed: "1.0.post1"}, Affected},
		{"pep440 dev release is below alpha", "PyPI", "1.0.dev1", Range{Introduced: "1.0a1", Fixed: "1.0"}, NotAffected},
		{"pep440 rc is below release", "PyPI", "1.0rc1", Range{Introduced: "0", Fixed: "1.0"}, Affected},
		{"pep440 implicit zero is equal", "PyPI", "1.0", Range{Introduced: "0", Fixed: "1.0.0"}, NotAffected},
		{"pep440 epoch outranks release", "PyPI", "1!1.0", Range{Introduced: "0", Fixed: "2.0"}, NotAffected},
		{"pep440 is case insensitive", "PyPI", "1.0RC1", Range{Introduced: "0", Fixed: "1.0"}, Affected},

		// Semver reads a hyphen suffix as a pre-release of the release before it.
		{"maven service pack is above release", "Maven", "1.0-sp", Range{Introduced: "0", Fixed: "1.0"}, NotAffected},
		{"maven final equals release", "Maven", "1.0-final", Range{Introduced: "0", Fixed: "1.0"}, NotAffected},
		// ASCII order puts SNAPSHOT below rc1. Maven puts rc1 below SNAPSHOT.
		{"maven rc is below snapshot", "Maven", "1.0-rc1", Range{Introduced: "0", Fixed: "1.0-SNAPSHOT"}, Affected},
		{"maven snapshot is below release", "Maven", "1.0-SNAPSHOT", Range{Introduced: "0", Fixed: "1.0"}, Affected},

		{"go module accepts leading v", "Go", "v1.2.3", Range{Introduced: "0", Fixed: "1.2.4"}, Affected},
		{"go pseudo-version precedes its base", "Go", "v1.2.3-0.20210101000000-abcdef123456", Range{Introduced: "0", Fixed: "1.2.3"}, Affected},
		{"go build metadata is ignored", "Go", "1.2.3+incompatible", Range{Introduced: "0", Fixed: "1.2.3"}, NotAffected},
		{"crates pre-release is below release", "crates.io", "1.0.0-alpha", Range{Introduced: "0", Fixed: "1.0.0"}, Affected},
		{"hex pre-release is below release", "Hex", "1.0.0-rc.1", Range{Introduced: "0", Fixed: "1.0.0"}, Affected},
		{"pub build number outranks release", "Pub", "1.0.0+1", Range{Introduced: "0", Fixed: "1.0.0"}, NotAffected},
		{"nuget compares a fourth component", "NuGet", "1.0.0.1", Range{Introduced: "0", Fixed: "1.0.0.2"}, Affected},
		{"nuget fourth component is above three", "NuGet", "1.0.0.1", Range{Introduced: "0", Fixed: "1.0.0"}, NotAffected},
		{"rubygems letter segment is a pre-release", "RubyGems", "1.0.0.pre", Range{Introduced: "0", Fixed: "1.0.0"}, Affected},
		{"packagist beta is below release", "Packagist", "1.0.0-beta1", Range{Introduced: "0", Fixed: "1.0.0"}, Affected},
		{"packagist accepts leading v", "Packagist", "v1.0.0", Range{Introduced: "0", Fixed: "1.0.0"}, NotAffected},
		{"alpine package revision below fix", "Alpine:v3.20", "1.0.0-r1", Range{Introduced: "0", Fixed: "1.0.0-r2"}, Affected},
		{"alpine suffix is below release", "Alpine:v3.20", "1.0_alpha1-r0", Range{Introduced: "0", Fixed: "1.0-r0"}, Affected},
		{"rpm epoch outranks upstream", "Red Hat:rhel_aus:8.4::appstream", "2.0-1.el8", Range{Introduced: "0", Fixed: "1:1.0-1.el8"}, Affected},
		{"rpm tilde sorts before release", "Red Hat", "1.0~rc1-1.el8_9", Range{Introduced: "0", Fixed: "1.0-1.el8_9"}, Affected},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertVerdict(t, tt.ecosystem, tt.version, tt.r, tt.want)
		})
	}
}

// TestCheck_IntroducedZero pins that "0" means "before every version". These
// versions all sort below a literal 0, so comparing against it would report
// them as not affected.
func TestCheck_IntroducedZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ecosystem string
		version   string
		fixed     string
	}{
		{"npm", "0.0.0-alpha", "1.0.0"},
		{"Debian:13", "0~rc1", "1.0"},
		{"PyPI", "0.dev1", "1.0"},
		{"Maven", "0-alpha", "1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.ecosystem, func(t *testing.T) {
			t.Parallel()
			assertVerdict(t, tt.ecosystem, tt.version, Range{Introduced: "0", Fixed: tt.fixed}, Affected)
		})
	}
}

func TestCheck_BoundInclusivity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
		r       Range
		want    Status
	}{
		{"below introduced", "0.9.0", Range{Introduced: "1.0.0", Fixed: "2.0.0"}, NotAffected},
		{"introduced is inclusive", "1.0.0", Range{Introduced: "1.0.0", Fixed: "2.0.0"}, Affected},
		{"just below fixed", "1.9.9", Range{Introduced: "1.0.0", Fixed: "2.0.0"}, Affected},
		{"fixed is exclusive", "2.0.0", Range{Introduced: "1.0.0", Fixed: "2.0.0"}, NotAffected},
		{"last affected is inclusive", "2.0.0", Range{Introduced: "1.0.0", LastAffected: "2.0.0"}, Affected},
		{"above last affected", "2.0.1", Range{Introduced: "1.0.0", LastAffected: "2.0.0"}, NotAffected},
		{"single affected version", "1.0.0", Range{Introduced: "1.0.0", LastAffected: "1.0.0"}, Affected},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertVerdict(t, "npm", tt.version, tt.r, tt.want)
		})
	}
}

func TestCheck_UnknownEcosystemCannotEvaluate(t *testing.T) {
	t.Parallel()

	// Lower-case names are what GHSA stores where OSV stores PyPI, Go and the rest.
	names := []string{
		"", "pip", "PIP", "pypi", "go", "maven", "nuget", "rubygems", "rust", "composer", "erlang", "pub",
		"actions", "Debain", "debian", "ubuntu", "red hat", "npm:foo", "PyPI:3.11", "Debian:", ":13", "cpe",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := Check(name, "1.0.0", Range{Introduced: "0", Fixed: "2.0.0"})
			if got != CannotEvaluate {
				t.Errorf("Check(%q) = %s, want %s", name, got, CannotEvaluate)
			}
			if !errors.Is(err, ErrUnknownEcosystem) {
				t.Errorf("Check(%q) err = %v, want ErrUnknownEcosystem", name, err)
			}
		})
	}
}

// TestCheck_MalformedValuesCannotEvaluate holds strings that semantic.Parse
// accepts in most ecosystems and then sorts above or below every real version.
func TestCheck_MalformedValuesCannotEvaluate(t *testing.T) {
	t.Parallel()

	malformed := []string{
		" ", "banana", "latest", "not a version", "???", "../../etc/passwd", "1.2.3 ; DROP", "v", "-", ":", "1:",
		"a:1.0", "١.٢.٣", "1.2.3\n", " 1.2.3", "1.2.3 ", "*",
		"1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",                         // git commit
		"1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1a2b3c4d5e6f7a8b9c0d1e2f", // sha-256 git commit
		strings.Repeat("1", maxVersionLen+1),
	}

	for _, ecosystem := range allEcosystems {
		for _, value := range malformed {
			t.Run(ecosystem+"/"+value, func(t *testing.T) {
				t.Parallel()

				got, err := Check(ecosystem, value, Range{Introduced: "0", Fixed: "2.0.0"})
				if got != CannotEvaluate || !errors.Is(err, ErrInvalidVersion) {
					t.Errorf("as version: got (%s, %v), want (%s, ErrInvalidVersion)", got, err, CannotEvaluate)
				}

				for slot, r := range map[string]Range{
					"introduced":    {Introduced: value, Fixed: "2.0.0"},
					"fixed":         {Introduced: "0", Fixed: value},
					"last_affected": {Introduced: "0", LastAffected: value},
				} {
					got, err := Check(ecosystem, "1.0.0", r)
					if got != CannotEvaluate || !errors.Is(err, ErrInvalidRange) {
						t.Errorf("as %s: got (%s, %v), want (%s, ErrInvalidRange)", slot, got, err, CannotEvaluate)
					}
				}
			})
		}
	}
}

// TestCheck_MalformedForEcosystem holds strings that look like versions but
// break the named ecosystem's own grammar.
func TestCheck_MalformedForEcosystem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		ecosystem string
		version   string
	}{
		{"pep440 legacy version", "PyPI", "1.0-foo"},
		{"pep440 trailing junk", "PyPI", "1.0.0.x"},
		{"semver has three numeric components", "npm", "1.2.3.4"},
		{"semver pre-release needs a hyphen", "npm", "1.2.3rc1"},
		{"semver empty pre-release", "npm", "1.2.3-"},
		{"semver empty identifier", "npm", "1.2.3-a..b"},
		{"nuget has four numeric components", "NuGet", "1.2.3.4.5"},
		{"maven starts with a digit", "Maven", "v1.0"},
		{"packagist branch alias", "Packagist", "dev-master"},
		{"rubygems has no leading v", "RubyGems", "v1.0"},
		{"dpkg empty revision", "Debian:13", "1.0-"},
		{"dpkg empty upstream", "Debian:13", "1:"},
		{"dpkg non-numeric epoch", "Debian:13", "a:1.0"},
		{"rpm empty upstream", "Red Hat", "1:"},
		{"apk unknown suffix", "Alpine", "1.0_banana"},
		{"apk revision needs digits", "Alpine", "1.0-rx"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Check(tt.ecosystem, tt.version, Range{Introduced: "0", Fixed: "2.0.0"})
			if got != CannotEvaluate || !errors.Is(err, ErrInvalidVersion) {
				t.Errorf("Check(%q, %q) = (%s, %v), want (%s, ErrInvalidVersion)", tt.ecosystem, tt.version, got, err, CannotEvaluate)
			}
		})
	}
}

func TestCheck_UnusableRangeCannotEvaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		r    Range
	}{
		{"no bounds", Range{}},
		{"introduced only", Range{Introduced: "1.0.0"}},
		{"introduced zero only", Range{Introduced: "0"}},
		{"fixed only", Range{Fixed: "2.0.0"}},
		{"last affected only", Range{LastAffected: "2.0.0"}},
		{"both upper bounds", Range{Introduced: "0", Fixed: "2.0.0", LastAffected: "1.9.0"}},
		{"fixed below introduced", Range{Introduced: "3.0.0", Fixed: "2.0.0"}},
		{"fixed equal to introduced", Range{Introduced: "2.0.0", Fixed: "2.0.0"}},
		{"last affected below introduced", Range{Introduced: "3.0.0", LastAffected: "2.0.0"}},
		{"fixed in zero", Range{Introduced: "0", Fixed: "0"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Check("npm", "1.0.0", tt.r)
			if got != CannotEvaluate || !errors.Is(err, ErrInvalidRange) {
				t.Errorf("Check(%+v) = (%s, %v), want (%s, ErrInvalidRange)", tt.r, got, err, CannotEvaluate)
			}

			got, err = CheckNumeric("1.0.0", tt.r)
			if got != CannotEvaluate || !errors.Is(err, ErrInvalidRange) {
				t.Errorf("CheckNumeric(%+v) = (%s, %v), want (%s, ErrInvalidRange)", tt.r, got, err, CannotEvaluate)
			}
		})
	}
}

func TestCheckNumeric(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
		r       Range
		want    Status
	}{
		{"nginx 1.9 is below 1.10", "1.9.0", Range{Introduced: "0", Fixed: "1.10.0"}, Affected},
		{"nginx 1.10 reaches fix", "1.10.0", Range{Introduced: "0", Fixed: "1.10.0"}, NotAffected},
		{"node 24.22.0 is below fix", "24.22.0", Range{Introduced: "24.0.0", Fixed: "24.22.1"}, Affected},
		{"node 24.22.1 reaches fix", "24.22.1", Range{Introduced: "24.0.0", Fixed: "24.22.1"}, NotAffected},
		{"missing components are zero", "1.24", Range{Introduced: "0", Fixed: "1.24.0"}, NotAffected},
		{"extra zero components are equal", "1.24.0.0", Range{Introduced: "1.24", LastAffected: "1.24"}, Affected},
		{"extra non-zero component is above", "1.24.0.1", Range{Introduced: "0", LastAffected: "1.24"}, NotAffected},
		{"leading zeros are numeric", "1.024", Range{Introduced: "0", Fixed: "1.24"}, NotAffected},
		{"below introduced", "1.0", Range{Introduced: "1.1", Fixed: "2.0"}, NotAffected},
		{"introduced is inclusive", "1.1", Range{Introduced: "1.1", Fixed: "2.0"}, Affected},
		{"last affected is inclusive", "2.0", Range{Introduced: "1.1", LastAffected: "2.0"}, Affected},
		{"beyond any machine integer", "99999999999999999999999.1", Range{Introduced: "0", Fixed: "99999999999999999999999.2"}, Affected},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := CheckNumeric(tt.version, tt.r)
			if err != nil {
				t.Fatalf("CheckNumeric(%q, %+v) err = %v", tt.version, tt.r, err)
			}
			if got != tt.want {
				t.Errorf("CheckNumeric(%q, %+v) = %s, want %s", tt.version, tt.r, got, tt.want)
			}
		})
	}
}

func TestCheckNumeric_AnythingElseCannotEvaluate(t *testing.T) {
	t.Parallel()

	values := []string{
		" ", "banana", "*", "-", "v1.24.0", "1.24.0-1", "1.24.x", "1.24.0rc1", "1.24.", ".1", "1..2", "1.24.0 ", " 1.24.0",
		"1.24.0\n", "1:1.24", "١.٢", strings.Repeat("1", maxVersionLen+1),
	}

	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			t.Parallel()

			got, err := CheckNumeric(value, Range{Introduced: "0", Fixed: "2.0"})
			if got != CannotEvaluate || !errors.Is(err, ErrInvalidVersion) {
				t.Errorf("as version: got (%s, %v), want (%s, ErrInvalidVersion)", got, err, CannotEvaluate)
			}

			got, err = CheckNumeric("1.0", Range{Introduced: "0", Fixed: value})
			if got != CannotEvaluate || !errors.Is(err, ErrInvalidRange) {
				t.Errorf("as fixed: got (%s, %v), want (%s, ErrInvalidRange)", got, err, CannotEvaluate)
			}
		})
	}

	got, err := CheckNumeric("", Range{Introduced: "0", Fixed: "2.0"})
	if got != CannotEvaluate || !errors.Is(err, ErrInvalidVersion) {
		t.Errorf("empty version: got (%s, %v), want (%s, ErrInvalidVersion)", got, err, CannotEvaluate)
	}
}

func TestCheck_EmptyVersionCannotEvaluate(t *testing.T) {
	t.Parallel()

	for _, ecosystem := range allEcosystems {
		got, err := Check(ecosystem, "", Range{Introduced: "0", Fixed: "2.0.0"})
		if got != CannotEvaluate || !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("%s: got (%s, %v), want (%s, ErrInvalidVersion)", ecosystem, got, err, CannotEvaluate)
		}
	}
}

func TestStatus(t *testing.T) {
	t.Parallel()

	var zero Status
	if zero != CannotEvaluate {
		t.Errorf("zero Status = %s, want %s", zero, CannotEvaluate)
	}

	for status, want := range map[Status]string{
		Affected:       "affected",
		NotAffected:    "not affected",
		CannotEvaluate: "cannot evaluate",
		Status(99):     "cannot evaluate",
	} {
		if got := status.String(); got != want {
			t.Errorf("Status(%d).String() = %q, want %q", int(status), got, want)
		}
	}
}

// FuzzCheck pins two properties for arbitrary input: the error is set exactly
// when the status is CannotEvaluate, and a version with no digit is never judged.
func FuzzCheck(f *testing.F) {
	for _, ecosystem := range allEcosystems {
		f.Add(ecosystem, "1.2.3", "0", "2.0.0", "")
		f.Add(ecosystem, "banana", "1.0", "", "2.0")
	}
	f.Add("Debian:13", "1:1.0~rc1-1", "0", "1:1.0-1", "")
	f.Add("PyPI", "1!1.0.post1.dev2+local.1", "1.0a1", "", "2.0")
	f.Add("Red Hat", "1:1.0~a^b-1.el8_9", "0", "2.0", "")

	f.Fuzz(func(t *testing.T, ecosystem, version, introduced, fixed, lastAffected string) {
		r := Range{Introduced: introduced, Fixed: fixed, LastAffected: lastAffected}

		for _, check := range []func() (Status, error){
			func() (Status, error) { return Check(ecosystem, version, r) },
			func() (Status, error) { return CheckNumeric(version, r) },
		} {
			got, err := check()
			if (err != nil) != (got == CannotEvaluate) {
				t.Errorf("status %s with err %v", got, err)
			}
			if got != CannotEvaluate && !strings.ContainsAny(version, "0123456789") {
				t.Errorf("version %q with no digit judged %s", version, got)
			}
		}
	})
}

func assertVerdict(t *testing.T, ecosystem, version string, r Range, want Status) {
	t.Helper()

	got, err := Check(ecosystem, version, r)
	if err != nil {
		t.Fatalf("Check(%q, %q, %+v) err = %v", ecosystem, version, r, err)
	}
	if got != want {
		t.Errorf("Check(%q, %q, %+v) = %s, want %s", ecosystem, version, r, got, want)
	}
}
