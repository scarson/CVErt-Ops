// ABOUTME: Tests the canonical ecosystem vocabulary, GHSA name mapping and package name folding.
// ABOUTME: Includes the real OSV distro strings observed in OSV data on 2026-11-08.
package ecosystem

import (
	"slices"
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	t.Parallel()
	valid := []string{
		"npm", "PyPI", "Maven", "Go", "crates.io", "RubyGems", "NuGet", "Hex", "Pub", "Packagist",
		"SwiftURL", "GitHub Actions", "Debian", "Ubuntu", "Alpine", "Red Hat", "Rocky Linux",
		"Debian:13", "Debian:5.0", "Ubuntu:26.04:LTS", "Ubuntu:Pro:FIPS-updates:22.04:LTS",
		"Ubuntu:Pro", "Alpine:v3.24", "Red Hat:enterprise_linux:8::appstream",
		"Packagist:https://packages.drupal.org/8", "SUSE:Linux Enterprise Live Patching 12 SP3",
		"BellSoft Hardened Containers:stream",
	}
	for _, v := range valid {
		if !Valid(v) {
			t.Errorf("Valid(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"", "pypi", "PIP", "pip", "cargo", "go", "maven", "NPM", "nuget", "rubygems", "hex", "pub",
		"packagist", "swift", "cocoapods", "rust", "composer", "erlang", "actions", "other",
		"Debian:", ":13", "npm:foo", "PyPI:3.11", "Debain:13", "GIT", "[EMPTY]",
		"Debian:1\x00", "Debian:" + strings.Repeat("9", 58),
	}
	for _, v := range invalid {
		if Valid(v) {
			t.Errorf("Valid(%q) = true, want false", v)
		}
	}
}

func TestNamesIsSortedCopy(t *testing.T) {
	t.Parallel()
	got := Names()
	if !slices.IsSorted(got) {
		t.Errorf("Names() not sorted: %v", got)
	}
	if !slices.Contains(got, "PyPI") || slices.Contains(got, "pypi") {
		t.Errorf("Names() = %v, want PyPI and not pypi", got)
	}
	got[0] = "mutated"
	if Names()[0] == "mutated" {
		t.Error("Names() returned shared storage")
	}
}

func TestFromGHSA(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"npm": "npm", "pip": "PyPI", "maven": "Maven", "go": "Go", "rust": "crates.io",
		"rubygems": "RubyGems", "nuget": "NuGet", "composer": "Packagist", "erlang": "Hex",
		"pub": "Pub", "swift": "SwiftURL", "actions": "GitHub Actions", "other": "other",
		"something-new": "something-new",
	}
	for in, want := range tests {
		if got := FromGHSA(in); got != want {
			t.Errorf("FromGHSA(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFoldPackageName(t *testing.T) {
	t.Parallel()
	tests := []struct{ eco, name, want string }{
		{"PyPI", "Django", "django"},
		{"PyPI", "Foo_Bar.baz", "foo-bar-baz"},
		{"PyPI", "foo--__..bar", "foo-bar"},
		{"npm", "Foo_Bar.baz", "foo_bar.baz"},
		{"NuGet", "TinyMCE", "tinymce"},
		{"Maven", "org.Example:Thing", "org.example:thing"},
		{"Debian:13", "OpenSSL", "openssl"},
	}
	for _, tt := range tests {
		if got := FoldPackageName(tt.eco, tt.name); got != tt.want {
			t.Errorf("FoldPackageName(%q, %q) = %q, want %q", tt.eco, tt.name, got, tt.want)
		}
	}
}

func TestFoldedNameSQL(t *testing.T) {
	t.Parallel()
	got := FoldedNameSQL("cap.ecosystem", "wi.package_name")
	for _, want := range []string{"cap.ecosystem = 'PyPI'", "regexp_replace(lower(wi.package_name), '[-_.]+', '-', 'g')", "ELSE lower(wi.package_name)"} {
		if !strings.Contains(got, want) {
			t.Errorf("FoldedNameSQL = %q, missing %q", got, want)
		}
	}
}

func TestOrdersBySemver(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"npm", "Go", "crates.io", "Hex", "Pub"} {
		if !OrdersBySemver(name) {
			t.Errorf("OrdersBySemver(%q) = false", name)
		}
	}
	for _, name := range []string{"PyPI", "Maven", "NuGet", "RubyGems", "Packagist", "Debian:13", ""} {
		if OrdersBySemver(name) {
			t.Errorf("OrdersBySemver(%q) = true", name)
		}
	}
}

func TestIsSubStream(t *testing.T) {
	t.Parallel()
	for _, eco := range []string{
		"Ubuntu:Pro:FIPS:20.04:LTS", "Ubuntu:Pro:FIPS-updates:22.04:LTS", "Ubuntu:Pro:FIPS-preview:22.04:LTS",
		"Ubuntu:Pro:Realtime:24.04:LTS", "Ubuntu:Nvidia-BlueField:22.04:LTS", "Ubuntu:SomeNewStream:26.04:LTS",
	} {
		if !IsSubStream(eco) {
			t.Errorf("IsSubStream(%q) = false, want true", eco)
		}
	}
	for _, eco := range []string{
		"Ubuntu:22.04:LTS", "Ubuntu:Pro:22.04:LTS", "Ubuntu:25.10", "Ubuntu:Pro:25.10", "Ubuntu", "Debian:13", "npm",
	} {
		if IsSubStream(eco) {
			t.Errorf("IsSubStream(%q) = true, want false", eco)
		}
	}
}

func TestReleaseStreams(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ecosystem string
		want      []string
	}{
		{"Ubuntu:22.04:LTS", []string{"Ubuntu:22.04:LTS", "Ubuntu:Pro:22.04:LTS"}},
		{"Ubuntu:Pro:22.04:LTS", []string{"Ubuntu:Pro:22.04:LTS", "Ubuntu:22.04:LTS"}},
		{"Ubuntu:25.10", []string{"Ubuntu:25.10", "Ubuntu:Pro:25.10"}},
		{"Ubuntu:Pro:25.10", []string{"Ubuntu:Pro:25.10", "Ubuntu:25.10"}},
		// Sub-streams have their own builds and are read alone.
		{"Ubuntu:Pro:FIPS-updates:22.04:LTS", []string{"Ubuntu:Pro:FIPS-updates:22.04:LTS"}},
		{"Ubuntu:Pro:Realtime:24.04:LTS", []string{"Ubuntu:Pro:Realtime:24.04:LTS"}},
		{"Ubuntu", []string{"Ubuntu"}},
		{"Debian:13", []string{"Debian:13"}},
		{"npm", []string{"npm"}},
	}
	for _, tt := range tests {
		got := ReleaseStreams(tt.ecosystem)
		if !slices.Equal(got, tt.want) {
			t.Errorf("ReleaseStreams(%q) = %q, want %q", tt.ecosystem, got, tt.want)
		}
	}
}
