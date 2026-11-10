// ABOUTME: Tests the package URL mapping to canonical ecosystems, names and versions.
// ABOUTME: Covers each purl type, distro qualifier form, epoch rule and refusal code.
package ecosystem

import (
	"errors"
	"strings"
	"testing"
)

func TestFromPurl(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in                 string
		eco, name, version string
	}{
		// Purl types (design section 3.2, first table).
		{"pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20"},
		{"pkg:npm/%40scope/name@1.0.0", "npm", "@scope/name", "1.0.0"},
		{"pkg:pypi/django@4.2.1", "PyPI", "django", "4.2.1"},
		{"pkg:golang/stdlib@1.26.0", "Go", "stdlib", "1.26.0"},
		{"pkg:golang/github.com/foo/bar@v1.2.3", "Go", "github.com/foo/bar", "v1.2.3"},
		{"pkg:maven/org.apache/log4j@2.14.0", "Maven", "org.apache:log4j", "2.14.0"},
		{"pkg:cargo/serde@1.0.0", "crates.io", "serde", "1.0.0"},
		{"pkg:gem/rails@7.0.1", "RubyGems", "rails", "7.0.1"},
		{"pkg:nuget/Newtonsoft.Json@13.0.1", "NuGet", "Newtonsoft.Json", "13.0.1"},
		{"pkg:pub/http@1.0.0", "Pub", "http", "1.0.0"},
		{"pkg:hex/phoenix@1.7.0", "Hex", "phoenix", "1.7.0"},
		{"pkg:composer/symfony/http@6.0", "Packagist", "symfony/http", "6.0"},
		{"pkg:deb/ubuntu/php8.5@8.5.4-0ubuntu1.4?distro=ubuntu-26.04", "Ubuntu:26.04:LTS", "php8.5", "8.5.4-0ubuntu1.4"},
		{"pkg:apk/alpine/musl@1.2.4-r0?distro=3.20.3", "Alpine:v3.20", "musl", "1.2.4-r0"},
		// Distro qualifiers (design section 3.2, second table).
		{"pkg:deb/ubuntu/php8.5@8.5.4-0ubuntu1.4?distro=ubuntu-25.10", "Ubuntu:25.10", "php8.5", "8.5.4-0ubuntu1.4"},
		{"pkg:deb/debian/curl@8.0?distro=debian-13", "Debian:13", "curl", "8.0"},
		{"pkg:deb/debian/curl@8.0?distro=debian-13.1", "Debian:13", "curl", "8.0"},
		{"pkg:apk/alpine/musl@1.2.4-r0?distro=alpine-3.20", "Alpine:v3.20", "musl", "1.2.4-r0"},
		{"pkg:deb/debian/curl@8.0?distro=trixie", "Debian:13", "curl", "8.0"},
		{"pkg:deb/ubuntu/curl@8.0?distro=resolute", "Ubuntu:26.04:LTS", "curl", "8.0"},
		{"pkg:deb/ubuntu/curl@8.0?distro=noble", "Ubuntu:24.04:LTS", "curl", "8.0"},
		{"pkg:deb/debian/curl@8.0?distro=bullseye", "Debian:11", "curl", "8.0"},
		{"pkg:deb/debian/curl@8.0?distro=bookworm", "Debian:12", "curl", "8.0"},
		{"pkg:deb/ubuntu/curl@8.0?distro=jammy", "Ubuntu:22.04:LTS", "curl", "8.0"},
		{"pkg:deb/ubuntu/curl@8.0?distro=plucky", "Ubuntu:25.04", "curl", "8.0"},
		{"pkg:deb/ubuntu/curl@8.0?distro=questing", "Ubuntu:25.10", "curl", "8.0"},
		{"pkg:deb/ubuntu/curl@8.0?distro=ubuntu-24.04", "Ubuntu:24.04:LTS", "curl", "8.0"},
		{"pkg:deb/ubuntu/curl@8.0?distro=ubuntu-14.04", "Ubuntu:14.04:LTS", "curl", "8.0"},
		{"pkg:deb/ubuntu/curl@8.0?distro=ubuntu-15.04", "Ubuntu:15.04", "curl", "8.0"},
		{"pkg:deb/debian/curl@8.0?distro=debian-10", "Debian:10", "curl", "8.0"},
		{"pkg:apk/alpine/musl@1.2.4-r0?distro=alpine-3.20.3", "Alpine:v3.20", "musl", "1.2.4-r0"},
		{"pkg:apk/alpine/musl@1.2.4-r0?distro=3.9", "Alpine:v3.9", "musl", "1.2.4-r0"},
		// packageurl-go lower-cases qualifier keys, so the distro is still read.
		{"pkg:deb/debian/curl@8.0?DISTRO=debian-13", "Debian:13", "curl", "8.0"},
		// Epoch qualifier.
		{"pkg:deb/debian/foo@1.0?distro=debian-13&epoch=2", "Debian:13", "foo", "2:1.0"},
		{"pkg:deb/debian/foo@2:1.0?distro=debian-13&epoch=2", "Debian:13", "foo", "2:1.0"},
		// Qualifiers other than distro, epoch and repository_url are ignored.
		{"pkg:deb/debian/foo@1.0?distro=debian-13&arch=amd64", "Debian:13", "foo", "1.0"},
		// No version: stored CNA package URLs have none.
		{"pkg:npm/fastify", "npm", "fastify", ""},
	}
	for _, tt := range tests {
		got, err := FromPurl(tt.in)
		if err != nil {
			t.Errorf("FromPurl(%q) error = %v, want none", tt.in, err)
			continue
		}
		want := PurlComponent{Ecosystem: tt.eco, Name: tt.name, Version: tt.version}
		if got != want {
			t.Errorf("FromPurl(%q) = %+v, want %+v", tt.in, got, want)
		}
	}
}

func TestFromPurlRefusals(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, code string }{
		{"not a purl", "invalid_purl"},
		{"pkg:composer/http@6.0", "invalid_purl"},
		{"pkg:maven/log4j@1", "invalid_purl"},
		{"pkg:hex/acme/foo@2.3.0", "unsupported_purl_namespace"},
		{"pkg:cargo/x/y@1", "unsupported_purl_namespace"},
		{"pkg:deb/kali/foo@1?distro=kali-2024", "unsupported_purl_namespace"},
		{"pkg:apk/wolfi/foo@1?distro=3.20", "unsupported_purl_namespace"},
		{"pkg:npm/foo@1?repository_url=https://r.example", "unsupported_repository"},
		{"pkg:npm/foo@1#sub", "invalid_purl"},
		{"pkg:rpm/redhat/foo@1", "unsupported_purl_type"},
		{"pkg:generic/foo@1", "unsupported_purl_type"},
		{"pkg:deb/debian/curl@8.0", "distro_required"},
		{"pkg:apk/alpine/musl@1.2.4-r0", "distro_required"},
		{"pkg:deb/ubuntu/x@1?distro=esm-infra/focal", "distro_not_recognised"},
		{"pkg:deb/ubuntu/x@1?distro=ubuntu-26", "distro_not_recognised"},
		{"pkg:deb/debian/x@1?distro=sid", "distro_not_recognised"},
		{"pkg:apk/alpine/x@1?distro=edge", "distro_not_recognised"},
		{"pkg:deb/ubuntu/x@1?distro=debian-13", "conflicting_distro"},
		{"pkg:deb/debian/x@1?distro=noble", "conflicting_distro"},
		{"pkg:deb/debian/x@1?distro=alpine-3.20", "conflicting_distro"},
		{"pkg:apk/alpine/x@1?distro=ubuntu-26.04", "conflicting_distro"},
		{"pkg:apk/alpine/x@1?distro=noble", "conflicting_distro"},
		{"pkg:deb/debian/foo@2:1.0?distro=debian-13&epoch=1", "conflicting_version"},
		{"pkg:deb/debian/foo@1?distro=debian-13&epoch=x", "invalid_purl"},
		{"pkg:npm/foo%00bar@1", "invalid_purl"},
		{"pkg:deb/debian/foo%00@1?distro=debian-13", "invalid_purl"},
		{"pkg:npm/foo@1%0A", "invalid_purl"},
		// Invalid UTF-8 would make PostgreSQL reject a whole request.
		{"pkg:npm/foo%FF@1", "invalid_purl"},
		{"pkg:npm/foo@1%C0%80", "invalid_purl"},
		{"pkg:deb/debian/foo%FF@1?distro=debian-13", "invalid_purl"},
		{"pkg:npm/foo%EF%BF%BD@1", "invalid_purl"},
		// packageurl-go lower-cases qualifier keys and refuses a repeated key.
		{"pkg:npm/foo@1?Repository_URL=https://r.example", "unsupported_repository"},
		{"pkg:deb/debian/x@1?distro=debian-13&DISTRO=noble", "invalid_purl"},
		// A namespace on a type whose packages have none could name a private package.
		{"pkg:pypi/acme/foo@1", "unsupported_purl_namespace"},
		{"pkg:gem/acme/foo@1", "unsupported_purl_namespace"},
		{"pkg:nuget/acme/foo@1", "unsupported_purl_namespace"},
		{"pkg:pub/acme/foo@1", "unsupported_purl_namespace"},
		// Release numbers are written without leading zeros, and Ubuntu's month has two digits.
		{"pkg:deb/ubuntu/x@1?distro=ubuntu-24.4", "distro_not_recognised"},
		{"pkg:deb/ubuntu/x@1?distro=ubuntu-024.04", "distro_not_recognised"},
		{"pkg:deb/ubuntu/x@1?distro=ubuntu-24.004", "distro_not_recognised"},
		{"pkg:deb/ubuntu/x@1?distro=ubuntu-24.04.1", "distro_not_recognised"},
		{"pkg:deb/debian/x@1?distro=debian-013", "distro_not_recognised"},
		{"pkg:apk/alpine/x@1?distro=03.20", "distro_not_recognised"},
		{"pkg:apk/alpine/x@1?distro=3.020", "distro_not_recognised"},
		{"pkg:apk/alpine/x@1?distro=v3.20", "distro_not_recognised"},
	}
	for _, tt := range tests {
		got, err := FromPurl(tt.in)
		var pe *PurlError
		if !errors.As(err, &pe) {
			t.Errorf("FromPurl(%q) = %+v, %v, want PurlError %q", tt.in, got, err, tt.code)
			continue
		}
		if pe.Code != tt.code {
			t.Errorf("FromPurl(%q) code = %q, want %q", tt.in, pe.Code, tt.code)
		}
		if got != (PurlComponent{}) {
			t.Errorf("FromPurl(%q) returned %+v with an error, want zero value", tt.in, got)
		}
	}
}

func TestPurlErrorMessage(t *testing.T) {
	t.Parallel()
	err := error(&PurlError{Code: "invalid_purl"})
	if got := err.Error(); got != "purl: invalid_purl" {
		t.Errorf("Error() = %q", got)
	}
}

func TestPackageKey(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"pkg:npm/fastify", "npm/fastify"},
		{"pkg:npm/%40Scope/Name", "npm/@scope/name"},
		{"pkg:pypi/friendly--bard", "PyPI/friendly-bard"},
		{"pkg:pypi/Friendly_Bard", "PyPI/friendly-bard"},
		{"pkg:npm/foo?repository_url=https://r.example", ""},
		{"pkg:hex/acme/foo", ""},
		{"pkg:deb/debian/curl?distro=debian-13", ""},
		{"pkg:apk/alpine/musl?distro=3.20", ""},
		{"pkg:npm/foo%FF", ""},
		{"not a purl", ""},
		{"", ""},
		{"pkg:npm/" + strings.Repeat("a", 8000), ""},
	}
	for _, tt := range tests {
		if got := PackageKey(tt.in); got != tt.want {
			t.Errorf("PackageKey(%.60q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPackageKeyLengthLimit(t *testing.T) {
	t.Parallel()
	// "npm/" is 4 bytes, so a name of maxPackageKeyBytes-4 bytes is the longest kept.
	longest := strings.Repeat("a", maxPackageKeyBytes-4)
	if got := PackageKey("pkg:npm/" + longest); got != "npm/"+longest {
		t.Errorf("PackageKey at the limit = %d bytes, want %d", len(got), maxPackageKeyBytes)
	}
	if got := PackageKey("pkg:npm/" + longest + "a"); got != "" {
		t.Errorf("PackageKey over the limit = %d bytes, want empty", len(got))
	}
}

func TestPackageKeyFor(t *testing.T) {
	t.Parallel()
	tests := []struct{ eco, name, want string }{
		{"PyPI", "friendly.bard", "PyPI/friendly-bard"},
		{"npm", "Fastify", "npm/fastify"},
		{"Maven", "org.Apache:Log4j", "Maven/org.apache:log4j"},
	}
	for _, tt := range tests {
		if got := PackageKeyFor(tt.eco, tt.name); got != tt.want {
			t.Errorf("PackageKeyFor(%q, %q) = %q, want %q", tt.eco, tt.name, got, tt.want)
		}
	}
}

func TestIsDistro(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"Debian:13", "Debian", "Ubuntu:26.04:LTS", "Wolfi", "Red Hat:x", "Alpine:v3.20"} {
		if !IsDistro(v) {
			t.Errorf("IsDistro(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"npm", "Packagist:x", "Root:x", "PyPI", ""} {
		if IsDistro(v) {
			t.Errorf("IsDistro(%q) = true, want false", v)
		}
	}
}

func TestNeedsRelease(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"Debian", "Ubuntu", "Alpine", "Red Hat"} {
		if !NeedsRelease(v) {
			t.Errorf("NeedsRelease(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"Debian:13", "Wolfi", "npm", "Packagist", "Root", ""} {
		if NeedsRelease(v) {
			t.Errorf("NeedsRelease(%q) = true, want false", v)
		}
	}
}

// TestDistrosAreCanonicalNames keeps the distro list inside the canonical vocabulary,
// so a misspelt entry cannot silently fail to mark a distribution.
func TestDistrosAreCanonicalNames(t *testing.T) {
	t.Parallel()
	for name := range distros {
		if !Valid(name) {
			t.Errorf("distros holds %q, which is not a canonical ecosystem name", name)
		}
	}
}
