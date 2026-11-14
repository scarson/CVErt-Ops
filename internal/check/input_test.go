// ABOUTME: Tests parsing of version check request items into packages, products and versions.
// ABOUTME: Covers each form, each error code, the field limits, the CPE rules and the order of checks.
package check

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// atLength builds prefix + padding + suffix with exactly n runes, padding with pad.
func atLength(t *testing.T, prefix, pad, suffix string, n int) string {
	t.Helper()
	fixed := len([]rune(prefix)) + len([]rune(suffix))
	if n < fixed {
		t.Fatalf("atLength: %d runes cannot hold the fixed parts (%d)", n, fixed)
	}
	return prefix + strings.Repeat(pad, n-fixed) + suffix
}

func TestParseItemAccepts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  RawItem
		want Item
	}{
		// Package form.
		{"ecosystem form", RawItem{ID: "web", Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
			Item{ID: "web", Package: &PackageRef{Ecosystem: "npm", Name: "lodash"}, Version: "4.17.20"}},
		{"distro ecosystem with a release", RawItem{Ecosystem: "Debian:13", Name: "curl", Version: "8.0"},
			Item{Package: &PackageRef{Ecosystem: "Debian:13", Name: "curl"}, Version: "8.0"}},
		{"name kept as given, folding happens at lookup", RawItem{Ecosystem: "PyPI", Name: "Django_Foo", Version: "1.0"},
			Item{Package: &PackageRef{Ecosystem: "PyPI", Name: "Django_Foo"}, Version: "1.0"}},
		{"v kept in package form", RawItem{Ecosystem: "Go", Name: "github.com/foo/bar", Version: "v1.2.3"},
			Item{Package: &PackageRef{Ecosystem: "Go", Name: "github.com/foo/bar"}, Version: "v1.2.3"}},

		// Purl form.
		{"purl with distro", RawItem{Purl: "pkg:deb/ubuntu/php8.5@8.5.4-0ubuntu1.4?distro=ubuntu-26.04"},
			Item{Package: &PackageRef{Ecosystem: "Ubuntu:26.04:LTS", Name: "php8.5"}, Version: "8.5.4-0ubuntu1.4"}},
		{"purl npm scoped", RawItem{Purl: "pkg:npm/%40scope/name@1.0.0"},
			Item{Package: &PackageRef{Ecosystem: "npm", Name: "@scope/name"}, Version: "1.0.0"}},
		{"v kept in purl form", RawItem{Purl: "pkg:golang/github.com/foo/bar@v1.2.3"},
			Item{Package: &PackageRef{Ecosystem: "Go", Name: "github.com/foo/bar"}, Version: "v1.2.3"}},
		{"purl epoch prepended", RawItem{Purl: "pkg:deb/debian/foo@1.0?distro=debian-13&epoch=2"},
			Item{Package: &PackageRef{Ecosystem: "Debian:13", Name: "foo"}, Version: "2:1.0"}},
		{"purl with an ignored qualifier", RawItem{Purl: "pkg:npm/foo@1.0.0?arch=x64"},
			Item{Package: &PackageRef{Ecosystem: "npm", Name: "foo"}, Version: "1.0.0"}},

		// CPE form.
		{"cpe with version field", RawItem{ID: "runner-node", CPE: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", Version: "24.22.0"},
			Item{ID: "runner-node", Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "24.22.0"}},
		{"cpe own version used", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:24.22.0:*:*:*:*:*:*:*"},
			Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "24.22.0"}},
		{"cpe own version equal to version field", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:24.22.0:*:*:*:*:*:*:*", Version: "24.22.0"},
			Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "24.22.0"}},
		{"cpe version dash with version field", RawItem{CPE: "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*", Version: "6.1"},
			Item{Product: &ProductRef{Part: "o", Vendor: "linux", Product: "linux_kernel"}, Version: "6.1"}},
		{"cpe part h", RawItem{CPE: "cpe:2.3:h:cisco:router:*:*:*:*:*:*:*:*", Version: "1.0"},
			Item{Product: &ProductRef{Part: "h", Vendor: "cisco", Product: "router"}, Version: "1.0"}},
		{"cpe lower-cased", RawItem{CPE: "cpe:2.3:A:NodeJS:Node.JS:*:*:*:*:*:*:*:*", Version: "1.0"},
			Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "1.0"}},
		{"cpe prefix lower-cased", RawItem{CPE: "CPE:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", Version: "1.0"},
			Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "1.0"}},
		{"cpe escaped colon stays in vendor", RawItem{CPE: `cpe:2.3:a:foo\:bar:baz:*:*:*:*:*:*:*:*`, Version: "1.0"},
			Item{Product: &ProductRef{Part: "a", Vendor: `foo\:bar`, Product: "baz"}, Version: "1.0"}},
		{"cpe escaped backslash before colon splits", RawItem{CPE: `cpe:2.3:a:foo\\:bar:*:*:*:*:*:*:*:*`, Version: "1.0"},
			Item{Product: &ProductRef{Part: "a", Vendor: `foo\\`, Product: "bar"}, Version: "1.0"}},
		{"cpe escaped asterisk is a literal vendor", RawItem{CPE: `cpe:2.3:a:\*:bar:*:*:*:*:*:*:*:*`, Version: "1.0"},
			Item{Product: &ProductRef{Part: "a", Vendor: `\*`, Product: "bar"}, Version: "1.0"}},
		// ".", "-" and "_" never need escaping, and NVD writes them bare.
		{"cpe redundant escape of a dot is dropped", RawItem{CPE: `cpe:2.3:a:nodejs:node\.js:*:*:*:*:*:*:*:*`, Version: "1.0"},
			Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "1.0"}},
		{"cpe redundant escapes of dash and underscore are dropped", RawItem{CPE: `cpe:2.3:a:a\-b\_c:d\-e\_f:*:*:*:*:*:*:*:*`, Version: "1.0"},
			Item{Product: &ProductRef{Part: "a", Vendor: "a-b_c", Product: "d-e_f"}, Version: "1.0"}},
		{"cpe escaped backslash before a dot is kept", RawItem{CPE: `cpe:2.3:a:foo\\.bar:baz:*:*:*:*:*:*:*:*`, Version: "1.0"},
			Item{Product: &ProductRef{Part: "a", Vendor: `foo\\.bar`, Product: "baz"}, Version: "1.0"}},
		{"cpe other escapes are kept with a redundant one dropped", RawItem{CPE: `cpe:2.3:a:foo\!bar:a\.b\:c:*:*:*:*:*:*:*:*`, Version: "1.0"},
			Item{Product: &ProductRef{Part: "a", Vendor: `foo\!bar`, Product: `a.b\:c`}, Version: "1.0"}},
		{"cpe form strips v in version field", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", Version: "v24.22.0"},
			Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "24.22.0"}},
		{"cpe form strips V in version field", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", Version: "V24.22.0"},
			Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "24.22.0"}},
		{"cpe form strips v in cpe version", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:v24.22.0:*:*:*:*:*:*:*"},
			Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "24.22.0"}},
		{"cpe form strips V in cpe version", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:V24.22.0:*:*:*:*:*:*:*"},
			Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "24.22.0"}},
		{"cpe version v and version field agree after stripping", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:v24.22.0:*:*:*:*:*:*:*", Version: "24.22.0"},
			Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "24.22.0"}},
		{"cpe form keeps vfoo", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", Version: "vfoo"},
			Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "vfoo"}},
		{"cpe form removes only one v", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", Version: "vv1"},
			Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "vv1"}},
		{"cpe version and version field differ only in case", RawItem{CPE: "cpe:2.3:a:acme:tool:1.0RC1:*:*:*:*:*:*:*", Version: "1.0RC1"},
			Item{Product: &ProductRef{Part: "a", Vendor: "acme", Product: "tool"}, Version: "1.0RC1"}},
		// An update component such as rc1 names a version other than the release,
		// so it is kept with the version and the version is not dotted numbers.
		{"cpe update component kept with the version", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:22.0.0:rc1:*:*:*:*:*:*"},
			Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "22.0.0-rc1"}},
		{"cpe update component kept with the version field", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:*:rc1:*:*:*:*:*:*", Version: "22.0.0"},
			Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "22.0.0-rc1"}},
		{"cpe update dash is no update", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:22.0.0:-:*:*:*:*:*:*"},
			Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}, Version: "22.0.0"}},
		{"cpe escaped plus in product", RawItem{CPE: `cpe:2.3:a:notepad-plus-plus:notepad\+\+:8.6:*:*:*:*:*:*:*`},
			Item{Product: &ProductRef{Part: "a", Vendor: "notepad-plus-plus", Product: `notepad\+\+`}, Version: "8.6"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			want := tt.want
			want.Index = 3
			got := ParseItem(3, tt.raw)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("ParseItem(%+v) =\n  %s\nwant\n  %s", tt.raw, describe(got), describe(want))
			}
		})
	}
}

func TestParseItemRefuses(t *testing.T) {
	t.Parallel()
	const cpe = "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"
	tests := []struct {
		name string
		raw  RawItem
		code string
	}{
		// Forms.
		{"no form", RawItem{}, "invalid_form"},
		{"version alone", RawItem{ID: "x", Version: "1.0"}, "invalid_form"},
		{"purl plus version", RawItem{Purl: "pkg:npm/foo@1.0.0", Version: "1.0.0"}, "invalid_form"},
		{"purl plus ecosystem and name", RawItem{Purl: "pkg:npm/foo@1.0.0", Ecosystem: "npm", Name: "foo"}, "invalid_form"},
		{"purl plus name", RawItem{Purl: "pkg:npm/foo@1.0.0", Name: "foo"}, "invalid_form"},
		{"purl plus cpe", RawItem{Purl: "pkg:npm/foo@1.0.0", CPE: cpe}, "invalid_form"},
		{"ecosystem without name", RawItem{Ecosystem: "npm", Version: "1.0"}, "invalid_form"},
		{"name without ecosystem", RawItem{Name: "lodash", Version: "1.0"}, "invalid_form"},
		{"cpe plus name", RawItem{CPE: cpe, Name: "node", Version: "1.0"}, "invalid_form"},
		{"cpe plus ecosystem and name", RawItem{CPE: cpe, Ecosystem: "npm", Name: "node", Version: "1.0"}, "invalid_form"},

		// Ecosystem form.
		{"misspelt ecosystem", RawItem{Ecosystem: "Debain:13", Name: "curl", Version: "1.0"}, "invalid_ecosystem"},
		{"ecosystem in wrong case", RawItem{Ecosystem: "NPM", Name: "lodash", Version: "1.0"}, "invalid_ecosystem"},
		{"bare Debian", RawItem{Ecosystem: "Debian", Name: "curl", Version: "1.0"}, "ecosystem_release_required"},
		{"bare Ubuntu", RawItem{Ecosystem: "Ubuntu", Name: "curl", Version: "1.0"}, "ecosystem_release_required"},
		{"ecosystem form without version", RawItem{Ecosystem: "npm", Name: "lodash"}, "version_required"},

		// Purl form.
		{"not a purl", RawItem{Purl: "lodash@1.0.0"}, "invalid_purl"},
		{"purl with subpath", RawItem{Purl: "pkg:npm/foo@1#sub"}, "invalid_purl"},
		{"purl type not supported", RawItem{Purl: "pkg:rpm/redhat/foo@1"}, "unsupported_purl_type"},
		{"hex namespace", RawItem{Purl: "pkg:hex/acme/foo@2.3.0"}, "unsupported_purl_namespace"},
		{"repository_url", RawItem{Purl: "pkg:npm/foo@1?repository_url=https://r.example"}, "unsupported_repository"},
		{"download_url", RawItem{Purl: "pkg:npm/foo@1?download_url=https://x/y.tgz"}, "unsupported_repository"},
		{"vcs_url", RawItem{Purl: "pkg:npm/foo@1?vcs_url=git+https://x/y"}, "unsupported_repository"},
		{"download_url key in upper case", RawItem{Purl: "pkg:npm/foo@1?DOWNLOAD_URL=https://x/y.tgz"}, "unsupported_repository"},
		{"deb without distro", RawItem{Purl: "pkg:deb/debian/foo@1"}, "distro_required"},
		{"deb distro not recognised", RawItem{Purl: "pkg:deb/debian/foo@1?distro=sid"}, "distro_not_recognised"},
		{"deb distro of another family", RawItem{Purl: "pkg:deb/ubuntu/foo@1?distro=debian-13"}, "conflicting_distro"},
		{"deb epoch conflicts with version", RawItem{Purl: "pkg:deb/debian/foo@2:1.0?distro=debian-13&epoch=1"}, "conflicting_version"},
		{"purl without version", RawItem{Purl: "pkg:npm/fastify"}, "version_required"},
		{"deb purl with epoch and no version", RawItem{Purl: "pkg:deb/debian/foo?distro=debian-13&epoch=2"}, "version_required"},

		// CPE form.
		{"cpe 2.2 URI", RawItem{CPE: "cpe:/a:nodejs:node.js:24.22.0", Version: "1.0"}, "invalid_cpe"},
		{"cpe wrong version prefix", RawItem{CPE: "cpe:2.2:a:nodejs:node.js:*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		{"cpe 12 components", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		{"cpe 14 components", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		{"cpe escaped colon leaves 12 components", RawItem{CPE: `cpe:2.3:a:foo\:bar:*:*:*:*:*:*:*:*`, Version: "1.0"}, "invalid_cpe"},
		{"cpe part asterisk", RawItem{CPE: "cpe:2.3:*:nodejs:node.js:*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		{"cpe part dash", RawItem{CPE: "cpe:2.3:-:nodejs:node.js:*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		{"cpe part empty", RawItem{CPE: "cpe:2.3::nodejs:node.js:*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		{"cpe part unknown", RawItem{CPE: "cpe:2.3:x:nodejs:node.js:*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		{"cpe vendor asterisk", RawItem{CPE: "cpe:2.3:a:*:node.js:*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		{"cpe vendor dash", RawItem{CPE: "cpe:2.3:a:-:node.js:*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		{"cpe vendor empty", RawItem{CPE: "cpe:2.3:a::node.js:*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		{"cpe product asterisk", RawItem{CPE: "cpe:2.3:a:nodejs:*:*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		{"cpe product dash", RawItem{CPE: "cpe:2.3:a:nodejs:-:*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		{"cpe product empty", RawItem{CPE: "cpe:2.3:a:nodejs::*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		// The escape before "-" is dropped, which would leave the NA value.
		{"cpe vendor escaped dash", RawItem{CPE: `cpe:2.3:a:\-:node.js:*:*:*:*:*:*:*:*`, Version: "1.0"}, "invalid_cpe"},
		{"cpe product escaped dash", RawItem{CPE: `cpe:2.3:a:acme:\-:1.0:*:*:*:*:*:*:*`}, "invalid_cpe"},
		{"cpe non-ASCII vendor", RawItem{CPE: "cpe:2.3:a:ärzte:app:*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		{"cpe space in vendor", RawItem{CPE: "cpe:2.3:a:node js:app:*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		// A CPE 2.3 formatted string escapes every character other than letters,
		// digits, ".", "-", "_" and the wildcards; NVD stores notepad\+\+, so a bare
		// "+" would find no row and read as nothing known.
		{"cpe unescaped plus in product", RawItem{CPE: "cpe:2.3:a:notepad-plus-plus:notepad++:8.6:*:*:*:*:*:*:*"}, "invalid_cpe"},
		{"cpe unescaped bang in vendor", RawItem{CPE: "cpe:2.3:a:foo!bar:app:*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_cpe"},
		{"cpe version asterisk and no version field", RawItem{CPE: cpe}, "version_required"},
		{"cpe version dash and no version field", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:-:*:*:*:*:*:*:*"}, "version_required"},
		{"cpe version empty and no version field", RawItem{CPE: "cpe:2.3:a:nodejs:node.js::*:*:*:*:*:*:*"}, "version_required"},
		{"cpe version and version field differ", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:24.22.0:*:*:*:*:*:*:*", Version: "24.22.1"}, "conflicting_version"},
		{"cpe version and version field differ after stripping v", RawItem{CPE: "cpe:2.3:a:nodejs:node.js:v24.22.0:*:*:*:*:*:*:*", Version: "v24.22.1"}, "conflicting_version"},

		// Control characters and invalid UTF-8, in every field.
		{"NUL in id", RawItem{ID: "a\x00b", Ecosystem: "npm", Name: "lodash", Version: "1.0"}, "invalid_characters"},
		{"NUL in name", RawItem{Ecosystem: "npm", Name: "lo\x00dash", Version: "1.0"}, "invalid_characters"},
		{"NUL in ecosystem", RawItem{Ecosystem: "npm\x00", Name: "lodash", Version: "1.0"}, "invalid_characters"},
		{"NUL in version", RawItem{Ecosystem: "npm", Name: "lodash", Version: "1.0\x00"}, "invalid_characters"},
		{"NUL in cpe", RawItem{CPE: "cpe:2.3:a:nodejs:node.js\x00:*:*:*:*:*:*:*:*", Version: "1.0"}, "invalid_characters"},
		{"NUL in purl", RawItem{Purl: "pkg:npm/foo\x00@1.0.0"}, "invalid_characters"},
		{"newline in name", RawItem{Ecosystem: "npm", Name: "lodash\n", Version: "1.0"}, "invalid_characters"},
		{"DEL in version", RawItem{Ecosystem: "npm", Name: "lodash", Version: "1.0\x7f"}, "invalid_characters"},
		{"C1 control in name", RawItem{Ecosystem: "npm", Name: "lodash\u0085", Version: "1.0"}, "invalid_characters"},
		{"invalid UTF-8 in name", RawItem{Ecosystem: "npm", Name: "lodash\xff", Version: "1.0"}, "invalid_characters"},

		// Field checks come before the form.
		{"control character before form", RawItem{Version: "1\x00"}, "invalid_characters"},
		{"length before form", RawItem{Purl: "pkg:npm/foo@1.0.0", Version: strings.Repeat("1", 257)}, "value_too_long"},
		{"length before ecosystem", RawItem{Ecosystem: "Debain:13", Name: strings.Repeat("a", 513), Version: "1.0"}, "value_too_long"},
		{"control character before cpe rules", RawItem{CPE: "cpe:2.3:a\x00", Version: "1.0"}, "invalid_characters"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ParseItem(7, tt.raw)
			assertRefused(t, got, 7, tt.code)
		})
	}
}

func TestParseItemLimits(t *testing.T) {
	t.Parallel()
	const cpePrefix, cpeSuffix = "cpe:2.3:a:", ":product:1.0:*:*:*:*:*:*:*"
	type limitCase struct {
		name string
		raw  func(n int) RawItem
		max  int
	}
	tests := []limitCase{
		{"purl", func(n int) RawItem { return RawItem{Purl: atLength(t, "pkg:npm/", "a", "@1.0.0", n)} }, 1024},
		{"cpe", func(n int) RawItem { return RawItem{CPE: atLength(t, cpePrefix, "a", cpeSuffix, n)} }, 512},
		// Multi-byte runes show the limits count characters, not bytes.
		{"name", func(n int) RawItem {
			return RawItem{Ecosystem: "npm", Name: strings.Repeat("é", n), Version: "1.0"}
		}, 512},
		{"version", func(n int) RawItem {
			return RawItem{Ecosystem: "npm", Name: "lodash", Version: strings.Repeat("1", n)}
		}, 256},
		{"id", func(n int) RawItem {
			return RawItem{ID: strings.Repeat("é", n), Ecosystem: "npm", Name: "lodash", Version: "1.0"}
		}, 128},
	}
	for _, tt := range tests {
		t.Run(tt.name+" at limit", func(t *testing.T) {
			t.Parallel()
			raw := tt.raw(tt.max)
			got := ParseItem(0, raw)
			if got.Error != nil {
				t.Fatalf("at %d characters: got error %q, want accepted", tt.max, got.Error.Code)
			}
		})
		t.Run(tt.name+" over limit", func(t *testing.T) {
			t.Parallel()
			got := ParseItem(0, tt.raw(tt.max+1))
			assertRefused(t, got, 0, "value_too_long")
		})
	}
}

func TestParseItemID(t *testing.T) {
	t.Parallel()
	t.Run("echoed on an invalid item", func(t *testing.T) {
		t.Parallel()
		got := ParseItem(2, RawItem{ID: "runner-node", Ecosystem: "Debain:13", Name: "curl", Version: "1.0"})
		if got.ID != "runner-node" || got.Index != 2 {
			t.Errorf("got ID %q Index %d, want runner-node and 2", got.ID, got.Index)
		}
	})
	t.Run("too long is not echoed", func(t *testing.T) {
		t.Parallel()
		got := ParseItem(2, RawItem{ID: strings.Repeat("a", 129), Ecosystem: "npm", Name: "lodash", Version: "1.0"})
		if got.ID != "" {
			t.Errorf("got ID %q, want it not echoed", got.ID)
		}
	})
	t.Run("control character is not echoed", func(t *testing.T) {
		t.Parallel()
		got := ParseItem(2, RawItem{ID: "a\x00", Ecosystem: "npm", Name: "lodash", Version: "1.0"})
		if got.ID != "" {
			t.Errorf("got ID %q, want it not echoed", got.ID)
		}
	})
	t.Run("echoed when another field is too long", func(t *testing.T) {
		t.Parallel()
		got := ParseItem(2, RawItem{ID: "web", Ecosystem: "npm", Name: "lodash", Version: strings.Repeat("1", 257)})
		if got.ID != "web" {
			t.Errorf("got ID %q, want web", got.ID)
		}
	})
}

// Every error code in design section 11 has a fixed message, and a message never
// repeats the caller's input.
func TestItemErrorMessages(t *testing.T) {
	t.Parallel()
	codes := []string{
		"invalid_form", "invalid_ecosystem", "ecosystem_release_required", "invalid_purl",
		"unsupported_purl_type", "unsupported_purl_namespace", "unsupported_repository",
		"distro_required", "distro_not_recognised", "conflicting_distro", "invalid_cpe",
		"version_required", "conflicting_version", "value_too_long", "invalid_characters",
	}
	if len(itemErrorMessages) != len(codes) {
		t.Errorf("itemErrorMessages has %d codes, want %d", len(itemErrorMessages), len(codes))
	}
	for _, code := range codes {
		if itemErrorMessages[code] == "" {
			t.Errorf("code %q has no message", code)
		}
	}

	raw := RawItem{ID: "secret-id", Ecosystem: "Debain:13", Name: "secret-name", Version: "9.9.9-secret"}
	got := ParseItem(0, raw)
	for _, s := range []string{raw.ID, raw.Ecosystem, raw.Name, raw.Version} {
		if got.Error == nil || strings.Contains(got.Error.Message, s) {
			t.Errorf("message %+v repeats input %q", got.Error, s)
		}
	}
}

func TestSplitCPE(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want []string
	}{
		{"a:b:c", []string{"a", "b", "c"}},
		{`a\:b:c`, []string{`a\:b`, "c"}},
		{`a\\:b`, []string{`a\\`, "b"}},
		{`a\\\:b`, []string{`a\\\:b`}},
		{`a\`, []string{`a\`}},
		{"::", []string{"", "", ""}},
		{"", []string{""}},
		{"cpe:2.3:a:nodejs:node.js:24.22.0:*:*:*:*:*:*:*",
			[]string{"cpe", "2.3", "a", "nodejs", "node.js", "24.22.0", "*", "*", "*", "*", "*", "*", "*"}},
	}
	for _, tt := range tests {
		if got := splitCPE(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("splitCPE(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// productValueAsCPE is a rule's product value placed in a full CPE 2.3 name, as
// the version check endpoint would receive it.
func productValueAsCPE(v string) RawItem {
	return RawItem{CPE: "cpe:2.3:a:" + v + ":1.0:*:*:*:*:*:*:*"}
}

func TestParseProductValueAccepts(t *testing.T) {
	t.Parallel()
	long := atLength(t, "acme:", "x", "", 255)
	tests := []struct {
		raw  string
		want ProductRef
	}{
		{"nodejs:node.js", ProductRef{Vendor: "nodejs", Product: "node.js"}},
		{"NodeJS:Node.JS", ProductRef{Vendor: "nodejs", Product: "node.js"}},
		{`nodejs:node\.js`, ProductRef{Vendor: "nodejs", Product: "node.js"}},
		{`1und1:1\&1_online_storage`, ProductRef{Vendor: "1und1", Product: `1\&1_online_storage`}},
		{"microsoft:.net", ProductRef{Vendor: "microsoft", Product: ".net"}},
		{"f5:nginx_open_source", ProductRef{Vendor: "f5", Product: "nginx_open_source"}},
		{`notepad-plus-plus:notepad\+\+`, ProductRef{Vendor: "notepad-plus-plus", Product: `notepad\+\+`}},
		{long, ProductRef{Vendor: "acme", Product: strings.Repeat("x", 250)}},
		// An escaped wildcard is a literal character, and an escaped backslash
		// at the end escapes nothing after it.
		{`nodejs:node\*`, ProductRef{Vendor: "nodejs", Product: `node\*`}},
		{`nodejs:node.js\\`, ProductRef{Vendor: "nodejs", Product: `node.js\\`}},
	}
	for _, tt := range tests {
		got, err := ParseProductValue(tt.raw)
		if err != nil {
			t.Errorf("ParseProductValue(%q) error %q, want %+v", tt.raw, err, tt.want)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseProductValue(%q) = %+v, want %+v", tt.raw, got, tt.want)
		}
		// Design section 3.1: every product a rule accepts, the check accepts too.
		if item := ParseItem(0, productValueAsCPE(tt.raw)); item.Error != nil {
			t.Errorf("the check refuses accepted value %q: %+v", tt.raw, *item.Error)
		}
	}
}

func TestParseProductValueRefuses(t *testing.T) {
	t.Parallel()
	const (
		tooLong    = "value must not exceed 255 characters"
		notASCII   = "value must be printable ASCII with no spaces, as a CPE 2.3 name is"
		notPair    = `value must be "vendor:product", the vendor and product of a CPE 2.3 name, for example "nodejs:node.js"`
		notLiteral = `vendor and product must be literal names, not "*", "-" or a pattern with "*" or "?"`
		backslash  = "vendor and product must not end in an unescaped backslash"
	)
	kelvin := "nodejs:" + string(rune(0x212A)) + "node"
	tests := []struct {
		raw  string
		want string
		// checkAccepts is what the version check does with the value in a full
		// CPE. The rule refuses unescaped "*" and "?" that the check accepts
		// (design section 3.1); every other refusal here the check makes too,
		// except the length, whose limit there is the whole CPE's.
		checkAccepts bool
	}{
		{atLength(t, "acme:", "x", "", 256), tooLong, true},
		{kelvin, notASCII, false},
		{"nodejs node.js", notASCII, false},
		{" ", notASCII, false},
		{"", notPair, false},
		{"nodejs", notPair, false},
		{"a:b:c", notPair, false},
		{":node.js", notPair, false},
		{"nodejs:", notPair, false},
		{"*:node.js", notLiteral, false},
		{"nodejs:-", notLiteral, false},
		{"nodejs:node*", notLiteral, true},
		{"nodejs:no?de", notLiteral, true},
		{`nodejs:\-`, notLiteral, false},
		{`nodejs:node.js\`, backslash, false},
		{"notepad-plus-plus:notepad++",
			`character "+" must be escaped with a backslash, as NVD writes CPE names (for example "notepad\+\+")`, false},
	}
	for _, tt := range tests {
		got, err := ParseProductValue(tt.raw)
		if err == nil {
			t.Errorf("ParseProductValue(%q) = %+v, want error %q", tt.raw, got, tt.want)
		} else if err.Error() != tt.want {
			t.Errorf("ParseProductValue(%q) error %q, want %q", tt.raw, err, tt.want)
		}
		item := ParseItem(0, productValueAsCPE(tt.raw))
		if accepted := item.Error == nil; accepted != tt.checkAccepts {
			t.Errorf("the check on %q: accepted %v, want %v (%s)", tt.raw, accepted, tt.checkAccepts, describe(item))
		}
		if !tt.checkAccepts && item.Error != nil && item.Error.Code != "invalid_cpe" {
			t.Errorf("the check refuses %q with %q, want invalid_cpe", tt.raw, item.Error.Code)
		}
	}
}

func assertRefused(t *testing.T, got Item, index int, code string) {
	t.Helper()
	if got.Error == nil {
		t.Fatalf("got %s, want error %q", describe(got), code)
	}
	if got.Error.Code != code {
		t.Errorf("got error %q, want %q", got.Error.Code, code)
	}
	if got.Error.Message == "" {
		t.Errorf("error %q has no message", got.Error.Code)
	}
	if got.Index != index {
		t.Errorf("got Index %d, want %d", got.Index, index)
	}
	if got.Package != nil || got.Product != nil || got.Version != "" {
		t.Errorf("refused item carries a component: %s", describe(got))
	}
}

// describe prints an Item with its pointer fields followed, for failure messages.
func describe(it Item) string {
	s := fmt.Sprintf("{Index:%d ID:%q Version:%q", it.Index, it.ID, it.Version)
	if it.Package != nil {
		s += fmt.Sprintf(" Package:%+v", *it.Package)
	}
	if it.Product != nil {
		s += fmt.Sprintf(" Product:%+v", *it.Product)
	}
	if it.Error != nil {
		s += fmt.Sprintf(" Error:%+v", *it.Error)
	}
	return s + "}"
}
