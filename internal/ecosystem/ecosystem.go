// ABOUTME: The canonical package ecosystem vocabulary, using OSV's names.
// ABOUTME: Validates names from API callers, maps GHSA's spellings, and folds package names for comparison.

// Package ecosystem is the single definition of package ecosystem names. The names
// are those in OSV's ecosystems.txt, because OSV rows are stored as OSV sends them.
package ecosystem

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxValueLen matches the CHECK constraint on watchlist_items.ecosystem.
const maxValueLen = 64

// names holds OSV's ecosystems.txt as of 2026-11-08, without "[EMPTY]" and "GIT",
// which are not values of package.ecosystem.
var names = []string{
	"AlmaLinux", "Alpaquita", "Alpine", "Android", "Azure Linux", "BellSoft Hardened Containers",
	"Bitnami", "CRAN", "Chainguard", "CleanStart", "Debian", "Echo", "GHC", "GSD", "GitHub Actions",
	"Go", "Hackage", "Hex", "Julia", "Linux", "Mageia", "Maven", "MinimOS", "NuGet", "OSS-Fuzz",
	"Packagist", "Pub", "PyPI", "Red Hat", "Red Hat Lightwell", "Rocky Linux", "Root", "RubyGems",
	"SUSE", "SwiftURL", "TuxCare", "UVI", "Ubuntu", "VSCode", "Wolfi", "crates.io", "npm", "opam",
	"openEuler", "openSUSE",
}

// takesSuffix holds the names OSV data uses with a suffix after the first colon,
// usually a release, such as Debian:13 or Ubuntu:26.04:LTS.
var takesSuffix = map[string]bool{
	"AlmaLinux": true, "Alpaquita": true, "Alpine": true, "Azure Linux": true,
	"BellSoft Hardened Containers": true, "Debian": true, "Echo": true, "Mageia": true,
	"Packagist": true, "Red Hat": true, "Red Hat Lightwell": true, "Rocky Linux": true,
	"Root": true, "SUSE": true, "TuxCare": true, "Ubuntu": true, "VSCode": true,
	"openEuler": true, "openSUSE": true,
}

// fromGHSA maps the REST API's package.ecosystem values to canonical names.
var fromGHSA = map[string]string{
	"actions": "GitHub Actions", "composer": "Packagist", "erlang": "Hex", "go": "Go",
	"maven": "Maven", "npm": "npm", "nuget": "NuGet", "pip": "PyPI", "pub": "Pub",
	"rubygems": "RubyGems", "rust": "crates.io", "swift": "SwiftURL",
}

var semverEcosystems = map[string]bool{"npm": true, "Go": true, "crates.io": true, "Hex": true, "Pub": true}

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// Names returns the canonical base names, sorted bytewise.
func Names() []string {
	sorted := slices.Clone(names)
	slices.Sort(sorted)
	return sorted
}

// Valid reports whether value is a canonical base name, or one that takes a suffix
// followed by a colon and a suffix. Matching is exact, including case.
func Valid(value string) bool {
	if value == "" || utf8.RuneCountInString(value) > maxValueLen || strings.ContainsFunc(value, unicode.IsControl) {
		return false
	}
	base, suffix, hasSuffix := strings.Cut(value, ":")
	if !slices.Contains(names, base) {
		return false
	}
	return !hasSuffix || (takesSuffix[base] && suffix != "")
}

// FromGHSA returns the canonical name for a GHSA ecosystem. A name it does not
// know, such as "other", is returned unchanged.
func FromGHSA(name string) string {
	if canonical, ok := fromGHSA[name]; ok {
		return canonical
	}
	return name
}

// FoldPackageName returns the form of name used to compare packages: lower case,
// and for PyPI with runs of separators collapsed as PEP 503 specifies. Stored rows
// keep the upstream spelling; only comparisons use this form.
func FoldPackageName(ecosystem, name string) string {
	folded := strings.ToLower(name)
	if ecosystem == "PyPI" {
		return pypiSeparators.ReplaceAllString(folded, "-")
	}
	return folded
}

// FoldedNameSQL returns a SQL expression that applies FoldPackageName's rule to a
// name column, for queries that compare package names in the database.
func FoldedNameSQL(ecosystemColumn, nameColumn string) string {
	return fmt.Sprintf(`CASE WHEN %s = 'PyPI' THEN regexp_replace(lower(%s), '[-_.]+', '-', 'g') ELSE lower(%s) END`,
		ecosystemColumn, nameColumn, nameColumn)
}

// OrdersBySemver reports whether an ecosystem's native version order is SemVer, so
// an OSV range typed SEMVER and one typed ECOSYSTEM mean the same thing there.
func OrdersBySemver(ecosystem string) bool {
	return semverEcosystems[ecosystem]
}
