// ABOUTME: Checks package versions using the ordering native to each OSV ecosystem.
// ABOUTME: Gates syntax first, because the comparison library accepts malformed strings.
package version

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

const (
	semverIdentifiers = `[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*`
	semverSuffixes    = `(?:-` + semverIdentifiers + `)?(?:\+` + semverIdentifiers + `)?$`
)

// The patterns below are the only check on syntax. semantic.Parse succeeds for
// nearly any string in most ecosystems and then sorts it above or below every
// real version, so "banana" would compare as a version and could report "not
// affected". For PyPI the same applies to anything outside PEP 440, which it
// keeps as a "legacy" version below all others.
var (
	semverSyntax   = regexp.MustCompile(`^v?[0-9]+(?:\.[0-9]+){0,2}` + semverSuffixes)
	nugetSyntax    = regexp.MustCompile(`^v?[0-9]+(?:\.[0-9]+){0,3}` + semverSuffixes)
	mavenSyntax    = regexp.MustCompile(`^[0-9][0-9A-Za-z._+-]*$`)
	composerSyntax = regexp.MustCompile(`^v?[0-9][0-9A-Za-z._+-]*$`)
	gemSyntax      = regexp.MustCompile(`^[0-9]+(?:\.[0-9A-Za-z]+)*(?:-` + semverIdentifiers + `)?$`)
	dpkgSyntax     = regexp.MustCompile(`^(?:[0-9]+:)?[0-9](?:[0-9A-Za-z.+~-]*[0-9A-Za-z.+~])?$`)
	rpmSyntax      = regexp.MustCompile(`^(?:[0-9]+:)?[0-9](?:[0-9A-Za-z._+~^-]*[0-9A-Za-z._+~^])?$`)
	apkSyntax      = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*[a-z]?(?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)[0-9]*)*(?:-r[0-9]+)?$`)
	// From PEP 440 Appendix B, without the surrounding whitespace it tolerates.
	pep440Syntax = regexp.MustCompile(`(?i)^v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*` +
		`(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?` +
		`(?:-[0-9]+|[-_.]?(?:post|rev|r)[-_.]?[0-9]*)?` +
		`(?:[-_.]?dev[-_.]?[0-9]*)?` +
		`(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)

	// gitCommit matches the commit hashes in OSV ranges of type GIT, which have
	// no version order. One can start with a digit and pass the patterns above.
	gitCommit = regexp.MustCompile(`^[0-9a-f]{40}(?:[0-9a-f]{24})?$`)
)

// ecosystemRule describes one ecosystem. A release suffix is the part of a
// distribution's name after the first colon, such as Ubuntu:26.04:LTS.
type ecosystemRule struct {
	syntax             *regexp.Regexp
	takesReleaseSuffix bool
}

// ecosystems holds every supported ecosystem under its OSV name. Names are
// matched exactly, so GHSA's lower-case spellings such as "pip" are unknown
// until stored names are normalised.
var ecosystems = map[string]ecosystemRule{
	"npm":       {syntax: semverSyntax},
	"Go":        {syntax: semverSyntax},
	"crates.io": {syntax: semverSyntax},
	"Hex":       {syntax: semverSyntax},
	"Pub":       {syntax: semverSyntax},
	"NuGet":     {syntax: nugetSyntax},
	"PyPI":      {syntax: pep440Syntax},
	"Maven":     {syntax: mavenSyntax},
	"Packagist": {syntax: composerSyntax},
	"RubyGems":  {syntax: gemSyntax},
	"Debian":    {syntax: dpkgSyntax, takesReleaseSuffix: true},
	"Ubuntu":    {syntax: dpkgSyntax, takesReleaseSuffix: true},
	"Alpine":    {syntax: apkSyntax, takesReleaseSuffix: true},
	"Red Hat":   {syntax: rpmSyntax, takesReleaseSuffix: true},
}

// Check reports whether version is inside r under the ordering of the named
// OSV ecosystem. The returned error is non-nil exactly when the status is
// CannotEvaluate, and it says why.
func Check(ecosystem, version string, r Range) (Status, error) {
	name, rule, err := lookupEcosystem(ecosystem)
	if err != nil {
		return CannotEvaluate, err
	}

	return scheme{
		valid: func(v string) bool {
			return len(v) <= maxVersionLen && !gitCommit.MatchString(v) && rule.syntax.MatchString(v)
		},
		compare: func(a, b string) (int, error) {
			return compareInEcosystem(name, a, b)
		},
	}.check(version, r)
}

func lookupEcosystem(ecosystem string) (string, ecosystemRule, error) {
	name, suffix, hasSuffix := strings.Cut(ecosystem, ":")

	rule, ok := ecosystems[name]
	if !ok || (hasSuffix && (!rule.takesReleaseSuffix || suffix == "")) {
		return "", ecosystemRule{}, fmt.Errorf("%w: %q", ErrUnknownEcosystem, ecosystem)
	}
	return name, rule, nil
}

func compareInEcosystem(name, a, b string) (int, error) {
	av, err := semantic.Parse(a, name)
	if err != nil {
		return 0, fmt.Errorf("parse %q: %w", a, err)
	}
	bv, err := semantic.Parse(b, name)
	if err != nil {
		return 0, fmt.Errorf("parse %q: %w", b, err)
	}
	return av.Compare(bv)
}
