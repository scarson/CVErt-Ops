// ABOUTME: Maps package URLs to canonical ecosystems, package names and versions.
// ABOUTME: Requests and stored CNA package identities share this mapping, so one package has one identity.
package ecosystem

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"

	packageurl "github.com/package-url/packageurl-go"
)

// PurlError carries a stable code that the check endpoint returns as error.code.
type PurlError struct {
	Code string
}

func (e *PurlError) Error() string { return "purl: " + e.Code }

func purlError(code string) error { return &PurlError{Code: code} }

// PurlComponent is what a package URL identifies. Version is empty when the
// purl has none, as stored CNA package URLs do not.
type PurlComponent struct {
	Ecosystem string
	Name      string
	Version   string
}

var purlEcosystems = map[string]string{
	"npm": "npm", "pypi": "PyPI", "golang": "Go", "maven": "Maven", "cargo": "crates.io",
	"gem": "RubyGems", "nuget": "NuGet", "hex": "Hex", "pub": "Pub", "composer": "Packagist",
}

// distroCodenames holds releases that OSV's purls and the purl specification name
// by codename. An unlisted codename is refused, never guessed.
var distroCodenames = map[string]struct{ family, ecosystem string }{
	"bullseye": {"debian", "Debian:11"},
	"bookworm": {"debian", "Debian:12"},
	"trixie":   {"debian", "Debian:13"},
	"jammy":    {"ubuntu", "Ubuntu:22.04:LTS"},
	"noble":    {"ubuntu", "Ubuntu:24.04:LTS"},
	"plucky":   {"ubuntu", "Ubuntu:25.04"},
	"questing": {"ubuntu", "Ubuntu:25.10"},
	"resolute": {"ubuntu", "Ubuntu:26.04:LTS"},
}

var (
	debDistro    = regexp.MustCompile(`^(ubuntu|debian)-([0-9]+)(?:\.([0-9]+))?$`)
	alpineDistro = regexp.MustCompile(`^(?:alpine-)?([0-9]+)\.([0-9]+)(?:\.[0-9]+)?$`)
	allDigits    = regexp.MustCompile(`^[0-9]+$`)
	leadingEpoch = regexp.MustCompile(`^([0-9]+):`)
)

// FromPurl resolves a package URL. A purl that could name a package the public
// registry does not hold is refused rather than mapped to the public name.
func FromPurl(raw string) (PurlComponent, error) {
	p, err := packageurl.FromString(raw)
	if err != nil || p.Subpath != "" {
		return PurlComponent{}, purlError("invalid_purl")
	}
	qualifiers := p.Qualifiers.Map()
	if _, ok := qualifiers["repository_url"]; ok {
		return PurlComponent{}, purlError("unsupported_repository")
	}

	switch p.Type {
	case "deb":
		eco, err := debEcosystem(p.Namespace, qualifiers["distro"])
		if err != nil {
			return PurlComponent{}, err
		}
		version, err := applyEpoch(p.Version, qualifiers["epoch"])
		if err != nil {
			return PurlComponent{}, err
		}
		return validated(PurlComponent{Ecosystem: eco, Name: p.Name, Version: version})
	case "apk":
		eco, err := alpineEcosystem(p.Namespace, qualifiers["distro"])
		if err != nil {
			return PurlComponent{}, err
		}
		return validated(PurlComponent{Ecosystem: eco, Name: p.Name, Version: p.Version})
	}

	eco, ok := purlEcosystems[p.Type]
	if !ok {
		return PurlComponent{}, purlError("unsupported_purl_type")
	}
	name, err := joinPurlName(p.Type, p.Namespace, p.Name)
	if err != nil {
		return PurlComponent{}, err
	}
	return validated(PurlComponent{Ecosystem: eco, Name: name, Version: p.Version})
}

// validated refuses control characters, which percent-decoding can produce. PostgreSQL
// rejects NUL in text and in jsonb, so a stored one would fail the whole CVE's merge.
func validated(c PurlComponent) (PurlComponent, error) {
	if strings.ContainsFunc(c.Name+c.Version, unicode.IsControl) {
		return PurlComponent{}, purlError("invalid_purl")
	}
	return c, nil
}

func joinPurlName(purlType, namespace, name string) (string, error) {
	switch purlType {
	case "npm", "golang":
		if namespace == "" {
			return name, nil
		}
		return namespace + "/" + name, nil
	case "maven":
		if namespace == "" {
			return "", purlError("invalid_purl")
		}
		return namespace + ":" + name, nil
	case "composer":
		if namespace == "" {
			return "", purlError("invalid_purl")
		}
		return namespace + "/" + name, nil
	}
	if namespace != "" {
		return "", purlError("unsupported_purl_namespace")
	}
	return name, nil
}

func debEcosystem(namespace, distro string) (string, error) {
	if namespace != "debian" && namespace != "ubuntu" {
		return "", purlError("unsupported_purl_namespace")
	}
	if distro == "" {
		return "", purlError("distro_required")
	}
	if named, ok := distroCodenames[distro]; ok {
		if named.family != namespace {
			return "", purlError("conflicting_distro")
		}
		return named.ecosystem, nil
	}
	if strings.HasPrefix(distro, "alpine-") {
		return "", purlError("conflicting_distro")
	}
	m := debDistro.FindStringSubmatch(distro)
	if m == nil {
		return "", purlError("distro_not_recognised")
	}
	family, major, minor := m[1], m[2], m[3]
	if family != namespace {
		return "", purlError("conflicting_distro")
	}
	if family == "debian" {
		return "Debian:" + major, nil
	}
	if minor == "" {
		return "", purlError("distro_not_recognised")
	}
	eco := "Ubuntu:" + major + "." + minor
	if year, err := strconv.Atoi(major); err == nil && year%2 == 0 && minor == "04" {
		eco += ":LTS"
	}
	return eco, nil
}

func alpineEcosystem(namespace, distro string) (string, error) {
	if namespace != "alpine" {
		return "", purlError("unsupported_purl_namespace")
	}
	if distro == "" {
		return "", purlError("distro_required")
	}
	if _, named := distroCodenames[distro]; named || debDistro.MatchString(distro) {
		return "", purlError("conflicting_distro")
	}
	m := alpineDistro.FindStringSubmatch(distro)
	if m == nil {
		return "", purlError("distro_not_recognised")
	}
	return "Alpine:v" + m[1] + "." + m[2], nil
}

func applyEpoch(version, epoch string) (string, error) {
	if epoch == "" {
		return version, nil
	}
	if !allDigits.MatchString(epoch) {
		return "", purlError("invalid_purl")
	}
	if m := leadingEpoch.FindStringSubmatch(version); m != nil {
		if strings.TrimLeft(m[1], "0") != strings.TrimLeft(epoch, "0") {
			return "", purlError("conflicting_version")
		}
		return version, nil
	}
	if version == "" {
		return "", nil
	}
	return epoch + ":" + version, nil
}

// maxPackageKeyBytes keeps a stored key under the btree row limit. Upstream URLs
// have no length bound, and a key over the limit would fail the merge of the whole
// CVE. Any key a request can form is shorter: 64 characters of ecosystem and 512
// of name.
const maxPackageKeyBytes = 2600

// PackageKey returns the stored identity of a CNA package URL, or "" when the URL
// is refused, is too long to index, or names a distro package, whose CNA data
// describes upstream.
func PackageKey(raw string) string {
	c, err := FromPurl(raw)
	if err != nil || IsDistro(c.Ecosystem) {
		return ""
	}
	key := PackageKeyFor(c.Ecosystem, c.Name)
	if len(key) > maxPackageKeyBytes {
		return ""
	}
	return key
}

// PackageKeyFor returns the identity a package item looks up.
func PackageKeyFor(ecosystem, name string) string {
	return ecosystem + "/" + FoldPackageName(ecosystem, name)
}
