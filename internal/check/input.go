// ABOUTME: Parses version check request items into a package or product and a version.
// ABOUTME: Refuses an item with a stable error code so one bad item does not fail the request.
package check

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/scarson/cvert-ops/internal/ecosystem"
)

// Item is one parsed request item. Exactly one of Package or Product is set
// unless Error is.
type Item struct {
	Index   int
	ID      string
	Package *PackageRef
	Product *ProductRef
	Version string
	Error   *ItemError
}

// PackageRef names a package by canonical ecosystem and the name as given. The
// name is folded when lookup keys are built, not here.
type PackageRef struct{ Ecosystem, Name string }

// ProductRef holds lower-cased CPE attributes, as written, with escapes kept
// except the redundant ones dropRedundantEscapes removes.
type ProductRef struct{ Part, Vendor, Product string }

// ItemError is an item's refusal: a stable code from the API's error.code
// enumeration and a fixed sentence that never repeats the caller's input.
type ItemError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// RawItem is the request body's item.
type RawItem struct {
	ID        string `json:"id,omitempty"`
	Purl      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	CPE       string `json:"cpe,omitempty"`
	Version   string `json:"version,omitempty"`
}

// Field limits in characters (design section 3.4). maxVersionLen matches
// internal/version's own limit.
const (
	maxPurlLen    = 1024
	maxCPELen     = 512
	maxNameLen    = 512
	maxVersionLen = 256
	maxIDLen      = 128
)

// cpeComponents is the number of colon-separated components in a CPE 2.3
// formatted string, counting the "cpe" and "2.3" prefixes.
const cpeComponents = 13

var itemErrorMessages = map[string]string{
	"invalid_form":               "An item must hold exactly one of: purl alone, ecosystem with name, or cpe.",
	"invalid_ecosystem":          "The ecosystem is not a recognised OSV ecosystem name.",
	"ecosystem_release_required": "This distribution ecosystem must name a release.",
	"invalid_purl":               "The purl could not be parsed, or has a subpath.",
	"unsupported_purl_type":      "This purl type is not supported; use the ecosystem form.",
	"unsupported_purl_namespace": "This purl type does not take a namespace here, so the package may not be public.",
	"unsupported_repository":     "A purl naming its own repository or download location is not supported.",
	"distro_required":            "This purl type needs a distro qualifier naming the release.",
	"distro_not_recognised":      "The purl's distro qualifier does not name a supported release.",
	"conflicting_distro":         "The purl's distro qualifier names a different distribution from its namespace.",
	"invalid_cpe":                "The cpe must be a CPE 2.3 formatted string with literal part, vendor and product.",
	"version_required":           "The item does not state a version.",
	"conflicting_version":        "The item states two different versions.",
	"value_too_long":             "A field is longer than its limit.",
	"invalid_characters":         "A field contains control characters or invalid UTF-8.",
}

// ParseItem checks one request item and resolves it to a package or product and
// the version to compare. Field lengths and characters are checked first, then the
// form, then the form's own rules.
func ParseItem(index int, raw RawItem) Item {
	item := Item{Index: index}
	if checkField(raw.ID, maxIDLen) == "" {
		item.ID = raw.ID
	}
	fields := []struct {
		value string
		limit int
	}{
		{raw.ID, maxIDLen}, {raw.Purl, maxPurlLen}, {raw.Ecosystem, 0},
		{raw.Name, maxNameLen}, {raw.CPE, maxCPELen}, {raw.Version, maxVersionLen},
	}
	for _, f := range fields {
		if code := checkField(f.value, f.limit); code != "" {
			return refuse(item, code)
		}
	}

	switch {
	case raw.Purl != "":
		if raw.Ecosystem != "" || raw.Name != "" || raw.CPE != "" || raw.Version != "" {
			return refuse(item, "invalid_form")
		}
		return parsePurl(item, raw.Purl)
	case raw.CPE != "":
		if raw.Ecosystem != "" || raw.Name != "" {
			return refuse(item, "invalid_form")
		}
		return parseCPE(item, raw.CPE, raw.Version)
	case raw.Ecosystem != "" && raw.Name != "":
		return parsePackage(item, raw.Ecosystem, raw.Name, raw.Version)
	default:
		return refuse(item, "invalid_form")
	}
}

// checkField returns value_too_long when value has more than limit characters (a
// limit of 0 sets none), and invalid_characters when it holds a control character
// or invalid UTF-8, which PostgreSQL rejects in a query parameter.
func checkField(value string, limit int) string {
	if limit > 0 && utf8.RuneCountInString(value) > limit {
		return "value_too_long"
	}
	if !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
		return "invalid_characters"
	}
	return ""
}

func refuse(item Item, code string) Item {
	return Item{Index: item.Index, ID: item.ID, Error: &ItemError{Code: code, Message: itemErrorMessages[code]}}
}

func parsePackage(item Item, eco, name, version string) Item {
	if !ecosystem.Valid(eco) {
		return refuse(item, "invalid_ecosystem")
	}
	if ecosystem.NeedsRelease(eco) {
		return refuse(item, "ecosystem_release_required")
	}
	if version == "" {
		return refuse(item, "version_required")
	}
	item.Package = &PackageRef{Ecosystem: eco, Name: name}
	item.Version = version
	return item
}

// parsePurl refuses download_url and vcs_url itself: FromPurl also maps stored CNA
// package URLs, which keep their key with these qualifiers because CNA data can
// only condemn a version, while a request answered for the public package could
// get a wrong "not affected" for a private fork.
func parsePurl(item Item, raw string) Item {
	p, err := packageurl.FromString(raw)
	if err != nil {
		return refuse(item, "invalid_purl")
	}
	qualifiers := p.Qualifiers.Map()
	for _, key := range []string{"download_url", "vcs_url"} {
		if _, ok := qualifiers[key]; ok {
			return refuse(item, "unsupported_repository")
		}
	}

	c, err := ecosystem.FromPurl(raw)
	if err != nil {
		var purlErr *ecosystem.PurlError
		if errors.As(err, &purlErr) && itemErrorMessages[purlErr.Code] != "" {
			return refuse(item, purlErr.Code)
		}
		return refuse(item, "invalid_purl")
	}
	if ecosystem.NeedsRelease(c.Ecosystem) {
		return refuse(item, "ecosystem_release_required")
	}
	if c.Version == "" {
		return refuse(item, "version_required")
	}
	item.Package = &PackageRef{Ecosystem: c.Ecosystem, Name: c.Name}
	item.Version = c.Version
	return item
}

// parseCPE reads part, vendor, product and the CPE's own version from a CPE 2.3
// formatted string. The version component counts as stated unless it is "*", "-"
// or empty. Both versions lose one leading "v" or "V" before a digit, because
// node --version prints v24.22.0 and product versions compare as dotted numbers.
//
// A CPE 2.3 formatted string is printable ASCII, so any other character refuses
// the item before lower-casing: Go's strings.ToLower and PostgreSQL's lower(),
// which folds stored CNA names, can disagree outside ASCII, and a key that
// misses its stored rows would read as not affected.
func parseCPE(item Item, raw, version string) Item {
	if strings.ContainsFunc(raw, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		return refuse(item, "invalid_cpe")
	}
	cpe := strings.ToLower(raw)
	if !strings.HasPrefix(cpe, "cpe:2.3:") {
		return refuse(item, "invalid_cpe")
	}
	parts := splitCPE(cpe)
	if len(parts) != cpeComponents {
		return refuse(item, "invalid_cpe")
	}
	part, vendor, product := parts[2], parts[3], parts[4]
	if part != "a" && part != "o" && part != "h" || !literalCPEValue(vendor) || !literalCPEValue(product) {
		return refuse(item, "invalid_cpe")
	}

	stated := stripVersionPrefix(version)
	own := parts[5]
	if own == "*" || own == "-" {
		own = ""
	}
	own = stripVersionPrefix(own)
	switch {
	case stated != "" && own != "" && !strings.EqualFold(stated, own):
		return refuse(item, "conflicting_version")
	case stated == "" && own == "":
		return refuse(item, "version_required")
	case stated == "":
		stated = own
	}
	item.Product = &ProductRef{Part: part, Vendor: dropRedundantEscapes(vendor), Product: dropRedundantEscapes(product)}
	item.Version = stated
	return item
}

func literalCPEValue(v string) bool {
	return v != "" && v != "*" && v != "-"
}

// dropRedundantEscapes removes the backslash before ".", "-" or "_" in a CPE
// value. These never need escaping in a CPE 2.3 formatted string and NVD writes
// them bare, so "node\.js" must read NVD's "node.js" rows and the name table's
// key. Every other escape is kept as written.
func dropRedundantEscapes(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			i++
			if c := v[i]; c != '.' && c != '-' && c != '_' {
				b.WriteByte('\\')
			}
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

// stripVersionPrefix removes one leading "v" or "V" when a digit follows it.
func stripVersionPrefix(v string) string {
	if len(v) >= 2 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}

// splitCPE splits a CPE 2.3 formatted string on its unescaped colons. A backslash
// escapes the character after it, so "foo\:bar" is one value and "foo\\:bar" is
// two. Escapes are kept as written in the returned values.
func splitCPE(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case ':':
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}
