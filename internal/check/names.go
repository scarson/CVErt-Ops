// ABOUTME: The CNA vendor and product names to look up for a CPE product (design section 4.5).
// ABOUTME: Always the CPE's own name, plus the names a small table adds for products whose CNA spelling differs.
package check

import (
	"slices"
	"strings"
)

// CNAName is one way to find CNA rows for a CPE product.
type CNAName struct {
	Vendor, Product string
	Prefix          bool
}

// Matches reports whether a stored CNA vendor and product carry this name,
// compared in lower case: the vendor equal, and the product equal or, for a
// prefix name, starting with the name's product.
func (n CNAName) Matches(vendor, product string) bool {
	//nolint:staticcheck // SA6005: lower-case equality, as the SQL lookup's lower() compares; EqualFold folds some characters differently, such as U+0130.
	if strings.ToLower(vendor) != strings.ToLower(n.Vendor) {
		return false
	}
	product, want := strings.ToLower(product), strings.ToLower(n.Product)
	if n.Prefix {
		return strings.HasPrefix(product, want)
	}
	return product == want
}

type cnaMapping struct {
	Names    []CNAName
	Fragment string // product-name fragment for the nearby-name check
	Vendor   string // CNA vendor for the nearby-name check
}

var (
	nodeMapping = cnaMapping{
		Names:    []CNAName{{Vendor: "nodejs", Product: "node"}, {Vendor: "nodejs", Product: "nodejs"}},
		Fragment: "node", Vendor: "nodejs",
	}
	nginxMapping = cnaMapping{
		Names:    []CNAName{{Vendor: "f5", Product: "nginx open source"}, {Vendor: "f5", Product: "nginx"}},
		Fragment: "nginx", Vendor: "f5",
	}
	// The prefix holds every major's spelling: ".NET 6.0", ".NET 9.0 runtime".
	dotnetMapping = cnaMapping{
		Names:    []CNAName{{Vendor: "microsoft", Product: ".net ", Prefix: true}},
		Fragment: ".net", Vendor: "microsoft",
	}
)

// cnaNames is design section 4.5's table: further CNA names for CPE products
// whose CNA records spell the vendor or product differently. It is keyed by
// "vendor:product" as ProductRef holds a CPE (lower case, escapes as written),
// and every name is lower case.
var cnaNames = map[string]cnaMapping{
	"nodejs:node.js":        nodeMapping,
	"php:php":               {Names: []CNAName{{Vendor: "php group", Product: "php"}}, Fragment: "php", Vendor: "php group"},
	"f5:nginx":              nginxMapping,
	"nginx:nginx":           nginxMapping,
	"microsoft:.net":        dotnetMapping,
	"microsoft:.net_core":   dotnetMapping,
	"postgresql:postgresql": {Names: []CNAName{{Vendor: "n/a", Product: "postgresql"}}, Fragment: "postgresql", Vendor: "n/a"},
	"python:python": {
		Names:    []CNAName{{Vendor: "python software foundation", Product: "cpython"}},
		Fragment: "python", Vendor: "python software foundation",
	},
}

// NamesFor returns every CNA name to look up: always the CPE's own, plus the
// table's. mapped is true when a table row exists.
//
// The CPE's own name is its vendor and product as plain text: each CPE escape
// becomes the character it quotes, and an unescaped "_" is read as a space. The
// mapping gives the vendor and name fragment for the nearby-name check: the
// table's, or with no table row the CPE's own name. Every name is listed once.
func NamesFor(p ProductRef) (names []CNAName, mapping cnaMapping, mapped bool) {
	own := CNAName{Vendor: cnaText(p.Vendor), Product: cnaText(p.Product)}
	names = []CNAName{own}
	row, mapped := cnaNames[p.Vendor+":"+p.Product]
	if !mapped {
		return names, cnaMapping{Fragment: own.Product, Vendor: own.Vendor}, false
	}
	for _, n := range row.Names {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	row.Names = slices.Clone(row.Names)
	return names, row, true
}

// cnaText turns a CPE vendor or product into the plain text a CNA record uses:
// a backslash and the character after it become that character, and an
// unescaped "_" becomes a space. A trailing lone backslash is kept.
func cnaText(cpeValue string) string {
	var b strings.Builder
	for i := 0; i < len(cpeValue); i++ {
		switch c := cpeValue[i]; {
		case c == '\\' && i+1 < len(cpeValue):
			i++
			b.WriteByte(cpeValue[i])
		case c == '_':
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
