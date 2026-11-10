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
	// CPEs are the CPE "vendor:product" keys, as ProductRef holds them, that
	// name one product. A CPE item reads the NVD rows under each of them.
	CPEs     []string
	Names    []CNAName
	Fragment string // product-name fragment for the nearby-name check
	Vendor   string // CNA vendor for the nearby-name check
}

// cnaTable is design section 4.5's table: further CNA names for CPE products
// whose CNA records spell the vendor or product differently. CPEs are lower
// case with escapes as written, and every name is lower case. A row with two
// CPE spellings treats them as one product, so an item under either reads NVD
// rows under both: older nginx CVEs are under nginx:nginx only.
var cnaTable = []cnaMapping{
	{
		CPEs:     []string{"nodejs:node.js"},
		Names:    []CNAName{{Vendor: "nodejs", Product: "node"}, {Vendor: "nodejs", Product: "nodejs"}},
		Fragment: "node", Vendor: "nodejs",
	},
	{CPEs: []string{"php:php"}, Names: []CNAName{{Vendor: "php group", Product: "php"}}, Fragment: "php", Vendor: "php group"},
	{
		CPEs: []string{"f5:nginx", "nginx:nginx"},
		// nginx / nginx is the spelling of CVE-2017-7529 (design section 2).
		Names: []CNAName{
			{Vendor: "f5", Product: "nginx open source"}, {Vendor: "f5", Product: "nginx"}, {Vendor: "nginx", Product: "nginx"},
		},
		Fragment: "nginx", Vendor: "f5",
	},
	{
		CPEs: []string{"microsoft:.net", "microsoft:.net_core"},
		// The prefix holds every major's spelling: ".NET 6.0", ".NET 9.0 runtime".
		Names:    []CNAName{{Vendor: "microsoft", Product: ".net ", Prefix: true}},
		Fragment: ".net", Vendor: "microsoft",
	},
	{
		CPEs:     []string{"postgresql:postgresql"},
		Names:    []CNAName{{Vendor: "n/a", Product: "postgresql"}},
		Fragment: "postgresql", Vendor: "n/a",
	},
	{
		CPEs:     []string{"python:python"},
		Names:    []CNAName{{Vendor: "python software foundation", Product: "cpython"}},
		Fragment: "python", Vendor: "python software foundation",
	},
}

// cnaNames finds cnaTable's row for a CPE "vendor:product".
var cnaNames = indexCNATable(cnaTable)

func indexCNATable(table []cnaMapping) map[string]cnaMapping {
	index := map[string]cnaMapping{}
	for _, row := range table {
		for _, cpe := range row.CPEs {
			index[cpe] = row
		}
	}
	return index
}

// NamesFor returns every CNA name to look up: always the CPE's own, plus the
// table's. mapped is true when a table row exists.
//
// The CPE's own name is its vendor and product as plain text: each CPE escape
// becomes the character it quotes, and an unescaped "_" is read as a space. The
// mapping gives the CPE spellings whose NVD rows are the product's, and the
// vendor and name fragment for the nearby-name check: the table's, or with no
// table row the CPE's own. Every name is listed once.
func NamesFor(p ProductRef) (names []CNAName, mapping cnaMapping, mapped bool) {
	ownCPE := p.Vendor + ":" + p.Product
	own := CNAName{Vendor: cnaText(p.Vendor), Product: cnaText(p.Product)}
	names = []CNAName{own}
	row, mapped := cnaNames[ownCPE]
	if !mapped {
		return names, cnaMapping{CPEs: []string{ownCPE}, Fragment: own.Product, Vendor: own.Vendor}, false
	}
	for _, n := range row.Names {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	row.CPEs, row.Names = slices.Clone(row.CPEs), slices.Clone(row.Names)
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
