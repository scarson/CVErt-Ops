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
// case and spelled as ProductRef holds them, with no backslash before ".", "-"
// or "_", and every name is lower case. A row with two
// CPE spellings treats them as one product, so an item under either reads NVD
// rows under both: older nginx CVEs are under nginx:nginx only.
var cnaTable = []cnaMapping{
	{
		// NVD files Node 0.6 to 0.10 under nodejs:nodejs.
		CPEs:     []string{"nodejs:node.js", "nodejs:nodejs"},
		Names:    []CNAName{{Vendor: "nodejs", Product: "node"}, {Vendor: "nodejs", Product: "nodejs"}},
		Fragment: "node", Vendor: "nodejs",
	},
	{CPEs: []string{"php:php"}, Names: []CNAName{{Vendor: "php group", Product: "php"}}, Fragment: "php", Vendor: "php group"},
	{
		// NVD files recent nginx CVEs under f5:nginx_open_source.
		CPEs: []string{"f5:nginx", "nginx:nginx", "f5:nginx_open_source"},
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

// otherProducts lists, by CPE "vendor:product", CNA products that a name or a
// nearby name of that CPE would find but that are other products. Such a row is
// neither a name row for an item of the CPE nor a nearby row that blocks it.
// Names are lower case, as CNAName.Matches compares them.
//
//   - The .NET Framework is a separate product from .NET: its versions are 2.x to
//     4.x, and Microsoft lists a ".NET x.0" entry beside it when both are
//     affected. ".NET Framework 4.8" also starts with the .NET prefix.
//   - OpenAPI.NET is a separate library.
//   - Ruby's OpenSSL extension is part of Ruby; NVD files it as ruby-lang:ruby.
//
// ASP.NET Core is not listed: it ships inside the .NET SDK and shared runtime.
var otherProducts = map[string][]CNAName{
	"microsoft:.net":      dotNetOtherProducts,
	"microsoft:.net_core": dotNetOtherProducts,
	"openssl:openssl":     {{Vendor: "openssl", Product: "openssl extension of ruby (git trunk)"}},
}

var dotNetOtherProducts = []CNAName{
	{Vendor: "microsoft", Product: ".net framework", Prefix: true},
	{Vendor: "microsoft", Product: "microsoft .net framework", Prefix: true},
	{Vendor: "microsoft", Product: "openapi.net"},
}

// isOtherProduct reports whether a stored CNA vendor and product is one of
// names, the other products of an item's CPE.
func isOtherProduct(names []CNAName, vendor, product string) bool {
	return slices.ContainsFunc(names, func(n CNAName) bool { return n.Matches(vendor, product) })
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
// table's. cpes are the CPE "vendor:product" spellings whose NVD rows are the
// product's: the table row's, or with no table row the CPE's own. mapped is
// true when a table row exists.
//
// The CPE's own name is its vendor and product as plain text (ownNames). Every
// name is listed once. The nearby-name check's vendors and fragments come from
// nearbyNames.
func NamesFor(p ProductRef) (names []CNAName, cpes []string, mapped bool) {
	ownCPE := p.Vendor + ":" + p.Product
	names = ownNames(p)
	row, mapped := cnaNames[ownCPE]
	if !mapped {
		return names, []string{ownCPE}, false
	}
	for _, n := range row.Names {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return names, slices.Clone(row.CPEs), true
}

// nearbyNames returns the vendors and name fragments of the nearby-name check
// (design section 4.5), each as a CNAName whose Product is the fragment: the
// table's for a CPE with a table row, otherwise the CPE's own names.
func nearbyNames(p ProductRef) []CNAName {
	if row, ok := cnaNames[p.Vendor+":"+p.Product]; ok {
		return []CNAName{{Vendor: row.Vendor, Product: row.Fragment}}
	}
	return ownNames(p)
}

// ownNames returns the CPE's own vendor and product as plain text: each CPE
// escape becomes the character it quotes, and an unescaped "_" is read as a
// space. When the CPE holds an unescaped "_", the names with "_" kept follow,
// because some CNAs write the vendor or product as the CPE does. Each spelling
// of the vendor ("_" as a space, then kept) is paired with each spelling of the
// product in the same order, so a CNA that reads one "_" as a space and keeps
// the other is found too. Each name is listed once.
func ownNames(p ProductRef) []CNAName {
	var names []CNAName
	for _, vendor := range []string{cnaText(p.Vendor, ' '), cnaText(p.Vendor, '_')} {
		for _, product := range []string{cnaText(p.Product, ' '), cnaText(p.Product, '_')} {
			if n := (CNAName{Vendor: vendor, Product: product}); !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	return names
}

// cnaText turns a CPE vendor or product into the plain text a CNA record uses:
// a backslash and the character after it become that character, and an
// unescaped "_" becomes the byte underscore (a space, or "_" to keep it). A
// trailing lone backslash is kept.
func cnaText(cpeValue string, underscore byte) string {
	var b strings.Builder
	for i := 0; i < len(cpeValue); i++ {
		switch c := cpeValue[i]; {
		case c == '\\' && i+1 < len(cpeValue):
			i++
			b.WriteByte(cpeValue[i])
		case c == '_':
			b.WriteByte(underscore)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
