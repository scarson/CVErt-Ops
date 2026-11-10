// ABOUTME: Tests the CNA names looked up for a CPE product: its own name, the design section 4.5 table, and de-duplication.
// ABOUTME: Also tests how a CNA name matches a stored vendor and product, exactly or by prefix, without regard to case.
package check

import (
	"reflect"
	"testing"
)

func TestNamesFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		product     ProductRef
		wantNames   []CNAName
		wantMapping cnaMapping
		wantMapped  bool
	}{
		{
			name:    "nodejs:node.js: its own name and both table names",
			product: ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"},
			wantNames: []CNAName{
				{Vendor: "nodejs", Product: "node.js"},
				{Vendor: "nodejs", Product: "node"},
				{Vendor: "nodejs", Product: "nodejs"},
			},
			wantMapping: cnaMapping{
				Names:    []CNAName{{Vendor: "nodejs", Product: "node"}, {Vendor: "nodejs", Product: "nodejs"}},
				Fragment: "node", Vendor: "nodejs",
			},
			wantMapped: true,
		},
		{
			name:        "openssl:openssl: its own name only, not mapped",
			product:     ProductRef{Part: "a", Vendor: "openssl", Product: "openssl"},
			wantNames:   []CNAName{{Vendor: "openssl", Product: "openssl"}},
			wantMapping: cnaMapping{Fragment: "openssl", Vendor: "openssl"},
		},
		{
			name:        "apache:http_server: underscore read as a space",
			product:     ProductRef{Part: "a", Vendor: "apache", Product: "http_server"},
			wantNames:   []CNAName{{Vendor: "apache", Product: "http server"}},
			wantMapping: cnaMapping{Fragment: "http server", Vendor: "apache"},
		},
		{
			name:    "nginx:nginx: its own name and the table's F5 names",
			product: ProductRef{Part: "a", Vendor: "nginx", Product: "nginx"},
			wantNames: []CNAName{
				{Vendor: "nginx", Product: "nginx"},
				{Vendor: "f5", Product: "nginx open source"},
				{Vendor: "f5", Product: "nginx"},
			},
			wantMapping: cnaMapping{
				Names:    []CNAName{{Vendor: "f5", Product: "nginx open source"}, {Vendor: "f5", Product: "nginx"}},
				Fragment: "nginx", Vendor: "f5",
			},
			wantMapped: true,
		},
		{
			name:    "f5:nginx: its own name equals a table name and is listed once",
			product: ProductRef{Part: "a", Vendor: "f5", Product: "nginx"},
			wantNames: []CNAName{
				{Vendor: "f5", Product: "nginx"},
				{Vendor: "f5", Product: "nginx open source"},
			},
			wantMapping: cnaMapping{
				Names:    []CNAName{{Vendor: "f5", Product: "nginx open source"}, {Vendor: "f5", Product: "nginx"}},
				Fragment: "nginx", Vendor: "f5",
			},
			wantMapped: true,
		},
		{
			name:    "microsoft:.net: the .net prefix",
			product: ProductRef{Part: "a", Vendor: "microsoft", Product: ".net"},
			wantNames: []CNAName{
				{Vendor: "microsoft", Product: ".net"},
				{Vendor: "microsoft", Product: ".net ", Prefix: true},
			},
			wantMapping: cnaMapping{
				Names:    []CNAName{{Vendor: "microsoft", Product: ".net ", Prefix: true}},
				Fragment: ".net", Vendor: "microsoft",
			},
			wantMapped: true,
		},
		{
			name:    "microsoft:.net_core: the .net prefix",
			product: ProductRef{Part: "a", Vendor: "microsoft", Product: ".net_core"},
			wantNames: []CNAName{
				{Vendor: "microsoft", Product: ".net core"},
				{Vendor: "microsoft", Product: ".net ", Prefix: true},
			},
			wantMapping: cnaMapping{
				Names:    []CNAName{{Vendor: "microsoft", Product: ".net ", Prefix: true}},
				Fragment: ".net", Vendor: "microsoft",
			},
			wantMapped: true,
		},
		{
			name:    "php:php",
			product: ProductRef{Part: "a", Vendor: "php", Product: "php"},
			wantNames: []CNAName{
				{Vendor: "php", Product: "php"},
				{Vendor: "php group", Product: "php"},
			},
			wantMapping: cnaMapping{Names: []CNAName{{Vendor: "php group", Product: "php"}}, Fragment: "php", Vendor: "php group"},
			wantMapped:  true,
		},
		{
			name:    "postgresql:postgresql",
			product: ProductRef{Part: "a", Vendor: "postgresql", Product: "postgresql"},
			wantNames: []CNAName{
				{Vendor: "postgresql", Product: "postgresql"},
				{Vendor: "n/a", Product: "postgresql"},
			},
			wantMapping: cnaMapping{Names: []CNAName{{Vendor: "n/a", Product: "postgresql"}}, Fragment: "postgresql", Vendor: "n/a"},
			wantMapped:  true,
		},
		{
			name:    "python:python",
			product: ProductRef{Part: "a", Vendor: "python", Product: "python"},
			wantNames: []CNAName{
				{Vendor: "python", Product: "python"},
				{Vendor: "python software foundation", Product: "cpython"},
			},
			wantMapping: cnaMapping{
				Names:    []CNAName{{Vendor: "python software foundation", Product: "cpython"}},
				Fragment: "python", Vendor: "python software foundation",
			},
			wantMapped: true,
		},
		{
			// CNA names are plain text, so a CPE escape becomes the character it quotes.
			name:        `foo\:bar:product: an escaped vendor becomes foo:bar`,
			product:     ProductRef{Part: "a", Vendor: `foo\:bar`, Product: "product"},
			wantNames:   []CNAName{{Vendor: "foo:bar", Product: "product"}},
			wantMapping: cnaMapping{Fragment: "product", Vendor: "foo:bar"},
		},
		{
			// An escaped underscore is a literal underscore, not a space.
			name:        `vendor:a\_b_c\.d\\e: escapes and underscores`,
			product:     ProductRef{Part: "a", Vendor: "vendor", Product: `a\_b_c\.d\\e`},
			wantNames:   []CNAName{{Vendor: "vendor", Product: `a_b c.d\e`}},
			wantMapping: cnaMapping{Fragment: `a_b c.d\e`, Vendor: "vendor"},
		},
		{
			// The table is keyed by the CPE's spelling as written, so an escaped
			// spelling of a mapped product finds its own name but no table row.
			name:        `microsoft:\.net: escaped spelling is not a table key`,
			product:     ProductRef{Part: "a", Vendor: "microsoft", Product: `\.net`},
			wantNames:   []CNAName{{Vendor: "microsoft", Product: ".net"}},
			wantMapping: cnaMapping{Fragment: ".net", Vendor: "microsoft"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			names, mapping, mapped := NamesFor(tt.product)
			if !reflect.DeepEqual(names, tt.wantNames) {
				t.Errorf("names:\n got  %+v\n want %+v", names, tt.wantNames)
			}
			if !reflect.DeepEqual(mapping, tt.wantMapping) {
				t.Errorf("mapping:\n got  %+v\n want %+v", mapping, tt.wantMapping)
			}
			if mapped != tt.wantMapped {
				t.Errorf("mapped = %v, want %v", mapped, tt.wantMapped)
			}
		})
	}
}

// Every table key is a lower-cased vendor:product, as ProductRef holds a CPE,
// and every table name is lower case, as names are compared.
func TestCNANamesTableIsLowerCase(t *testing.T) {
	t.Parallel()
	for key, m := range cnaNames {
		if key != lowerASCII(key) {
			t.Errorf("table key %q is not lower case", key)
		}
		for _, n := range m.Names {
			if n.Vendor != lowerASCII(n.Vendor) || n.Product != lowerASCII(n.Product) {
				t.Errorf("table %q holds name %+v, not lower case", key, n)
			}
		}
		if m.Fragment == "" || m.Vendor == "" || len(m.Names) == 0 {
			t.Errorf("table %q is incomplete: %+v", key, m)
		}
	}
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// The caller may change what NamesFor returns without changing the table.
func TestNamesForDoesNotShareTheTable(t *testing.T) {
	t.Parallel()
	_, mapping, _ := NamesFor(ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"})
	mapping.Names[0].Product = "changed"
	_, again, _ := NamesFor(ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"})
	if again.Names[0].Product != "node" {
		t.Errorf("NamesFor returned the table's own slice: table now holds %+v", again.Names)
	}
}

func TestCNANameMatches(t *testing.T) {
	t.Parallel()
	dotnet := CNAName{Vendor: "microsoft", Product: ".net ", Prefix: true}
	node := CNAName{Vendor: "nodejs", Product: "node"}
	tests := []struct {
		name            string
		n               CNAName
		vendor, product string
		want            bool
	}{
		{name: "prefix: .NET 6.0", n: dotnet, vendor: "Microsoft", product: ".NET 6.0", want: true},
		{name: "prefix: .NET 9.0 runtime", n: dotnet, vendor: "Microsoft", product: ".NET 9.0 runtime", want: true},
		// The design's prefix also holds .NET Framework: its rows are read as
		// .NET rows, so their 4.x versions bear only on 4.x versions.
		{name: "prefix: .NET Framework 4.8", n: dotnet, vendor: "Microsoft", product: ".NET Framework 4.8", want: true},
		{name: "prefix: .NET alone lacks the space", n: dotnet, vendor: "Microsoft", product: ".NET", want: false},
		{name: "prefix: other vendor", n: dotnet, vendor: "Contoso", product: ".NET 6.0", want: false},
		{name: "exact: same name in another case", n: node, vendor: "NodeJS", product: "Node", want: true},
		{name: "exact: longer product does not match", n: node, vendor: "nodejs", product: "node-fetch", want: false},
		{name: "exact: other vendor", n: node, vendor: "nodejs foundation", product: "node", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.n.Matches(tt.vendor, tt.product); got != tt.want {
				t.Errorf("%+v.Matches(%q, %q) = %v, want %v", tt.n, tt.vendor, tt.product, got, tt.want)
			}
		})
	}
}
