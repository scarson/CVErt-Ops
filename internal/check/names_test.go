// ABOUTME: Tests the CNA names looked up for a CPE product: its own name, the design section 4.5 table, and de-duplication.
// ABOUTME: Also tests how a CNA name matches a stored vendor and product, exactly or by prefix, without regard to case.
package check

import (
	"reflect"
	"slices"
	"testing"
)

func TestNamesFor(t *testing.T) {
	t.Parallel()
	// Both CPE spellings of nginx, and of .NET, share one table row, so each
	// spelling reads the other's NVD rows.
	nginx := []string{"f5:nginx", "nginx:nginx"}
	dotnet := []string{"microsoft:.net", "microsoft:.net_core"}
	tests := []struct {
		name       string
		product    ProductRef
		wantNames  []CNAName
		wantCPEs   []string
		wantMapped bool
	}{
		{
			name:    "nodejs:node.js: its own name and both table names",
			product: ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"},
			wantNames: []CNAName{
				{Vendor: "nodejs", Product: "node.js"},
				{Vendor: "nodejs", Product: "node"},
				{Vendor: "nodejs", Product: "nodejs"},
			},
			wantCPEs:   []string{"nodejs:node.js"},
			wantMapped: true,
		},
		{
			name:      "openssl:openssl: its own name only, not mapped",
			product:   ProductRef{Part: "a", Vendor: "openssl", Product: "openssl"},
			wantNames: []CNAName{{Vendor: "openssl", Product: "openssl"}},
			wantCPEs:  []string{"openssl:openssl"},
		},
		{
			// A CNA may also write the CPE's "_" as it is.
			name:      "apache:http_server: underscore read as a space and kept",
			product:   ProductRef{Part: "a", Vendor: "apache", Product: "http_server"},
			wantNames: []CNAName{{Vendor: "apache", Product: "http server"}, {Vendor: "apache", Product: "http_server"}},
			wantCPEs:  []string{"apache:http_server"},
		},
		{
			// A CNA may read one "_" as a space and keep the other.
			name:    "acme_corp:foo_bar: every mix of underscore spellings",
			product: ProductRef{Part: "a", Vendor: "acme_corp", Product: "foo_bar"},
			wantNames: []CNAName{
				{Vendor: "acme corp", Product: "foo bar"}, {Vendor: "acme corp", Product: "foo_bar"},
				{Vendor: "acme_corp", Product: "foo bar"}, {Vendor: "acme_corp", Product: "foo_bar"},
			},
			wantCPEs: []string{"acme_corp:foo_bar"},
		},
		{
			name:    "nginx:nginx: its own name equals a table name and is listed once",
			product: ProductRef{Part: "a", Vendor: "nginx", Product: "nginx"},
			wantNames: []CNAName{
				{Vendor: "nginx", Product: "nginx"},
				{Vendor: "f5", Product: "nginx open source"},
				{Vendor: "f5", Product: "nginx"},
			},
			wantCPEs:   nginx,
			wantMapped: true,
		},
		{
			name:    "f5:nginx: its own name equals a table name and is listed once",
			product: ProductRef{Part: "a", Vendor: "f5", Product: "nginx"},
			wantNames: []CNAName{
				{Vendor: "f5", Product: "nginx"},
				{Vendor: "f5", Product: "nginx open source"},
				{Vendor: "nginx", Product: "nginx"},
			},
			wantCPEs:   nginx,
			wantMapped: true,
		},
		{
			name:    "microsoft:.net: the .net prefix",
			product: ProductRef{Part: "a", Vendor: "microsoft", Product: ".net"},
			wantNames: []CNAName{
				{Vendor: "microsoft", Product: ".net"},
				{Vendor: "microsoft", Product: ".net ", Prefix: true},
			},
			wantCPEs:   dotnet,
			wantMapped: true,
		},
		{
			name:    "microsoft:.net_core: the .net prefix",
			product: ProductRef{Part: "a", Vendor: "microsoft", Product: ".net_core"},
			wantNames: []CNAName{
				{Vendor: "microsoft", Product: ".net core"},
				{Vendor: "microsoft", Product: ".net_core"},
				{Vendor: "microsoft", Product: ".net ", Prefix: true},
			},
			wantCPEs:   dotnet,
			wantMapped: true,
		},
		{
			name:    "php:php",
			product: ProductRef{Part: "a", Vendor: "php", Product: "php"},
			wantNames: []CNAName{
				{Vendor: "php", Product: "php"},
				{Vendor: "php group", Product: "php"},
			},
			wantCPEs:   []string{"php:php"},
			wantMapped: true,
		},
		{
			name:    "postgresql:postgresql",
			product: ProductRef{Part: "a", Vendor: "postgresql", Product: "postgresql"},
			wantNames: []CNAName{
				{Vendor: "postgresql", Product: "postgresql"},
				{Vendor: "n/a", Product: "postgresql"},
			},
			wantCPEs:   []string{"postgresql:postgresql"},
			wantMapped: true,
		},
		{
			name:    "python:python",
			product: ProductRef{Part: "a", Vendor: "python", Product: "python"},
			wantNames: []CNAName{
				{Vendor: "python", Product: "python"},
				{Vendor: "python software foundation", Product: "cpython"},
			},
			wantCPEs:   []string{"python:python"},
			wantMapped: true,
		},
		{
			// CNA names are plain text, so a CPE escape becomes the character it quotes.
			name:      `foo\:bar:product: an escaped vendor becomes foo:bar`,
			product:   ProductRef{Part: "a", Vendor: `foo\:bar`, Product: "product"},
			wantNames: []CNAName{{Vendor: "foo:bar", Product: "product"}},
			wantCPEs:  []string{`foo\:bar:product`},
		},
		{
			// An escaped underscore is a literal underscore, not a space.
			name:      `vendor:a\_b_c\.d\\e: escapes and underscores`,
			product:   ProductRef{Part: "a", Vendor: "vendor", Product: `a\_b_c\.d\\e`},
			wantNames: []CNAName{{Vendor: "vendor", Product: `a_b c.d\e`}, {Vendor: "vendor", Product: `a_b_c.d\e`}},
			wantCPEs:  []string{`vendor:a\_b_c\.d\\e`},
		},
		{
			// The table is looked up by the ProductRef's spelling as given. parseCPE
			// drops the backslash before ".", so a request's \.net reaches the table
			// (TestKeysForRedundantEscapes); a ProductRef built with the escape finds
			// no table row, and its own name reads the escape as ".".
			name:      `microsoft:\.net built directly: no table row, own name .net`,
			product:   ProductRef{Part: "a", Vendor: "microsoft", Product: `\.net`},
			wantNames: []CNAName{{Vendor: "microsoft", Product: ".net"}},
			wantCPEs:  []string{`microsoft:\.net`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			names, cpes, mapped := NamesFor(tt.product)
			if !reflect.DeepEqual(names, tt.wantNames) {
				t.Errorf("names:\n got  %+v\n want %+v", names, tt.wantNames)
			}
			if !reflect.DeepEqual(cpes, tt.wantCPEs) {
				t.Errorf("CPE spellings = %q, want %q", cpes, tt.wantCPEs)
			}
			if mapped != tt.wantMapped {
				t.Errorf("mapped = %v, want %v", mapped, tt.wantMapped)
			}
		})
	}
}

// TestNearbyNames checks the vendors and name fragments of the nearby-name
// check: the table's for a mapped CPE, and for any other CPE its own name, with
// "_" read as a space and, when the name holds one, with "_" kept, in the vendor
// and the fragment independently.
func TestNearbyNames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		product ProductRef
		want    []CNAName
	}{
		{name: "mapped nodejs:node.js", product: ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"},
			want: []CNAName{{Vendor: "nodejs", Product: "node"}}},
		{name: "mapped php:php", product: ProductRef{Part: "a", Vendor: "php", Product: "php"},
			want: []CNAName{{Vendor: "php group", Product: "php"}}},
		{name: "mapped f5:nginx", product: ProductRef{Part: "a", Vendor: "f5", Product: "nginx"},
			want: []CNAName{{Vendor: "f5", Product: "nginx"}}},
		{name: "mapped nginx:nginx: the table's vendor, not its own", product: ProductRef{Part: "a", Vendor: "nginx", Product: "nginx"},
			want: []CNAName{{Vendor: "f5", Product: "nginx"}}},
		{name: "mapped microsoft:.net", product: ProductRef{Part: "a", Vendor: "microsoft", Product: ".net"},
			want: []CNAName{{Vendor: "microsoft", Product: ".net"}}},
		{name: "mapped microsoft:.net_core: no underscore spellings", product: ProductRef{Part: "a", Vendor: "microsoft", Product: ".net_core"},
			want: []CNAName{{Vendor: "microsoft", Product: ".net"}}},
		{name: "mapped postgresql:postgresql", product: ProductRef{Part: "a", Vendor: "postgresql", Product: "postgresql"},
			want: []CNAName{{Vendor: "n/a", Product: "postgresql"}}},
		{name: "mapped python:python", product: ProductRef{Part: "a", Vendor: "python", Product: "python"},
			want: []CNAName{{Vendor: "python software foundation", Product: "python"}}},
		{name: "no underscore: one", product: ProductRef{Part: "a", Vendor: "acme", Product: "widget"},
			want: []CNAName{{Vendor: "acme", Product: "widget"}}},
		{name: "underscore in the product", product: ProductRef{Part: "a", Vendor: "acme", Product: "foo_bar"},
			want: []CNAName{{Vendor: "acme", Product: "foo bar"}, {Vendor: "acme", Product: "foo_bar"}}},
		{name: "underscore in the vendor", product: ProductRef{Part: "a", Vendor: "acme_corp", Product: "widget"},
			want: []CNAName{{Vendor: "acme corp", Product: "widget"}, {Vendor: "acme_corp", Product: "widget"}}},
		{name: "underscores in both: every mix", product: ProductRef{Part: "a", Vendor: "acme_corp", Product: "foo_bar"},
			want: []CNAName{
				{Vendor: "acme corp", Product: "foo bar"}, {Vendor: "acme corp", Product: "foo_bar"},
				{Vendor: "acme_corp", Product: "foo bar"}, {Vendor: "acme_corp", Product: "foo_bar"},
			}},
		{name: "an escaped underscore is already kept", product: ProductRef{Part: "a", Vendor: "acme", Product: `foo\_bar`},
			want: []CNAName{{Vendor: "acme", Product: "foo_bar"}}},
		{name: "escapes read as the characters they quote", product: ProductRef{Part: "a", Vendor: `foo\:bar`, Product: "product"},
			want: []CNAName{{Vendor: "foo:bar", Product: "product"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := nearbyNames(tt.product); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("nearbyNames = %+v, want %+v", got, tt.want)
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
		if !slices.Contains(m.CPEs, key) {
			t.Errorf("table %q lists CPEs %q, which do not hold its own key", key, m.CPEs)
		}
	}
}

// Every CPE a table row lists finds that row, and no CPE is in two rows.
func TestCNATableIndexesEveryCPE(t *testing.T) {
	t.Parallel()
	listed := 0
	for _, m := range cnaTable {
		listed += len(m.CPEs)
		for _, cpe := range m.CPEs {
			if !reflect.DeepEqual(cnaNames[cpe], m) {
				t.Errorf("CPE %q finds %+v, want its row %+v", cpe, cnaNames[cpe], m)
			}
		}
	}
	if listed != len(cnaNames) {
		t.Errorf("table rows list %d CPEs, index holds %d: a CPE is in two rows", listed, len(cnaNames))
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
	node := ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}
	names, cpes, _ := NamesFor(node)
	names[1].Product = "changed"
	cpes[0] = "changed"
	again, againCPEs, _ := NamesFor(node)
	if again[1].Product != "node" || againCPEs[0] != "nodejs:node.js" {
		t.Errorf("NamesFor returned the table's own slices: table now gives %+v and %q", again, againCPEs)
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
		{name: "exact: underscore kept", n: CNAName{Vendor: "acme", Product: "foo_bar"}, vendor: "Acme", product: "Foo_Bar", want: true},
		{name: "exact: underscore kept is not a space", n: CNAName{Vendor: "acme", Product: "foo_bar"}, vendor: "acme", product: "foo bar", want: false},
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
