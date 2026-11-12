// ABOUTME: Tests the lookup keys built from request items: distinct across the request, and the keys each item uses.
// ABOUTME: Covers folded package names, CPE prefix bounds, CNA name bounds cut to 256 runes, and nearby-name keys.
package check

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// keysItems is a request whose items share keys: two spellings of one npm
// package, two .NET CPEs that share a CNA prefix and a nearby-name key, and an
// invalid item.
func keysItems() []Item {
	return parseItems(
		RawItem{Ecosystem: "npm", Name: "Fastify", Version: "1.0.0"},
		RawItem{Ecosystem: "npm", Name: "fastify", Version: "2.0.0"},
		RawItem{Ecosystem: "Ubuntu:26.04:LTS", Name: "php8.5", Version: "8.5.4-0ubuntu1.4"},
		RawItem{CPE: "cpe:2.3:a:nodejs:node.js:24.22.0:*:*:*:*:*:*:*"},
		RawItem{CPE: "cpe:2.3:a:microsoft:.net:9.0.1:*:*:*:*:*:*:*"},
		RawItem{CPE: "cpe:2.3:a:microsoft:.net_core:9.0.1:*:*:*:*:*:*:*"},
		RawItem{Ecosystem: "npm"},
		RawItem{Ecosystem: "PyPI", Name: "Foo_Bar", Version: "1.0"},
	)
}

func exactName(vendor, product string) CNANameKey {
	return CNANameKey{V: vendor, Lo: product, Hi: product + "\x01", FullVendor: vendor, FullProduct: product}
}

// vendorRange is the range on cpe_normalized of every CPE of part:vendor.
func vendorRange(part, vendor string) CPEKey {
	lo := "cpe:2.3:" + part + ":" + vendor + ":"
	return CPEKey{Lo: lo, Hi: "cpe:2.3:" + part + ":" + vendor + ";", Prefix: lo}
}

func TestKeysFor(t *testing.T) {
	t.Parallel()
	want := Keys{
		Packages: []PackageKey{
			{Ecosystem: "npm", Name: "fastify"},
			{Ecosystem: "Ubuntu:26.04:LTS", Name: "php8.5"},
			{Ecosystem: "PyPI", Name: "foo-bar"},
		},
		CPEPrefixes: []CPEKey{
			{Lo: "cpe:2.3:a:nodejs:node.js:", Hi: "cpe:2.3:a:nodejs:node.js;", Prefix: "cpe:2.3:a:nodejs:node.js:", Floor: "24.22.0"},
			{Lo: "cpe:2.3:a:microsoft:.net:", Hi: "cpe:2.3:a:microsoft:.net;", Prefix: "cpe:2.3:a:microsoft:.net:", Floor: "9.0.1"},
			{Lo: "cpe:2.3:a:microsoft:.net_core:", Hi: "cpe:2.3:a:microsoft:.net_core;", Prefix: "cpe:2.3:a:microsoft:.net_core:", Floor: "9.0.1"},
		},
		CNANames: []CNANameKey{
			exactName("nodejs", "node.js"),
			exactName("nodejs", "node"),
			exactName("nodejs", "nodejs"),
			exactName("microsoft", ".net"),
			{V: "microsoft", Lo: ".net ", Hi: ".net!", FullVendor: "microsoft", FullProduct: ""},
			exactName("microsoft", ".net core"),
			exactName("microsoft", ".net_core"),
		},
		CNAPackageKeys: []string{"npm/fastify", "PyPI/foo-bar"},
		CNANear: []CNANearKey{
			{V: "nodejs", FullVendor: "nodejs", Fragment: "node", VendorRanges: []CPEKey{vendorRange("a", "nodejs")}},
			{V: "microsoft", FullVendor: "microsoft", Fragment: ".net", VendorRanges: []CPEKey{vendorRange("a", "microsoft")}},
		},
	}
	got := KeysFor(keysItems())
	if !reflect.DeepEqual(got, want) {
		t.Errorf("KeysFor =\n%+v\nwant\n%+v", got, want)
	}
}

// TestKeysForItemUses checks the keys each item uses, by index into Keys.
func TestKeysForItemUses(t *testing.T) {
	t.Parallel()
	_, uses := keysWithUses(keysItems())
	none := itemKeys{pkg: -1, cnaPackage: -1}
	want := []itemKeys{
		{pkg: 0, cnaPackage: 0},
		{pkg: 0, cnaPackage: 0},
		{pkg: 1, cnaPackage: -1}, // distro items use no CNA rows
		{pkg: -1, cpes: []int{0}, cnaNames: []int{0, 1, 2}, cnaPackage: -1, near: []int{0}},
		// Both .NET spellings read the NVD rows under each.
		{pkg: -1, cpes: []int{1, 2}, cnaNames: []int{3, 4}, cnaPackage: -1, near: []int{1}},
		{pkg: -1, cpes: []int{1, 2}, cnaNames: []int{5, 6, 4}, cnaPackage: -1, near: []int{1}},
		none, // an invalid item uses no keys
		{pkg: 2, cnaPackage: 1},
	}
	if !reflect.DeepEqual(uses, want) {
		t.Errorf("item keys =\n%+v\nwant\n%+v", uses, want)
	}
}

func TestKeysForInvalidItemsOnly(t *testing.T) {
	t.Parallel()
	if got := KeysFor(parseItems(RawItem{CPE: "nope"}, RawItem{})); !reflect.DeepEqual(got, Keys{}) {
		t.Errorf("KeysFor of invalid items = %+v, want no keys", got)
	}
}

// TestKeysForCPESpellings checks that a CPE with a name table row reads the NVD
// rows of every CPE spelling the row lists, with the item's own part, that the
// shared prefixes are read once when both spellings are in one request, and
// that a CPE with no table row reads only its own prefix.
func TestKeysForCPESpellings(t *testing.T) {
	t.Parallel()
	prefix := func(part, vendor, product, floor string) CPEKey {
		lo := "cpe:2.3:" + part + ":" + vendor + ":" + product + ":"
		return CPEKey{Lo: lo, Hi: strings.TrimSuffix(lo, ":") + ";", Prefix: lo, Floor: floor}
	}
	keys, uses := keysWithUses(parseItems(
		RawItem{CPE: "cpe:2.3:a:f5:nginx:1.13.0:*:*:*:*:*:*:*"},
		RawItem{CPE: "cpe:2.3:a:nginx:nginx:1.13.0:*:*:*:*:*:*:*"},
		RawItem{CPE: "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"},
		RawItem{CPE: "cpe:2.3:o:f5:nginx:1.13.0:*:*:*:*:*:*:*"},
	))
	wantPrefixes := []CPEKey{
		prefix("a", "f5", "nginx", "1.13.0"), prefix("a", "nginx", "nginx", "1.13.0"),
		prefix("a", "acme", "widget", "1.0"),
		prefix("o", "f5", "nginx", "1.13.0"), prefix("o", "nginx", "nginx", "1.13.0"),
	}
	if !reflect.DeepEqual(keys.CPEPrefixes, wantPrefixes) {
		t.Errorf("CPE keys =\n%+v\nwant\n%+v", keys.CPEPrefixes, wantPrefixes)
	}
	wantUses := [][]int{{0, 1}, {0, 1}, {2}, {3, 4}}
	for i, want := range wantUses {
		if !reflect.DeepEqual(uses[i].cpes, want) {
			t.Errorf("item %d CPE keys = %v, want %v", i, uses[i].cpes, want)
		}
	}
	// Both nginx spellings also read the CNA name nginx / nginx.
	if !slices.Contains(keys.CNANames, exactName("nginx", "nginx")) {
		t.Errorf("CNA name keys = %+v, want nginx / nginx among them", keys.CNANames)
	}
}

// TestKeysForNearbyVendorRanges checks the CPE vendors whose NVD rows lift a
// nearby-name key: for a CPE with a table row, the vendor of every CPE spelling
// the row lists, with the item's part, so both nginx spellings share one key;
// for a CPE with no table row, its own vendor.
func TestKeysForNearbyVendorRanges(t *testing.T) {
	t.Parallel()
	keys, uses := keysWithUses(parseItems(
		RawItem{CPE: "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"},
		RawItem{CPE: "cpe:2.3:a:f5:nginx:1.20.0:*:*:*:*:*:*:*"},
		RawItem{CPE: "cpe:2.3:o:f5:nginx:1.20.0:*:*:*:*:*:*:*"},
		RawItem{CPE: "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"},
	))
	want := []CNANearKey{
		{V: "f5", FullVendor: "f5", Fragment: "nginx", VendorRanges: []CPEKey{vendorRange("a", "f5"), vendorRange("a", "nginx")}},
		{V: "f5", FullVendor: "f5", Fragment: "nginx", VendorRanges: []CPEKey{vendorRange("o", "f5"), vendorRange("o", "nginx")}},
		{V: "acme", FullVendor: "acme", Fragment: "widget", VendorRanges: []CPEKey{vendorRange("a", "acme")}},
	}
	if !reflect.DeepEqual(keys.CNANear, want) {
		t.Errorf("nearby-name keys =\n%+v\nwant\n%+v", keys.CNANear, want)
	}
	wantUses := [][]int{{0}, {0}, {1}, {2}}
	for i, w := range wantUses {
		if !reflect.DeepEqual(uses[i].near, w) {
			t.Errorf("item %d nearby-name keys = %v, want %v", i, uses[i].near, w)
		}
	}
}

// TestKeysForRedundantEscapes checks that a CPE escaping "." reads the keys of
// the same CPE written as NVD writes it, including its name table row.
func TestKeysForRedundantEscapes(t *testing.T) {
	t.Parallel()
	got := KeysFor(parseItems(RawItem{CPE: `cpe:2.3:a:nodejs:node\.js:24.22.0:*:*:*:*:*:*:*`}))
	want := KeysFor(parseItems(RawItem{CPE: "cpe:2.3:a:nodejs:node.js:24.22.0:*:*:*:*:*:*:*"}))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("KeysFor(node\\.js) =\n%+v\nwant\n%+v", got, want)
	}
}

// TestKeysForCPEEscapes checks that a CPE prefix keeps its escapes as written,
// and that the CNA names read them as plain text, with an unescaped "_" read as
// a space and also kept.
func TestKeysForCPEEscapes(t *testing.T) {
	t.Parallel()
	got := KeysFor(parseItems(RawItem{CPE: `cpe:2.3:a:foo\:bar:baz_qux:1.0:*:*:*:*:*:*:*`}))
	wantCPE := []CPEKey{{Lo: `cpe:2.3:a:foo\:bar:baz_qux:`, Hi: `cpe:2.3:a:foo\:bar:baz_qux;`, Prefix: `cpe:2.3:a:foo\:bar:baz_qux:`, Floor: "1.0"}}
	if !reflect.DeepEqual(got.CPEPrefixes, wantCPE) {
		t.Errorf("CPE keys = %+v, want %+v", got.CPEPrefixes, wantCPE)
	}
	wantNames := []CNANameKey{exactName("foo:bar", "baz qux"), exactName("foo:bar", "baz_qux")}
	if !reflect.DeepEqual(got.CNANames, wantNames) {
		t.Errorf("CNA name keys = %+v, want %+v", got.CNANames, wantNames)
	}
	own := []CPEKey{vendorRange("a", `foo\:bar`)}
	wantNear := []CNANearKey{
		{V: "foo:bar", FullVendor: "foo:bar", Fragment: "baz qux", VendorRanges: own},
		{V: "foo:bar", FullVendor: "foo:bar", Fragment: "baz_qux", VendorRanges: own},
	}
	if !reflect.DeepEqual(got.CNANear, wantNear) {
		t.Errorf("nearby-name keys = %+v, want %+v", got.CNANear, wantNear)
	}
}

// TestKeysForLongNames checks that CNA names are cut to 256 runes, as SQL left()
// cuts, with the exact bound built after the cut and the whole name kept for the
// recheck. The item is built directly: a request CPE of 512 characters cannot
// hold two names over 256, but a table name or a later limit could.
func TestKeysForLongNames(t *testing.T) {
	t.Parallel()
	vendor := strings.Repeat("v", 300)
	product := strings.Repeat("é", 300)
	got := KeysFor([]Item{{Product: &ProductRef{Part: "a", Vendor: vendor, Product: product}, Version: "1.0"}})
	if len(got.CNANames) != 1 {
		t.Fatalf("CNA name keys = %d, want 1", len(got.CNANames))
	}
	k := got.CNANames[0]
	cutVendor, cutProduct := strings.Repeat("v", 256), strings.Repeat("é", 256)
	want := CNANameKey{V: cutVendor, Lo: cutProduct, Hi: cutProduct + "\x01", FullVendor: vendor, FullProduct: product}
	if k != want {
		t.Errorf("long CNA name key: V %d runes, Lo %d runes, Hi %q suffix; want V and Lo 256 runes and Hi Lo+\\x01",
			utf8.RuneCountInString(k.V), utf8.RuneCountInString(k.Lo), k.Hi[len(k.Hi)-1:])
	}
	near := got.CNANear[0]
	if near.V != cutVendor || near.FullVendor != vendor || near.Fragment != product {
		t.Errorf("long nearby-name key: V %d runes, FullVendor %d runes, Fragment %d runes; want 256, 300, 300",
			utf8.RuneCountInString(near.V), utf8.RuneCountInString(near.FullVendor), utf8.RuneCountInString(near.Fragment))
	}
}

// TestCPEKeyCutToIndexLength checks that a CPE key's range is on the first 512
// runes of its prefix, as cve_cpe_matches_check_idx holds them, and that the
// whole prefix is kept for the store to recheck.
func TestCPEKeyCutToIndexLength(t *testing.T) {
	t.Parallel()
	short := "cpe:2.3:a:nodejs:node.js:"
	if got, want := CPEKeyFor(short), (CPEKey{Lo: short, Hi: "cpe:2.3:a:nodejs:node.js;", Prefix: short}); got != want {
		t.Errorf("CPEKeyFor(%q) = %+v, want %+v", short, got, want)
	}

	// Two-byte runes, so a cut by bytes would differ from SQL left by characters.
	product := strings.Repeat("é", 600)
	long := "cpe:2.3:a:v:" + product + ":"
	got := CPEKeyFor(long)
	lo := string([]rune(long)[:512])
	if got.Lo != lo || got.Hi != nextPrefix(lo) || got.Prefix != long {
		t.Errorf("long CPE key: Lo %d runes, Hi %q…, Prefix %d runes; want Lo 512 runes, Hi Lo with its last rune incremented, Prefix %d runes",
			utf8.RuneCountInString(got.Lo), got.Hi[len(got.Hi)-4:], utf8.RuneCountInString(got.Prefix), utf8.RuneCountInString(long))
	}

	keys := KeysFor([]Item{{Product: &ProductRef{Part: "a", Vendor: "v", Product: product}}})
	if len(keys.CPEPrefixes) != 1 || keys.CPEPrefixes[0] != got {
		t.Errorf("KeysFor CPE keys = %+v, want the one CPEKeyFor builds", keys.CPEPrefixes)
	}
	if len(keys.CNANear) != 1 || !reflect.DeepEqual(keys.CNANear[0].VendorRanges, []CPEKey{CPEKeyFor("cpe:2.3:a:v:")}) {
		t.Errorf("KeysFor nearby-name vendor ranges = %+v, want the one CPEKeyFor builds", keys.CNANear)
	}
}

func TestNextPrefix(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{".net ", ".net!"},
		{"ab", "ac"},
		{"aé", "aê"},
		{"a" + string(rune(0xD7FF)), "a" + string(rune(0xE000))}, // skips the surrogate range
		{"a" + string(rune(utf8.MaxRune)), "b"},
	}
	for _, tt := range tests {
		got := nextPrefix(tt.in)
		if got != tt.want {
			t.Errorf("nextPrefix(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if got <= tt.in {
			t.Errorf("nextPrefix(%q) = %q is not above it", tt.in, got)
		}
	}
}

// TestCNANamePrefixesHaveUpperBounds checks every prefix in the table gives an
// interval holding its own prefix.
func TestCNANamePrefixesHaveUpperBounds(t *testing.T) {
	t.Parallel()
	for cpe, mapping := range cnaNames {
		for _, n := range mapping.Names {
			if !n.Prefix {
				continue
			}
			k := cnaNameKey(n)
			if k.Lo >= k.Hi || !strings.HasPrefix(k.Lo, strings.ToLower(n.Product)) {
				t.Errorf("%s: prefix %q gives key %+v", cpe, n.Product, k)
			}
		}
	}
}
