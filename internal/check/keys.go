// ABOUTME: The lookup keys the store reads for a version check request, distinct across its items.
// ABOUTME: Also records which keys each item uses, so Evaluate can gather that item's rows.
package check

import (
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/scarson/cvert-ops/internal/ecosystem"
)

// cnaNameRunes is how many characters of a CNA vendor or product the index
// holds, as SQL left(lower(...), 256) cuts them.
const cnaNameRunes = 256

// Keys is what the store must read, distinct across the request. Each slice's
// position is the key index that rows in Candidates refer to.
type Keys struct {
	Packages       []PackageKey // ecosystem and folded name
	CPEPrefixes    []CPEKey     // Lo "cpe:2.3:a:nodejs:node.js:", Hi "cpe:2.3:a:nodejs:node.js;"
	CNANames       []CNANameKey // see CNANameKey
	CNAPackageKeys []string     // ecosystem.PackageKeyFor; non-distro package items only
	CNANear        []CNANearKey // see CNANearKey
}

// PackageKey is an ecosystem and a package name folded by ecosystem.FoldPackageName.
type PackageKey struct{ Ecosystem, Name string }

// CPEKey is the range [Lo, Hi) on cpe_normalized holding every CPE of one
// part:vendor:product, as written with its escapes: Lo ends in ":" and Hi is Lo
// with that ":" replaced by ";", the next byte.
type CPEKey struct{ Lo, Hi string }

// CNANameKey finds CNA rows for one CNAName. Names are lower-cased and cut to
// 256 runes, as the index holds them. V is the cut vendor, and [Lo, Hi) is a
// range on the cut product: for an exact name Lo is the cut product and Hi is
// Lo + "\x01", built after the cut so a long name cannot collapse the range; for
// a prefix, Lo is the cut prefix and Hi the prefix with its last rune
// incremented. FullVendor and FullProduct are the whole lower-cased names, which
// the store rechecks because the index holds only 256 runes; FullProduct is ""
// for a prefix, which needs no recheck of the product.
type CNANameKey struct{ V, Lo, Hi, FullVendor, FullProduct string }

// CNANearKey finds CNA rows near a product's CNA name (design section 4.5): rows
// under vendor FullVendor (V is it cut to 256 runes) whose lower-cased product
// contains Fragment, on CVEs with no cve_cpe_matches row in [VendorLo, VendorHi),
// the range of the item's own CPE vendor.
type CNANearKey struct{ V, FullVendor, Fragment, VendorLo, VendorHi string }

// Candidates holds the rows read for each key, in Keys order, and whether a key
// reached its per-key limit.
type Candidates struct {
	Packages       []KeyRows[PackageRow]
	CPEs           []KeyRows[CPERow]
	CNANames       []KeyRows[CNARow]
	CNAPackageKeys []KeyRows[CNARow]
	CNANear        []KeyRows[CNANearRow]
}

// KeyRows is the rows read for one key. Overflow is true when the key reached
// its per-key limit, so Rows is not all of them.
type KeyRows[T any] struct {
	Rows     []T
	Overflow bool
}

// CNANearRow is one cve_cna_affected row a CNANearKey found, with its vendor and
// product as stored. Status is its CVE's cves.status.
type CNANearRow struct{ CVEID, Vendor, Product, Status string }

// itemKeys holds the indices into Keys of the keys one item uses; -1 for none.
type itemKeys struct {
	pkg        int
	cpes       []int
	cnaNames   []int
	cnaPackage int
	near       int
}

// KeysFor returns the distinct keys of the valid items.
func KeysFor(items []Item) Keys {
	keys, _ := keysWithUses(items)
	return keys
}

// keysWithUses returns KeysFor's keys and, for each item, the keys it uses. An
// invalid item uses none.
func keysWithUses(items []Item) (Keys, []itemKeys) {
	var b keyBuilder
	uses := make([]itemKeys, len(items))
	for i, item := range items {
		use := itemKeys{pkg: -1, cnaPackage: -1, near: -1}
		switch {
		case item.Error != nil:
		case item.Package != nil:
			eco, name := item.Package.Ecosystem, item.Package.Name
			use.pkg = add(&b.packages, &b.keys.Packages, PackageKey{Ecosystem: eco, Name: ecosystem.FoldPackageName(eco, name)})
			// The CNA describes the upstream package, not a distro's build of it.
			if key := ecosystem.PackageKeyFor(eco, name); !ecosystem.IsDistro(eco) && key != "" {
				use.cnaPackage = add(&b.cnaPackages, &b.keys.CNAPackageKeys, key)
			}
		case item.Product != nil:
			p := *item.Product
			names, mapping, _ := NamesFor(p)
			// Every spelling the mapping lists is this product, with the item's part.
			for _, cpe := range mapping.CPEs {
				lo := "cpe:2.3:" + p.Part + ":" + cpe + ":"
				use.cpes = append(use.cpes, add(&b.cpes, &b.keys.CPEPrefixes, CPEKey{Lo: lo, Hi: upperOfPrefix(lo)}))
			}
			for _, n := range names {
				k := add(&b.cnaNames, &b.keys.CNANames, cnaNameKey(n))
				if !slices.Contains(use.cnaNames, k) {
					use.cnaNames = append(use.cnaNames, k)
				}
			}
			vendor := strings.ToLower(mapping.Vendor)
			vendorLo := "cpe:2.3:" + p.Part + ":" + p.Vendor + ":"
			use.near = add(&b.near, &b.keys.CNANear, CNANearKey{
				V: cutRunes(vendor), FullVendor: vendor, Fragment: strings.ToLower(mapping.Fragment),
				VendorLo: vendorLo, VendorHi: upperOfPrefix(vendorLo),
			})
		}
		uses[i] = use
	}
	return b.keys, uses
}

// keyBuilder holds Keys with an index of each slice, so each key is added once.
type keyBuilder struct {
	keys        Keys
	packages    map[PackageKey]int
	cpes        map[CPEKey]int
	cnaNames    map[CNANameKey]int
	cnaPackages map[string]int
	near        map[CNANearKey]int
}

// add returns key's position in keys, appending it the first time it is seen.
func add[K comparable](index *map[K]int, keys *[]K, key K) int {
	if *index == nil {
		*index = map[K]int{}
	}
	if i, ok := (*index)[key]; ok {
		return i
	}
	(*index)[key] = len(*keys)
	*keys = append(*keys, key)
	return len(*keys) - 1
}

// upperOfPrefix turns a CPE prefix ending in ":" into the bound just above every
// string it starts: the same prefix ending in ";".
func upperOfPrefix(lo string) string {
	return strings.TrimSuffix(lo, ":") + ";"
}

// cnaNameKey builds the key for one CNA name, as CNANameKey describes.
func cnaNameKey(n CNAName) CNANameKey {
	vendor, product := strings.ToLower(n.Vendor), strings.ToLower(n.Product)
	lo := cutRunes(product)
	if n.Prefix {
		return CNANameKey{V: cutRunes(vendor), Lo: lo, Hi: nextPrefix(lo), FullVendor: vendor}
	}
	return CNANameKey{V: cutRunes(vendor), Lo: lo, Hi: lo + "\x01", FullVendor: vendor, FullProduct: product}
}

// cutRunes returns the first 256 runes of s, as SQL left(s, 256) does.
func cutRunes(s string) string {
	n := 0
	for i := range s {
		if n == cnaNameRunes {
			return s[:i]
		}
		n++
	}
	return s
}

// nextPrefix returns the least string above every string that starts with s:
// s with its last rune incremented. Incrementing skips the surrogate range,
// which UTF-8 cannot hold; a last rune that is already the highest is dropped
// and the rune before it incremented; for a string of only that rune there is no
// such string, and the result is "". Bytewise order of UTF-8 is rune order, so
// the result bounds the prefix in the database's C collation too.
func nextPrefix(s string) string {
	for s != "" {
		r, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
		switch r {
		case utf8.MaxRune:
			continue
		case 0xD7FF:
			return s + string(rune(0xE000))
		default:
			return s + string(r+1)
		}
	}
	return s
}
