// ABOUTME: The lookup keys the store reads for a version check request, distinct across its items.
// ABOUTME: Also records which keys each item uses, so Evaluate can gather that item's rows.
package check

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/scarson/cvert-ops/internal/ecosystem"
	"github.com/scarson/cvert-ops/internal/version"
)

// cnaNameRunes is how many characters of a CNA vendor or product the index
// holds, as SQL left(lower(...), 256) cuts them.
const cnaNameRunes = 256

// CPEKeyRunes is how many characters of cpe_normalized cve_cpe_matches_check_idx
// holds, as SQL left(cpe_normalized, 512) cuts them.
const CPEKeyRunes = 512

// CPEIndexExpr is the expression cve_cpe_matches_check_idx indexes, on column:
// its first CPEKeyRunes characters, so a CPE of any length fits a btree row.
// The C collation lets a range on a CPE prefix use the index whatever the
// database collation. A statement ranges on it with a CPEKey's Lo and Hi and
// rechecks the key's whole Prefix with starts_with.
func CPEIndexExpr(column string) string {
	return fmt.Sprintf(`left(%s, %d) COLLATE "C"`, column, CPEKeyRunes)
}

// CNANameIndexExpr is one of the expressions cve_cna_affected_check_idx
// indexes, on column (vendor or product): its first cnaNameRunes characters,
// lower-cased, which CNANameKeyFor cuts its names to match.
func CNANameIndexExpr(column string) string {
	return fmt.Sprintf(`left(lower(%s), %d) COLLATE "C"`, column, cnaNameRunes)
}

// Keys is what the store must read, distinct across the request. Each slice's
// position is the key index that rows in Candidates refer to.
type Keys struct {
	Packages       []PackageKey // ecosystem and folded name
	CPEPrefixes    []CPEKey     // Lo "cpe:2.3:a:nodejs:node.js:", Hi "cpe:2.3:a:nodejs:node.js;", Floor "24.22"
	CNANames       []CNANameKey // see CNANameKey
	CNAPackageKeys []string     // ecosystem.PackageKeyFor; non-distro package items only
	CNANear        []CNANearKey // see CNANearKey
}

// PackageKey is an ecosystem and a package name folded by ecosystem.FoldPackageName.
type PackageKey struct{ Ecosystem, Name string }

// CPEKey finds every CPE that starts with Prefix: one part:vendor:product, or
// one part:vendor in CNANearKey.VendorRanges, ending in ":", with escapes as
// ProductRef holds them: as written, except that parseCPE drops the backslash
// before ".", "-" and "_", which NVD writes bare. [Lo, Hi) is the range on the
// first CPEKeyRunes runes of cpe_normalized, as the index holds them: Lo is
// Prefix cut to that length and Hi is Lo with its last rune incremented, built
// after the cut, so for a Prefix within the length Hi is Prefix ending in ";".
// The store rechecks Prefix against the whole value. CPEKeyFor builds the
// three.
//
// A request has one key for each product, so every item of the product shares
// one read, as Keys promises. Floor is the lowest dotted-number version among
// the items that use the key, or "" when none is dotted numbers. The store then
// leaves out the rows whose ranges lie wholly below Floor (CPERowBelow) and
// returns one CPERow per CVE counting them. Such a row answers NotAffected for
// every dotted-number version at or above Floor, so for each of those items. An
// item whose version is not dotted numbers can be compared with no row, and
// answers invalid_version from left-out rows as from stored ones
// (EvaluateCPERows).
//
// The rows a key returns therefore depend on the request's other items of the
// same product, and so does whether the key passes its row limit. A key with a
// floor never returns more rows than the same key with none.
type CPEKey struct{ Lo, Hi, Prefix, Floor string }

// CPEKeyFor returns the key, with no floor, for the CPEs starting with prefix.
func CPEKeyFor(prefix string) CPEKey {
	lo := cutRunes(prefix, CPEKeyRunes)
	return CPEKey{Lo: lo, Hi: nextPrefix(lo), Prefix: prefix}
}

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
// contains Fragment, on CVEs with no cve_cpe_matches row in any of VendorRanges.
// VendorRanges holds, with the item's part, the vendor of every CPE spelling
// whose NVD rows the item reads: for a CPE with a name table row, each vendor
// of the row's CPEs, so both nginx spellings are lifted by an NVD row under f5
// or nginx; otherwise the CPE's own vendor.
type CNANearKey struct {
	V, FullVendor, Fragment string
	VendorRanges            []CPEKey
}

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

// itemKeys holds the indices into Keys of the keys one item uses; -1 or empty
// for none. pkgs holds one package key per ecosystem whose rows apply to the
// item's package (ecosystem.ReleaseStreams).
type itemKeys struct {
	pkgs       []int
	cpes       []int
	cnaNames   []int
	cnaPackage int
	near       []int
	// otherProducts are the CNA products the item's CNA rows must not be read
	// as (otherProducts in names.go).
	otherProducts []CNAName
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
		use := itemKeys{cnaPackage: -1}
		switch {
		case item.Error != nil:
		case item.Package != nil:
			eco, name := item.Package.Ecosystem, item.Package.Name
			for _, stream := range ecosystem.ReleaseStreams(eco) {
				key := PackageKey{Ecosystem: stream, Name: ecosystem.FoldPackageName(stream, name)}
				use.pkgs = append(use.pkgs, add(&b.packages, &b.keys.Packages, key))
			}
			// The CNA describes the upstream package, not a distro's build of it.
			if key := ecosystem.PackageKeyFor(eco, name); !ecosystem.IsDistro(eco) && key != "" {
				use.cnaPackage = add(&b.cnaPackages, &b.keys.CNAPackageKeys, key)
			}
		case item.Product != nil:
			p := *item.Product
			use.otherProducts = OtherProductsFor(p)
			names, cpes, _ := NamesFor(p)
			// Every spelling NamesFor lists is this product, with the item's part.
			var vendorRanges []CPEKey
			for _, cpe := range cpes {
				use.cpes = append(use.cpes, b.addCPE(CPEKeyFor("cpe:2.3:"+p.Part+":"+cpe+":"), item.Version))
				if r := CPEKeyFor("cpe:2.3:" + p.Part + ":" + splitCPE(cpe)[0] + ":"); !slices.Contains(vendorRanges, r) {
					vendorRanges = append(vendorRanges, r)
				}
			}
			for _, n := range names {
				k := add(&b.cnaNames, &b.keys.CNANames, CNANameKeyFor(n))
				if !slices.Contains(use.cnaNames, k) {
					use.cnaNames = append(use.cnaNames, k)
				}
			}
			for _, n := range nearbyNames(p) {
				vendor := strings.ToLower(n.Vendor)
				use.near = append(use.near, b.addNear(CNANearKey{
					V: cutRunes(vendor, cnaNameRunes), FullVendor: vendor, Fragment: strings.ToLower(n.Product), VendorRanges: vendorRanges,
				}))
			}
		}
		uses[i] = use
	}
	for i, floor := range b.cpeFloors {
		b.keys.CPEPrefixes[i].Floor = floor.lowest
	}
	return b.keys, uses
}

// cpeFloor follows the versions of the items that use one CPE key: lowest is
// the lowest dotted-number version so far, "" while there is none. A version
// that is not dotted numbers is passed over: every row answers invalid_version
// for it, so it needs no row the floor leaves out (EvaluateCPERows).
type cpeFloor struct{ lowest string }

// keyBuilder holds Keys with an index of each slice, so each key is added once.
type keyBuilder struct {
	keys        Keys
	packages    map[PackageKey]int
	cpes        map[CPEKey]int // by Lo and Hi; Floor is set once every item is seen
	cpeFloors   []cpeFloor     // one per CPE key
	cnaNames    map[CNANameKey]int
	cnaPackages map[string]int
	near        map[string]int // by nearKeyID
}

// add returns key's position in keys, appending it the first time it is seen.
func add[K comparable](index *map[K]int, keys *[]K, key K) int {
	return addByID(index, keys, key, key)
}

// addByID is add for a key identified by id, for a key type that cannot be a
// map key itself.
func addByID[I comparable, K any](index *map[I]int, keys *[]K, id I, key K) int {
	if *index == nil {
		*index = map[I]int{}
	}
	if i, ok := (*index)[id]; ok {
		return i
	}
	(*index)[id] = len(*keys)
	*keys = append(*keys, key)
	return len(*keys) - 1
}

// addNear returns a nearby-name key's position in Keys.CNANear, appending it the
// first time it is seen.
func (b *keyBuilder) addNear(k CNANearKey) int {
	return addByID(&b.near, &b.keys.CNANear, nearKeyID(k), k)
}

// nearKeyID identifies a nearby-name key by all of its fields, joined by "\x00".
// No field holds "\x00": parseCPE takes only printable ASCII, and the name
// table's names are lower-case text.
func nearKeyID(k CNANearKey) string {
	fields := []string{k.V, k.FullVendor, k.Fragment}
	for _, r := range k.VendorRanges {
		fields = append(fields, r.Prefix)
	}
	return strings.Join(fields, "\x00")
}

// addCPE returns the position in Keys.CPEPrefixes of key, which has no floor
// yet, appending it the first time it is seen, and takes ver, the version of
// an item that uses it, into the key's floor.
func (b *keyBuilder) addCPE(key CPEKey, ver string) int {
	i := add(&b.cpes, &b.keys.CPEPrefixes, key)
	if i == len(b.cpeFloors) {
		b.cpeFloors = append(b.cpeFloors, cpeFloor{})
	}
	f := &b.cpeFloors[i]
	// NumericOrder refuses a version that is not dotted numbers.
	if _, err := version.NumericOrder(ver, ver); err != nil {
		return i
	}
	if c, _ := version.NumericOrder(ver, f.lowest); f.lowest == "" || c < 0 {
		f.lowest = ver
	}
	return i
}

// CNANameKeyFor builds the key for one CNA name, as CNANameKey describes.
func CNANameKeyFor(n CNAName) CNANameKey {
	vendor, product := strings.ToLower(n.Vendor), strings.ToLower(n.Product)
	lo := cutRunes(product, cnaNameRunes)
	if n.Prefix {
		return CNANameKey{V: cutRunes(vendor, cnaNameRunes), Lo: lo, Hi: nextPrefix(lo), FullVendor: vendor}
	}
	return CNANameKey{V: cutRunes(vendor, cnaNameRunes), Lo: lo, Hi: lo + "\x01", FullVendor: vendor, FullProduct: product}
}

// cutRunes returns the first max runes of s, as SQL left(s, max) does.
func cutRunes(s string, max int) string {
	n := 0
	for i := range s {
		if n == max {
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
