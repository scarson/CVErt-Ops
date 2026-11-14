// ABOUTME: Unit tests for ComputeMatchInputsHash over CNA names and vulnerable CPE match keys.
// ABOUTME: Covers ordering, duplicates, ASCII-only case folding, the vulnerable flag, and inputs that must not count.
package merge

import (
	"testing"

	"github.com/scarson/cvert-ops/internal/feed"
)

const (
	nodeCPE   = "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"
	opensslCPE = "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"
)

func TestComputeMatchInputsHash_CaseOnlyCNACopiesHashAlike(t *testing.T) {
	t.Parallel()
	// MITRE carries the CNA's spelling, and NVD's relay of the same record can
	// differ only in ASCII case. lower() folds both alike, so the match is the same.
	mitre := []feed.CNAAffected{{Vendor: "Node.js", Product: "Node.js"}}
	nvd := []feed.CNAAffected{{Vendor: "node.js", Product: "node.js"}}
	if a, b := ComputeMatchInputsHash(mitre, nil), ComputeMatchInputsHash(nvd, nil); a != b {
		t.Errorf("Node.js and node.js copies hash differently: %s vs %s", a, b)
	}
}

func TestComputeMatchInputsHash_KelvinSignDiffersFromK(t *testing.T) {
	t.Parallel()
	// strings.ToLower maps KELVIN SIGN (U+212A) to "k". PostgreSQL's lower() may
	// not, so a change from one to the other can change a SQL match and must
	// change the hash.
	kelvin := []feed.CNAAffected{{Vendor: "v", Product: string(rune(0x212A)) + "node"}}
	ascii := []feed.CNAAffected{{Vendor: "v", Product: "knode"}}
	if a, b := ComputeMatchInputsHash(kelvin, nil), ComputeMatchInputsHash(ascii, nil); a == b {
		t.Errorf("KELVIN SIGN + node and knode hash alike (%s), want different hashes", a)
	}
}

func TestComputeMatchInputsHash_OrderAndDuplicatesDoNotCount(t *testing.T) {
	t.Parallel()
	cna := []feed.CNAAffected{
		{Vendor: "nodejs", Product: "node"},
		{Vendor: "openssl", Product: "openssl"},
	}
	cpe := []feed.CPEMatch{
		{CPENormalized: nodeCPE, Vulnerable: true},
		{CPENormalized: opensslCPE, Vulnerable: true},
	}
	base := ComputeMatchInputsHash(cna, cpe)

	reordered := ComputeMatchInputsHash(
		[]feed.CNAAffected{cna[1], cna[0]},
		[]feed.CPEMatch{cpe[1], cpe[0]},
	)
	if reordered != base {
		t.Errorf("reordered inputs hash %s, want %s", reordered, base)
	}

	// The same pair in another case, and a second range of one CPE product,
	// add no distinct entry.
	duplicated := ComputeMatchInputsHash(
		append(cna, feed.CNAAffected{Vendor: "NodeJS", Product: "Node"}),
		append(cpe, feed.CPEMatch{CPENormalized: "cpe:2.3:a:nodejs:node.js:20.1.0:*:*:*:*:*:*:*", Vulnerable: true}),
	)
	if duplicated != base {
		t.Errorf("duplicated inputs hash %s, want %s", duplicated, base)
	}
}

func TestComputeMatchInputsHash_VulnerableFlag(t *testing.T) {
	t.Parallel()
	vulnerable := ComputeMatchInputsHash(nil, []feed.CPEMatch{{CPENormalized: nodeCPE, Vulnerable: true}})
	notVulnerable := ComputeMatchInputsHash(nil, []feed.CPEMatch{{CPENormalized: nodeCPE, Vulnerable: false}})
	empty := ComputeMatchInputsHash(nil, nil)

	if vulnerable == notVulnerable {
		t.Error("flipping vulnerable did not change the hash")
	}
	if notVulnerable != empty {
		t.Errorf("a non-vulnerable match changed the hash: %s, want the empty hash %s", notVulnerable, empty)
	}
	// A non-vulnerable match beside a vulnerable one adds nothing either.
	both := ComputeMatchInputsHash(nil, []feed.CPEMatch{
		{CPENormalized: nodeCPE, Vulnerable: true},
		{CPENormalized: opensslCPE, Vulnerable: false},
	})
	if both != vulnerable {
		t.Errorf("a non-vulnerable match beside a vulnerable one changed the hash: %s, want %s", both, vulnerable)
	}
}

func TestComputeMatchInputsHash_CNARowsCount(t *testing.T) {
	t.Parallel()
	one := []feed.CNAAffected{{Vendor: "nodejs", Product: "node"}}
	two := append([]feed.CNAAffected{{Vendor: "openssl", Product: "openssl"}}, one...)
	if ComputeMatchInputsHash(one, nil) == ComputeMatchInputsHash(two, nil) {
		t.Error("adding a CNA row did not change the hash")
	}

	// A CNA product correction from n/a to a name changes the hash.
	na := []feed.CNAAffected{{Vendor: "nodejs", Product: "n/a"}}
	if ComputeMatchInputsHash(na, nil) == ComputeMatchInputsHash(one, nil) {
		t.Error("changing the CNA product did not change the hash")
	}

	// Vendor and product stay paired: swapping them across rows is a change.
	paired := []feed.CNAAffected{{Vendor: "a", Product: "b"}, {Vendor: "c", Product: "d"}}
	swapped := []feed.CNAAffected{{Vendor: "a", Product: "d"}, {Vendor: "c", Product: "b"}}
	if ComputeMatchInputsHash(paired, nil) == ComputeMatchInputsHash(swapped, nil) {
		t.Error("re-pairing vendors and products did not change the hash")
	}

	// A missing vendor is "", which is not the same as a product-only row
	// holding the vendor's name.
	noVendor := []feed.CNAAffected{{Product: "node"}}
	noProduct := []feed.CNAAffected{{Vendor: "node"}}
	if ComputeMatchInputsHash(noVendor, nil) == ComputeMatchInputsHash(noProduct, nil) {
		t.Error("a row with no vendor and a row with no product hash alike")
	}
}

func TestComputeMatchInputsHash_OtherFieldsDoNotCount(t *testing.T) {
	t.Parallel()
	cna := []feed.CNAAffected{{Vendor: "nodejs", Product: "node"}}
	cpe := []feed.CPEMatch{{CPENormalized: nodeCPE, Vulnerable: true}}
	base := ComputeMatchInputsHash(cna, cpe)

	cnaVersions := []feed.CNAAffected{{
		Vendor: "nodejs", Product: "node", PackageName: "node", CollectionURL: "https://example.test",
		PackageKey: "npm/node", DefaultStatus: "affected",
		Versions: []feed.CNAVersion{{Version: "20.0.0", LessThan: "20.1.0", Status: "affected"}},
	}}
	cpeVersions := []feed.CPEMatch{{
		CPE: "cpe:2.3:a:NodeJS:Node.js:*:*:*:*:*:*:*:*", CPENormalized: nodeCPE,
		VersionStartIncluding: "20.0.0", VersionEndExcluding: "20.1.0", Vulnerable: true,
	}}
	if got := ComputeMatchInputsHash(cnaVersions, cpeVersions); got != base {
		t.Errorf("versions and other fields changed the hash: %s, want %s", got, base)
	}
}

func TestComputeMatchInputsHash_EmptyIsStable(t *testing.T) {
	t.Parallel()
	nilHash := ComputeMatchInputsHash(nil, nil)
	emptyHash := ComputeMatchInputsHash([]feed.CNAAffected{}, []feed.CPEMatch{})
	if nilHash != emptyHash {
		t.Errorf("nil and empty inputs hash %s and %s, want one hash", nilHash, emptyHash)
	}
	if len(nilHash) != 64 {
		t.Errorf("hash %q is not 64 hex characters", nilHash)
	}
}
