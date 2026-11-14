// ABOUTME: Computes match_inputs_hash: the rule match inputs that are not material_hash inputs.
// ABOUTME: CNA vendor and product names and the part:vendor:product of NVD vulnerable CPE matches (design section 7).
package merge

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	jsoncanonical "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"

	"github.com/scarson/cvert-ops/internal/check"
	"github.com/scarson/cvert-ops/internal/feed"
)

// matchInputs is the JSON document match_inputs_hash covers. CNA holds
// [vendor, product] pairs and CPE holds part:vendor:product keys, each list
// sorted and distinct.
type matchInputs struct {
	CNA [][2]string `json:"cna"`
	CPE []string    `json:"cpe"`
}

// ComputeMatchInputsHash returns the hex-encoded SHA-256 of the JCS (RFC 8785)
// serialization of the alert rule match inputs that material_hash leaves out:
//   - each CNA row's vendor and product, ASCII lower-cased, a missing value as "";
//   - the CPEProductKey of each CPE match with Vulnerable set.
//
// A change to it re-checks the CVE against alert rules without moving
// material_hash, so rules whose match did not change do not fire again
// (MATCH-2 design section 7). Versions and every other field are left out.
//
// Only ASCII A to Z are lower-cased. strings.ToLower also folds non-ASCII
// letters, such as KELVIN SIGN to "k", that PostgreSQL's lower() does not fold
// under some database character types, so a change between them could change
// a SQL match while leaving a fully lower-cased hash unchanged. Two values equal
// after ASCII lower-casing differ only in ASCII case, which every lower() folds
// alike, so this hash moves whenever the match can change.
func ComputeMatchInputsHash(cna []feed.CNAAffected, cpe []feed.CPEMatch) string {
	in := matchInputs{CNA: make([][2]string, 0, len(cna)), CPE: make([]string, 0, len(cpe))}
	for _, a := range cna {
		in.CNA = append(in.CNA, [2]string{lowerASCII(a.Vendor), lowerASCII(a.Product)})
	}
	for _, m := range cpe {
		if !m.Vulnerable {
			continue
		}
		// A CPE with no product component can match no product condition.
		if key := check.CPEProductKey(m.CPENormalized); key != "" {
			in.CPE = append(in.CPE, key)
		}
	}
	slices.SortFunc(in.CNA, func(a, b [2]string) int {
		return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1]))
	})
	in.CNA = slices.Compact(in.CNA)
	slices.Sort(in.CPE)
	in.CPE = slices.Compact(in.CPE)

	raw, err := json.Marshal(in)
	if err != nil {
		// json.Marshal on string arrays never fails.
		panic(fmt.Sprintf("merge: marshal match inputs: %v", err))
	}
	jcs, err := jsoncanonical.Transform(raw)
	if err != nil {
		// JCS transform fails only on invalid JSON, which cannot happen here.
		panic(fmt.Sprintf("merge: JCS transform of match inputs: %v", err))
	}
	sum := sha256.Sum256(jcs)
	return hex.EncodeToString(sum[:])
}

// lowerASCII lower-cases ASCII A to Z and leaves every other rune as it is.
func lowerASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}
