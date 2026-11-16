// ABOUTME: Canonicalizes JSON hash input per RFC 8785 (JSON Canonicalization Scheme).
// ABOUTME: material_hash and match_inputs_hash both hash the output of canonicalJSON.
package merge

import (
	"encoding/json/jsontext"
	"slices"
)

// canonicalJSON returns the RFC 8785 canonical form of raw: object members
// sorted by UTF-16 code units, no insignificant whitespace, numbers in their
// shortest ECMAScript form and strings with minimal escaping. It fails on input
// that is not valid JSON, has duplicate object member names or holds invalid
// UTF-8, none of which encoding/json's Marshal produces. raw is not modified.
func canonicalJSON(raw []byte) ([]byte, error) {
	v := jsontext.Value(slices.Clone(raw))
	err := v.Canonicalize()
	return v, err
}
