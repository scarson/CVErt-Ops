// ABOUTME: Canonicalizes JSON hash input per RFC 8785 (JSON Canonicalization Scheme).
// ABOUTME: material_hash and match_inputs_hash both hash the output of canonicalJSON.
package merge

import (
	jsoncanonical "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// canonicalJSON returns the RFC 8785 canonical form of raw: object members
// sorted by UTF-16 code units, no insignificant whitespace, numbers in their
// shortest ECMAScript form and strings with minimal escaping. It fails only on
// input that is not valid JSON.
func canonicalJSON(raw []byte) ([]byte, error) {
	return jsoncanonical.Transform(raw)
}
