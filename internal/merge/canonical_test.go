// ABOUTME: Tests canonicalJSON's RFC 8785 output byte for byte, the input material_hash and match_inputs_hash hash.
// ABOUTME: Each value is marshaled with encoding/json as the hash code does, then compared to a literal canonical form.
package merge

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
)

func float64Ptr(f float64) *float64 { return &f }

// canonicalCases are Go values covering every value kind that MaterialFields
// and matchInputs marshal (strings, bools, float64 pointers, string slices,
// [2]string arrays, slices of structs), plus numbers at float64 boundaries,
// every string escape encoding/json emits, and object keys whose UTF-16 order
// differs from their UTF-8 order. Each value is wrapped as {"v": value}, since
// the hash code always canonicalizes a JSON object. want is the RFC 8785 form;
// the RFC's reference Go implementation produced the same bytes for every case.
var canonicalCases = []struct {
	name  string
	want  string
	value any
}{
	// Floats used by CVSS and EPSS scores.
	{"cvss 9.8", "{\"v\":9.8}", 9.8},
	{"cvss 10.0", "{\"v\":10}", 10.0},
	{"cvss 0.1", "{\"v\":0.1}", 0.1},
	{"cvss 7.25", "{\"v\":7.25}", 7.25},
	{"cvss 4.35", "{\"v\":4.35}", 4.35},
	{"epss 0.00043", "{\"v\":0.00043}", 0.00043},
	{"epss 1e-7", "{\"v\":1e-7}", 1e-7},
	{"1e-6", "{\"v\":0.000001}", 1e-6},
	{"one third", "{\"v\":0.3333333333333333}", 1.0 / 3},
	{"negative", "{\"v\":-1.5}", -1.5},
	{"zero", "{\"v\":0}", 0.0},
	{"negative zero", "{\"v\":0}", math.Copysign(0, -1)},
	{"negative zero pointer", "{\"v\":0}", float64Ptr(math.Copysign(0, -1))},
	{"nil float pointer", "{\"v\":null}", (*float64)(nil)},
	// Float64 boundaries and exponent switch points.
	{"smallest subnormal", "{\"v\":5e-324}", 5e-324},
	{"smallest normal", "{\"v\":2.2250738585072014e-308}", 2.2250738585072014e-308},
	{"largest float64", "{\"v\":1.7976931348623157e+308}", 1.7976931348623157e308},
	{"1e20", "{\"v\":100000000000000000000}", 1e20},
	{"1e21", "{\"v\":1e+21}", 1e21},
	{"-1e21", "{\"v\":-1e+21}", -1e21},
	{"max safe integer as float", "{\"v\":9007199254740991}", 9007199254740991.0},
	// Integers beyond 2^53 lose precision in both implementations.
	{"int64 2^53+1", "{\"v\":9007199254740992}", int64(9007199254740993)},
	{"int64 123456789012345678", "{\"v\":123456789012345680}", int64(123456789012345678)},
	{"int64 -2^53-1", "{\"v\":-9007199254740992}", int64(-9007199254740993)},
	{"max uint64", "{\"v\":18446744073709552000}", uint64(math.MaxUint64)},
	{"int 42", "{\"v\":42}", 42},
	// Strings, including every escape encoding/json emits.
	{"empty string", "{\"v\":\"\"}", ""},
	{"latin e acute", "{\"v\":\"\u00e9\"}", "\u00e9"},
	{"cjk", "{\"v\":\"\u65e5\u672c\"}", "\u65e5\u672c"},
	{"html characters", "{\"v\":\"<>&\"}", "<>&"},
	{"line separator", "{\"v\":\"\u2028\"}", "\u2028"},
	{"paragraph separator", "{\"v\":\"\u2029\"}", "\u2029"},
	{"replacement character", "{\"v\":\"\ufffd\"}", "\ufffd"},
	{"invalid UTF-8 byte", "{\"v\":\"a\ufffdb\"}", "a\xffb"},
	{"UTF-8 encoded surrogate", "{\"v\":\"\ufffd\ufffd\ufffd\"}", "\xed\xa0\x80"},
	{"astral emoji", "{\"v\":\"\U0001f600\"}", "\U0001f600"},
	{"control 0x01", "{\"v\":\"\\u0001\"}", "\x01"},
	{"control 0x00", "{\"v\":\"\\u0000\"}", "\x00"},
	{"control 0x1f", "{\"v\":\"\\u001f\"}", "\x1f"},
	{"delete 0x7f", "{\"v\":\"\x7f\"}", "\x7f"},
	{"tab", "{\"v\":\"\\t\"}", "\t"},
	{"short escapes", "{\"v\":\"\\b\\f\\n\\r\"}", "\b\f\n\r"},
	{"quote and backslash", "{\"v\":\"\\\"\\\\\"}", "\"\\"},
	{"slash", "{\"v\":\"a/b\"}", "a/b"},
	{"mixed", "{\"v\":\"x<\u2028>\u00e9\\t\\u0001&\\\"y\"}", "x<\u2028>\u00e9\t\x01&\"y"},
	// Booleans and null.
	{"true", "{\"v\":true}", true},
	{"false", "{\"v\":false}", false},
	{"null", "{\"v\":null}", nil},
	// Containers.
	{"empty string slice", "{\"v\":[]}", []string{}},
	{"nil string slice", "{\"v\":null}", []string(nil)},
	{"empty map", "{\"v\":{}}", map[string]any{}},
	{"empty struct", "{\"v\":{}}", struct{}{}},
	{"empty pair slice", "{\"v\":[]}", [][2]string{}},
	{"string slice", "{\"v\":[\"cpe:2.3:a:openssl:openssl\",\"CWE-79\"]}", []string{"cpe:2.3:a:openssl:openssl", "CWE-79"}},
	{"pair slice", "{\"v\":[[\"node.js\",\"node.js\"],[\"openssl\",\"openssl\"]]}", [][2]string{{"node.js", "node.js"}, {"openssl", "openssl"}}},
	{"struct fields not in sorted order", "{\"v\":{\"alpha\":1,\"mid\":[\"b\",\"a\"],\"zeta\":\"z\"}}", struct {
		Zeta  string   `json:"zeta"`
		Alpha int      `json:"alpha"`
		Mid   []string `json:"mid"`
	}{"z", 1, []string{"b", "a"}}},
	{"map with unsorted keys", "{\"v\":{\"Mid\":true,\"_\":null,\"alpha\":\"a\",\"zeta\":1}}", map[string]any{"zeta": 1, "alpha": "a", "Mid": true, "_": nil}},
	{"keys ordered by UTF-16 code units", "{\"v\":{\"z\":4,\"\u00e9\":3,\"\U0001f600\":2,\"\ue000\":1}}", map[string]any{
		"\ue000":     1,
		"\U0001f600": 2,
		"\u00e9":     3,
		"z":          4,
	}},
	{"keys needing escapes", "{\"v\":{\"\\u0001\":4,\"\\\"\":3,\"&\":5,\"<\":1,\"\u2028\":2}}", map[string]any{"<": 1, "\u2028": 2, "\"": 3, "\x01": 4, "&": 5}},
	{"nested arrays of objects", "{\"v\":[{\"a\":[{\"x\":\"q\",\"y\":2.5}],\"b\":1},[{\"c\":[],\"d\":false}],{}]}", []any{
		map[string]any{"b": 1, "a": []any{map[string]any{"y": 2.5, "x": "q"}}},
		[]any{map[string]any{"d": false, "c": []any{}}},
		map[string]any{},
	}},
	{"material fields", "{\"v\":{\"affected_cpes\":[],\"affected_packages\":[{\"ecosystem\":\"npm\",\"fixed\":\"1.2.3\",\"introduced\":\"0\",\"package_name\":\"<pkg>\"},{\"ecosystem\":\"PyPI\",\"last_affected\":\"2.0\",\"package_name\":\"\u00e9t\",\"range_class\":\"ecosystem\"}],\"cvss_v3_score\":9.8,\"cvss_v3_vector\":\"CVSS:3.1/A:H/AC:L/AV:N/C:H/I:H/PR:N/S:U/UI:N\",\"cvss_v4_vector\":\"\",\"cwe_ids\":[\"CWE-22\",\"CWE-79\"],\"exploit_available\":true,\"in_cisa_kev\":false,\"severity\":\"critical\",\"status\":\"published\"}}", MaterialFields{
		Status:       "published",
		Severity:     "critical",
		CVSSv3Score:  float64Ptr(9.8),
		CVSSv3Vector: "CVSS:3.1/A:H/AC:L/AV:N/C:H/I:H/PR:N/S:U/UI:N",
		CVSSv4Vector: "",
		CWEIDs:       []string{"CWE-22", "CWE-79"},
		ExploitAvail: true,
		InCISAKEV:    false,
		AffectedPkgs: []affectedPkgKey{
			{Ecosystem: "npm", PackageName: "<pkg>", Introduced: "0", Fixed: "1.2.3"},
			{Ecosystem: "PyPI", PackageName: "\u00e9t", LastAffected: "2.0", RangeClass: "ecosystem"},
		},
		AffectedCPEs: []string{},
	}},
	{"match inputs", "{\"v\":{\"cna\":[[\"\",\"\"],[\"node.js\",\"node.js\"]],\"cpe\":[\"a:openssl:openssl\"]}}", matchInputs{
		CNA: [][2]string{{"", ""}, {"node.js", "node.js"}},
		CPE: []string{"a:openssl:openssl"},
	}},
}

// TestCanonical_RFC8785Output pins canonicalJSON's output for every case, so a
// change in canonicalization that would move material_hash or
// match_inputs_hash fails here with the differing bytes.
func TestCanonical_RFC8785Output(t *testing.T) {
	t.Parallel()
	for _, tc := range canonicalCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, err := json.Marshal(map[string]any{"v": tc.value})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			before := bytes.Clone(raw)
			got, err := canonicalJSON(raw)
			if err != nil {
				t.Fatalf("canonicalJSON(%s): %v", raw, err)
			}
			if string(got) != tc.want {
				t.Errorf("canonicalJSON(%s)\n got: %s\nwant: %s", raw, got, tc.want)
			}
			if !bytes.Equal(raw, before) {
				t.Errorf("canonicalJSON modified its input: %s, was %s", raw, before)
			}
		})
	}
}

// TestCanonical_RejectsInvalidInput requires canonicalJSON to fail on input
// encoding/json's Marshal never produces, so ComputeMaterialHash and
// ComputeMatchInputsHash panic rather than hash it.
func TestCanonical_RejectsInvalidInput(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		`{"a":1,"a":2}`,
		"{\"a\":\"\xff\"}",
		`{"a":1}x`,
		`{"a":1} {"b":2}`,
		`{"a":01}`,
		`{"a":}`,
		``,
	} {
		if got, err := canonicalJSON([]byte(in)); err == nil {
			t.Errorf("canonicalJSON(%q) = %q, want an error", in, got)
		}
	}
}
