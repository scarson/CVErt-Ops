// ABOUTME: Tests that cve_id eq, neq, in and not_in compare a CVE ID in any case with the stored upper-case ID.
// ABOUTME: Other identifiers, such as GHSA IDs, which are mixed case, are compared as written.
package dsl_test

import (
	"reflect"
	"testing"

	"github.com/lib/pq"
)

func TestCompile_CVEIDValuesTakeTheStoredCase(t *testing.T) {
	t.Parallel()
	tests := []struct {
		cond string
		want any
	}{
		{`{"field":"cve_id","operator":"eq","value":"cve-2024-1234"}`, "CVE-2024-1234"},
		{`{"field":"cve_id","operator":"neq","value":"Cve-2024-1234"}`, "CVE-2024-1234"},
		{`{"field":"cve_id","operator":"eq","value":"GHSA-abcd-EFGH-ijkl"}`, "GHSA-abcd-EFGH-ijkl"},
		{`{"field":"cve_id","operator":"in","value":["cve-2024-1","GHSA-abcd-EFGH-ijkl","CVE-2024-2"]}`,
			pq.StringArray{"CVE-2024-1", "GHSA-abcd-EFGH-ijkl", "CVE-2024-2"}},
		{`{"field":"cve_id","operator":"not_in","value":["cve-2024-1"]}`, pq.StringArray{"CVE-2024-1"}},
		// Not a whole CVE ID: compared as written.
		{`{"field":"cve_id","operator":"eq","value":"cve-2024-1234x"}`, "cve-2024-1234x"},
	}
	for _, tt := range tests {
		c := compileRule(t, ruleJSON("and", tt.cond), nil)
		_, args := whereOf(t, c, nil)
		if len(args) != 1 {
			t.Fatalf("%s: args = %v, want one", tt.cond, args)
		}
		got := args[0]
		if a, ok := got.(*pq.StringArray); ok {
			got = *a
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: arg = %#v, want %#v", tt.cond, got, tt.want)
		}
	}
}
