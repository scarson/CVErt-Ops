// ABOUTME: Tests for the JoinForFTS full-text search helper.
// ABOUTME: Covers nil, empty, single-term, and multi-term inputs.
package merge

import (
	"testing"
)

func TestJoinForFTS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []string
		want  string
	}{
		{
			name:  "nil slice",
			input: nil,
			want:  "",
		},
		{
			name:  "empty slice",
			input: []string{},
			want:  "",
		},
		{
			name:  "single term",
			input: []string{"buffer-overflow"},
			want:  "buffer-overflow",
		},
		{
			name:  "multiple terms",
			input: []string{"CWE-79", "CWE-89", "CWE-502"},
			want:  "CWE-79 CWE-89 CWE-502",
		},
		{
			name:  "terms with spaces preserved",
			input: []string{"foo bar", "baz"},
			want:  "foo bar baz",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := JoinForFTS(tc.input)
			if got != tc.want {
				t.Errorf("JoinForFTS(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
