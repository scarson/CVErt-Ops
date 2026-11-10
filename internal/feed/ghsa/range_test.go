// ABOUTME: Tests that GHSA vulnerable_version_range strings convert to range bounds and OSV events.
// ABOUTME: The range grammar itself is tested with version.ParseRangeExpression.
package ghsa

import (
	"encoding/json"
	"testing"
)

// The conversion keeps every bound, and the advisory's ecosystem decides whether
// the first patched version sorts above an inclusive upper bound.
func TestParseVulnerableRange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, eco, raw, patched string
		want                    rangeBounds
		wantOK                  bool
	}{
		{"lower and exclusive upper", "RubyGems", ">= 1.8.0, < 1.11.4", "1.11.4", rangeBounds{Introduced: "1.8.0", Fixed: "1.11.4"}, true},
		{"inclusive upper unpatched", "RubyGems", "<= 0.2.0", "", rangeBounds{Introduced: "0", LastAffected: "0.2.0"}, true},
		{"inclusive upper patched", "RubyGems", "<= 0.9.0", "0.10.0", rangeBounds{Introduced: "0", Fixed: "0.10.0"}, true},
		{"no comparator keeps declared bound", "GitHub Actions", "<= 2.0", "3.0", rangeBounds{Introduced: "0", LastAffected: "2.0"}, true},
		{"garbage", "RubyGems", "banana", "", rangeBounds{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseVulnerableRange(tt.eco, tt.raw, tt.patched)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("got %+v ok=%v, want %+v ok=%v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestBoundsEvents(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		bounds rangeBounds
		want   string
	}{
		{"fixed", rangeBounds{Introduced: "1.0", Fixed: "2.0"}, `[{"introduced":"1.0"},{"fixed":"2.0"}]`},
		{"last affected", rangeBounds{Introduced: "1.0", LastAffected: "1.5"}, `[{"introduced":"1.0"},{"last_affected":"1.5"}]`},
		{"open ended", rangeBounds{Introduced: "1.0"}, `[{"introduced":"1.0"}]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := boundsEvents(tt.bounds); string(got) != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
	if got := boundsEvents(rangeBounds{}); got != nil {
		t.Errorf("no bounds: got %s, want nil", json.RawMessage(got))
	}
}
