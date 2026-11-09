// ABOUTME: Tests that every vulnerable_version_range form maps to the right range bounds.
// ABOUTME: Strings are taken from real reviewed GHSA advisories.
package ghsa

import (
	"encoding/json"
	"testing"
)

func TestParseVulnerableRange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, raw, patched string
		want               rangeBounds
		wantOK             bool
	}{
		{"lower and exclusive upper", ">= 1.8.0, < 1.11.4", "1.11.4", rangeBounds{Introduced: "1.8.0", Fixed: "1.11.4"}, true},
		{"lower and exclusive upper unpatched", ">= 3.3.0, < 3.9.0", "", rangeBounds{Introduced: "3.3.0", Fixed: "3.9.0"}, true},
		{"exclusive upper only", "< 1.3.2", "1.3.2", rangeBounds{Introduced: "0", Fixed: "1.3.2"}, true},
		{"exclusive upper only unpatched", "< 2.0.4", "", rangeBounds{Introduced: "0", Fixed: "2.0.4"}, true},
		{"exclusive upper wins over patched", "< 2.0", "1.9.5", rangeBounds{Introduced: "0", Fixed: "2.0"}, true},
		{"lower and inclusive upper patched", ">= 4.2.0, <= 4.2.7.0", "4.2.7.1", rangeBounds{Introduced: "4.2.0", Fixed: "4.2.7.1"}, true},
		{"lower and inclusive upper unpatched", ">= 1.3, <= 1.3.1", "", rangeBounds{Introduced: "1.3", LastAffected: "1.3.1"}, true},
		{"inclusive upper patched", "<= 0.9.0", "0.10.0", rangeBounds{Introduced: "0", Fixed: "0.10.0"}, true},
		{"inclusive upper unpatched", "<= 0.2.0", "", rangeBounds{Introduced: "0", LastAffected: "0.2.0"}, true},
		{"exact patched", "= 5.0.0", "5.0.0.1", rangeBounds{Introduced: "5.0.0", Fixed: "5.0.0.1"}, true},
		{"exact unpatched", "= 0.7.246", "", rangeBounds{Introduced: "0.7.246", LastAffected: "0.7.246"}, true},
		{"exact with suffix", "= 2.6.3-CUSTOM", "", rangeBounds{Introduced: "2.6.3-CUSTOM", LastAffected: "2.6.3-CUSTOM"}, true},
		{"open from a version", ">= 1.0.0", "", rangeBounds{Introduced: "1.0.0"}, true},
		{"open from a version patched", ">= 1.0.0", "2.0.0", rangeBounds{Introduced: "1.0.0", Fixed: "2.0.0"}, true},
		{"from zero", ">= 0", "", rangeBounds{Introduced: "0"}, true},
		{"from zero dotted", ">= 0.0.0", "", rangeBounds{Introduced: "0"}, true},
		{"exclusive zero", "> 0", "", rangeBounds{Introduced: "0"}, true},
		{"exclusive zero dotted with upper", "> 0.0.0, < 3.4.0", "3.4.0", rangeBounds{Introduced: "0", Fixed: "3.4.0"}, true},
		{"exclusive lower", "> 0.7.1, < 1.0.4", "1.0.4", rangeBounds{Introduced: "0.7.1", Fixed: "1.0.4"}, true},
		{"exclusive lower inclusive upper patched", "> 1.4.1, <= 1.5", "1.5.1", rangeBounds{Introduced: "1.4.1", Fixed: "1.5.1"}, true},
		{"exclusive lower inclusive upper unpatched", "> 0.0.12, <= 1.1.39", "", rangeBounds{Introduced: "0.0.12", LastAffected: "1.1.39"}, true},
		{"exclusive lower only", "> 2.0", "", rangeBounds{Introduced: "2.0"}, true},
		{"go pseudo versions", "> 0.0.0-20201116123734-de1c1243f4dd, < 0.0.0-20210518124745-db7f0bcec27b", "0.0.0-20210518124745-db7f0bcec27b", rangeBounds{Introduced: "0.0.0-20201116123734-de1c1243f4dd", Fixed: "0.0.0-20210518124745-db7f0bcec27b"}, true},
		{"prerelease lower", ">= 2.0-beta9, < 2.3.1", "2.3.1", rangeBounds{Introduced: "2.0-beta9", Fixed: "2.3.1"}, true},
		{"qualifier upper", "<= 1.2.1.2-jre17", "", rangeBounds{Introduced: "0", LastAffected: "1.2.1.2-jre17"}, true},
		{"patched below inclusive upper keeps the declared range", ">= 1.0.0, <= 3.0.0", "2.0.0", rangeBounds{Introduced: "1.0.0", LastAffected: "3.0.0"}, true},
		{"patched equal to inclusive upper keeps the declared range", "<= 2.0.0", "2.0.0", rangeBounds{Introduced: "0", LastAffected: "2.0.0"}, true},
		{"patched equal to exact version keeps the declared version", "= 1.0.0", "1.0.0", rangeBounds{Introduced: "1.0.0", LastAffected: "1.0.0"}, true},
		{"patched not above open lower bound stays open", ">= 1.0.0", "0.9.0", rangeBounds{Introduced: "1.0.0"}, true},
		{"empty with patched", "", "4.17.21", rangeBounds{Introduced: "0", Fixed: "4.17.21"}, true},
		{"empty unpatched", "", "", rangeBounds{}, false},
		{"not-equal operator", "!= 1.0", "", rangeBounds{}, false},
		{"three constraints", ">= 1.0, < 2.0, < 3.0", "", rangeBounds{}, false},
		{"two lower bounds", ">= 1.0, > 2.0", "", rangeBounds{}, false},
		{"two upper bounds", "< 1.0, <= 2.0", "", rangeBounds{}, false},
		{"exact with another constraint", "= 1.0, < 2.0", "", rangeBounds{}, false},
		{"garbage", "banana", "", rangeBounds{}, false},
		{"operator with no version", ">=", "", rangeBounds{}, false},
		{"inclusive upper with no version", "<=", "", rangeBounds{}, false},
		{"doubled operator", ">=> 1.0", "", rangeBounds{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseVulnerableRange("RubyGems", tt.raw, tt.patched)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// An ecosystem with no comparator cannot prove the patched version is above the
// bound, so the declared bound stands.
func TestParseVulnerableRange_NoComparatorKeepsDeclaredBound(t *testing.T) {
	t.Parallel()
	got, ok := parseVulnerableRange("GitHub Actions", "<= 2.0", "3.0")
	want := rangeBounds{Introduced: "0", LastAffected: "2.0"}
	if !ok || got != want {
		t.Errorf("got %+v ok=%v, want %+v", got, ok, want)
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
