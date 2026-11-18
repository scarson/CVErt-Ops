// ABOUTME: Tests that every range expression form maps to the right range bounds.
// ABOUTME: Strings are taken from real reviewed GHSA advisories and CNA records.
package version

import "testing"

func TestParseRangeExpression(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, raw, patched string
		want               Range
		wantOK             bool
	}{
		{"lower and exclusive upper", ">= 1.8.0, < 1.11.4", "1.11.4", Range{Introduced: "1.8.0", Fixed: "1.11.4"}, true},
		{"lower and exclusive upper unpatched", ">= 3.3.0, < 3.9.0", "", Range{Introduced: "3.3.0", Fixed: "3.9.0"}, true},
		{"exclusive upper only", "< 1.3.2", "1.3.2", Range{Introduced: "0", Fixed: "1.3.2"}, true},
		{"exclusive upper only unpatched", "< 2.0.4", "", Range{Introduced: "0", Fixed: "2.0.4"}, true},
		{"exclusive upper wins over patched", "< 2.0", "1.9.5", Range{Introduced: "0", Fixed: "2.0"}, true},
		{"lower and inclusive upper patched", ">= 4.2.0, <= 4.2.7.0", "4.2.7.1", Range{Introduced: "4.2.0", Fixed: "4.2.7.1"}, true},
		{"lower and inclusive upper unpatched", ">= 1.3, <= 1.3.1", "", Range{Introduced: "1.3", LastAffected: "1.3.1"}, true},
		{"inclusive upper patched", "<= 0.9.0", "0.10.0", Range{Introduced: "0", Fixed: "0.10.0"}, true},
		{"inclusive upper unpatched", "<= 0.2.0", "", Range{Introduced: "0", LastAffected: "0.2.0"}, true},
		{"exact patched", "= 5.0.0", "5.0.0.1", Range{Introduced: "5.0.0", Fixed: "5.0.0.1"}, true},
		{"exact unpatched", "= 0.7.246", "", Range{Introduced: "0.7.246", LastAffected: "0.7.246"}, true},
		{"exact with suffix", "= 2.6.3-CUSTOM", "", Range{Introduced: "2.6.3-CUSTOM", LastAffected: "2.6.3-CUSTOM"}, true},
		{"open from a version", ">= 1.0.0", "", Range{Introduced: "1.0.0"}, true},
		{"open from a version patched", ">= 1.0.0", "2.0.0", Range{Introduced: "1.0.0", Fixed: "2.0.0"}, true},
		{"from zero", ">= 0", "", Range{Introduced: "0"}, true},
		{"from zero dotted", ">= 0.0.0", "", Range{Introduced: "0"}, true},
		{"exclusive zero", "> 0", "", Range{Introduced: "0"}, true},
		{"exclusive zero dotted with upper", "> 0.0.0, < 3.4.0", "3.4.0", Range{Introduced: "0", Fixed: "3.4.0"}, true},
		{"exclusive lower", "> 0.7.1, < 1.0.4", "1.0.4", Range{Introduced: "0.7.1", Fixed: "1.0.4"}, true},
		{"exclusive lower inclusive upper patched", "> 1.4.1, <= 1.5", "1.5.1", Range{Introduced: "1.4.1", Fixed: "1.5.1"}, true},
		{"exclusive lower inclusive upper unpatched", "> 0.0.12, <= 1.1.39", "", Range{Introduced: "0.0.12", LastAffected: "1.1.39"}, true},
		{"exclusive lower only", "> 2.0", "", Range{Introduced: "2.0"}, true},
		{"go pseudo versions", "> 0.0.0-20201116123734-de1c1243f4dd, < 0.0.0-20210518124745-db7f0bcec27b", "0.0.0-20210518124745-db7f0bcec27b", Range{Introduced: "0.0.0-20201116123734-de1c1243f4dd", Fixed: "0.0.0-20210518124745-db7f0bcec27b"}, true},
		{"prerelease lower", ">= 2.0-beta9, < 2.3.1", "2.3.1", Range{Introduced: "2.0-beta9", Fixed: "2.3.1"}, true},
		{"qualifier upper", "<= 1.2.1.2-jre17", "", Range{Introduced: "0", LastAffected: "1.2.1.2-jre17"}, true},
		{"patched below inclusive upper keeps the declared range", ">= 1.0.0, <= 3.0.0", "2.0.0", Range{Introduced: "1.0.0", LastAffected: "3.0.0"}, true},
		{"patched equal to inclusive upper keeps the declared range", "<= 2.0.0", "2.0.0", Range{Introduced: "0", LastAffected: "2.0.0"}, true},
		{"patched equal to exact version keeps the declared version", "= 1.0.0", "1.0.0", Range{Introduced: "1.0.0", LastAffected: "1.0.0"}, true},
		{"patched not above open lower bound stays open", ">= 1.0.0", "0.9.0", Range{Introduced: "1.0.0"}, true},
		{"empty with patched", "", "4.17.21", Range{Introduced: "0", Fixed: "4.17.21"}, true},
		{"empty unpatched", "", "", Range{}, false},
		{"not-equal operator", "!= 1.0", "", Range{}, false},
		{"three constraints", ">= 1.0, < 2.0, < 3.0", "", Range{}, false},
		{"two lower bounds", ">= 1.0, > 2.0", "", Range{}, false},
		{"two upper bounds", "< 1.0, <= 2.0", "", Range{}, false},
		{"exact with another constraint", "= 1.0, < 2.0", "", Range{}, false},
		{"garbage", "banana", "", Range{}, false},
		{"operator with no version", ">=", "", Range{}, false},
		{"inclusive upper with no version", "<=", "", Range{}, false},
		{"doubled operator", ">=> 1.0", "", Range{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := ParseRangeExpression("RubyGems", tt.raw, tt.patched)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A CNA record's free-text version has no ecosystem and no first patched version,
// so the stated bounds are kept as written.
func TestParseRangeExpression_NoEcosystem(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, raw string
		want      Range
		wantOK    bool
	}{
		{"lower and inclusive upper", ">= 20.0.0, <= 20.10.27", Range{Introduced: "20.0.0", LastAffected: "20.10.27"}, true},
		{"lower and exclusive upper", ">= 1.0.0, < 1.4.2", Range{Introduced: "1.0.0", Fixed: "1.4.2"}, true},
		{"open from a version", ">= 2.0", Range{Introduced: "2.0"}, true},
		// With no first patched version, an empty expression has nothing to report.
		{"empty", "", Range{}, false},
		// A hyphen range is not part of the grammar, so it is not read.
		{"hyphen range", "0.5.6 - 1.13.2", Range{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := ParseRangeExpression("", tt.raw, "")
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("got %+v ok=%v, want %+v ok=%v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// An ecosystem with no comparator cannot prove the patched version is above the
// bound, so the declared bound stands.
func TestParseRangeExpression_NoComparatorKeepsDeclaredBound(t *testing.T) {
	t.Parallel()
	for _, ecosystem := range []string{"GitHub Actions", ""} {
		got, ok := ParseRangeExpression(ecosystem, "<= 2.0", "3.0")
		want := Range{Introduced: "0", LastAffected: "2.0"}
		if !ok || got != want {
			t.Errorf("%q: got %+v ok=%v, want %+v", ecosystem, got, ok, want)
		}
		got, ok = ParseRangeExpression(ecosystem, "= 1.0", "3.0")
		want = Range{Introduced: "1.0", LastAffected: "1.0"}
		if !ok || got != want {
			t.Errorf("%q exact: got %+v ok=%v, want %+v", ecosystem, got, ok, want)
		}
	}
}
