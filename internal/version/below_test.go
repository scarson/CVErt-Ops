// ABOUTME: Tests ProductRangeBelow, the rule that lets a version check skip NVD ranges lying wholly below a version.
// ABOUTME: Pins that such a range answers NotAffected for the version and for every dotted-number version at or above it.
package version

import "testing"

func TestProductRangeBelow(t *testing.T) {
	t.Parallel()
	exact := func(v string) Range { return Range{Introduced: v, LastAffected: v} }
	tests := []struct {
		name    string
		version string
		r       Range
		want    bool
	}{
		{"exact release below", "6.12.0", exact("2.6.32"), true},
		{"exact release, shorter and below", "6.12.0", exact("6"), true},
		{"exact release equal", "6.12.0", exact("6.12.0"), false},
		{"exact release equal with missing zero", "6.12.0", exact("6.12"), false},
		{"exact release above", "6.12.0", exact("6.12.1"), false},
		{"exact suffixed release, lower leading number", "6.12.0", exact("2.6.22_rc7"), true},
		{"exact suffixed release, same leading numbers", "2.6.22", exact("2.6.22_rc7"), false},
		{"exact suffixed release, version longer on the same leading numbers", "2.6.22.1", exact("2.6.22_rc7"), false},
		{"exact release 0", "1.0", exact("0"), true},

		{"range ending below, exclusive", "6.12.0", Range{Introduced: "5.15", Fixed: "5.15.100"}, true},
		{"range ending below, inclusive", "6.12.0", Range{Introduced: "5.15", LastAffected: "5.15.100"}, true},
		{"range ending at the version, exclusive", "6.12.0", Range{Introduced: "6.1", Fixed: "6.12.0"}, false},
		{"range ending at the version, inclusive", "6.12.0", Range{Introduced: "6.1", LastAffected: "6.12"}, false},
		{"range containing the version", "6.12.0", Range{Introduced: "6.1", Fixed: "6.13"}, false},
		{"range above the version", "6.12.0", Range{Introduced: "6.13", Fixed: "6.14"}, false},
		{"range from the start, ending below", "6.12.0", Range{Introduced: "0", Fixed: "2.6.9"}, true},
		{"range from the start, suffixed end below", "3.5.4", Range{Introduced: "0", Fixed: "1.0.2zf"}, true},
		{"suffixed bounds below", "3.5.4", Range{Introduced: "1.0.0", Fixed: "1.0.2zf"}, true},
		{"suffixed start below", "3.5.4", Range{Introduced: "1.0b1", LastAffected: "2.0"}, true},
		{"no upper bound", "6.12.0", Range{Introduced: "2.6"}, false},
		{"both upper bounds", "6.12.0", Range{Introduced: "2.6", Fixed: "2.7", LastAffected: "2.7"}, false},
		{"no introduced bound", "6.12.0", Range{Fixed: "2.7"}, false},

		// A range CheckProduct refuses is kept, so its refusal still holds the version.
		{"inverted range below", "6.12.0", Range{Introduced: "3.0", Fixed: "2.0"}, false},
		{"empty exclusive range below", "6.12.0", Range{Introduced: "2.0", Fixed: "2.0"}, false},
		{"empty exclusive range at the start", "6.12.0", Range{Introduced: "0", Fixed: "0"}, false},
		{"empty exclusive range at the start, other spelling", "6.12.0", Range{Introduced: "0", Fixed: "0.0"}, false},
		{"bounds with no decided order", "3.5.4", Range{Introduced: "1.0.2", Fixed: "1.0.2zf"}, false},
		{"one value, inclusive", "6.12.0", Range{Introduced: "2.0", LastAffected: "2.0"}, true},
		{"one value, inclusive, at the start", "6.12.0", Range{Introduced: "0", LastAffected: "0"}, true},

		// Bounds that are never compared by leading numbers.
		{"epoch", "6.12.0", exact("1:2.0"), false},
		{"escaped epoch", "6.12.0", exact(`1\:2.0`), false},
		{"PEP 440 epoch", "6.12.0", exact("1!2.0"), false},
		{"wildcard", "6.12.0", exact("1*"), false},
		{"single-character wildcard", "6.12.0", exact("1?"), false},
		{"encoded character", "6.12.0", exact("1%3a2.4"), false},
		{"escaped character", "6.12.0", exact(`1.2\(55\)se`), false},
		{"no leading digit", "6.12.0", exact("v1.2"), false},
		{"empty", "6.12.0", exact(""), false},
		{"oversized bound", "6.12.0", exact("1." + string(make([]byte, 300))), false},

		{"version is not dotted numbers", "6.12.0-rc1", exact("2.6.32"), false},
		{"version is empty", "", exact("2.6.32"), false},

		{"components compare by value, not as text", "10.0", exact("9.5"), true},
		{"leading zeros are ignored", "2.10", exact("2.09"), true},
		{"equal apart from leading zeros", "2.9", exact("2.09"), false},
		{"numbers longer than any integer type", "100000000000000000000000000000.1", exact("99999999999999999999999999999.5"), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ProductRangeBelow(tc.version, tc.r); got != tc.want {
				t.Errorf("ProductRangeBelow(%q, %+v) = %v, want %v", tc.version, tc.r, got, tc.want)
			}
		})
	}
}

// TestProductRangeBelow_NeverHidesAnAnswer checks, over every range built from a
// set of bounds, what skipping a range relies on: when ProductRangeBelow reports
// a range for a version, CheckProduct answers NotAffected for that version and
// for every version at or above it.
func TestProductRangeBelow_NeverHidesAnAnswer(t *testing.T) {
	t.Parallel()
	versions := []string{"0", "0.0", "0.9", "1", "1.0", "1.0.0", "1.0.1", "1.0.2", "1.0.2.5", "1.0.3", "1.1", "1.9",
		"2", "2.0", "2.0.0.1", "2.6", "2.6.22", "2.6.22.1", "2.6.23", "2.10", "2.09", "3", "3.5.4", "10", "10.0.1"}
	bounds := append([]string{"", "1.0b1", "1.0.2zf", "1.0.2a", "2.0b10", "2.6.22_rc7", "2.6_test9", "2.6.22-rc1",
		"1:2.0", `1\:2.0`, "1!2.0", "1*", "1?", "1%3a2.4", `1.2\(55\)se`, "v1.2", "rc1", "-", "*", "0.", ".5", "1..2"},
		versions...)

	var ranges []Range
	for _, intro := range bounds {
		for _, upper := range bounds {
			ranges = append(ranges,
				Range{Introduced: intro, Fixed: upper},
				Range{Introduced: intro, LastAffected: upper},
				Range{Introduced: intro, Fixed: upper, LastAffected: upper})
		}
	}

	below := 0
	for _, v := range versions {
		for _, r := range ranges {
			if !ProductRangeBelow(v, r) {
				continue
			}
			below++
			for _, c := range versions {
				if order, err := NumericOrder(c, v); err != nil || order < 0 {
					continue
				}
				if status, err := CheckProduct(c, r); status != NotAffected {
					t.Errorf("ProductRangeBelow(%q, %+v) is true, but CheckProduct(%q) = %v (%v)", v, r, c, status, err)
				}
			}
		}
	}
	if below == 0 {
		t.Fatal("no range was reported below any version: the test checked nothing")
	}
}

// TestProductRangeBelow_FindsWhatCheckProductClears states how much the rule
// finds: for ranges of dotted-number bounds, every range whose upper bound is
// below the version.
func TestProductRangeBelow_FindsWhatCheckProductClears(t *testing.T) {
	t.Parallel()
	versions := []string{"0.9", "1", "1.0.1", "1.0.2", "1.1", "2", "2.6", "2.6.22", "2.6.22.1", "2.10", "3.5.4", "10"}
	for _, v := range versions {
		for _, intro := range append([]string{"0"}, versions...) {
			for _, upper := range versions {
				for _, r := range []Range{{Introduced: intro, Fixed: upper}, {Introduced: intro, LastAffected: upper}} {
					status, _ := CheckNumeric(v, r)
					aboveUpper, _ := NumericOrder(v, upper)
					want := status == NotAffected && aboveUpper > 0
					if got := ProductRangeBelow(v, r); got != want {
						t.Errorf("ProductRangeBelow(%q, %+v) = %v, want %v", v, r, got, want)
					}
				}
			}
		}
	}
}
