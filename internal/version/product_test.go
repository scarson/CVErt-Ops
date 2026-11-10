// ABOUTME: Tests CheckProduct, the check for NVD CPE ranges whose bounds may not be dotted numbers.
// ABOUTME: Pins that a suffixed bound decides only by a differing leading number, and never guesses otherwise.
package version

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckProduct(t *testing.T) {
	t.Parallel()
	exact := func(v string) Range { return Range{Introduced: v, LastAffected: v} }
	tests := []struct {
		name    string
		version string
		r       Range
		want    Status
		wantErr error
	}{
		// Bounds that are dotted numbers read exactly as CheckNumeric reads them.
		{"numeric inside", "1.5", Range{Introduced: "1.0", Fixed: "2.0"}, Affected, nil},
		{"numeric at fix", "2.0.0", Range{Introduced: "1.0", Fixed: "2.0"}, NotAffected, nil},
		{"numeric unbounded", "9.9", Range{Introduced: "1.0"}, Affected, nil},
		{"numeric inverted", "1.5", Range{Introduced: "2.0", Fixed: "1.0"}, CannotEvaluate, ErrInvalidRange},

		// An exact release that is not dotted numbers: decided only by a differing leading number.
		{"exact release, other major", "8.4.14", exact("2.0b10"), NotAffected, nil},
		{"exact release, below", "1.9", exact("2.0b10"), NotAffected, nil},
		{"exact release, same leading numbers", "2.0", exact("2.0b10"), CannotEvaluate, ErrInvalidRange},
		{"exact release, longer version on same leading numbers", "2.0.1", exact("2.0b10"), CannotEvaluate, ErrInvalidRange},
		{"exact letter release, other patch", "1.0.1", exact("1.0.2a"), NotAffected, nil},
		{"exact letter release, same patch", "1.0.2", exact("1.0.2a"), CannotEvaluate, ErrInvalidRange},

		// Bounds with a decided order: an ordinary range, each comparison by leading numbers.
		{"suffixed fix, version past it", "3.5.4", Range{Introduced: "1.0.0", Fixed: "1.0.2zf"}, NotAffected, nil},
		{"suffixed fix, version below start", "0.9.8", Range{Introduced: "1.0.0", Fixed: "1.0.2zf"}, NotAffected, nil},
		{"suffixed fix, version inside", "1.0.1", Range{Introduced: "1.0.0", Fixed: "1.0.2zf"}, Affected, nil},
		{"suffixed fix, version on its leading numbers", "1.0.2", Range{Introduced: "1.0.0", Fixed: "1.0.2zf"}, CannotEvaluate, ErrInvalidRange},
		{"suffixed last affected, version inside", "2.6.30", Range{Introduced: "2.6.0", LastAffected: "2.6.32-rc1"}, Affected, nil},
		{"suffixed start, version inside", "1.5", Range{Introduced: "1.0b1", Fixed: "2.0"}, Affected, nil},
		{"suffixed start, version on its leading numbers", "1.0", Range{Introduced: "1.0b1", Fixed: "2.0"}, CannotEvaluate, ErrInvalidRange},
		{"suffixed unbounded start, version above", "3.0", Range{Introduced: "2.0b1"}, Affected, nil},
		{"decided inverted range", "1.5", Range{Introduced: "2.0b1", Fixed: "1.0"}, CannotEvaluate, ErrInvalidRange},
		{"escaped suffix decides by leading numbers", "15.2", exact(`12.2\(55\)se`), NotAffected, nil},

		// Bounds whose order is not decided: Not affected only on the same side of both.
		{"undecided bounds, version above both", "3.5.4", Range{Introduced: "1.0.2", Fixed: "1.0.2zf"}, NotAffected, nil},
		{"undecided bounds, version below both", "1.0.1", Range{Introduced: "1.0.2", Fixed: "1.0.2zf"}, NotAffected, nil},
		{"undecided bounds, version on the start", "1.0.2", Range{Introduced: "1.0.2", Fixed: "1.0.2zf"}, CannotEvaluate, ErrInvalidRange},
		{"undecided bounds, version decided against one only", "2.4.0", Range{Introduced: "2.4.1", Fixed: "2.4a"}, CannotEvaluate, ErrInvalidRange},

		// Bounds that are never compared.
		{"epoch bound", "2.3", Range{Introduced: "0", Fixed: "1:2.4"}, CannotEvaluate, ErrInvalidRange},
		{"escaped epoch bound", "2.3", Range{Introduced: "0", Fixed: `1\:2.4`}, CannotEvaluate, ErrInvalidRange},
		{"PEP 440 epoch bound", "2.3", Range{Introduced: "0", Fixed: "1!2.4"}, CannotEvaluate, ErrInvalidRange},
		{"no leading digit", "2.3", Range{Introduced: "0", Fixed: "v2.4"}, CannotEvaluate, ErrInvalidRange},
		{"oversized bound", "2.3", Range{Introduced: "0", Fixed: "3" + strings.Repeat("a", maxVersionLen)}, CannotEvaluate, ErrInvalidRange},
		{"no introduced", "2.3", Range{Fixed: "2.4a"}, CannotEvaluate, ErrInvalidRange},
		{"both upper bounds", "2.3", Range{Introduced: "0", Fixed: "2.4a", LastAffected: "2.4b"}, CannotEvaluate, ErrInvalidRange},

		// The item version must still be dotted numbers.
		{"suffixed item version", "1.1.1w", exact("1.0.2a"), CannotEvaluate, ErrInvalidVersion},
		{"suffixed item version, numeric range", "1.1.1w", Range{Introduced: "1.0", Fixed: "2.0"}, CannotEvaluate, ErrInvalidVersion},
	}
	for _, tt := range tests {
		got, err := CheckProduct(tt.version, tt.r)
		if got != tt.want {
			t.Errorf("%s: CheckProduct(%q, %+v) = %v, want %v", tt.name, tt.version, tt.r, got, tt.want)
		}
		switch {
		case tt.wantErr == nil && err != nil:
			t.Errorf("%s: err = %v, want nil", tt.name, err)
		case tt.wantErr != nil && !errors.Is(err, tt.wantErr):
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.wantErr)
		}
	}
}

// TestCheckProduct_NumericBoundsMatchCheckNumeric pins that rows whose bounds are
// all dotted numbers answer exactly as CheckNumeric answers them.
func TestCheckProduct_NumericBoundsMatchCheckNumeric(t *testing.T) {
	t.Parallel()
	ranges := []Range{
		{Introduced: "0", Fixed: "1.2"},
		{Introduced: "1.0", LastAffected: "1.0"},
		{Introduced: "1.2", Fixed: "1.2"},
		{Introduced: "1.0", Fixed: "2.0", LastAffected: "2.0"},
		{Introduced: "", Fixed: "2.0"},
		{Introduced: "3.0"},
	}
	for _, r := range ranges {
		for _, v := range []string{"0", "1.0", "1.0.0", "1.2", "1.10", "2.0", "3.0.1"} {
			wantStatus, wantErr := CheckNumeric(v, r)
			gotStatus, gotErr := CheckProduct(v, r)
			if gotStatus != wantStatus || (gotErr == nil) != (wantErr == nil) {
				t.Errorf("CheckProduct(%q, %+v) = (%v, %v), CheckNumeric = (%v, %v)", v, r, gotStatus, gotErr, wantStatus, wantErr)
			}
		}
	}
}
