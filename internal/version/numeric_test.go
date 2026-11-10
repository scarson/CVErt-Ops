// ABOUTME: Tests the dotted numeric ordering used for products with no package ecosystem.
// ABOUTME: Pins that anything other than dotted numbers is an error, never a guessed order.
package version

import (
	"errors"
	"strings"
	"testing"
)

func TestNumericOrder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		a, b string
		want int
	}{
		{"1.2", "1.10", -1},
		{"1.10", "1.2", 1},
		{"1.2", "1.2.0", 0},
		{"20.10.27", "20.10.3", 1},
	}
	for _, tt := range tests {
		got, err := NumericOrder(tt.a, tt.b)
		if err != nil || sign(got) != tt.want {
			t.Errorf("NumericOrder(%q, %q) = (%d, %v), want sign %d", tt.a, tt.b, got, err, tt.want)
		}
	}
}

func TestNumericOrder_UnreadableIsError(t *testing.T) {
	t.Parallel()
	for _, pair := range [][2]string{
		{"1.2rc1", "1.2"},
		{"1.2", "1.2rc1"},
		{"1.24.0-1", "1.24.0"},
		{"", "1.0"},
		{"1.0", strings.Repeat("1", maxVersionLen+1)},
	} {
		if _, err := NumericOrder(pair[0], pair[1]); !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("NumericOrder(%q, %q) err = %v, want ErrInvalidVersion", pair[0], pair[1], err)
		}
	}
}
