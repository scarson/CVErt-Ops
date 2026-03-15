// ABOUTME: Tests for shared nullable type conversion helpers.
// ABOUTME: Covers NullString (value-based) and NullStringPtr (pointer-based).
package dbutil

import (
	"testing"
)

func TestNullString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantValid bool
		wantStr   string
	}{
		{name: "empty string", input: "", wantValid: false, wantStr: ""},
		{name: "non-empty string", input: "published", wantValid: true, wantStr: "published"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := NullString(tc.input)
			if got.Valid != tc.wantValid {
				t.Errorf("NullString(%q).Valid = %v, want %v", tc.input, got.Valid, tc.wantValid)
			}
			if got.String != tc.wantStr {
				t.Errorf("NullString(%q).String = %q, want %q", tc.input, got.String, tc.wantStr)
			}
		})
	}
}

func TestNullStringPtr(t *testing.T) {
	t.Parallel()

	t.Run("nil pointer", func(t *testing.T) {
		t.Parallel()
		got := NullStringPtr(nil)
		if got.Valid {
			t.Error("NullStringPtr(nil).Valid = true, want false")
		}
	})

	t.Run("non-nil pointer", func(t *testing.T) {
		t.Parallel()
		s := "hello"
		got := NullStringPtr(&s)
		if !got.Valid {
			t.Error("NullStringPtr(&s).Valid = false, want true")
		}
		if got.String != "hello" {
			t.Errorf("NullStringPtr(&s).String = %q, want %q", got.String, "hello")
		}
	})

	t.Run("non-nil empty string pointer", func(t *testing.T) {
		t.Parallel()
		s := ""
		got := NullStringPtr(&s)
		if !got.Valid {
			t.Error("NullStringPtr pointer to empty string should be Valid=true")
		}
		if got.String != "" {
			t.Errorf("NullStringPtr(&\"\").String = %q, want %q", got.String, "")
		}
	})
}

// TestNullString_vs_NullStringPtr_EmptyString documents the intentional
// semantic difference: NullString("") → Valid=false (empty means absent),
// NullStringPtr(&"") → Valid=true (pointer exists, value is empty).
func TestNullString_vs_NullStringPtr_EmptyString(t *testing.T) {
	t.Parallel()
	byValue := NullString("")
	s := ""
	byPtr := NullStringPtr(&s)

	if byValue.Valid {
		t.Error("NullString(\"\") should be Valid=false")
	}
	if !byPtr.Valid {
		t.Error("NullStringPtr(&\"\") should be Valid=true")
	}
}
