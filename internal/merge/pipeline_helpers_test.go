// ABOUTME: Tests for unexported helper functions in the merge pipeline.
// ABOUTME: Covers sql.Null* converters, derefString, and slice builders.
package merge

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
)

// ── toNullString ─────────────────────────────────────────────────────────────

func TestToNullString(t *testing.T) {
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
			got := toNullString(tc.input)
			if got.Valid != tc.wantValid {
				t.Errorf("toNullString(%q).Valid = %v, want %v", tc.input, got.Valid, tc.wantValid)
			}
			if got.String != tc.wantStr {
				t.Errorf("toNullString(%q).String = %q, want %q", tc.input, got.String, tc.wantStr)
			}
		})
	}
}

// ── toNullStringPtr ──────────────────────────────────────────────────────────

func TestToNullStringPtr(t *testing.T) {
	t.Parallel()

	t.Run("nil pointer", func(t *testing.T) {
		t.Parallel()
		got := toNullStringPtr(nil)
		if got.Valid {
			t.Error("toNullStringPtr(nil).Valid = true, want false")
		}
	})

	t.Run("non-nil pointer", func(t *testing.T) {
		t.Parallel()
		s := "hello"
		got := toNullStringPtr(&s)
		if !got.Valid {
			t.Error("toNullStringPtr(&s).Valid = false, want true")
		}
		if got.String != "hello" {
			t.Errorf("toNullStringPtr(&s).String = %q, want %q", got.String, "hello")
		}
	})

	t.Run("non-nil empty string pointer", func(t *testing.T) {
		t.Parallel()
		s := ""
		got := toNullStringPtr(&s)
		if !got.Valid {
			t.Error("toNullStringPtr pointer to empty string should be Valid=true")
		}
		if got.String != "" {
			t.Errorf("toNullStringPtr(&\"\").String = %q, want %q", got.String, "")
		}
	})
}

// ── toNullFloat64 ────────────────────────────────────────────────────────────

func TestToNullFloat64(t *testing.T) {
	t.Parallel()

	t.Run("nil pointer", func(t *testing.T) {
		t.Parallel()
		got := toNullFloat64(nil)
		if got.Valid {
			t.Error("toNullFloat64(nil).Valid = true, want false")
		}
	})

	t.Run("non-nil pointer", func(t *testing.T) {
		t.Parallel()
		f := 9.8
		got := toNullFloat64(&f)
		if !got.Valid {
			t.Error("toNullFloat64(&f).Valid = false, want true")
		}
		if got.Float64 != 9.8 {
			t.Errorf("toNullFloat64(&f).Float64 = %f, want %f", got.Float64, 9.8)
		}
	})

	t.Run("non-nil zero value", func(t *testing.T) {
		t.Parallel()
		f := 0.0
		got := toNullFloat64(&f)
		if !got.Valid {
			t.Error("toNullFloat64 pointer to zero should be Valid=true")
		}
		if got.Float64 != 0.0 {
			t.Errorf("toNullFloat64(&0.0).Float64 = %f, want 0.0", got.Float64)
		}
	})
}

// ── toNullTimePtr ────────────────────────────────────────────────────────────

func TestToNullTimePtr(t *testing.T) {
	t.Parallel()

	t.Run("nil pointer", func(t *testing.T) {
		t.Parallel()
		got := toNullTimePtr(nil)
		if got.Valid {
			t.Error("toNullTimePtr(nil).Valid = true, want false")
		}
	})

	t.Run("non-nil pointer", func(t *testing.T) {
		t.Parallel()
		ts := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
		got := toNullTimePtr(&ts)
		if !got.Valid {
			t.Error("toNullTimePtr(&ts).Valid = false, want true")
		}
		if !got.Time.Equal(ts) {
			t.Errorf("toNullTimePtr(&ts).Time = %v, want %v", got.Time, ts)
		}
	})
}

// ── toNullRawMessage ─────────────────────────────────────────────────────────

func TestToNullRawMessage(t *testing.T) {
	t.Parallel()

	t.Run("nil message", func(t *testing.T) {
		t.Parallel()
		got := toNullRawMessage(nil)
		if got.Valid {
			t.Error("toNullRawMessage(nil).Valid = true, want false")
		}
	})

	t.Run("non-nil message", func(t *testing.T) {
		t.Parallel()
		msg := json.RawMessage(`{"key":"value"}`)
		got := toNullRawMessage(msg)
		if !got.Valid {
			t.Error("toNullRawMessage(msg).Valid = false, want true")
		}
		if string(got.RawMessage) != `{"key":"value"}` {
			t.Errorf("toNullRawMessage(msg).RawMessage = %s, want %s", got.RawMessage, msg)
		}
	})
}

// ── derefString ──────────────────────────────────────────────────────────────

func TestDerefString(t *testing.T) {
	t.Parallel()

	t.Run("nil pointer", func(t *testing.T) {
		t.Parallel()
		if got := derefString(nil); got != "" {
			t.Errorf("derefString(nil) = %q, want %q", got, "")
		}
	})

	t.Run("non-nil pointer", func(t *testing.T) {
		t.Parallel()
		s := "hello"
		if got := derefString(&s); got != "hello" {
			t.Errorf("derefString(&s) = %q, want %q", got, "hello")
		}
	})

	t.Run("non-nil empty string", func(t *testing.T) {
		t.Parallel()
		s := ""
		if got := derefString(&s); got != "" {
			t.Errorf("derefString(&\"\") = %q, want %q", got, "")
		}
	})
}

// ── buildAffectedPkgKeys ────────────────────────────────────────────────────

func TestBuildAffectedPkgKeys(t *testing.T) {
	t.Parallel()

	t.Run("empty slice", func(t *testing.T) {
		t.Parallel()
		got := buildAffectedPkgKeys(nil)
		if len(got) != 0 {
			t.Errorf("buildAffectedPkgKeys(nil) returned %d items, want 0", len(got))
		}
	})

	t.Run("single package", func(t *testing.T) {
		t.Parallel()
		pkgs := []feed.AffectedPackage{
			{Ecosystem: "npm", PackageName: "lodash", Introduced: "4.0.0", Fixed: "4.17.21"},
		}
		got := buildAffectedPkgKeys(pkgs)
		if len(got) != 1 {
			t.Fatalf("buildAffectedPkgKeys returned %d items, want 1", len(got))
		}
		if got[0].Ecosystem != "npm" {
			t.Errorf("Ecosystem = %q, want %q", got[0].Ecosystem, "npm")
		}
		if got[0].PackageName != "lodash" {
			t.Errorf("PackageName = %q, want %q", got[0].PackageName, "lodash")
		}
		if got[0].Introduced != "4.0.0" {
			t.Errorf("Introduced = %q, want %q", got[0].Introduced, "4.0.0")
		}
		if got[0].Fixed != "4.17.21" {
			t.Errorf("Fixed = %q, want %q", got[0].Fixed, "4.17.21")
		}
	})

	t.Run("multiple packages", func(t *testing.T) {
		t.Parallel()
		pkgs := []feed.AffectedPackage{
			{Ecosystem: "npm", PackageName: "lodash", Introduced: "0.0.0", Fixed: "4.17.21"},
			{Ecosystem: "pip", PackageName: "requests", Introduced: "2.0.0", Fixed: "2.32.0"},
		}
		got := buildAffectedPkgKeys(pkgs)
		if len(got) != 2 {
			t.Fatalf("buildAffectedPkgKeys returned %d items, want 2", len(got))
		}
		if got[0].Ecosystem != "npm" || got[1].Ecosystem != "pip" {
			t.Errorf("ecosystems = [%q, %q], want [%q, %q]",
				got[0].Ecosystem, got[1].Ecosystem, "npm", "pip")
		}
	})

	t.Run("extra fields not copied", func(t *testing.T) {
		t.Parallel()
		// Namespace, RangeType, LastAffected, Events are not part of the key.
		pkgs := []feed.AffectedPackage{
			{
				Ecosystem:    "npm",
				PackageName:  "foo",
				Namespace:    "should-be-ignored",
				RangeType:    "SEMVER",
				Introduced:   "1.0.0",
				Fixed:        "2.0.0",
				LastAffected: "1.9.9",
				Events:       json.RawMessage(`[{"introduced":"1.0.0"}]`),
			},
		}
		got := buildAffectedPkgKeys(pkgs)
		if len(got) != 1 {
			t.Fatalf("expected 1 key, got %d", len(got))
		}
		// affectedPkgKey only has Ecosystem, PackageName, Introduced, Fixed.
		if got[0].Ecosystem != "npm" || got[0].PackageName != "foo" ||
			got[0].Introduced != "1.0.0" || got[0].Fixed != "2.0.0" {
			t.Error("key fields should match the source package's ecosystem/name/introduced/fixed")
		}
	})
}

// ── buildCPEStrings ─────────────────────────────────────────────────────────

func TestBuildCPEStrings(t *testing.T) {
	t.Parallel()

	t.Run("empty slice", func(t *testing.T) {
		t.Parallel()
		got := buildCPEStrings(nil)
		if len(got) != 0 {
			t.Errorf("buildCPEStrings(nil) returned %d items, want 0", len(got))
		}
	})

	t.Run("single CPE", func(t *testing.T) {
		t.Parallel()
		cpes := []feed.AffectedCPE{
			{CPE: "cpe:2.3:a:Foo:Bar:1.0:*", CPENormalized: "cpe:2.3:a:foo:bar:1.0:*"},
		}
		got := buildCPEStrings(cpes)
		if len(got) != 1 {
			t.Fatalf("buildCPEStrings returned %d items, want 1", len(got))
		}
		if got[0] != "cpe:2.3:a:foo:bar:1.0:*" {
			t.Errorf("got %q, want %q", got[0], "cpe:2.3:a:foo:bar:1.0:*")
		}
	})

	t.Run("multiple CPEs", func(t *testing.T) {
		t.Parallel()
		cpes := []feed.AffectedCPE{
			{CPE: "cpe:2.3:a:foo:bar:1.0:*", CPENormalized: "cpe:2.3:a:foo:bar:1.0:*"},
			{CPE: "cpe:2.3:a:baz:qux:2.0:*", CPENormalized: "cpe:2.3:a:baz:qux:2.0:*"},
		}
		got := buildCPEStrings(cpes)
		if len(got) != 2 {
			t.Fatalf("buildCPEStrings returned %d items, want 2", len(got))
		}
		if got[0] != "cpe:2.3:a:foo:bar:1.0:*" || got[1] != "cpe:2.3:a:baz:qux:2.0:*" {
			t.Errorf("got %v, want [cpe:2.3:a:foo:bar:1.0:* cpe:2.3:a:baz:qux:2.0:*]", got)
		}
	})
}

// ── collectPackageNames ─────────────────────────────────────────────────────

func TestCollectPackageNames(t *testing.T) {
	t.Parallel()

	t.Run("empty slice", func(t *testing.T) {
		t.Parallel()
		got := collectPackageNames(nil)
		if len(got) != 0 {
			t.Errorf("collectPackageNames(nil) returned %d items, want 0", len(got))
		}
	})

	t.Run("single package", func(t *testing.T) {
		t.Parallel()
		pkgs := []feed.AffectedPackage{
			{Ecosystem: "npm", PackageName: "lodash"},
		}
		got := collectPackageNames(pkgs)
		if len(got) != 1 {
			t.Fatalf("expected 1 name, got %d", len(got))
		}
		if got[0] != "lodash" {
			t.Errorf("got %q, want %q", got[0], "lodash")
		}
	})

	t.Run("deduplication", func(t *testing.T) {
		t.Parallel()
		pkgs := []feed.AffectedPackage{
			{Ecosystem: "npm", PackageName: "lodash", Introduced: "1.0.0"},
			{Ecosystem: "npm", PackageName: "lodash", Introduced: "2.0.0"},
			{Ecosystem: "pip", PackageName: "requests"},
		}
		got := collectPackageNames(pkgs)
		if len(got) != 2 {
			t.Fatalf("expected 2 unique names, got %d: %v", len(got), got)
		}
	})

	t.Run("order preservation", func(t *testing.T) {
		t.Parallel()
		pkgs := []feed.AffectedPackage{
			{Ecosystem: "npm", PackageName: "axios"},
			{Ecosystem: "pip", PackageName: "flask"},
			{Ecosystem: "npm", PackageName: "lodash"},
			{Ecosystem: "npm", PackageName: "axios"}, // duplicate — should be skipped
		}
		got := collectPackageNames(pkgs)
		if len(got) != 3 {
			t.Fatalf("expected 3 unique names, got %d: %v", len(got), got)
		}
		want := []string{"axios", "flask", "lodash"}
		for i, w := range want {
			if got[i] != w {
				t.Errorf("got[%d] = %q, want %q", i, got[i], w)
			}
		}
	})
}
