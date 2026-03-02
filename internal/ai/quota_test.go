// ABOUTME: Tests for AI quota resolution logic.
// ABOUTME: Validates per-org override > tier default > fallback precedence.
package ai_test

import (
	"testing"

	"github.com/scarson/cvert-ops/internal/ai"
)

func TestResolveLimit_Override(t *testing.T) {
	t.Parallel()
	got := ai.ResolveLimit(500, true, ai.TierLimits{Free: 10, Pro: 100, Enterprise: 1000}, "free")
	if got != 500 {
		t.Errorf("ResolveLimit with override = %d, want 500", got)
	}
}

func TestResolveLimit_TierDefault(t *testing.T) {
	t.Parallel()
	limits := ai.TierLimits{Free: 10, Pro: 100, Enterprise: 1000}
	tests := []struct {
		tier string
		want int
	}{
		{"free", 10},
		{"pro", 100},
		{"enterprise", 1000},
		{"unknown", 10}, // falls back to Free
	}
	for _, tt := range tests {
		got := ai.ResolveLimit(0, false, limits, tt.tier)
		if got != tt.want {
			t.Errorf("ResolveLimit(tier=%q) = %d, want %d", tt.tier, got, tt.want)
		}
	}
}
