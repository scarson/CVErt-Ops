// ABOUTME: Tests for the Gemini LLMClient adapter.
// ABOUTME: Validates construction, API key validation, and interface compliance.
package ai_test

import (
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/ai"
)

func TestNewGeminiClient_MissingAPIKey(t *testing.T) {
	t.Parallel()
	_, err := ai.NewGeminiClient("", "gemini-2.0-flash", 30*time.Second)
	if err == nil {
		t.Fatal("expected error for empty API key")
	}
}

func TestNewGeminiClient_ValidConfig(t *testing.T) {
	t.Parallel()
	// This test just verifies construction doesn't panic.
	// It does NOT make real API calls.
	c, err := ai.NewGeminiClient("test-key", "gemini-2.0-flash", 30*time.Second)
	if err != nil {
		t.Fatalf("NewGeminiClient: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

// Compile-time interface compliance check.
var _ ai.LLMClient = (*ai.GeminiClient)(nil)
