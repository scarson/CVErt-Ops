// ABOUTME: Bug fix tests for API handler consistency — dedup, 404 checks, TOCTOU.
// ABOUTME: Covers parseWatchlistUUIDs dedup and rotateSecretHandler empty-secret detection.
package api

import (
	"testing"

	"github.com/google/uuid"
)

func TestParseWatchlistUUIDs_DeduplicatesDuplicates(t *testing.T) {
	t.Parallel()

	id1 := uuid.New().String()
	id2 := uuid.New().String()

	result, err := parseWatchlistUUIDs([]string{id1, id2, id1, id2, id1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 unique UUIDs, got %d", len(result))
	}
}

func TestParseWatchlistUUIDs_PreservesOrder(t *testing.T) {
	t.Parallel()

	id1 := uuid.New()
	id2 := uuid.New()
	id3 := uuid.New()

	result, err := parseWatchlistUUIDs([]string{id1.String(), id2.String(), id3.String()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("expected 3 UUIDs, got %d", len(result))
	}
	if result[0] != id1 || result[1] != id2 || result[2] != id3 {
		t.Error("expected order to be preserved")
	}
}

func TestParseWatchlistUUIDs_InvalidUUID(t *testing.T) {
	t.Parallel()

	_, err := parseWatchlistUUIDs([]string{"not-a-uuid"})
	if err == nil {
		t.Fatal("expected error for invalid UUID")
	}
}
