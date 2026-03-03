// ABOUTME: Integration tests for CVE search queries against real Postgres.
// ABOUTME: Validates FTS join, severity filter, and combined search paths.
package store_test

import (
	"context"
	"testing"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestSearchCVEs_FTSBasic(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed two CVEs with distinct descriptions.
	db.SeedTestCVE(t, "CVE-2024-1111", "high", &testutil.SeedCVEOpts{
		DescriptionPrimary: "Buffer overflow in libfoo allows remote code execution",
	})
	db.SeedTestCVE(t, "CVE-2024-2222", "medium", &testutil.SeedCVEOpts{
		DescriptionPrimary: "SQL injection in web admin panel",
	})

	// Search for "buffer overflow" — should match only CVE-2024-1111.
	results, err := db.SearchCVEs(ctx, store.SearchParams{Q: "buffer overflow", Limit: 10}) //nolint:exhaustruct // test: only FTS field
	if err != nil {
		t.Fatalf("SearchCVEs: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-1111" {
		t.Errorf("expected CVE-2024-1111, got %s", results[0].CveID)
	}
}

func TestSearchCVEs_FTSByCVEID(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-3333", "critical", nil)
	db.SeedTestCVE(t, "CVE-2024-4444", "low", nil)

	// Search by CVE ID text — the CVE ID is indexed with weight D.
	results, err := db.SearchCVEs(ctx, store.SearchParams{Q: "CVE-2024-3333", Limit: 10}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-3333" {
		t.Errorf("expected CVE-2024-3333, got %s", results[0].CveID)
	}
}

func TestSearchCVEs_FTSNoMatch(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-5555", "high", &testutil.SeedCVEOpts{
		DescriptionPrimary: "Memory corruption in kernel module",
	})

	results, err := db.SearchCVEs(ctx, store.SearchParams{Q: "javascript prototype pollution", Limit: 10}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestSearchCVEs_FTSWithSeverityFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-6666", "critical", &testutil.SeedCVEOpts{
		DescriptionPrimary: "Remote code execution via deserialization",
	})
	db.SeedTestCVE(t, "CVE-2024-7777", "low", &testutil.SeedCVEOpts{
		DescriptionPrimary: "Remote code execution via path traversal",
	})

	// Both match "remote code execution" but only one is critical.
	results, err := db.SearchCVEs(ctx, store.SearchParams{ //nolint:exhaustruct // test
		Q:        "remote code execution",
		Severity: []string{"critical"},
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("SearchCVEs: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-6666" {
		t.Errorf("expected CVE-2024-6666, got %s", results[0].CveID)
	}
}
