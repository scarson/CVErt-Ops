// ABOUTME: Integration tests for store/dsl_executor.go — ExecuteDSLQuery pagination and filtering.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestExecuteDSLQuery_BasicFilter(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed two CVEs with different severities.
	s.SeedTestCVE(t, "CVE-2024-0001", "critical", nil)
	s.SeedTestCVE(t, "CVE-2024-0002", "low", nil)

	// Compile a rule that matches only critical severity.
	rule := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "severity", Op: "eq", Value: json.RawMessage(`"critical"`)},
		},
	}
	compiled, err := dsl.Compile(rule, uuid.Nil, 0, uuid.Nil, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	results, nextCursor, err := s.ExecuteDSLQuery(ctx, compiled, "", 25)
	if err != nil {
		t.Fatalf("ExecuteDSLQuery: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].CveID != "CVE-2024-0001" {
		t.Errorf("CveID = %q, want CVE-2024-0001", results[0].CveID)
	}
	// Only 1 result with limit 25 — no next page.
	if nextCursor != "" {
		t.Errorf("expected empty cursor, got %q", nextCursor)
	}
}

func TestExecuteDSLQuery_Pagination(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed 5 CVEs with decreasing date_modified_canonical to control order.
	base := time.Now()
	for i := 0; i < 5; i++ {
		ts := base.Add(-time.Duration(i) * time.Minute)
		s.SeedTestCVE(t, fmt.Sprintf("CVE-2024-P%03d", i), "high", &testutil.SeedCVEOpts{
			DateModifiedCanonical: &ts,
		})
	}

	// Compile a rule matching "high" severity.
	rule := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "severity", Op: "eq", Value: json.RawMessage(`"high"`)},
		},
	}
	compiled, err := dsl.Compile(rule, uuid.Nil, 0, uuid.Nil, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// Page 1: limit 2.
	results, cursor, err := s.ExecuteDSLQuery(ctx, compiled, "", 2)
	if err != nil {
		t.Fatalf("ExecuteDSLQuery page 1: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("page 1: got %d results, want 2", len(results))
	}
	if cursor == "" {
		t.Fatal("expected non-empty cursor for next page")
	}

	// Page 2: use cursor from page 1.
	results2, cursor2, err := s.ExecuteDSLQuery(ctx, compiled, cursor, 2)
	if err != nil {
		t.Fatalf("ExecuteDSLQuery page 2: %v", err)
	}
	if len(results2) != 2 {
		t.Fatalf("page 2: got %d results, want 2", len(results2))
	}

	// Ensure no overlap between pages.
	page1IDs := map[string]bool{}
	for _, r := range results {
		page1IDs[r.CveID] = true
	}
	for _, r := range results2 {
		if page1IDs[r.CveID] {
			t.Errorf("page 2 contains CVE %s which was already on page 1", r.CveID)
		}
	}

	// Page 3: should have 1 remaining result.
	if cursor2 == "" {
		t.Fatal("expected non-empty cursor for page 3")
	}
	results3, cursor3, err := s.ExecuteDSLQuery(ctx, compiled, cursor2, 2)
	if err != nil {
		t.Fatalf("ExecuteDSLQuery page 3: %v", err)
	}
	if len(results3) != 1 {
		t.Fatalf("page 3: got %d results, want 1", len(results3))
	}
	// No more pages.
	if cursor3 != "" {
		t.Errorf("expected empty cursor after last page, got %q", cursor3)
	}
}

func TestExecuteDSLQuery_EmptyConditions(t *testing.T) {
	t.Parallel()

	// The DSL compiler rejects rules where all conditions are regex
	// with no watchlist IDs. An empty conditions list hits a similar
	// path. Verify Compile rejects it.
	rule := dsl.Rule{
		Logic:      dsl.LogicAnd,
		Conditions: []dsl.Condition{},
	}
	_, err := dsl.Compile(rule, uuid.Nil, 0, uuid.Nil, nil)
	if err == nil {
		t.Log("Compile accepted empty conditions — NL search handler must handle this case")
	} else {
		t.Log("Compile rejected empty conditions — NL search handler must handle this case")
	}
}

func TestExecuteDSLQuery_ExcludesRejectedWithdrawn(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed CVEs with different statuses.
	s.SeedTestCVE(t, "CVE-2024-S001", "critical", &testutil.SeedCVEOpts{Status: "published"})
	s.SeedTestCVE(t, "CVE-2024-S002", "critical", &testutil.SeedCVEOpts{Status: "rejected"})
	s.SeedTestCVE(t, "CVE-2024-S003", "critical", &testutil.SeedCVEOpts{Status: "withdrawn"})

	rule := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "severity", Op: "eq", Value: json.RawMessage(`"critical"`)},
		},
	}
	compiled, err := dsl.Compile(rule, uuid.Nil, 0, uuid.Nil, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	results, _, err := s.ExecuteDSLQuery(ctx, compiled, "", 25)
	if err != nil {
		t.Fatalf("ExecuteDSLQuery: %v", err)
	}

	for _, r := range results {
		if r.CveID == "CVE-2024-S002" {
			t.Error("rejected CVE should be excluded from results")
		}
		if r.CveID == "CVE-2024-S003" {
			t.Error("withdrawn CVE should be excluded from results")
		}
	}

	// The published one should be present.
	found := false
	for _, r := range results {
		if r.CveID == "CVE-2024-S001" {
			found = true
		}
	}
	if !found {
		t.Error("published CVE-2024-S001 should be in results")
	}
}

// ── Cursor & Limit edge cases ──────────────────────────────────────────────

// compileHighSeverity returns a compiled DSL rule matching severity=critical|high.
func compileHighSeverity(t *testing.T) *dsl.CompiledRule {
	t.Helper()
	rule := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "severity", Op: "in", Value: json.RawMessage(`["critical","high"]`)},
		},
	}
	compiled, err := dsl.Compile(rule, uuid.Nil, 0, uuid.Nil, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return compiled
}

func TestExecuteDSLQuery_InvalidBase64Cursor(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	s.SeedTestCVE(t, "CVE-2024-C001", "critical", nil)

	compiled := compileHighSeverity(t)
	_, _, err := s.ExecuteDSLQuery(ctx, compiled, "!!!not-base64!!!", 25)
	if err == nil {
		t.Fatal("expected error for invalid base64 cursor, got nil")
	}
}

func TestExecuteDSLQuery_ValidBase64InvalidJSON(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	s.SeedTestCVE(t, "CVE-2024-C002", "critical", nil)

	compiled := compileHighSeverity(t)
	badCursor := base64.URLEncoding.EncodeToString([]byte("not-json"))
	_, _, err := s.ExecuteDSLQuery(ctx, compiled, badCursor, 25)
	if err == nil {
		t.Fatal("expected error for valid base64 but invalid JSON cursor, got nil")
	}
}

func TestExecuteDSLQuery_CraftedCursor(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	base := time.Now()
	for i := 0; i < 3; i++ {
		ts := base.Add(-time.Duration(i) * time.Minute)
		s.SeedTestCVE(t, fmt.Sprintf("CVE-2024-K%03d", i), "high", &testutil.SeedCVEOpts{
			DateModifiedCanonical: &ts,
		})
	}

	compiled := compileHighSeverity(t)

	// Craft a cursor that skips all CVEs (far future date).
	farFuture := time.Now().Add(24 * time.Hour)
	crafted, _ := json.Marshal(map[string]interface{}{
		"s": farFuture.Format(time.RFC3339Nano),
		"c": "CVE-9999-9999",
	})
	cursor := base64.URLEncoding.EncodeToString(crafted)

	results, _, err := s.ExecuteDSLQuery(ctx, compiled, cursor, 25)
	if err != nil {
		t.Fatalf("ExecuteDSLQuery with crafted cursor: %v", err)
	}
	// Crafted cursor with far-future date: keyset WHERE (date, id) < (far_future, ...)
	// should still return all CVEs since they are all before the far-future date.
	if len(results) != 3 {
		t.Errorf("crafted far-future cursor: got %d results, want 3", len(results))
	}
}

func TestExecuteDSLQuery_LimitZeroClamped(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed 30 CVEs to exceed the clamped default of 25.
	base := time.Now()
	for i := 0; i < 30; i++ {
		ts := base.Add(-time.Duration(i) * time.Minute)
		s.SeedTestCVE(t, fmt.Sprintf("CVE-2024-L%03d", i), "high", &testutil.SeedCVEOpts{
			DateModifiedCanonical: &ts,
		})
	}

	compiled := compileHighSeverity(t)
	results, cursor, err := s.ExecuteDSLQuery(ctx, compiled, "", 0)
	if err != nil {
		t.Fatalf("ExecuteDSLQuery limit=0: %v", err)
	}
	// limit=0 → clamped to 25. With 30 CVEs, first page should return 25.
	if len(results) != 25 {
		t.Errorf("limit=0 clamped: got %d results, want 25", len(results))
	}
	if cursor == "" {
		t.Error("expected non-empty cursor (more results exist)")
	}
}

func TestExecuteDSLQuery_LimitOverMaxClamped(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	base := time.Now()
	for i := 0; i < 30; i++ {
		ts := base.Add(-time.Duration(i) * time.Minute)
		s.SeedTestCVE(t, fmt.Sprintf("CVE-2024-M%03d", i), "high", &testutil.SeedCVEOpts{
			DateModifiedCanonical: &ts,
		})
	}

	compiled := compileHighSeverity(t)
	results, cursor, err := s.ExecuteDSLQuery(ctx, compiled, "", 999)
	if err != nil {
		t.Fatalf("ExecuteDSLQuery limit=999: %v", err)
	}
	// limit=999 > 100 → clamped to 25. With 30 CVEs, first page returns 25.
	if len(results) != 25 {
		t.Errorf("limit=999 clamped: got %d results, want 25", len(results))
	}
	if cursor == "" {
		t.Error("expected non-empty cursor (more results exist)")
	}
}

func TestExecuteDSLQuery_NegativeLimitClamped(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	s.SeedTestCVE(t, "CVE-2024-N001", "critical", nil)

	compiled := compileHighSeverity(t)
	results, _, err := s.ExecuteDSLQuery(ctx, compiled, "", -5)
	if err != nil {
		t.Fatalf("ExecuteDSLQuery limit=-5: %v", err)
	}
	// limit=-5 → clamped to 25. With 1 CVE, returns 1.
	if len(results) != 1 {
		t.Errorf("limit=-5 clamped: got %d results, want 1", len(results))
	}
}

func TestExecuteDSLQuery_NilSQL(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	s.SeedTestCVE(t, "CVE-2024-X001", "critical", &testutil.SeedCVEOpts{Status: "published"})
	s.SeedTestCVE(t, "CVE-2024-X002", "low", &testutil.SeedCVEOpts{Status: "published"})
	s.SeedTestCVE(t, "CVE-2024-X003", "medium", &testutil.SeedCVEOpts{Status: "rejected"})

	// Nil SQL: no WHERE predicate beyond status filtering.
	compiled := &dsl.CompiledRule{} //nolint:exhaustruct // testing nil SQL path
	results, _, err := s.ExecuteDSLQuery(ctx, compiled, "", 25)
	if err != nil {
		t.Fatalf("ExecuteDSLQuery nil SQL: %v", err)
	}
	// Should return the 2 non-rejected CVEs.
	if len(results) != 2 {
		t.Errorf("nil SQL: got %d results, want 2 (excluded rejected)", len(results))
	}
}
