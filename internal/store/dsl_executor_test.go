// ABOUTME: Integration tests for store/dsl_executor.go — ExecuteDSLQuery pagination and filtering.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
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
	for i := range 5 {
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
		t.Fatal("expected Compile to reject empty conditions")
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
	for i := range 3 {
		ts := base.Add(-time.Duration(i) * time.Minute)
		s.SeedTestCVE(t, fmt.Sprintf("CVE-2024-K%03d", i), "high", &testutil.SeedCVEOpts{
			DateModifiedCanonical: &ts,
		})
	}

	compiled := compileHighSeverity(t)

	// Craft a cursor that skips all CVEs (far future date).
	farFuture := time.Now().Add(24 * time.Hour)
	crafted, _ := json.Marshal(map[string]any{
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
	for i := range 30 {
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
	for i := range 30 {
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

func TestExecuteDSLQuery_AppliesPostFilters(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed 3 CVEs: two with "apache" in description, one without.
	s.SeedTestCVE(t, "CVE-2024-PF01", "high", &testutil.SeedCVEOpts{
		DescriptionPrimary: "apache http server remote code execution",
	})
	s.SeedTestCVE(t, "CVE-2024-PF02", "high", &testutil.SeedCVEOpts{
		DescriptionPrimary: "windows kernel privilege escalation",
	})
	s.SeedTestCVE(t, "CVE-2024-PF03", "high", &testutil.SeedCVEOpts{
		DescriptionPrimary: "apache tomcat denial of service",
	})

	// Compile a rule with severity=high, then attach a regex PostFilter manually.
	rule := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "severity", Op: "eq", Value: json.RawMessage(`"high"`)},
		},
	}
	compiled, compileErr := dsl.Compile(rule, uuid.Nil, 0, uuid.Nil, nil)
	if compileErr != nil {
		t.Fatalf("Compile: %v", compileErr)
	}
	compiled.PostFilters = []dsl.PostFilter{
		{Negate: false, Pattern: regexp.MustCompile("apache")},
	}

	results, _, err := s.ExecuteDSLQuery(ctx, compiled, "", 25)
	if err != nil {
		t.Fatalf("ExecuteDSLQuery: %v", err)
	}
	// PostFilter should reduce 3 high-severity CVEs to 2 matching "apache".
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 (PostFilter 'apache')", len(results))
	}
	for _, r := range results {
		if r.CveID == "CVE-2024-PF02" {
			t.Error("CVE-2024-PF02 (windows) should be excluded by PostFilter")
		}
	}
}

func TestExecuteDSLQuery_PostFilterPagination(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed 30 CVEs with controlled timestamps and descriptions.
	// 10 contain "buffer overflow" (matching the PostFilter regex).
	// 20 do not match.
	base := time.Now()
	for i := range 30 {
		ts := base.Add(-time.Duration(i) * time.Minute)
		desc := "unrelated vulnerability in some library"
		if i%3 == 0 {
			// i=0,3,6,9,12,15,18,21,24,27 → 10 matching CVEs
			desc = "buffer overflow in network stack"
		}
		s.SeedTestCVE(t, fmt.Sprintf("CVE-2024-FP%02d", i), "high", &testutil.SeedCVEOpts{
			DateModifiedCanonical: &ts,
			DescriptionPrimary:    desc,
		})
	}

	// Compile a rule matching severity=high, then attach a regex PostFilter
	// that only keeps CVEs with "buffer overflow" in the description.
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
	compiled.PostFilters = []dsl.PostFilter{
		{Negate: false, Pattern: regexp.MustCompile("buffer overflow")},
	}

	// limit=15: SQL fetches 16 rows (limit+1). Of those 16, only ~5-6 match
	// the PostFilter. The pagination decision must use the pre-filter count
	// (16 > 15 → has next page) rather than the post-filter count.
	results, nextCursor, err := s.ExecuteDSLQuery(ctx, compiled, "", 15)
	if err != nil {
		t.Fatalf("ExecuteDSLQuery: %v", err)
	}

	// SQL fetches 16 rows (indices 0-15). Of those, i%3==0 matches: 0,3,6,9,12,15 → 6 results.
	if len(results) != 6 {
		t.Fatalf("expected 6 PostFilter-matching results, got %d", len(results))
	}

	// The critical assertion: nextCursor must be non-empty because there are
	// more rows in the DB beyond the first SQL fetch of 16.
	if nextCursor == "" {
		t.Error("expected non-empty nextCursor: PostFilter reduced results below limit, " +
			"but more unfiltered rows exist in the database")
	}
}

func TestExecuteDSLQuery_PostFilterLastPage(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed 5 CVEs: 2 match "buffer overflow", 3 do not.
	// With limit=10, SQL fetches all 5 (< limit+1), so this is the last page.
	base := time.Now()
	for i := range 5 {
		ts := base.Add(-time.Duration(i) * time.Minute)
		desc := "unrelated vulnerability"
		if i == 1 || i == 3 {
			desc = "buffer overflow in parser"
		}
		s.SeedTestCVE(t, fmt.Sprintf("CVE-2024-LP%02d", i), "high", &testutil.SeedCVEOpts{
			DateModifiedCanonical: &ts,
			DescriptionPrimary:    desc,
		})
	}

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
	compiled.PostFilters = []dsl.PostFilter{
		{Negate: false, Pattern: regexp.MustCompile("buffer overflow")},
	}

	results, nextCursor, err := s.ExecuteDSLQuery(ctx, compiled, "", 10)
	if err != nil {
		t.Fatalf("ExecuteDSLQuery: %v", err)
	}

	// PostFilter should keep 2 results.
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	// This IS the last page (only 5 rows total, limit=10). No spurious cursor.
	if nextCursor != "" {
		t.Errorf("expected empty cursor on last page with PostFilter, got %q", nextCursor)
	}
}

func TestExecuteDSLQuery_PostFilterAllFiltered(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed 20 CVEs: none in the first limit+1 rows match the PostFilter regex,
	// but more rows exist in the DB. This exercises the preFetchCursorRow fallback
	// when PostFilter removes ALL visible rows.
	base := time.Now()
	for i := range 20 {
		ts := base.Add(-time.Duration(i) * time.Minute)
		desc := "unrelated vulnerability in some library"
		// Only the last few CVEs match — they won't appear in the first page fetch.
		if i >= 18 {
			desc = "buffer overflow in network stack"
		}
		s.SeedTestCVE(t, fmt.Sprintf("CVE-2024-AF%02d", i), "high", &testutil.SeedCVEOpts{
			DateModifiedCanonical: &ts,
			DescriptionPrimary:    desc,
		})
	}

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
	compiled.PostFilters = []dsl.PostFilter{
		{Negate: false, Pattern: regexp.MustCompile("buffer overflow")},
	}

	// limit=5: SQL fetches 6 rows (limit+1). None of the first 6 rows (indices 0-5)
	// match "buffer overflow", so PostFilter removes ALL of them. But preFetchCount
	// is 6 > 5, so a cursor must be emitted using the preFetchCursorRow fallback.
	results, nextCursor, err := s.ExecuteDSLQuery(ctx, compiled, "", 5)
	if err != nil {
		t.Fatalf("ExecuteDSLQuery: %v", err)
	}

	// All rows on this page were filtered out.
	if len(results) != 0 {
		t.Fatalf("expected 0 results (all filtered), got %d", len(results))
	}

	// Cursor must be non-empty — more rows exist in the DB beyond this fetch.
	if nextCursor == "" {
		t.Error("expected non-empty nextCursor when PostFilter removes all rows but more DB rows exist")
	}
}

func TestExecuteDSLQuery_PostFilterCaseInsensitive(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed a CVE with mixed-case description.
	s.SeedTestCVE(t, "CVE-2024-CI01", "high", &testutil.SeedCVEOpts{
		DescriptionPrimary: "Critical Buffer Overflow in Chrome",
	})

	// Compile a rule matching severity=high, then attach regex PostFilters.
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

	t.Run("lowercase regex matches mixed-case description", func(t *testing.T) {
		// The alert evaluator uses lower(cves.description_primary) in SQL,
		// so a lowercase regex should match mixed-case text in PostFilter too.
		compiled.PostFilters = []dsl.PostFilter{
			{Negate: false, Pattern: regexp.MustCompile("buffer overflow")},
		}

		results, _, err := s.ExecuteDSLQuery(ctx, compiled, "", 25)
		if err != nil {
			t.Fatalf("ExecuteDSLQuery: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("got %d results, want 1: lowercase regex should match mixed-case description", len(results))
		}
		if results[0].CveID != "CVE-2024-CI01" {
			t.Errorf("CveID = %q, want CVE-2024-CI01", results[0].CveID)
		}
	})

	t.Run("lowercase regex matches lowered target text", func(t *testing.T) {
		// "critical buffer" (lowercase) should match because the target text
		// is lowered before matching, matching the alert evaluator's lower() semantics.
		compiled.PostFilters = []dsl.PostFilter{
			{Negate: false, Pattern: regexp.MustCompile("critical buffer")},
		}

		results, _, err := s.ExecuteDSLQuery(ctx, compiled, "", 25)
		if err != nil {
			t.Fatalf("ExecuteDSLQuery: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("got %d results, want 1: lowercase regex should match lowered target", len(results))
		}
	})

	t.Run("mixed-case regex does not match lowered target", func(t *testing.T) {
		// "Critical Buffer" has uppercase letters. The target text is lowered to
		// "critical buffer overflow in chrome", so "Critical" (uppercase C) should
		// NOT match. This proves we lowercase the target, not the regex.
		compiled.PostFilters = []dsl.PostFilter{
			{Negate: false, Pattern: regexp.MustCompile("Critical Buffer")},
		}

		results, _, err := s.ExecuteDSLQuery(ctx, compiled, "", 25)
		if err != nil {
			t.Fatalf("ExecuteDSLQuery: %v", err)
		}
		if len(results) != 0 {
			t.Fatalf("got %d results, want 0: mixed-case regex should not match lowered target", len(results))
		}
	})
}
