// ABOUTME: Unit tests for applyPostFilters covering regex match, negate, multi-filter AND/OR semantics.
// ABOUTME: Uses package alert (internal test) to access the unexported applyPostFilters function.
package alert

import (
	"regexp"
	"testing"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
)

func TestApplyPostFilters_NoFilters(t *testing.T) {
	candidates := []cveSummary{
		{CVEID: "CVE-1", Description: "apache server"},
		{CVEID: "CVE-2", Description: "windows kernel"},
	}
	result := applyPostFilters(candidates, nil, dsl.LogicAnd)
	if len(result) != 2 {
		t.Fatalf("want 2 candidates with no filters, got %d", len(result))
	}
}

func TestApplyPostFilters_RegexMatch(t *testing.T) {
	candidates := []cveSummary{
		{CVEID: "CVE-1", Description: "apache http server vulnerability"},
		{CVEID: "CVE-2", Description: "windows kernel flaw"},
		{CVEID: "CVE-3", Description: "apache tomcat rce"},
	}
	filters := []dsl.PostFilter{
		{Negate: false, Pattern: regexp.MustCompile("apache")},
	}
	result := applyPostFilters(candidates, filters, dsl.LogicAnd)
	if len(result) != 2 {
		t.Fatalf("want 2 matches for 'apache', got %d", len(result))
	}
	for _, r := range result {
		if r.CVEID == "CVE-2" {
			t.Fatal("CVE-2 should not match 'apache'")
		}
	}
}

func TestApplyPostFilters_RegexNegate(t *testing.T) {
	candidates := []cveSummary{
		{CVEID: "CVE-1", Description: "apache http server vulnerability"},
		{CVEID: "CVE-2", Description: "windows kernel flaw"},
		{CVEID: "CVE-3", Description: "apache tomcat rce"},
	}
	// Negate=true: exclude candidates that match "apache"
	filters := []dsl.PostFilter{
		{Negate: true, Pattern: regexp.MustCompile("apache")},
	}
	result := applyPostFilters(candidates, filters, dsl.LogicAnd)
	if len(result) != 1 {
		t.Fatalf("want 1 candidate after negated 'apache' filter, got %d", len(result))
	}
	if result[0].CVEID != "CVE-2" {
		t.Fatalf("want CVE-2, got %s", result[0].CVEID)
	}
}

func TestApplyPostFilters_MultipleFiltersAND(t *testing.T) {
	candidates := []cveSummary{
		{CVEID: "CVE-1", Description: "apache http server remote code execution"},
		{CVEID: "CVE-2", Description: "apache tomcat information disclosure"},
		{CVEID: "CVE-3", Description: "windows kernel remote code execution"},
	}
	// Both filters must match (AND semantics): contains "apache" AND contains "remote"
	filters := []dsl.PostFilter{
		{Negate: false, Pattern: regexp.MustCompile("apache")},
		{Negate: false, Pattern: regexp.MustCompile("remote")},
	}
	result := applyPostFilters(candidates, filters, dsl.LogicAnd)
	if len(result) != 1 {
		t.Fatalf("want 1 candidate matching both 'apache' AND 'remote', got %d", len(result))
	}
	if result[0].CVEID != "CVE-1" {
		t.Fatalf("want CVE-1, got %s", result[0].CVEID)
	}
}

func TestApplyPostFilters_NegateWithPositive(t *testing.T) {
	candidates := []cveSummary{
		{CVEID: "CVE-1", Description: "apache http server remote code execution"},
		{CVEID: "CVE-2", Description: "apache tomcat information disclosure"},
		{CVEID: "CVE-3", Description: "windows kernel remote code execution"},
	}
	// Match "remote" AND NOT "apache"
	filters := []dsl.PostFilter{
		{Negate: false, Pattern: regexp.MustCompile("remote")},
		{Negate: true, Pattern: regexp.MustCompile("apache")},
	}
	result := applyPostFilters(candidates, filters, dsl.LogicAnd)
	if len(result) != 1 {
		t.Fatalf("want 1 candidate matching 'remote' AND NOT 'apache', got %d", len(result))
	}
	if result[0].CVEID != "CVE-3" {
		t.Fatalf("want CVE-3, got %s", result[0].CVEID)
	}
}

func TestApplyPostFilters_EmptyCandidates(t *testing.T) {
	filters := []dsl.PostFilter{
		{Negate: false, Pattern: regexp.MustCompile("apache")},
	}
	result := applyPostFilters(nil, filters, dsl.LogicAnd)
	if len(result) != 0 {
		t.Fatalf("want 0 results from empty candidates, got %d", len(result))
	}
}

func TestApplyPostFilters_NoMatchesReturnsNil(t *testing.T) {
	candidates := []cveSummary{
		{CVEID: "CVE-1", Description: "windows kernel"},
	}
	filters := []dsl.PostFilter{
		{Negate: false, Pattern: regexp.MustCompile("apache")},
	}
	result := applyPostFilters(candidates, filters, dsl.LogicAnd)
	if len(result) != 0 {
		t.Fatalf("want 0 matches, got %d", len(result))
	}
}

func TestApplyPostFilters_ORLogic(t *testing.T) {
	candidates := []cveSummary{
		{CVEID: "CVE-1", Description: "apache http server vulnerability"},
		{CVEID: "CVE-2", Description: "windows kernel flaw"},
		{CVEID: "CVE-3", Description: "linux privilege escalation"},
	}
	// OR logic: matches "apache" OR "windows"
	filters := []dsl.PostFilter{
		{Negate: false, Pattern: regexp.MustCompile("apache")},
		{Negate: false, Pattern: regexp.MustCompile("windows")},
	}
	result := applyPostFilters(candidates, filters, dsl.LogicOr)
	if len(result) != 2 {
		t.Fatalf("want 2 candidates matching 'apache' OR 'windows', got %d", len(result))
	}
	ids := map[string]bool{}
	for _, r := range result {
		ids[r.CVEID] = true
	}
	if !ids["CVE-1"] || !ids["CVE-2"] {
		t.Fatalf("want CVE-1 and CVE-2, got %v", ids)
	}
}

func TestApplyPostFilters_ORLogicNegate(t *testing.T) {
	candidates := []cveSummary{
		{CVEID: "CVE-1", Description: "apache http server vulnerability"},
		{CVEID: "CVE-2", Description: "windows kernel flaw"},
		{CVEID: "CVE-3", Description: "linux privilege escalation"},
	}
	// OR logic: NOT "apache" OR matches "linux" → CVE-2 and CVE-3 match NOT "apache", CVE-3 matches "linux"
	filters := []dsl.PostFilter{
		{Negate: true, Pattern: regexp.MustCompile("apache")},
		{Negate: false, Pattern: regexp.MustCompile("linux")},
	}
	result := applyPostFilters(candidates, filters, dsl.LogicOr)
	if len(result) != 2 {
		t.Fatalf("want 2 candidates, got %d", len(result))
	}
	ids := map[string]bool{}
	for _, r := range result {
		ids[r.CVEID] = true
	}
	if !ids["CVE-2"] || !ids["CVE-3"] {
		t.Fatalf("want CVE-2 and CVE-3, got %v", ids)
	}
}
