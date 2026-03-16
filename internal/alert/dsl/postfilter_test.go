// ABOUTME: Tests for the generic ApplyPostFilters function.
// ABOUTME: Validates AND/OR logic, negation, field targeting, and empty filter passthrough.
package dsl

import (
	"regexp"
	"testing"
)

// testTarget is a minimal PostFilterTarget for testing.
type testTarget struct {
	id   string
	desc string
}

func (t testTarget) PostFilterField(field string) string {
	if field == "cve_id" {
		return t.id
	}
	return t.desc
}

func TestApplyPostFilters_EmptyFilters(t *testing.T) {
	candidates := []testTarget{
		{id: "CVE-2024-0001", desc: "buffer overflow in kernel"},
		{id: "CVE-2024-0002", desc: "sql injection in webapp"},
	}
	result := ApplyPostFilters(candidates, nil, LogicAnd)
	if len(result) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result))
	}
}

func TestApplyPostFilters_ANDLogic(t *testing.T) {
	candidates := []testTarget{
		{id: "CVE-2024-0001", desc: "buffer overflow in kernel"},
		{id: "CVE-2024-0002", desc: "buffer overflow in webapp"},
		{id: "CVE-2024-0003", desc: "sql injection in webapp"},
	}
	filters := []PostFilter{
		{Field: "description_primary", Pattern: regexp.MustCompile("buffer")},
		{Field: "description_primary", Pattern: regexp.MustCompile("kernel")},
	}
	result := ApplyPostFilters(candidates, filters, LogicAnd)
	if len(result) != 1 {
		t.Fatalf("expected 1 AND match, got %d", len(result))
	}
	if result[0].PostFilterField("cve_id") != "CVE-2024-0001" {
		t.Fatalf("expected CVE-2024-0001, got %s", result[0].PostFilterField("cve_id"))
	}
}

func TestApplyPostFilters_ORLogic(t *testing.T) {
	candidates := []testTarget{
		{id: "CVE-2024-0001", desc: "buffer overflow in kernel"},
		{id: "CVE-2024-0002", desc: "sql injection in webapp"},
		{id: "CVE-2024-0003", desc: "xss in frontend"},
	}
	filters := []PostFilter{
		{Field: "description_primary", Pattern: regexp.MustCompile("buffer")},
		{Field: "description_primary", Pattern: regexp.MustCompile("injection")},
	}
	result := ApplyPostFilters(candidates, filters, LogicOr)
	if len(result) != 2 {
		t.Fatalf("expected 2 OR matches, got %d", len(result))
	}
}

func TestApplyPostFilters_Negate(t *testing.T) {
	candidates := []testTarget{
		{id: "CVE-2024-0001", desc: "buffer overflow in kernel"},
		{id: "CVE-2024-0002", desc: "sql injection in webapp"},
	}
	filters := []PostFilter{
		{Field: "description_primary", Negate: true, Pattern: regexp.MustCompile("buffer")},
	}
	result := ApplyPostFilters(candidates, filters, LogicAnd)
	if len(result) != 1 {
		t.Fatalf("expected 1 negated match, got %d", len(result))
	}
	if result[0].PostFilterField("cve_id") != "CVE-2024-0002" {
		t.Fatalf("expected CVE-2024-0002, got %s", result[0].PostFilterField("cve_id"))
	}
}

func TestApplyPostFilters_CVEIDField(t *testing.T) {
	candidates := []testTarget{
		{id: "CVE-2024-0001", desc: "buffer overflow"},
		{id: "CVE-2024-0002", desc: "sql injection"},
		{id: "CVE-2025-1234", desc: "xss"},
	}
	filters := []PostFilter{
		{Field: "cve_id", Pattern: regexp.MustCompile("CVE-2024")},
	}
	result := ApplyPostFilters(candidates, filters, LogicAnd)
	if len(result) != 2 {
		t.Fatalf("expected 2 cve_id matches, got %d", len(result))
	}
}

func TestApplyPostFilters_ANDWithNegate(t *testing.T) {
	candidates := []testTarget{
		{id: "CVE-2024-0001", desc: "buffer overflow in kernel"},
		{id: "CVE-2024-0002", desc: "buffer overflow in webapp"},
		{id: "CVE-2024-0003", desc: "sql injection in webapp"},
	}
	filters := []PostFilter{
		{Field: "description_primary", Pattern: regexp.MustCompile("buffer")},
		{Field: "description_primary", Negate: true, Pattern: regexp.MustCompile("kernel")},
	}
	result := ApplyPostFilters(candidates, filters, LogicAnd)
	if len(result) != 1 {
		t.Fatalf("expected 1 match, got %d", len(result))
	}
	if result[0].PostFilterField("cve_id") != "CVE-2024-0002" {
		t.Fatalf("expected CVE-2024-0002, got %s", result[0].PostFilterField("cve_id"))
	}
}

func TestApplyPostFilters_ORNoneMatch(t *testing.T) {
	candidates := []testTarget{
		{id: "CVE-2024-0001", desc: "buffer overflow"},
		{id: "CVE-2024-0002", desc: "sql injection"},
	}
	filters := []PostFilter{
		{Field: "description_primary", Pattern: regexp.MustCompile("xss")},
	}
	result := ApplyPostFilters(candidates, filters, LogicOr)
	if len(result) != 0 {
		t.Fatalf("expected 0 OR matches, got %d", len(result))
	}
}
