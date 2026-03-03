// ABOUTME: Tests for the DSL schema description builder used in NL search system prompts.
// ABOUTME: Validates field coverage, operator presence, determinism, and prompt version stability.
package ai_test

import (
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/ai"
)

func TestBuildSchemaDescription_ContainsAllFields(t *testing.T) {
	t.Parallel()
	desc := ai.BuildSchemaDescription()
	expectedFields := []string{
		"cve_id", "severity", "cvss_v3_score", "cvss_v4_score",
		"epss_score", "date_published", "date_modified_source_max",
		"cwe_ids", "in_cisa_kev", "exploit_available",
		"affected.ecosystem", "affected.package",
		"description_primary", "fts_query",
	}
	for _, f := range expectedFields {
		if !strings.Contains(desc, f) {
			t.Errorf("schema description missing field %q", f)
		}
	}
}

func TestBuildSchemaDescription_ContainsOperators(t *testing.T) {
	t.Parallel()
	desc := ai.BuildSchemaDescription()
	for _, op := range []string{"eq", "gte", "in", "contains", "matches"} {
		if !strings.Contains(desc, op) {
			t.Errorf("schema description missing operator %q", op)
		}
	}
}

func TestBuildSchemaDescription_Deterministic(t *testing.T) {
	t.Parallel()
	d1 := ai.BuildSchemaDescription()
	d2 := ai.BuildSchemaDescription()
	if d1 != d2 {
		t.Error("BuildSchemaDescription is not deterministic")
	}
}

func TestPromptVersion_Stable(t *testing.T) {
	t.Parallel()
	v1 := ai.PromptVersion()
	v2 := ai.PromptVersion()
	if v1 != v2 {
		t.Errorf("PromptVersion not stable: %q vs %q", v1, v2)
	}
	if len(v1) != 8 {
		t.Errorf("PromptVersion length = %d, want 8", len(v1))
	}
}

func TestBuildSchemaDescription_NullableAnnotation(t *testing.T) {
	t.Parallel()
	desc := ai.BuildSchemaDescription()
	// At least one nullable field should produce "Nullable: true".
	if !strings.Contains(desc, "Nullable: true") {
		t.Error("schema description missing Nullable annotation")
	}
}

func TestBuildSchemaDescription_EnumValues(t *testing.T) {
	t.Parallel()
	desc := ai.BuildSchemaDescription()
	// severity has enum values: critical, high, medium, low, none.
	if !strings.Contains(desc, "Values:") {
		t.Error("schema description missing Values annotation for enum fields")
	}
	if !strings.Contains(desc, "critical") {
		t.Error("schema description missing 'critical' enum value for severity")
	}
}

func TestBuildSchemaDescription_FieldsSortedByName(t *testing.T) {
	t.Parallel()
	desc := ai.BuildSchemaDescription()
	// Extract field names from "- fieldname (type: ...)" lines.
	lines := strings.Split(desc, "\n")
	var fieldNames []string
	for _, l := range lines {
		if strings.HasPrefix(l, "- ") {
			paren := strings.Index(l, " (type:")
			if paren > 2 {
				fieldNames = append(fieldNames, l[2:paren])
			}
		}
	}
	if len(fieldNames) < 5 {
		t.Fatalf("expected at least 5 fields, got %d", len(fieldNames))
	}
	for i := 1; i < len(fieldNames); i++ {
		if fieldNames[i-1] > fieldNames[i] {
			t.Errorf("fields not sorted: %q > %q", fieldNames[i-1], fieldNames[i])
		}
	}
}
