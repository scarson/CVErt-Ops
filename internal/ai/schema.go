// ABOUTME: Generates the DSL schema description for the NL search system prompt.
// ABOUTME: Iterates the DSL field registry in deterministic order for stable prompt versioning.
package ai

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
)

var (
	schemaOnce sync.Once
	schemaDesc string
	promptVer  string
)

// BuildSchemaDescription generates a text description of all queryable
// fields, their types, valid operators, and enum values. The output is
// deterministic (sorted by field name) so that the prompt version hash
// is stable across process restarts.
func BuildSchemaDescription() string {
	schemaOnce.Do(buildSchema)
	return schemaDesc
}

// PromptVersion returns the first 8 hex characters of the SHA-256 hash
// of the system prompt. Changes automatically when the schema changes.
func PromptVersion() string {
	schemaOnce.Do(buildSchema)
	return promptVer
}

func buildSchema() {
	fields := dsl.ExportFieldDescriptions()
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Name < fields[j].Name
	})

	var b strings.Builder
	b.WriteString("You translate natural language queries about CVEs into structured JSON.\n")
	b.WriteString("Output a JSON object with \"logic\" (\"and\" or \"or\") and \"conditions\" array.\n")
	b.WriteString("Each condition has \"field\", \"operator\", and \"value\".\n\n")
	b.WriteString("Available fields:\n\n")

	for _, f := range fields {
		fmt.Fprintf(&b, "- %s (type: %s)\n", f.Name, f.TypeDesc)
		fmt.Fprintf(&b, "  Operators: %s\n", strings.Join(f.ValidOps, ", "))
		if len(f.EnumValues) > 0 {
			fmt.Fprintf(&b, "  Values: %s\n", strings.Join(f.EnumValues, ", "))
		}
		if f.Nullable {
			b.WriteString("  Nullable: true\n")
		}
		b.WriteByte('\n')
	}

	b.WriteString("Notes:\n")
	b.WriteString("- Use \"fts_query\" with \"matches\" for full-text search across CVE descriptions.\n")
	b.WriteString("- Use \"severity\" with values: critical, high, medium, low, none.\n")
	b.WriteString("- Date values must be RFC 3339 format (e.g., \"2024-01-01T00:00:00Z\").\n")
	b.WriteString("- For numeric ranges, use gte/lte (e.g., cvss_v3_score gte 7.0).\n")
	b.WriteString("- Use \"and\" logic unless the user explicitly says \"or\".\n")

	schemaDesc = b.String()
	h := sha256.Sum256([]byte(schemaDesc))
	promptVer = fmt.Sprintf("%x", h[:4])
}
