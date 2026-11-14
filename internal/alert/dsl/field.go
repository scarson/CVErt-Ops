// ABOUTME: Field registry for the alert DSL — maps field names to kinds, SQL expressions, and valid operators.
// ABOUTME: Used by the validator (semantic checks) and compiler (SQL/PostFilter generation).
package dsl

import "github.com/scarson/cvert-ops/internal/ecosystem"

type fieldKind int

const (
	kindString   fieldKind = iota // eq/neq/in/not_in; string scalar or array
	kindEnum                      // eq/neq/in/not_in; validated against enumValues
	kindFloat                     // gt/gte/lt/lte/eq/neq; float64 value
	kindTime                      // gt/gte/lt/lte/eq/neq; RFC 3339 string → time.Time
	kindBool                      // eq only; bool value
	kindStrArray                  // contains_any/contains_all; []string value
	kindText                      // contains/starts_with/ends_with/regex; string value
	kindAffected                  // EXISTS subquery on cve_affected_packages
	kindFTS                       // matches; websearch_to_tsquery
	kindProduct                   // affected.cpe_product: eq/in; CPE vendor:product
)

type fieldSpec struct {
	kind       fieldKind
	sqlExpr    string // unaliased column reference; empty for kindAffected
	validOps   []string
	nullable   bool
	enumValues []string // non-nil for kindEnum and kindAffected with enum sub-fields
}

var severityEnum = []string{"critical", "high", "medium", "low", "none"}
var ecosystemEnum = ecosystem.Names()

var numericOps = []string{"gt", "gte", "lt", "lte", "eq", "neq"}
var setOps = []string{"eq", "neq", "in", "not_in"}
var arrayOps = []string{"contains_any", "contains_all"}
var textOps = []string{"contains", "starts_with", "ends_with", "regex"}

// packageOps adds exact match to the substring operators: eq and in compare
// names after folding for the row's ecosystem (ecosystem.FoldPackageName).
var packageOps = []string{"contains", "starts_with", "ends_with", "eq", "in"}
var ftsOps = []string{"matches"}

// fields is the authoritative registry of all supported DSL fields.
var fields = map[string]fieldSpec{
	"cve_id": {kindString, "cves.cve_id", append(setOps, "regex"), false, nil},
	// Rule values are lowercase, and feeds store severity in either case.
	"severity":                 {kindEnum, "lower(cves.severity)", setOps, false, severityEnum},
	"cvss_v3_score":            {kindFloat, "cves.cvss_v3_score", numericOps, true, nil},
	"cvss_v4_score":            {kindFloat, "cves.cvss_v4_score", numericOps, true, nil},
	"epss_score":               {kindFloat, "cves.epss_score", numericOps, true, nil},
	"date_published":           {kindTime, "cves.date_published", numericOps, true, nil},
	"date_modified_source_max": {kindTime, "cves.date_modified_source_max", numericOps, false, nil},
	"cwe_ids":                  {kindStrArray, "cves.cwe_ids", arrayOps, false, nil},
	"in_cisa_kev":              {kindBool, "cves.in_cisa_kev", []string{"eq"}, false, nil},
	"exploit_available":        {kindBool, "cves.exploit_available", []string{"eq"}, false, nil},
	"affected.ecosystem":       {kindAffected, "", setOps, false, ecosystemEnum},
	"affected.package":         {kindAffected, "", packageOps, false, nil},
	"affected.cpe_product":     {kindProduct, "", []string{"eq", "in"}, false, nil},
	"description_primary":      {kindText, "cves.description_primary", textOps, false, nil},
	"fts_query":                {kindFTS, "", ftsOps, false, nil},
}

// FieldDescription describes a queryable field for external consumers.
type FieldDescription struct {
	Name       string
	TypeDesc   string
	ValidOps   []string
	EnumValues []string
	Nullable   bool
}

// ExportFieldDescriptions returns a description of every registered field.
func ExportFieldDescriptions() []FieldDescription {
	result := make([]FieldDescription, 0, len(fields))
	for name, spec := range fields {
		fd := FieldDescription{
			Name:     name,
			ValidOps: spec.validOps,
			Nullable: spec.nullable,
		}
		switch spec.kind {
		case kindFloat:
			fd.TypeDesc = "number"
		case kindTime:
			fd.TypeDesc = "datetime (RFC 3339)"
		case kindBool:
			fd.TypeDesc = "boolean"
		case kindString:
			fd.TypeDesc = "string"
		case kindEnum:
			fd.TypeDesc = "enum"
			fd.EnumValues = spec.enumValues
		case kindStrArray:
			fd.TypeDesc = "string array"
		case kindText:
			fd.TypeDesc = "text"
		case kindAffected:
			fd.TypeDesc = "affected product"
			fd.EnumValues = spec.enumValues
		case kindFTS:
			fd.TypeDesc = "full-text search"
		case kindProduct:
			fd.TypeDesc = "CPE vendor:product"
		}
		result = append(result, fd)
	}
	return result
}
