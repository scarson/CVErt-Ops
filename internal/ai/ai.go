// ABOUTME: LLMClient interface and supporting types for AI-powered features.
// ABOUTME: Abstracts vendor (Gemini) behind an interface for testability.
package ai

import (
	"context"
	"encoding/json"
)

// LLMClient abstracts the LLM vendor for structured query generation and
// CVE summarization.
type LLMClient interface {
	// GenerateStructuredQuery sends a natural language query with a schema
	// description and returns structured DSL JSON.
	GenerateStructuredQuery(ctx context.Context, prompt string) (GenerateResult, error)
	// Summarize generates a plain-text summary of a CVE from structured input.
	Summarize(ctx context.Context, input CVESummaryInput) (SummarizeResult, error)
}

// GenerateResult holds the LLM response for a structured query request.
type GenerateResult struct {
	QueryJSON    json.RawMessage
	InputTokens  int
	OutputTokens int
}

// SummarizeResult holds the LLM response for a summarization request.
type SummarizeResult struct {
	Summary      string
	InputTokens  int
	OutputTokens int
}

// CVESummaryInput contains the sanitized CVE fields sent to the LLM.
type CVESummaryInput struct {
	CVEID            string   `json:"cve_id"`
	Severity         string   `json:"severity"`
	CVSSV3Score      *float64 `json:"cvss_v3_score,omitempty"`
	CVSSV4Score      *float64 `json:"cvss_v4_score,omitempty"`
	EPSSScore        *float64 `json:"epss_score,omitempty"`
	CWEIDs           []string `json:"cwe_ids,omitempty"`
	AffectedPackages []string `json:"affected_packages,omitempty"`
	Description      string   `json:"description"`
	InCISAKEV        bool     `json:"in_cisa_kev"`
	ExploitAvailable bool     `json:"exploit_available"`
}
