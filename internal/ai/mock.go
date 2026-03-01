// ABOUTME: Deterministic mock LLMClient for testing without Gemini credentials.
// ABOUTME: Returns canned responses; enabled via GEMINI_MOCK=true.
package ai

import (
	"context"
	"encoding/json"
)

// Compile-time interface compliance check.
var _ LLMClient = (*MockClient)(nil)

// MockClient implements LLMClient with deterministic canned responses.
// Set Err to a non-nil value to simulate LLM failures.
type MockClient struct {
	Err error
}

// NewMockClient returns a mock LLM client for testing.
func NewMockClient() *MockClient {
	return &MockClient{}
}

// GenerateStructuredQuery returns a canned DSL JSON response.
func (m *MockClient) GenerateStructuredQuery(_ context.Context, _ string) (GenerateResult, error) {
	if m.Err != nil {
		return GenerateResult{}, m.Err
	}
	raw := json.RawMessage(`{"logic":"and","conditions":[{"field":"severity","operator":"in","value":["critical","high"]}]}`)
	return GenerateResult{
		QueryJSON:    raw,
		InputTokens:  10,
		OutputTokens: 20,
	}, nil
}

// Summarize returns a canned summary incorporating the CVE ID.
func (m *MockClient) Summarize(_ context.Context, input CVESummaryInput) (SummarizeResult, error) {
	if m.Err != nil {
		return SummarizeResult{}, m.Err
	}
	return SummarizeResult{
		Summary:      "This is a mock summary for " + input.CVEID + ".",
		InputTokens:  15,
		OutputTokens: 25,
	}, nil
}
