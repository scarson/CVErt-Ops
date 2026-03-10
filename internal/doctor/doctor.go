// ABOUTME: Doctor check framework — defines Check interface and Runner for system health verification.
// ABOUTME: Used by both CLI (`cvert-ops doctor`) and API (`GET /api/v1/admin/doctor`).
package doctor

import (
	"context"
)

// Status constants for check results.
const (
	StatusPass = "pass"
	StatusWarn = "warn"
	StatusFail = "fail"
)

// Check is a single diagnostic check. Implementations verify one aspect of
// system health and return a status with a human-readable message.
type Check interface {
	Name() string
	Run(ctx context.Context) (status string, message string, err error)
}

// Result holds the outcome of a single check execution.
type Result struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// Run executes all checks and returns their results. Checks that return an
// error are recorded as "fail" with the error message.
func Run(ctx context.Context, checks []Check) []Result {
	results := make([]Result, 0, len(checks))
	for _, c := range checks {
		status, msg, err := c.Run(ctx)
		r := Result{
			Name:    c.Name(),
			Status:  status,
			Message: msg,
		}
		if err != nil {
			r.Status = StatusFail
			r.Error = err.Error()
			if r.Message == "" {
				r.Message = err.Error()
			}
		}
		results = append(results, r)
	}
	return results
}

// HasFailures returns true if any result has status "fail".
func HasFailures(results []Result) bool {
	for _, r := range results {
		if r.Status == StatusFail {
			return true
		}
	}
	return false
}
