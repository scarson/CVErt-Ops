// ABOUTME: Types shared by every verdict source: verdicts, reasons, matched ranges and outcomes.
// ABOUTME: Also the work meter that stops comparison work when the request's context ends.
package check

import (
	"context"

	"github.com/scarson/cvert-ops/internal/version"
)

// Verdict is one advisory's answer for one component. The zero value is
// CannotEvaluate, so an unset verdict never reads as "not affected".
type Verdict int

// The verdicts. NotAffected is internal: an advisory that does not affect the
// component is counted, not listed, so the API's verdict values omit it.
const (
	CannotEvaluate Verdict = iota
	Affected
	NotAffected
)

// Reason values are the API's reason enumeration (design section 11).
type Reason string

// The reasons a verdict can carry. Each is a stable API value.
const (
	ReasonUnknownVersionScheme  Reason = "unknown_version_scheme"
	ReasonInvalidVersion        Reason = "invalid_version"
	ReasonInvalidRange          Reason = "invalid_range"
	ReasonCommitRangesOnly      Reason = "commit_ranges_only"
	ReasonNoVersionBounds       Reason = "no_version_bounds"
	ReasonCNACannotClear        Reason = "cna_cannot_clear"
	ReasonCNAIndeterminate      Reason = "cna_indeterminate"
	ReasonCNANameUncertain      Reason = "cna_name_uncertain"
	ReasonCNAProductNotMapped   Reason = "cna_product_not_mapped"
	ReasonDataIncomplete        Reason = "data_incomplete"
	ReasonDistroPackageNotFound Reason = "distro_package_not_found"
	ReasonTooManyCandidates     Reason = "too_many_candidates"
	ReasonTooManyRanges         Reason = "too_many_ranges"
)

// Matched is one range that contains the version, for the response.
type Matched struct {
	Evidence, CPE, Introduced, Fixed, LastAffected string
}

// Outcome is what one source says about one advisory.
type Outcome struct {
	Verdict    Verdict
	Reason     Reason
	Matched    []Matched
	Candidates []string // upper bounds of ranges reporting Affected
	Ranges     []Bound  // every range, for validating fix candidates
	Comparable bool     // at least one row was compared
}

// Bound is one range with the order that reads it.
type Bound struct {
	Range version.Range
	Check func(version string, r version.Range) (version.Status, error)
}

// workMeter stops comparison work when the request's context ends, because a
// context cannot interrupt pure computation. Every loop that compares versions
// calls Tick once per range or candidate and leaves the loop when it returns false.
type workMeter struct {
	ctx    context.Context
	ticks  int
	err    error
	onTick func() // test hook, nil in production
}

func newWorkMeter(ctx context.Context) *workMeter { return &workMeter{ctx: ctx} }

// Tick checks the context every 1,000 calls and reports whether work may continue.
func (m *workMeter) Tick() bool {
	if m.err != nil {
		return false
	}
	if m.onTick != nil {
		m.onTick()
	}
	m.ticks++
	if m.ticks%1000 == 0 {
		m.err = m.ctx.Err()
	}
	return m.err == nil
}

// Err reports the context's error at the moment it is asked, so a short request
// cancelled between multiples of 1,000 ticks is still noticed.
func (m *workMeter) Err() error {
	if m.err == nil {
		m.err = m.ctx.Err()
	}
	return m.err
}
