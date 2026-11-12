// ABOUTME: Types shared by every verdict source: verdicts, reasons, matched ranges and outcomes.
// ABOUTME: Also the rule combining one advisory's rows, and the work meter that stops work when the context ends.
package check

import (
	"context"
	"errors"

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
	// ReasonEvaluationFailed is a comparison that failed for a reason the
	// version package did not classify. No path gives one today.
	ReasonEvaluationFailed        Reason = "evaluation_failed"
	ReasonSDKVersionNotComparable Reason = "sdk_version_not_comparable"
	ReasonDistroStreamIncomplete  Reason = "distro_stream_incomplete"
)

// Matched is one range that contains the version, for the response. Ecosystem
// is the stored ecosystem of a package range.
type Matched struct {
	Evidence, CPE, Ecosystem, Introduced, Fixed, LastAffected string
}

// Outcome is what one source says about one advisory.
//
// InvalidVersion, UnknownVersionScheme and EvaluationFailed record failures of
// any row, whatever Reason shows: a row gave invalid_version, a row gave
// unknown_version_scheme, or a row's comparison failed with an error reasonFor
// cannot classify. Item status reads them (design section 4.7), because one
// row's reason can hide another's.
type Outcome struct {
	Verdict              Verdict
	Reason               Reason
	Matched              []Matched
	Candidates           []string // upper bounds of ranges reporting Affected
	Ranges               []Bound  // every range, for validating fix candidates
	Comparable           bool     // at least one row was compared
	InvalidVersion       bool
	UnknownVersionScheme bool
	EvaluationFailed     bool
}

// Bound is one range with the order that reads it.
type Bound struct {
	Range version.Range
	Check func(version string, r version.Range) (version.Status, error)
}

// rowVerdicts combines the verdicts of one advisory's rows for one version, by
// the rule design section 4.1 sets: Affected if any row contains the version,
// NotAffected only if some row excludes it and no row could not be compared,
// and CannotEvaluate otherwise, with the reason of its first row that could not
// be compared. Every verdict source records its rows here in stored order.
type rowVerdicts struct {
	out                                            Outcome
	anyAffected, anyNotAffected, anyCannotEvaluate bool
}

// compare checks ver against one row's bound and records the result. matched
// names the row's evidence (and CPE, for an NVD row); a row that contains the
// version is reported with it and the bound's range. Only a fixed bound becomes
// a fix candidate, because a last_affected bound does not say what fixes the
// problem (design section 7).
func (v *rowVerdicts) compare(ver string, b Bound, matched Matched) {
	v.out.Ranges = append(v.out.Ranges, b)
	status, err := b.Check(ver, b.Range)
	switch status {
	case version.Affected:
		v.anyAffected = true
		matched.Introduced, matched.Fixed, matched.LastAffected = b.Range.Introduced, b.Range.Fixed, b.Range.LastAffected
		v.out.Matched = append(v.out.Matched, matched)
		if b.Range.Fixed != "" {
			v.out.Candidates = append(v.out.Candidates, b.Range.Fixed)
		}
	case version.NotAffected:
		v.anyNotAffected = true
	default:
		v.cannotEvaluate(reasonFor(err))
	}
}

// refuse records a row that is not compared because its stored shape gives no
// range to compare against. b must answer CannotEvaluate for every version, so
// fix reporting never clears a candidate against it.
func (v *rowVerdicts) refuse(b Bound, reason Reason) {
	v.out.Ranges = append(v.out.Ranges, b)
	v.cannotEvaluate(reason)
}

func (v *rowVerdicts) cannotEvaluate(reason Reason) {
	if !v.anyCannotEvaluate {
		v.out.Reason = reason
	}
	v.anyCannotEvaluate = true
	switch reason {
	case ReasonInvalidVersion:
		v.out.InvalidVersion = true
	case ReasonUnknownVersionScheme:
		v.out.UnknownVersionScheme = true
	case "":
		v.out.EvaluationFailed = true
	}
}

// outcome returns the combined verdict. With no rows recorded it is CannotEvaluate.
func (v *rowVerdicts) outcome() Outcome {
	out := v.out
	out.Comparable = v.anyAffected || v.anyNotAffected
	switch {
	case v.anyAffected:
		out.Verdict = Affected
		out.Reason = ""
	case v.anyNotAffected && !v.anyCannotEvaluate:
		out.Verdict = NotAffected
	default:
		out.Verdict = CannotEvaluate
	}
	return out
}

// reasonFor maps the error of a version check that could not be evaluated to
// the API's reason.
func reasonFor(err error) Reason {
	switch {
	case errors.Is(err, version.ErrUnknownEcosystem):
		return ReasonUnknownVersionScheme
	case errors.Is(err, version.ErrInvalidVersion):
		return ReasonInvalidVersion
	case errors.Is(err, version.ErrInvalidRange):
		return ReasonInvalidRange
	default:
		return ""
	}
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
