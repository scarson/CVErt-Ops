// ABOUTME: Decides whether a version falls inside one advisory's affected range.
// ABOUTME: Anything not reliably comparable is "cannot evaluate", never "not affected".

// Package version checks a version against an affected range using the
// comparison rules native to the advisory's ecosystem (PLAN.md §9.2).
//
// The result has three values because a false "not affected" is the failure
// that matters in a vulnerability product: it tells someone to stop looking. A
// version, range or ecosystem this package cannot compare reliably therefore
// reports CannotEvaluate.
package version

import (
	"errors"
	"fmt"
)

// maxVersionLen rejects oversized strings before they reach any parser. Go
// pseudo-versions and RPM module builds, the longest real versions, stay well
// under this.
const maxVersionLen = 256

// introducedAtStart is the OSV schema's marker for "before every version". It
// is not compared, because some real versions sort below a literal 0: 0~rc1 in
// dpkg and 0.0.0-alpha in semver are both affected by a range starting here.
const introducedAtStart = "0"

// Status is the outcome of checking a version against an affected range. The
// zero value is CannotEvaluate, so an unset Status never reads as "not affected".
type Status int

const (
	// CannotEvaluate means the version, range or ecosystem cannot be compared
	// reliably. It says nothing about whether the version is affected.
	CannotEvaluate Status = iota
	// Affected means the version is inside the range.
	Affected
	// NotAffected means the version is outside this one range. An advisory can
	// have several ranges, so a caller must check them all before concluding
	// that the advisory does not apply.
	NotAffected
)

// String returns the status in the words shown to a person.
func (s Status) String() string {
	switch s {
	case Affected:
		return "affected"
	case NotAffected:
		return "not affected"
	default:
		return "cannot evaluate"
	}
}

// Reasons for a CannotEvaluate result. Check and CheckNumeric return one of
// these, testable with errors.Is, exactly when the status is CannotEvaluate.
var (
	ErrUnknownEcosystem = errors.New("unknown ecosystem")
	ErrInvalidVersion   = errors.New("invalid version")
	ErrInvalidRange     = errors.New("invalid range")
)

// Range is one affected range in OSV terms: from Introduced (inclusive) up to
// Fixed (exclusive) or LastAffected (inclusive).
//
// A range with no upper bound is affected from Introduced onwards, as the OSV
// schema defines it. Fixed and LastAffected must not both be set.
type Range struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

// scheme is one way of validating and ordering version strings.
type scheme struct {
	valid   func(string) bool
	compare func(a, b string) (int, error)
}

func (s scheme) check(version string, r Range) (Status, error) {
	if !s.valid(version) {
		return CannotEvaluate, ErrInvalidVersion
	}
	if err := s.validateRange(r); err != nil {
		return CannotEvaluate, err
	}

	if r.Introduced != introducedAtStart {
		c, err := s.compare(version, r.Introduced)
		if err != nil {
			return CannotEvaluate, fmt.Errorf("%w: %w", ErrInvalidVersion, err)
		}
		if c < 0 {
			return NotAffected, nil
		}
	}

	upper, inclusive, bounded := r.upperBound()
	if !bounded {
		return Affected, nil
	}
	c, err := s.compare(version, upper)
	if err != nil {
		return CannotEvaluate, fmt.Errorf("%w: %w", ErrInvalidVersion, err)
	}
	if c < 0 || (inclusive && c == 0) {
		return Affected, nil
	}
	return NotAffected, nil
}

// order compares two versions: negative when a sorts below b, positive when
// above. It returns ErrInvalidVersion when either is not a valid version of the
// scheme, because the comparison would then be a guess.
func (s scheme) order(a, b string) (int, error) {
	for _, v := range []string{a, b} {
		if !s.valid(v) {
			return 0, fmt.Errorf("%w: %q", ErrInvalidVersion, v)
		}
	}
	return s.compare(a, b)
}

// upperBound returns the range's single upper bound, whether it is inclusive, and
// whether the range has one.
func (r Range) upperBound() (bound string, inclusive, bounded bool) {
	if r.LastAffected != "" {
		return r.LastAffected, true, true
	}
	return r.Fixed, false, r.Fixed != ""
}

// validateRange rejects a range whose bounds are missing, malformed or out of
// order. An inverted range contains no version, so evaluating it would report
// everything as not affected.
func (s scheme) validateRange(r Range) error {
	switch {
	case r.Introduced == "":
		return fmt.Errorf("%w: no introduced bound", ErrInvalidRange)
	case r.Fixed != "" && r.LastAffected != "":
		return fmt.Errorf("%w: both fixed and last_affected", ErrInvalidRange)
	}

	upper, inclusive, bounded := r.upperBound()
	if !s.valid(r.Introduced) || (bounded && !s.valid(upper)) {
		return fmt.Errorf("%w: malformed bound", ErrInvalidRange)
	}
	if !bounded {
		return nil
	}

	c, err := s.compare(upper, r.Introduced)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRange, err)
	}
	if c < 0 || (c == 0 && !inclusive) {
		return fmt.Errorf("%w: upper bound does not follow introduced", ErrInvalidRange)
	}
	return nil
}
