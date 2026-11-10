// ABOUTME: Checks a product version against an NVD CPE range whose bounds may not be dotted numbers.
// ABOUTME: A bound such as 1.0.2zf is compared by its leading dotted numbers, and only where they differ.
package version

import (
	"fmt"
	"regexp"
	"strings"
)

// leadingNumbers matches the dotted numbers a bound starts with: 1.0.2 in
// 1.0.2zf, 2.0 in 2.0b10.
var leadingNumbers = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*`)

// CheckProduct reports whether version is inside r for a product with no
// ecosystem to supply ordering rules (design section 4.2). The version must be
// dotted numbers. A range whose bounds are all dotted numbers answers exactly as
// CheckNumeric answers it.
//
// Old NVD analysis also names bounds such as 2.0b10 or 1.0.2zf. Such a bound is
// compared by its leading dotted numbers, component by component over the
// components both sides have, and the comparison counts only where they differ:
// 8.4.14 is above 2.0b10, but 1.0.2 against 1.0.2zf is not decided, because the
// suffix's meaning belongs to the product. A suffix cannot carry a version past
// a different leading number, except an epoch (1:2.0, 1!2.0), so a bound whose
// suffix starts with one is not compared. Anything not decided reports
// CannotEvaluate with ErrInvalidRange.
//
// When the range's own bounds have no decided order (1.0.2 and 1.0.2zf, or an
// exact release 2.0b10 to 2.0b10), the range cannot be read as running either
// way, so the version reports NotAffected only when it is decided below both
// bounds or above both, and never Affected.
func CheckProduct(version string, r Range) (Status, error) {
	if !numericScheme.valid(version) {
		return CannotEvaluate, ErrInvalidVersion
	}
	if numericBounds(r) {
		return CheckNumeric(version, r)
	}
	switch {
	case r.Introduced == "":
		return CannotEvaluate, fmt.Errorf("%w: no introduced bound", ErrInvalidRange)
	case r.Fixed != "" && r.LastAffected != "":
		return CannotEvaluate, fmt.Errorf("%w: both fixed and last_affected", ErrInvalidRange)
	}
	upper, inclusive, bounded := r.upperBound()
	for _, b := range []string{r.Introduced, upper} {
		if b != "" && !comparableBound(b) {
			return CannotEvaluate, fmt.Errorf("%w: bound %q cannot be compared", ErrInvalidRange, b)
		}
	}

	ordered := true
	if bounded && r.Introduced != introducedAtStart {
		c, decided := leadingOrder(upper, r.Introduced)
		switch {
		case !decided:
			ordered = false
		case c < 0 || (c == 0 && !inclusive):
			return CannotEvaluate, fmt.Errorf("%w: upper bound does not follow introduced", ErrInvalidRange)
		}
	}
	if !ordered {
		return outsideBoth(version, r.Introduced, upper)
	}

	if r.Introduced != introducedAtStart {
		c, decided := leadingOrder(version, r.Introduced)
		if !decided {
			return CannotEvaluate, fmt.Errorf("%w: %q against introduced %q is not decided", ErrInvalidRange, version, r.Introduced)
		}
		if c < 0 {
			return NotAffected, nil
		}
	}
	if !bounded {
		return Affected, nil
	}
	c, decided := leadingOrder(version, upper)
	if !decided {
		return CannotEvaluate, fmt.Errorf("%w: %q against upper bound %q is not decided", ErrInvalidRange, version, upper)
	}
	if c < 0 || (inclusive && c == 0) {
		return Affected, nil
	}
	return NotAffected, nil
}

// numericBounds reports whether every bound r sets is dotted numbers.
func numericBounds(r Range) bool {
	for _, b := range []string{r.Introduced, r.Fixed, r.LastAffected} {
		if b != "" && !numericScheme.valid(b) {
			return false
		}
	}
	return true
}

// comparableBound reports whether a bound that is not dotted numbers may be
// compared by its leading dotted numbers: it has some, and what follows them is
// not an epoch separator, plain or CPE-escaped.
func comparableBound(b string) bool {
	if len(b) > maxVersionLen {
		return false
	}
	lead := leadingNumbers.FindString(b)
	if lead == "" {
		return false
	}
	rest := strings.TrimPrefix(b[len(lead):], `\`)
	return !strings.HasPrefix(rest, ":") && !strings.HasPrefix(rest, "!")
}

// outsideBoth answers a range whose bounds have no decided order: NotAffected
// when version is decided below both bounds or above both, otherwise
// CannotEvaluate. upper is "" for a range with no upper bound.
func outsideBoth(version, introduced, upper string) (Status, error) {
	ci, okI := leadingOrder(version, introduced)
	cu, okU := leadingOrder(version, upper)
	if okI && okU && ((ci < 0 && cu < 0) || (ci > 0 && cu > 0)) {
		return NotAffected, nil
	}
	return CannotEvaluate, fmt.Errorf("%w: %q is not decided against %q and %q", ErrInvalidRange, version, introduced, upper)
}

// leadingOrder compares a and b, and reports whether the order is decided. Two
// dotted-number strings compare numerically. Otherwise the order is decided only
// by the first component, among those both leading parts have, where they differ.
func leadingOrder(a, b string) (int, bool) {
	if numericScheme.valid(a) && numericScheme.valid(b) {
		c, err := compareNumeric(a, b)
		return c, err == nil
	}
	as := strings.Split(leadingNumbers.FindString(a), ".")
	bs := strings.Split(leadingNumbers.FindString(b), ".")
	for i := range min(len(as), len(bs)) {
		if as[i] == "" || bs[i] == "" {
			return 0, false
		}
		if c := compareDigits(as[i], bs[i]); c != 0 {
			return c, true
		}
	}
	return 0, false
}

// compareDigits orders two digit strings by value, without converting them, so
// any length compares correctly.
func compareDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}
