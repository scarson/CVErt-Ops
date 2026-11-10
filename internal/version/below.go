// ABOUTME: Finds NVD CPE ranges that lie wholly below a product version, as a Go rule and as the same rule in SQL.
// ABOUTME: CheckProduct answers NotAffected on such a range for the version and for every dotted-number version at or above it.
package version

import "strings"

// ProductRangeBelow reports whether r lies wholly below version, so that
// CheckProduct answers NotAffected for version and for every dotted-number
// version at or above it. A version check uses it to leave such ranges unread
// (design section 4.2): the range cannot contain the version, and cannot
// contain a fix candidate, which is above the version.
//
// It reports true only when all of these hold, and false whenever one is in
// doubt, because a range wrongly reported here would be a wrong "not affected":
//
//   - version is dotted numbers;
//   - r has an introduced bound and exactly one upper bound;
//   - the upper bound follows introduced: decided above it, or the identical
//     string with an inclusive upper bound, so CheckProduct does not refuse the
//     range as inverted or empty;
//   - the upper bound is decided below version.
//
// "Decided" is leadingOrder's decision, taken only between bounds that hold
// none of the characters comparableBound looks for (plainBound).
func ProductRangeBelow(version string, r Range) bool {
	if !numericScheme.valid(version) || r.Introduced == "" || (r.Fixed != "" && r.LastAffected != "") {
		return false
	}
	upper, inclusive, bounded := r.upperBound()
	if !bounded {
		return false
	}
	if !decidedBelow(r.Introduced, upper) && (r.Introduced != upper || !inclusive) {
		return false
	}
	return decidedBelow(upper, version)
}

// decidedBelow reports whether a is decided below b, both being plain bounds.
func decidedBelow(a, b string) bool {
	if !plainBound(a) || !plainBound(b) {
		return false
	}
	c, decided := leadingOrder(a, b)
	return decided && c < 0
}

// plainBound reports a bound that starts with a digit, is no longer than
// maxVersionLen and holds none of % * ? \ : and !. Every plain bound is one
// comparableBound accepts, or dotted numbers. It is narrower than
// comparableBound (an escaped character anywhere excludes the bound) so that
// SQL can state the same test.
func plainBound(b string) bool {
	return b != "" && len(b) <= maxVersionLen && b[0] >= '0' && b[0] <= '9' && !strings.ContainsAny(b, `%*?\:!`)
}

// BoundSQL names the SQL expressions that describe one bound of a range, or a
// version: Text is its text, Leading is LeadingSQL of that text and Dotted is
// DottedSQL of it. A caller computes each once per row and names the result, so
// the comparison below does not parse a bound again each time it reads it.
type BoundSQL struct{ Text, Leading, Dotted string }

// LeadingSQL returns a SQL expression for the leading dotted numbers of the
// text expression x as numeric[], or NULL when x is not a plain bound
// (plainBound). The cast runs only after the length test: numeric takes at most
// 131,072 digits.
func LeadingSQL(x string) string {
	return "(CASE WHEN octet_length(" + x + ") <= 256 AND " + x + ` ~ '^[0-9][^%*?\\:!]*$'` +
		" THEN string_to_array(substring(" + x + ` from '^[0-9]+(?:\.[0-9]+)*'), '.')::numeric[] END)`
}

// DottedSQL returns a SQL boolean expression: whether the text expression x is
// written as dotted numbers.
func DottedSQL(x string) string {
	return "(" + x + ` ~ '^[0-9]+(\.[0-9]+)*$')`
}

// ProductRangeBelowSQL returns a SQL boolean expression that is true exactly
// when ProductRangeBelow is true for the range from introduced to upper.
// inclusive is a SQL boolean expression saying whether upper is a last-affected
// bound. upper.Text is empty for a range with no single upper bound, and
// version.Text is empty for a version that is not dotted numbers. The expression is
// not NULL when no Text and no Dotted is NULL and inclusive is not NULL.
// introduced.Leading is read only where introduced.Text differs from upper.Text,
// so a caller may leave it NULL where they are equal.
func ProductRangeBelowSQL(introduced, upper, version BoundSQL, inclusive string) string {
	return "(" + upper.Text + " <> '' AND " + version.Dotted +
		" AND ((" + introduced.Text + " = " + upper.Text + " AND " + inclusive + ") OR " + decidedBelowSQL(introduced, upper) + ")" +
		" AND " + decidedBelowSQL(upper, version) + ")"
}

// decidedBelowSQL is decidedBelow in SQL. Two arrays cut to the components both
// have compare as leadingOrder compares leading numbers: the first difference
// decides. With no difference there, two dotted-number strings still have an
// order, missing components counting as zero: a is below b when b has a
// further component above zero.
func decidedBelowSQL(a, b BoundSQL) string {
	shared := "LEAST(cardinality(" + a.Leading + "), cardinality(" + b.Leading + "))"
	return "(" + a.Leading + " IS NOT NULL AND " + b.Leading + " IS NOT NULL AND (" +
		a.Leading + "[1:" + shared + "] < " + b.Leading + "[1:" + shared + "]" +
		" OR (" + a.Dotted + " AND " + b.Dotted +
		" AND " + a.Leading + "[1:" + shared + "] = " + b.Leading + "[1:" + shared + "]" +
		" AND 0 < ANY (" + b.Leading + "[" + shared + " + 1:]))))"
}
