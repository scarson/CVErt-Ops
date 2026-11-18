// ABOUTME: Checks versions of products with no package ecosystem, such as CPE products.
// ABOUTME: Compares dotted numeric versions numerically; anything else cannot be evaluated.
package version

import (
	"math/big"
	"regexp"
	"strings"
)

var numericSyntax = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*$`)

// CheckNumeric reports whether version is inside r for a product with no
// ecosystem to supply ordering rules. Only dotted numeric versions are ordered:
// 1.24.0-1 or 1.24rc1 have a meaning this package cannot know without the
// product's own rules, so they report CannotEvaluate. Missing components count
// as zero. The returned error is non-nil exactly when the status is CannotEvaluate.
func CheckNumeric(version string, r Range) (Status, error) {
	return numericScheme.check(version, r)
}

// NumericOrder is the Order of CheckNumeric.
func NumericOrder(a, b string) (int, error) {
	return numericScheme.order(a, b)
}

var numericScheme = scheme{
	valid: func(v string) bool {
		return len(v) <= maxVersionLen && numericSyntax.MatchString(v)
	},
	compare: compareNumeric,
}

func compareNumeric(a, b string) (int, error) {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := range max(len(as), len(bs)) {
		if c := numericComponent(as, i).Cmp(numericComponent(bs, i)); c != 0 {
			return c, nil
		}
	}
	return 0, nil
}

// numericComponent returns component i, or zero past the end. The syntax check
// has already confirmed each component is digits, and big.Int holds any length.
func numericComponent(components []string, i int) *big.Int {
	n := new(big.Int)
	if i < len(components) {
		n.SetString(components[i], 10)
	}
	return n
}
