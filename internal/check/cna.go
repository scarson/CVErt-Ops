// ABOUTME: Reads CNA affected[].versions entries for one version, as segments (design section 4.3).
// ABOUTME: CNA data can report Affected, Indeterminate or no version information, never Not affected.
package check

import (
	"math/big"
	"regexp"
	"slices"
	"strings"

	"github.com/scarson/cvert-ops/internal/version"
)

// evidenceCNA is the API's evidence value for a CNA affected[] entry.
const evidenceCNA = "cna"

// belowEverything is a lower bound read as below every version, as version.Check
// reads an introduced "0": some real versions, such as 0.0.0-alpha, sort below a
// literal 0.
const belowEverything = "0"

// CNAVersion mirrors one stored versions[] element.
type CNAVersion struct {
	Version         string      `json:"version"`
	LessThan        string      `json:"less_than"`
	LessThanOrEqual string      `json:"less_than_or_equal"`
	Status          string      `json:"status"`
	VersionType     string      `json:"version_type"`
	Changes         []CNAChange `json:"changes"`
}

// CNAChange mirrors one stored versions[].changes[] element: from At onward the
// status is Status.
type CNAChange struct {
	At     string `json:"at"`
	Status string `json:"status"`
}

// Reading is what a CNA entry says about one version, weakest first, so the
// strongest of several entries is their maximum.
type Reading int

// The readings, weakest first.
const (
	NoStatement Reading = iota
	NoVersionInfo
	Indeterminate
	AffectedReading
)

// CNARow is one cve_cna_affected row: an advisory's CNA entry for one product,
// with its versions array decoded.
type CNARow struct {
	CVEID, Vendor, Product string
	Versions               []CNAVersion
}

// CNAResult is what an advisory's CNA rows say about one version: the strongest
// reading over every versions element, and, from each element reading Affected,
// its fix candidate (when it names one) and the segment that contains the version.
type CNAResult struct {
	Reading    Reading
	Candidates []string
	Matched    []Matched
}

// reading is one entry's answer, with the fix it names and the segment that
// contains the version when it reports Affected.
type reading struct {
	result    Reading
	candidate string
	matched   segment
}

var (
	lineWildcard = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)*)\.\*$`)
	freeTextForm = regexp.MustCompile(`[<>=]`)
)

// orderFor returns the comparator design section 4.3 assigns to a versionType,
// or nil when versions of that type cannot be compared.
func orderFor(versionType string) version.Order {
	switch versionType {
	case "semver":
		return version.SemverOrder
	case "python":
		return version.EcosystemOrder("PyPI")
	case "maven":
		return version.EcosystemOrder("Maven")
	case "rpm":
		return version.EcosystemOrder("Red Hat")
	case "custom", "":
		return version.NumericOrder
	}
	return nil
}

// hasNoVersionInformation reports an entry that states no version: a git commit
// range, or a sentinel version with no upper bound and no changes.
func hasNoVersionInformation(e CNAVersion) bool {
	if e.VersionType == "git" {
		return true
	}
	if e.LessThan != "" || e.LessThanOrEqual != "" || len(e.Changes) > 0 {
		return false
	}
	switch strings.ToLower(e.Version) {
	case "", "unspecified", "n/a", "unknown", "*":
		return true
	}
	return false
}

// bound is one edge of a segment.
type bound struct {
	value     string
	readable  bool
	wildcard  bool // the edge is a line wildcard; value is the first version past the line
	unlimited bool // no upper edge, or a bare "*"
	open      bool // a free-text range stated no upper edge, so every higher version is inside
}

type segment struct {
	start, end   bound
	endInclusive bool
	status       string
}

// ReadCNAEntries reads every versions element of an advisory's CNA rows for
// version ver, and returns the strongest reading, with the fix candidates and
// matched segments of the elements reading Affected. defaultStatus is never
// read: design section 4.3 gives it no meaning for a version.
//
// Every comparison calls m.Tick. Reading stops once m.Err is non-nil, and the
// result is then the zero CNAResult; the caller discards it and reports m.Err.
func ReadCNAEntries(m *workMeter, ver string, entries []CNARow) CNAResult {
	var out CNAResult
	for _, row := range entries {
		for _, e := range row.Versions {
			if m.Err() != nil {
				return CNAResult{}
			}
			r := readEntry(m, ver, e)
			out.Reading = max(out.Reading, r.result)
			if r.result != AffectedReading {
				continue
			}
			if r.candidate != "" {
				out.Candidates = append(out.Candidates, r.candidate)
			}
			out.Matched = append(out.Matched, matchedSegment(r.matched))
		}
	}
	if m.Err() != nil {
		return CNAResult{}
	}
	return out
}

// CNARangeCount counts an advisory's CNA rows toward the range limit: each
// versions element, plus its segments. It compares nothing, so an oversized
// entry is refused before its changes are sorted.
func CNARangeCount(entries []CNARow) int {
	n := 0
	for _, row := range entries {
		for _, v := range row.Versions {
			n += 2 + len(v.Changes)
		}
	}
	return n
}

// matchedSegment reports the segment that contains the version as a range. An
// exclusive end is the range's fixed bound, an inclusive end its last affected
// bound, and an open end neither.
func matchedSegment(s segment) Matched {
	m := Matched{Evidence: evidenceCNA, Introduced: s.start.value}
	switch {
	case s.end.open:
	case s.endInclusive:
		m.LastAffected = s.end.value
	default:
		m.Fixed = s.end.value
	}
	return m
}

func readEntry(m *workMeter, ver string, e CNAVersion) reading {
	if hasNoVersionInformation(e) {
		return reading{result: NoVersionInfo}
	}
	// An entry that is wholly unaffected can condemn nothing, whether or not its
	// bounds or the version can be read.
	if e.Status == "unaffected" && len(e.Changes) == 0 {
		return reading{result: NoStatement}
	}
	read := orderFor(e.VersionType)
	if read == nil {
		return reading{result: Indeterminate}
	}
	order := func(a, b string) (int, error) {
		if !m.Tick() {
			return 0, m.Err()
		}
		return read(a, b)
	}
	if _, err := order(ver, ver); err != nil {
		return reading{result: Indeterminate}
	}
	e, openEnded := expandFreeText(e)

	segments, ok := buildSegments(e, openEnded, order)
	if !ok {
		return unsortableReading(ver, e, order)
	}

	// A segment whose two edges can be read decides the answer outright.
	for i, s := range segments {
		if !s.start.readable || !s.end.readable || s.end.wildcard {
			continue
		}
		if !s.contains(ver, order) {
			continue
		}
		switch {
		case s.status == "affected":
			return reading{result: AffectedReading, candidate: fixCandidate(segments, i, e), matched: s}
		case s.status != "unaffected":
			return reading{result: Indeterminate}
		case i == 0, atStart(ver, s, order):
			return reading{result: NoStatement}
		default:
			return reading{result: Indeterminate}
		}
	}

	if first := segments[0]; first.status == "unaffected" && (len(segments) == 1 || isBelow(ver, segments[1].start, order)) {
		return reading{result: NoStatement}
	}
	for i, s := range segments {
		if i > 0 && s.status == "unaffected" && atStart(ver, s, order) {
			return reading{result: NoStatement}
		}
	}
	for _, s := range segments {
		if s.possiblyContains(ver, order) {
			return reading{result: Indeterminate}
		}
	}
	return reading{result: NoStatement}
}

// expandFreeText reads a free-text range such as ">= 20.0.0, <= 20.10.27", given
// as the version of an entry with no upper bound and no changes, with the GHSA
// range grammar. It reports true when the range states no upper bound, as for
// ">= 1.0.0". Text the grammar cannot read is left as it is, so it stays an
// unreadable bound and reads as Indeterminate.
func expandFreeText(e CNAVersion) (CNAVersion, bool) {
	if e.LessThan != "" || e.LessThanOrEqual != "" || len(e.Changes) > 0 || !freeTextForm.MatchString(e.Version) {
		return e, false
	}
	r, ok := version.ParseRangeExpression("", e.Version, "")
	if !ok {
		return e, false
	}
	e.Version, e.LessThan, e.LessThanOrEqual = r.Introduced, r.Fixed, r.LastAffected
	return e, r.Fixed == "" && r.LastAffected == ""
}

// lowerBound normalises a wildcard lower bound: 8.1.* becomes 8.1.
func lowerBound(v string) string {
	return strings.TrimSuffix(v, ".*")
}

// buildSegments splits an entry into segments: the first from the entry's
// version with its status, then one from each change, sorted by At under the
// entry's order. Each segment includes its start and stops before the next start;
// the last stops at the entry's upper bound. It returns false when the order
// cannot read some At, because the changes then have no reliable order.
func buildSegments(e CNAVersion, openEnded bool, order version.Order) ([]segment, bool) {
	changes := slices.Clone(e.Changes)
	// Each At is checked on its own, because a sort compares nothing when there
	// is only one change.
	for _, c := range changes {
		if _, err := order(c.At, c.At); err != nil {
			return nil, false
		}
	}
	var sortErr error
	slices.SortStableFunc(changes, func(a, b CNAChange) int {
		c, err := order(a.At, b.At)
		if err != nil && sortErr == nil {
			sortErr = err
		}
		return c
	})
	if sortErr != nil {
		return nil, false
	}

	segments := []segment{{start: newBound(lowerBound(e.Version), order), status: e.Status}}
	for _, c := range changes {
		status := c.Status
		if status == "" {
			status = "unknown"
		}
		segments = append(segments, segment{start: newBound(c.At, order), status: status})
	}
	for i := range len(segments) - 1 {
		segments[i].end = segments[i+1].start
	}

	last := &segments[len(segments)-1]
	switch {
	case openEnded:
		last.end = bound{readable: true, open: true}
	case e.LessThan != "" || e.LessThanOrEqual != "":
		last.end, last.endInclusive = upperBound(e, order)
	case len(e.Changes) == 0:
		// A single version. The edge is the stored version, before the lower
		// bound's wildcard is dropped: a single 8.1.* names the whole 8.1 line,
		// so its edge is unreadable rather than 8.1.
		last.end, last.endInclusive = readableBound(e.Version, order), true
	default:
		last.end = bound{unlimited: true}
	}
	return segments, true
}

// upperBound returns the entry's upper edge and whether it is inclusive. A bare
// "*" is unlimited and not readable. A line wildcard such as 12.* is readable,
// with value the first version past the line (13), and exclusive. An entry that
// sets both lessThan and lessThanOrEqual has an upper edge that is not readable.
func upperBound(e CNAVersion, order version.Order) (bound, bool) {
	if e.LessThan != "" && e.LessThanOrEqual != "" {
		return bound{value: e.LessThan}, false
	}
	value, inclusive := e.LessThan, false
	if e.LessThanOrEqual != "" {
		value, inclusive = e.LessThanOrEqual, true
	}
	if value == "*" {
		return bound{value: value, unlimited: true}, false
	}
	if m := lineWildcard.FindStringSubmatch(value); m != nil {
		return bound{value: nextLine(m[1]), readable: true, wildcard: true}, false
	}
	return readableBound(value, order), inclusive
}

// nextLine increments the last number of a dotted version: 12 becomes 13 and
// 1.2 becomes 1.3.
func nextLine(prefix string) string {
	head, last := "", prefix
	if i := strings.LastIndex(prefix, "."); i >= 0 {
		head, last = prefix[:i+1], prefix[i+1:]
	}
	n, _ := new(big.Int).SetString(last, 10) // lineWildcard matched digits
	return head + n.Add(n, big.NewInt(1)).String()
}

// newBound returns a segment's start. "0" is readable and below every version.
func newBound(value string, order version.Order) bound {
	if value == belowEverything {
		return bound{value: value, readable: true}
	}
	return readableBound(value, order)
}

// readableBound returns an edge that is readable when the order can read value.
func readableBound(value string, order version.Order) bound {
	_, err := order(value, value)
	return bound{value: value, readable: err == nil}
}

// contains reports whether ver is at or above the segment's start and either
// below its end, at an inclusive end, or under an open end. The caller has
// confirmed both edges are readable.
func (s segment) contains(ver string, order version.Order) bool {
	if s.start.value != belowEverything {
		c, err := order(ver, s.start.value)
		if err != nil || c < 0 {
			return false
		}
	}
	if s.end.open {
		return true
	}
	c, err := order(ver, s.end.value)
	if err != nil {
		return false
	}
	return c < 0 || (s.endInclusive && c == 0)
}

// possiblyContains reports whether ver is not provably below a readable start
// and not provably past a readable or wildcard end. Past means at or above an
// exclusive end, and above an inclusive one. An unlimited or open end is never
// passed.
func (s segment) possiblyContains(ver string, order version.Order) bool {
	if isBelow(ver, s.start, order) {
		return false
	}
	end := s.end
	if end.unlimited || end.open || !end.readable {
		return true
	}
	c, err := order(ver, end.value)
	if err != nil {
		return true
	}
	if s.endInclusive {
		return c <= 0
	}
	return c < 0
}

// isBelow reports whether ver is provably below the readable start b. A start of
// "0" is below every version.
func isBelow(ver string, b bound, order version.Order) bool {
	if !b.readable || b.value == belowEverything {
		return false
	}
	c, err := order(ver, b.value)
	return err == nil && c < 0
}

// atStart reports whether ver provably equals the readable start of s. A start
// of "0" is below every version, so no version equals it.
func atStart(ver string, s segment, order version.Order) bool {
	if !s.start.readable || s.start.value == belowEverything {
		return false
	}
	c, err := order(ver, s.start.value)
	return err == nil && c == 0
}

// fixCandidate returns the fix that segment i names: the start of the next
// segment when its status is unaffected; for the last segment, lessThan unless it
// is "*" or a line wildcard; otherwise none.
func fixCandidate(segments []segment, i int, e CNAVersion) string {
	if i+1 < len(segments) {
		if segments[i+1].status == "unaffected" {
			return segments[i+1].start.value
		}
		return ""
	}
	if e.LessThan != "" && e.LessThan != "*" && !lineWildcard.MatchString(e.LessThan) {
		return e.LessThan
	}
	return ""
}

// unsortableReading reads an entry whose changes cannot be ordered: Indeterminate
// when its lower bound cannot be read or ver is at or above it, and NoStatement
// below it.
func unsortableReading(ver string, e CNAVersion, order version.Order) reading {
	if isBelow(ver, newBound(lowerBound(e.Version), order), order) {
		return reading{result: NoStatement}
	}
	return reading{result: Indeterminate}
}
