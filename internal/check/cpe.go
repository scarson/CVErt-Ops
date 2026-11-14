// ABOUTME: Decides one advisory's verdict for a product version from its NVD cve_cpe_matches rows.
// ABOUTME: Applies design section 4.2's row rules and section 4.1's combining rule; anything uncertain is cannot evaluate.
package check

import "github.com/scarson/cvert-ops/internal/version"

// evidenceNVDCPE is the API's evidence value for a cve_cpe_matches range.
const evidenceNVDCPE = "nvd_cpe"

// CPERow is one cve_cpe_matches row with vulnerable = true. CPE is the stored
// cpe_normalized string; an absent bound is "". Status is its CVE's cves.status.
//
// A row with Below above zero is not a stored row: it stands for that many rows
// of the CVE, under one key, that the store left out because their ranges lie
// wholly below the key's floor (CPERowBelow). Its CPE and bounds are "".
type CPERow struct {
	CVEID, CPE, VersionStartIncluding, VersionStartExcluding, VersionEndIncluding, VersionEndExcluding string
	Status                                                                                             string
	Below                                                                                              int
}

// CPEProductKey returns the part:vendor:product of a stored cpe_normalized
// string, split on its unescaped colons, with escapes kept as stored. It returns
// "" for a string with fewer than 5 components, which names no product.
func CPEProductKey(cpeNormalized string) string {
	components := splitCPE(cpeNormalized)
	if len(components) < 5 {
		return ""
	}
	return components[2] + ":" + components[3] + ":" + components[4]
}

// CPERowBelow reports whether row's range lies wholly below ver, by
// version.ProductRangeBelow: the row answers NotAffected for ver and for every
// dotted-number version at or above it. The store's CPE lookup states the same
// rule in SQL and does not return such rows.
func CPERowBelow(ver string, row CPERow) bool {
	r, reason := cpeRange(row)
	return reason == "" && version.ProductRangeBelow(ver, r)
}

// EvaluateCPERows decides one advisory's verdict for version ver of a product,
// from that advisory's rows for the product's part:vendor:product. Every row is
// compared with version.CheckProduct, because a product has no ecosystem to
// define its order: dotted numbers, and bounds such as 1.0.2zf by their leading
// dotted numbers where those decide. Rows are combined as EvaluatePackageRows
// combines package rows; a versionEndExcluding bound of a row containing the
// version is a fix candidate, a versionEndIncluding bound is not.
//
// below is the number of the advisory's rows the store left out as lying wholly
// below the floor of ver's key, which is at or below ver. Each answers
// NotAffected, so they count as compared rows that exclude the version. They
// add no range for fix validation: a fix candidate is at or above ver, and such
// a row answers NotAffected there too.
//
// A version that is not dotted numbers cannot be compared with any row (design
// section 4.2), so an advisory with rows, stored or left out, answers
// CannotEvaluate with reason invalid_version, whichever row comes first. The
// store leaves rows out for such a version too, when another item of the
// product sets the key's floor.
//
// It calls m.Tick once per row and returns as soon as Tick refuses; the caller
// then discards the outcome and reports m.Err.
func EvaluateCPERows(m *workMeter, ver string, rows []CPERow, below int) Outcome {
	_, err := version.NumericOrder(ver, ver)
	dotted := err == nil
	var verdicts rowVerdicts
	verdicts.anyNotAffected = dotted && below > 0
	for _, row := range rows {
		if !m.Tick() {
			return Outcome{}
		}
		r, reason := cpeRange(row)
		if reason != "" {
			// An empty range answers CannotEvaluate for every version.
			verdicts.refuse(Bound{Check: version.CheckProduct}, reason)
			continue
		}
		verdicts.compare(ver, Bound{Range: r, Check: version.CheckProduct}, Matched{Evidence: evidenceNVDCPE, CPE: row.CPE})
	}
	out := verdicts.outcome()
	if !dotted && (len(rows) > 0 || below > 0) {
		out.Verdict, out.Reason = CannotEvaluate, ReasonInvalidVersion
	}
	return out
}

// cpeRange returns the range a row describes (design section 4.2), or the
// reason it describes none:
//
//   - Version component * (or empty) with any bound: Introduced is the start
//     bound, or "0" when there is none; Fixed is versionEndExcluding and
//     LastAffected is versionEndIncluding. versionStartExcluding is read as an
//     inclusive Introduced, so that one version reports affected.
//   - A literal version component with no bound: that version alone.
//   - Version component * with no bound, or -: no_version_bounds.
//
// Shapes the design does not describe answer invalid_range rather than a guess:
// a CPE that is not 13 components, both start bounds set, and a literal version
// component with bounds. Both end bounds set is left to CheckProduct, which
// reports it as an invalid range.
func cpeRange(row CPERow) (version.Range, Reason) {
	components := splitCPE(row.CPE)
	if len(components) != cpeComponents {
		return version.Range{}, ReasonInvalidRange
	}
	component := components[5] // after "cpe", "2.3", part, vendor and product
	bounded := row.VersionStartIncluding != "" || row.VersionStartExcluding != "" ||
		row.VersionEndIncluding != "" || row.VersionEndExcluding != ""

	switch {
	case component == "-":
		return version.Range{}, ReasonNoVersionBounds
	case component == "*" || component == "":
		if !bounded {
			return version.Range{}, ReasonNoVersionBounds
		}
		if row.VersionStartIncluding != "" && row.VersionStartExcluding != "" {
			return version.Range{}, ReasonInvalidRange
		}
		introduced := row.VersionStartIncluding + row.VersionStartExcluding
		if introduced == "" {
			introduced = "0"
		}
		return version.Range{
			Introduced: introduced, Fixed: row.VersionEndExcluding, LastAffected: row.VersionEndIncluding,
		}, ""
	case bounded:
		return version.Range{}, ReasonInvalidRange
	default:
		return version.Range{Introduced: component, LastAffected: component}, ""
	}
}
