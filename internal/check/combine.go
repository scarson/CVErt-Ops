// ABOUTME: Combines what an advisory's primary rows and its CNA entries say about one version (design section 4.4).
// ABOUTME: The primary rows are NVD CPE rows for a CPE item and package rows for a package item.
package check

import "slices"

// Combine returns one advisory's verdict from its primary rows' outcome and its
// CNA result, by the first of design section 4.4's five steps that applies:
//
//  1. Affected if the primary rows or a CNA entry report Affected.
//  2. CannotEvaluate, with the primary's reason, if a primary row cannot be compared.
//  3. CannotEvaluate, cna_indeterminate, if a CNA entry is Indeterminate.
//  4. NotAffected if the primary rows were compared and all report Not affected.
//     A CNA entry with no version information states no range, so it does not
//     stop this step.
//  5. Otherwise CannotEvaluate, cna_cannot_clear: CNA data never clears a version.
//
// hasPrimaryRows reports whether the advisory has any primary row for the
// component. The result keeps the primary's Ranges and Comparable; fix
// validation re-reads the CNA entries itself. An Affected result lists the
// primary's matches and candidates first, then the CNA's, in fresh slices.
func Combine(primary Outcome, hasPrimaryRows bool, cna CNAResult) Outcome {
	out := primary
	out.Matched, out.Candidates = nil, nil
	switch {
	case primary.Verdict == Affected || cna.Reading == AffectedReading:
		out.Verdict, out.Reason = Affected, ""
		out.Matched = slices.Concat(primary.Matched, cna.Matched)
		out.Candidates = slices.Concat(primary.Candidates, cna.Candidates)
	case hasPrimaryRows && primary.Verdict == CannotEvaluate:
		out.Verdict, out.Reason = CannotEvaluate, primary.Reason
	case cna.Reading == Indeterminate:
		out.Verdict, out.Reason = CannotEvaluate, ReasonCNAIndeterminate
	case hasPrimaryRows && primary.Verdict == NotAffected && primary.Comparable:
		out.Verdict, out.Reason = NotAffected, ""
	default:
		out.Verdict, out.Reason = CannotEvaluate, ReasonCNACannotClear
	}
	return out
}
