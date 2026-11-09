// ABOUTME: Collapses several cve_sources rows of one source into one patch, and unions version ranges.
// ABOUTME: Both results depend only on the set of rows, never on the order they arrived in.
package merge

import (
	"cmp"
	"slices"

	"github.com/scarson/cvert-ops/internal/ecosystem"
	"github.com/scarson/cvert-ops/internal/feed"
)

// sourceRow is one decoded cve_sources row.
type sourceRow struct {
	name  string
	id    string
	patch feed.CanonicalPatch
}

// isStatusAuthority reports whether a source decides a CVE's status, as opposed
// to publishing an advisory about it (PLAN.md §5.1).
func isStatusAuthority(source string) bool {
	return source == SourceMITRE || source == SourceNVD
}

// collapseSources returns one patch per source name. A withdrawn advisory says
// nothing about the CVE, so it contributes nothing, and a source left with no
// live advisory is absent. The second result reports that every row of every
// source is withdrawn; in that case each source keeps its first row.
func collapseSources(rows []sourceRow) (map[string]feed.CanonicalPatch, bool) {
	sorted := slices.Clone(rows)
	slices.SortFunc(sorted, func(a, b sourceRow) int {
		return cmp.Or(cmp.Compare(a.name, b.name), cmp.Compare(a.id, b.id))
	})

	allWithdrawn := len(sorted) > 0 && !slices.ContainsFunc(sorted, func(r sourceRow) bool { return !r.patch.IsWithdrawn })

	bySource := make(map[string][]feed.CanonicalPatch)
	for _, r := range sorted {
		bySource[r.name] = append(bySource[r.name], r.patch)
	}

	patches := make(map[string]feed.CanonicalPatch, len(bySource))
	for name, group := range bySource {
		live := slices.DeleteFunc(slices.Clone(group), func(p feed.CanonicalPatch) bool { return p.IsWithdrawn })
		switch {
		case len(live) > 0:
			patches[name] = mergeRows(live)
		case allWithdrawn || isStatusAuthority(name):
			patches[name] = group[0]
		}
	}
	return patches, allWithdrawn
}

// mergeRows combines the live rows of one source, in source_id order.
func mergeRows(rows []feed.CanonicalPatch) feed.CanonicalPatch {
	out := rows[0]
	out.CWEIDs = slices.Clone(out.CWEIDs)
	out.References = slices.Clone(out.References)
	out.AffectedPackages = slices.Clone(out.AffectedPackages)
	out.AffectedCPEs = slices.Clone(out.AffectedCPEs)
	out.CPEMatches = slices.Clone(out.CPEMatches)
	out.CNAAffected = slices.Clone(out.CNAAffected)

	for _, p := range rows[1:] {
		if out.Status == "" {
			out.Status = p.Status
		}
		out.DescriptionPrimary = firstNonNil(out.DescriptionPrimary, p.DescriptionPrimary)
		out.Severity = firstNonNil(out.Severity, p.Severity)
		out.CVSSv3Score, out.CVSSv3Vector = firstScore(out.CVSSv3Score, out.CVSSv3Vector, p.CVSSv3Score, p.CVSSv3Vector)
		out.CVSSv4Score, out.CVSSv4Vector = firstScore(out.CVSSv4Score, out.CVSSv4Vector, p.CVSSv4Score, p.CVSSv4Vector)
		out.ExploitAvailable = anyTrue(out.ExploitAvailable, p.ExploitAvailable)
		out.InCISAKEV = anyTrue(out.InCISAKEV, p.InCISAKEV)
		if p.DatePublished != nil && (out.DatePublished == nil || p.DatePublished.Before(*out.DatePublished)) {
			out.DatePublished = p.DatePublished
		}
		out.CWEIDs = append(out.CWEIDs, p.CWEIDs...)
		out.References = append(out.References, p.References...)
		out.AffectedPackages = append(out.AffectedPackages, p.AffectedPackages...)
		out.AffectedCPEs = append(out.AffectedCPEs, p.AffectedCPEs...)
		out.CPEMatches = append(out.CPEMatches, p.CPEMatches...)
		out.CNAAffected = append(out.CNAAffected, p.CNAAffected...)
	}
	return out
}

func firstNonNil[T any](a, b *T) *T {
	if a != nil {
		return a
	}
	return b
}

// firstScore keeps a score and its vector together. A row with a score replaces
// one that has only a vector, because a vector alone is never used as a score.
func firstScore(score *float64, vector *string, nextScore *float64, nextVector *string) (*float64, *string) {
	switch {
	case score != nil:
		return score, vector
	case nextScore != nil:
		return nextScore, nextVector
	case vector != nil:
		return nil, vector
	default:
		return nil, nextVector
	}
}

func anyTrue(a, b *bool) *bool {
	if a != nil && *a {
		return a
	}
	if b != nil {
		return b
	}
	return a
}

// rangeClass separates ranges whose bounds are compared differently. GIT ranges
// hold commit hashes. A SEMVER range in an ecosystem with another native order
// sorts some versions differently from an ECOSYSTEM range with the same bounds.
func rangeClass(p feed.AffectedPackage) string {
	switch {
	case p.RangeType == "GIT":
		return "GIT"
	case p.RangeType == "SEMVER" && !ecosystem.OrdersBySemver(p.Ecosystem):
		return "SEMVER"
	default:
		return ""
	}
}

// rangeKey identifies a distinct version range across sources.
type rangeKey struct {
	ecosystem    string
	packageName  string
	introduced   string
	fixed        string
	lastAffected string
	class        string
}

func keyOfRange(p feed.AffectedPackage) rangeKey {
	return rangeKey{
		ecosystem:    p.Ecosystem,
		packageName:  ecosystem.FoldPackageName(p.Ecosystem, p.PackageName),
		introduced:   p.Introduced,
		fixed:        p.Fixed,
		lastAffected: p.LastAffected,
		class:        rangeClass(p),
	}
}

// unionPackages returns every distinct range across sources, sorted by rangeKey.
// When several sources state the same range, the row from the highest-precedence
// source is kept (PLAN.md §5.1).
func unionPackages(patches map[string]feed.CanonicalPatch) []feed.AffectedPackage {
	seen := make(map[rangeKey]struct{})
	var out []feed.AffectedPackage
	for _, src := range slices.Concat(pkgPriority, otherSources(patches, pkgPriority)) {
		p, ok := patches[src]
		if !ok || p.IsWithdrawn {
			continue
		}
		for _, pkg := range p.AffectedPackages {
			key := keyOfRange(pkg)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, pkg)
		}
	}
	slices.SortFunc(out, func(a, b feed.AffectedPackage) int {
		ka, kb := keyOfRange(a), keyOfRange(b)
		return cmp.Or(
			cmp.Compare(ka.ecosystem, kb.ecosystem),
			cmp.Compare(ka.packageName, kb.packageName),
			cmp.Compare(ka.introduced, kb.introduced),
			cmp.Compare(ka.fixed, kb.fixed),
			cmp.Compare(ka.lastAffected, kb.lastAffected),
			cmp.Compare(ka.class, kb.class),
		)
	})
	return out
}
