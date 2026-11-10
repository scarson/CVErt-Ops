// ABOUTME: Evaluates a version check request: each item's advisories, verdicts and fixes, then its status.
// ABOUTME: Applies the item and advisory limits, retraction, nearby names and design section 4.7's status order.
package check

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/scarson/cvert-ops/internal/ecosystem"
	"github.com/scarson/cvert-ops/internal/version"
)

// Limits are the per-item row limit and the per-advisory range limit (design
// section 9).
type Limits struct{ ItemRows, AdvisoryRanges int }

// DefaultLimits are design section 9's limits: 50,000 rows for one item, over
// every key it uses, and 1,000 ranges for one component in one advisory.
var DefaultLimits = Limits{ItemRows: 50000, AdvisoryRanges: 1000}

// Response caps (design section 9). Counts and status use every advisory.
const (
	maxListedAdvisories = 100
	maxMatchedRanges    = 20
)

// errCandidatesMismatch reports Candidates whose slices are not one per key of
// KeysFor(items). Reading a missing key as no rows could clear a version, so
// the request is refused instead.
var errCandidatesMismatch = errors.New("check: candidates do not hold one entry per key of the request's items")

// Evaluate answers every item from data, the rows read for KeysFor(items), with
// the feeds' completeness and the enrichment rows of the advisories and their
// CVEs. It makes one work meter for the request and returns the context's error,
// with no results, as soon as the meter reports one.
func Evaluate(ctx context.Context, items []Item, data Candidates, feeds map[string]FeedStatus,
	enrichment map[string]CVEEnrichment) (Results, error) {
	return EvaluateWithLimits(ctx, items, data, feeds, enrichment, DefaultLimits)
}

// EvaluateWithLimits is Evaluate with the given limits.
func EvaluateWithLimits(ctx context.Context, items []Item, data Candidates, feeds map[string]FeedStatus,
	enrichment map[string]CVEEnrichment, limits Limits) (Results, error) {
	return evaluateItems(newWorkMeter(ctx), items, data, feeds, enrichment, limits)
}

// itemIdentity is what makes two items the same question: the parsed package or
// product and the version. Identical items share one evaluation.
type itemIdentity struct {
	pkg     PackageRef
	product ProductRef
	version string
}

func evaluateItems(m *workMeter, items []Item, data Candidates, feeds map[string]FeedStatus,
	enrichment map[string]CVEEnrichment, limits Limits) (Results, error) {
	keys, uses := keysWithUses(items)
	if !candidatesMatch(keys, data) {
		return Results{}, errCandidatesMismatch
	}

	out := Results{DataComplete: true, Feeds: []FeedStatus{}, Results: make([]ItemResult, len(items))}
	evaluated := map[itemIdentity]ItemResult{}
	var dependencies []string
	for i, item := range items {
		// ParseItem never returns an item with no form; one built elsewhere is
		// refused as ParseItem would refuse it, and keysWithUses gives it no keys.
		if item.Error == nil && item.Package == nil && item.Product == nil {
			item = refuse(item, "invalid_form")
		}
		identity := identityOf(item)
		res, seen := evaluated[identity]
		if item.Error != nil || !seen {
			res = evaluateItem(m, item, uses[i], data, feeds, enrichment, limits)
			if err := m.Err(); err != nil {
				return Results{}, err
			}
			if item.Error == nil {
				evaluated[identity] = res
			}
		}
		res.Index, res.ID = item.Index, nil
		if item.ID != "" {
			id := item.ID
			res.ID = &id
		}
		out.Results[i] = res

		if item.Error == nil {
			out.DataComplete = out.DataComplete && res.DataComplete
			for _, name := range feedsFor(item) {
				if !slices.Contains(dependencies, name) {
					dependencies = append(dependencies, name)
				}
			}
		}
	}
	slices.Sort(dependencies)
	for _, name := range dependencies {
		out.Feeds = append(out.Feeds, feedStatus(feeds, name))
	}
	return out, nil
}

func candidatesMatch(keys Keys, data Candidates) bool {
	return len(data.Packages) == len(keys.Packages) && len(data.CPEs) == len(keys.CPEPrefixes) &&
		len(data.CNANames) == len(keys.CNANames) && len(data.CNAPackageKeys) == len(keys.CNAPackageKeys) &&
		len(data.CNANear) == len(keys.CNANear)
}

func identityOf(item Item) itemIdentity {
	id := itemIdentity{version: item.Version}
	if item.Package != nil {
		id.pkg = *item.Package
	}
	if item.Product != nil {
		id.product = *item.Product
	}
	return id
}

// feedStatus returns a feed's status, incomplete when feeds does not hold it.
func feedStatus(feeds map[string]FeedStatus, name string) FeedStatus {
	if s, ok := feeds[name]; ok {
		return s
	}
	return FeedStatus{Name: name}
}

// isRetracted reports a cves.status that excludes the CVE from verdicts (design
// section 8), compared in lower case because feeds send mixed case.
func isRetracted(status string) bool {
	switch strings.ToLower(status) {
	case "rejected", "withdrawn":
		return true
	}
	return false
}

// advisoryRows is one advisory's rows for one item.
type advisoryRows struct {
	packages  []PackageRow
	cpes      []CPERow
	cpesBelow int // rows the store left out as lying wholly below the floor of the item's key
	cna       []CNARow
	nearby    bool // a nearby-name row that is not one of the item's CNA name rows
	retracted bool // a row's CVE is rejected or withdrawn
}

// itemRows is every row an item's keys returned, grouped by advisory.
type itemRows struct {
	advisories   map[string]*advisoryRows
	cnaNameFound bool // a CNA name key returned a row
}

func (r *itemRows) advisory(cveID, status string) *advisoryRows {
	a, ok := r.advisories[cveID]
	if !ok {
		a = &advisoryRows{}
		r.advisories[cveID] = a
	}
	a.retracted = a.retracted || isRetracted(status)
	return a
}

// overItemLimit reports whether an item's keys hold more rows than limit, before
// de-duplication, or one of them reached its per-key limit. It reads only the
// keys' sizes, so an item over its limit is refused before any row is grouped.
func overItemLimit(use itemKeys, data Candidates, limit int) bool {
	total, overflow := 0, false
	count := func(rows int, over bool) {
		total += rows
		overflow = overflow || over
	}
	if use.pkg >= 0 {
		count(len(data.Packages[use.pkg].Rows), data.Packages[use.pkg].Overflow)
	}
	if use.cnaPackage >= 0 {
		count(len(data.CNAPackageKeys[use.cnaPackage].Rows), data.CNAPackageKeys[use.cnaPackage].Overflow)
	}
	for _, k := range use.cpes {
		count(len(data.CPEs[k].Rows), data.CPEs[k].Overflow)
	}
	for _, k := range use.cnaNames {
		count(len(data.CNANames[k].Rows), data.CNANames[k].Overflow)
	}
	for _, k := range use.near {
		count(len(data.CNANear[k].Rows), data.CNANear[k].Overflow)
	}
	return overflow || total > limit
}

// rowsOf collects an item's rows from the keys it uses. CNA name rows are
// de-duplicated, because one stored row can come back through an exact name and
// a prefix. A nearby-name row that is one of those CNA name rows (same CVE,
// vendor and product, as stored) is dropped; any other marks its advisory.
func rowsOf(use itemKeys, data Candidates) itemRows {
	r := itemRows{advisories: map[string]*advisoryRows{}}
	if use.pkg >= 0 {
		kr := data.Packages[use.pkg]
		for _, row := range kr.Rows {
			a := r.advisory(row.CVEID, row.Status)
			a.packages = append(a.packages, row)
		}
	}
	if use.cnaPackage >= 0 {
		kr := data.CNAPackageKeys[use.cnaPackage]
		for _, row := range kr.Rows {
			a := r.advisory(row.CVEID, row.Status)
			a.cna = append(a.cna, row)
		}
	}
	for _, k := range use.cpes {
		kr := data.CPEs[k]
		for _, row := range kr.Rows {
			a := r.advisory(row.CVEID, row.Status)
			if row.Below > 0 {
				a.cpesBelow += row.Below
				continue
			}
			a.cpes = append(a.cpes, row)
		}
	}
	type nameRow struct{ cveID, vendor, product string }
	nameRows := map[nameRow]bool{}
	seen := map[string]bool{}
	for _, k := range use.cnaNames {
		kr := data.CNANames[k]
		for _, row := range kr.Rows {
			r.cnaNameFound = true
			nameRows[nameRow{row.CVEID, row.Vendor, row.Product}] = true
			identity := cnaRowIdentity(row)
			if seen[identity] {
				continue
			}
			seen[identity] = true
			a := r.advisory(row.CVEID, row.Status)
			a.cna = append(a.cna, row)
		}
	}
	for _, k := range use.near {
		kr := data.CNANear[k]
		for _, row := range kr.Rows {
			if nameRows[nameRow{row.CVEID, row.Vendor, row.Product}] {
				continue
			}
			r.advisory(row.CVEID, row.Status).nearby = true
		}
	}
	return r
}

// cnaRowIdentity identifies a CNA row by its CVE, vendor, product and versions.
func cnaRowIdentity(row CNARow) string {
	versions, _ := json.Marshal(row.Versions) // CNAVersion holds only strings and slices of them
	return strings.Join([]string{row.CVEID, row.Vendor, row.Product, string(versions)}, "\x00")
}

// evaluateItem answers one item. The caller discards the result when m.Err is
// non-nil afterwards.
func evaluateItem(m *workMeter, item Item, use itemKeys, data Candidates, feeds map[string]FeedStatus,
	enrichment map[string]CVEEnrichment, limits Limits) ItemResult {
	res := ItemResult{Advisories: []Advisory{}, Warnings: []string{}}
	if item.Error != nil {
		res.Status, res.Error = StatusInvalid, item.Error
		return res
	}
	res.Component = componentOf(item)
	res.DataComplete = true
	for _, name := range feedsFor(item) {
		res.DataComplete = res.DataComplete && feedStatus(feeds, name).Complete
	}

	if overItemLimit(use, data, limits.ItemRows) {
		res.Status, res.Reason = StatusCannotEvaluate, reasonPtr(ReasonTooManyCandidates)
		return res
	}
	rows := rowsOf(use, data)

	cveIDs := make([]string, 0, len(rows.advisories))
	for id := range rows.advisories {
		cveIDs = append(cveIDs, id)
	}
	slices.Sort(cveIDs)
	for _, id := range cveIDs {
		a := rows.advisories[id]
		if a.retracted {
			res.Counts.Retracted++
			continue
		}
		adv, verdict := evaluateAdvisory(m, item, id, a, enrichment, limits)
		if m.Err() != nil {
			return res
		}
		switch verdict {
		case Affected:
			res.Counts.Affected++
		case NotAffected:
			res.Counts.NotAffected++
			continue
		default:
			res.Counts.CannotEvaluate++
		}
		res.Advisories = append(res.Advisories, adv)
	}

	sortAdvisories(res.Advisories)
	if len(res.Advisories) > maxListedAdvisories {
		res.Advisories, res.AdvisoriesTruncated = res.Advisories[:maxListedAdvisories], true
	}
	setStatus(&res, item, rows)
	return res
}

// setStatus sets an evaluated item's status by design section 4.7, first match
// wins. The item's reason is set only by an item-level row; when the status
// comes from an advisory, each listed advisory carries its own.
func setStatus(res *ItemResult, item Item, rows itemRows) {
	unmapped := false
	if item.Product != nil {
		_, _, inTable := NamesFor(*item.Product)
		unmapped = !inTable && !rows.cnaNameFound
	}
	c := res.Counts
	switch {
	case c.Affected > 0:
		res.Status = StatusAffected
	case c.CannotEvaluate > 0:
		res.Status = StatusCannotEvaluate
	case c.NotAffected > 0 && !res.DataComplete:
		res.Status, res.Reason = StatusCannotEvaluate, reasonPtr(ReasonDataIncomplete)
	case c.NotAffected > 0 && unmapped:
		res.Status, res.Reason = StatusCannotEvaluate, reasonPtr(ReasonCNAProductNotMapped)
	case c.NotAffected > 0:
		res.Status = StatusNotAffected
	// Retracted rows count as rows: they prove the package name exists.
	case item.Package != nil && ecosystem.IsDistro(item.Package.Ecosystem) && len(rows.advisories) == 0:
		res.Status, res.Reason = StatusCannotEvaluate, reasonPtr(ReasonDistroPackageNotFound)
	default:
		res.Status = StatusNoAdvisoryFound
		if unmapped {
			res.Warnings = append(res.Warnings, warningCNAProductNotMapped)
		}
	}
}

// evaluateAdvisory decides one advisory's verdict for an item and, unless it is
// NotAffected, builds its listed form. The range limit is applied before any
// row is read, so an oversized entry costs no comparisons.
func evaluateAdvisory(m *workMeter, item Item, id string, a *advisoryRows, enrichment map[string]CVEEnrichment,
	limits Limits) (Advisory, Verdict) {
	var out Outcome
	switch {
	case len(a.packages)+len(a.cpes)+a.cpesBelow+CNARangeCount(a.cna) > limits.AdvisoryRanges:
		out = Outcome{Verdict: CannotEvaluate, Reason: ReasonTooManyRanges}
	case item.Package != nil:
		primary := EvaluatePackageRows(m, item.Package.Ecosystem, item.Version, a.packages)
		out = Combine(primary, len(a.packages) > 0, ReadCNAEntries(m, item.Version, a.cna))
	default:
		// The store's statement states no row order, and the advisory's reason
		// and its matched ranges follow the order rows are read in.
		slices.SortFunc(a.cpes, compareCPERows)
		primary := EvaluateCPERows(m, item.Version, a.cpes, a.cpesBelow)
		out = Combine(primary, len(a.cpes)+a.cpesBelow > 0, ReadCNAEntries(m, item.Version, a.cna))
	}
	if a.nearby && out.Verdict != Affected {
		out = Outcome{Verdict: CannotEvaluate, Reason: ReasonCNANameUncertain}
	}
	if out.Verdict == NotAffected {
		return Advisory{}, NotAffected
	}

	adv := Advisory{AdvisoryID: id, CVEIDs: CVEIDsFor(id), Verdict: VerdictCannotEvaluate, MatchedRanges: []MatchedRange{}}
	if out.Verdict == Affected {
		adv.Verdict = VerdictAffected
		if fixed, major := PickFix(m, item.Version, out.Candidates, fixOrder(item), out.Ranges, cnaReader(m, a.cna)); fixed != "" {
			adv.FixedVersion, adv.FixMajor = &fixed, major
		}
	} else if out.Reason != "" {
		adv.Reason = reasonPtr(out.Reason)
	}
	adv.MatchedRangesTotal = len(out.Matched)
	for _, matched := range out.Matched[:min(len(out.Matched), maxMatchedRanges)] {
		adv.MatchedRanges = append(adv.MatchedRanges, MatchedRange(matched))
	}
	own := enrichment[id]
	adv.Severity, adv.CVSSv3Score = own.Severity, own.CVSSv3Score
	adv.InCISAKEV, adv.EPSSScore = exploitData(adv.CVEIDs, enrichment)
	return adv, out.Verdict
}

// compareCPERows orders an advisory's rows by CPE, then by their four bounds, so
// that they are evaluated in one order however they were read.
func compareCPERows(a, b CPERow) int {
	return cmp.Or(
		strings.Compare(a.CPE, b.CPE),
		strings.Compare(a.VersionStartIncluding, b.VersionStartIncluding),
		strings.Compare(a.VersionStartExcluding, b.VersionStartExcluding),
		strings.Compare(a.VersionEndIncluding, b.VersionEndIncluding),
		strings.Compare(a.VersionEndExcluding, b.VersionEndExcluding),
	)
}

// fixOrder is the order fix candidates are compared in (design section 7): the
// ecosystem's for a package item, dotted numbers for a CPE item.
func fixOrder(item Item) version.Order {
	if item.Package != nil {
		return version.EcosystemOrder(item.Package.Ecosystem)
	}
	return version.NumericOrder
}

// cnaReader returns the reading of an advisory's CNA rows for a fix candidate,
// or nil when the advisory has none.
func cnaReader(m *workMeter, rows []CNARow) func(string) Reading {
	if len(rows) == 0 {
		return nil
	}
	return func(candidate string) Reading { return ReadCNAEntries(m, candidate, rows).Reading }
}

func componentOf(item Item) *Component {
	if item.Package != nil {
		return &Component{Kind: componentPackage, Ecosystem: item.Package.Ecosystem, Name: item.Package.Name, Version: item.Version}
	}
	p := item.Product
	return &Component{Kind: componentProduct, Part: p.Part, Vendor: p.Vendor, Product: p.Product, Version: item.Version}
}

func reasonPtr(r Reason) *Reason { return &r }
