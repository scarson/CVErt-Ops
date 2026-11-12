// ABOUTME: The version check response: per-item results, advisories, matched ranges, counts and feed status.
// ABOUTME: JSON field names and enumeration values are design section 11's API contract.
package check

// The item status values.
const (
	StatusAffected        = "affected"
	StatusNotAffected     = "not_affected"
	StatusCannotEvaluate  = "cannot_evaluate"
	StatusUnresolved      = "unresolved"
	StatusNoAdvisoryFound = "no_advisory_found"
	StatusInvalid         = "invalid"
)

// The advisory verdict values. An advisory that does not affect the component is
// counted, not listed, so it has no verdict value.
const (
	VerdictAffected       = "affected"
	VerdictCannotEvaluate = "cannot_evaluate"
)

// The component kinds.
const (
	componentPackage = "package"
	componentProduct = "product"
)

// warningCNAProductNotMapped is the warning on a no_advisory_found CPE item that
// has no CNA name.
const warningCNAProductNotMapped = "cna_product_not_mapped"

// Results is the response to one version check request.
type Results struct {
	DataComplete bool         `json:"data_complete"`
	Feeds        []FeedStatus `json:"feeds"`
	Results      []ItemResult `json:"results"`
}

// ItemResult is the answer for one request item. Reason is set only when an
// item-level rule of design section 4.7 gave the status.
type ItemResult struct {
	Index               int        `json:"index"`
	ID                  *string    `json:"id"`
	Status              string     `json:"status"`
	Reason              *Reason    `json:"reason"`
	Component           *Component `json:"component"`
	DataComplete        bool       `json:"data_complete"`
	Counts              Counts     `json:"counts"`
	Advisories          []Advisory `json:"advisories"`
	AdvisoriesTruncated bool       `json:"advisories_truncated"`
	Warnings            []string   `json:"warnings"`
	Error               *ItemError `json:"error"`
}

// Component is what an item was checked as: a package (ecosystem and name) or a
// product (CPE part, vendor and product), with the version as compared.
type Component struct {
	Kind      string `json:"kind"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Part      string `json:"part,omitempty"`
	Vendor    string `json:"vendor,omitempty"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version"`
}

// Counts are of advisory records, over every advisory found for the item, listed
// or not. CannotEvaluateByReason counts each advisory that cannot be evaluated
// under its one reason, so its values sum to CannotEvaluate.
type Counts struct {
	Affected               int            `json:"affected"`
	CannotEvaluate         int            `json:"cannot_evaluate"`
	NotAffected            int            `json:"not_affected"`
	Retracted              int            `json:"retracted"`
	CannotEvaluateByReason map[Reason]int `json:"cannot_evaluate_by_reason"`
}

// Advisory is one listed advisory: one that reports the component Affected or
// cannot be evaluated.
type Advisory struct {
	AdvisoryID         string         `json:"advisory_id"`
	CVEIDs             []string       `json:"cve_ids"`
	Verdict            string         `json:"verdict"`
	Reason             *Reason        `json:"reason"`
	FixedVersion       *string        `json:"fixed_version"`
	FixMajor           *string        `json:"fix_major"`
	FixEcosystem       *string        `json:"fix_ecosystem"`
	MatchedRanges      []MatchedRange `json:"matched_ranges"`
	MatchedRangesTotal int            `json:"matched_ranges_total"`
	Severity           *string        `json:"severity"`
	CVSSv3Score        *float64       `json:"cvss_v3_score"`
	EPSSScore          *float64       `json:"epss_score"`
	InCISAKEV          *bool          `json:"in_cisa_kev"`
}

// MatchedRange is one range that contains the version. CPE is set for NVD CPE
// evidence and Ecosystem for package range evidence; an absent bound is omitted.
type MatchedRange struct {
	Evidence     string `json:"evidence"`
	CPE          string `json:"cpe,omitempty"`
	Ecosystem    string `json:"ecosystem,omitempty"`
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}
