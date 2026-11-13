// ABOUTME: Handler for POST /orgs/{org_id}/check: which advisories affect each listed component version.
// ABOUTME: Declares the request and response types the spec documents; check.Results produces the same JSON.
package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/check"
	"github.com/scarson/cvert-ops/internal/store"
)

// Version check limits (design sections 3.4 and 9).
const (
	maxCheckItems = 500
	// maxConcurrentChecks is 1 until peak memory per check is measured: on the
	// complete corpus one 500-item request allocated 3.97 GiB in all, and the
	// process shares its container with the worker.
	maxConcurrentChecks = 1
	checkTimeout        = 30 * time.Second
	// checkWriteTimeout bounds writing a version check response to the client.
	checkWriteTimeout = 30 * time.Second
)

// problemTypeCandidateLimit marks a request that read more candidate rows or bytes
// than one request may. The caller splits the request.
const problemTypeCandidateLimit = "urn:cvert:error:candidate_limit_exceeded"

// pgQueryCanceled is PostgreSQL's query_canceled code, which a statement timeout
// reports.
const pgQueryCanceled = "57014"

// CheckRequest is the version check request body.
type CheckRequest struct {
	Items []CheckItem `json:"items" minItems:"1" maxItems:"500" doc:"The components to check, answered in this order. An item that cannot be read is answered with status invalid; the others are still answered."`
}

// CheckItem is one component: a purl alone, an ecosystem with a name and version,
// or a CPE with a version. Its fields match check.RawItem, which it converts to.
type CheckItem struct {
	ID        string `json:"id,omitempty" doc:"Caller's identifier for the item, echoed back. At most 128 characters."`
	Purl      string `json:"purl,omitempty" doc:"Package URL with a version. At most 1024 characters. Types npm, pypi, golang, maven, cargo, gem, nuget, pub, hex, composer, deb (with a distro qualifier) and apk (with a distro qualifier)."`
	Ecosystem string `json:"ecosystem,omitempty" doc:"OSV ecosystem name; a distribution ecosystem must name a release, such as Debian:13."`
	Name      string `json:"name,omitempty" doc:"Package name in the ecosystem. At most 512 characters."`
	CPE       string `json:"cpe,omitempty" doc:"CPE 2.3 formatted string with literal part, vendor and product. At most 512 characters."`
	Version   string `json:"version,omitempty" doc:"Version to check. At most 256 characters. With a CPE it may be omitted when the CPE's own version component holds it."`
}

// CheckResults is the version check response. The handler writes check.Results.
type CheckResults struct {
	DataComplete bool              `json:"data_complete" doc:"Every feed a valid item depends on has finished a full walk and succeeded within 7 days."`
	Feeds        []CheckFeedStatus `json:"feeds" doc:"The feeds the valid items depend on, sorted by name."`
	Results      []CheckItemResult `json:"results" doc:"One result per request item, in request order."`
}

// CheckFeedStatus is one feed's completeness.
type CheckFeedStatus struct {
	Name          string     `json:"name" doc:"Feed name, as feed_sync_state names it."`
	Complete      bool       `json:"complete" doc:"The feed has finished a full walk and succeeded within 7 days."`
	LastSuccessAt *time.Time `json:"last_success_at" doc:"When the feed last succeeded; null if never."`
}

// CheckItemResult is the answer for one item.
type CheckItemResult struct {
	Index               int             `json:"index" doc:"Position of the item in the request."`
	ID                  *string         `json:"id" doc:"The item's id, or null when it had none or it was too long."`
	Status              string          `json:"status" enum:"affected,not_affected,unresolved,cannot_evaluate,no_advisory_found,invalid" doc:"Only not_affected clears a version. affected: at least one advisory reports this version affected. not_affected: every advisory found was decided and none reports the version affected; the version is not in any analysed or CNA-named advisory held. unresolved: no advisory was established as affected, and the data leaves one or more advisories unresolved for this version; not a clean result: see each listed advisory's reason and counts.cannot_evaluate_by_reason, or the item's reason when set. cannot_evaluate: the check could not be completed for this item; see reason, or, when reason is null, the listed advisories. no_advisory_found: no matching advisory was found in the searched data, which is not a statement that the component is safe. invalid: the item could not be read; see error."`
	Reason              *string         `json:"reason" enum:"unknown_version_scheme,invalid_version,invalid_range,commit_ranges_only,no_version_bounds,cna_cannot_clear,cna_indeterminate,cna_name_uncertain,cna_product_not_mapped,data_incomplete,distro_package_not_found,too_many_candidates,too_many_ranges,evaluation_failed,sdk_version_not_comparable,distro_stream_incomplete,distro_lists_fixes_only" doc:"Set when an item-level rule gave the status; null when the status comes from the listed advisories, each of which carries its own reason. invalid_version: the item's own version order cannot read its version. sdk_version_not_comparable: a microsoft:.net or .net_core version numbered as an SDK (third component 100 or more, as 10.0.404); NVD and Microsoft state runtime versions, so send the runtime version (SDKs before 2.1.300 cannot be told apart). A .NET item checks the .NET runtime; ASP.NET Core is checked under its own CPE, microsoft:asp.net_core. too_many_ranges: an advisory has more ranges than the per-advisory limit. evaluation_failed: a comparison failed for an unclassified reason. data_incomplete: a feed the item depends on has not finished a full walk or has not succeeded for 7 days; it applies with no advisory too. distro_stream_incomplete: an Ubuntu stream other than a release's standard or plain Pro stream (FIPS or Realtime under Pro, NVIDIA BlueField) lists only some of its release's advisories, so its items are never cleared. distro_lists_fixes_only, with status unresolved: the distribution's feed records issued fixes only (Red Hat, AlmaLinux, Rocky Linux, Alpine, SUSE, openSUSE, Azure Linux, Mageia, TuxCare, openEuler and Red Hat Lightwell, and any distribution not known to record unfixed vulnerabilities), so no published fix is missing for this version, but a vulnerability the distribution has not fixed would not appear; a version below a published fix still answers affected."`
	Component           *CheckComponent `json:"component" doc:"What the item was checked as; null for an invalid item."`
	DataComplete        bool            `json:"data_complete" doc:"Every feed this item depends on is complete."`
	Counts              CheckCounts     `json:"counts" doc:"Counts of advisory records found for the item, by verdict."`
	Advisories          []CheckAdvisory `json:"advisories" doc:"Advisories that report the version affected or cannot be evaluated: affected first, then those in CISA KEV, then by score. At most 100."`
	AdvisoriesTruncated bool            `json:"advisories_truncated" doc:"More advisories applied than are listed. Status and counts use all of them."`
	Warnings            []string        `json:"warnings" enum:"cna_product_not_mapped" doc:"Warnings about the answer."`
	Error               *CheckItemError `json:"error" doc:"Why the item could not be read; null unless status is invalid."`
}

// CheckComponent is a package (ecosystem and name) or a product (CPE part,
// vendor and product), with the version as compared.
type CheckComponent struct {
	_         struct{} `nullable:"true"`
	Kind      string   `json:"kind" enum:"package,product" doc:"package for the purl and ecosystem forms, product for the CPE form."`
	Ecosystem string   `json:"ecosystem,omitempty" doc:"OSV ecosystem, for a package."`
	Name      string   `json:"name,omitempty" doc:"Package name as given, for a package."`
	Part      string   `json:"part,omitempty" doc:"CPE part, lower-cased, for a product."`
	Vendor    string   `json:"vendor,omitempty" doc:"CPE vendor, lower-cased, for a product."`
	Product   string   `json:"product,omitempty" doc:"CPE product, lower-cased, for a product."`
	Version   string   `json:"version" doc:"The version as compared."`
}

// CheckCounts are of advisory records, over every advisory found for the item.
type CheckCounts struct {
	Affected       int `json:"affected" doc:"Advisory records that report the version affected."`
	CannotEvaluate int `json:"cannot_evaluate" doc:"Advisory records that could not be evaluated for the version."`
	NotAffected    int `json:"not_affected" doc:"Advisory records that do not report the version affected."`
	Retracted      int `json:"retracted" doc:"Advisory records whose CVE is rejected or withdrawn; they take no part in the status."`

	CannotEvaluateByReason map[string]int `json:"cannot_evaluate_by_reason" doc:"The advisory records that could not be evaluated, by reason, counted before the listing limit: each record is counted once, under the reason it shows. The values sum to cannot_evaluate."`
}

// CheckAdvisory is one listed advisory.
type CheckAdvisory struct {
	AdvisoryID         string              `json:"advisory_id" doc:"Advisory or CVE ID; works with GET /cves/{cve_id}."`
	CVEIDs             []string            `json:"cve_ids" doc:"CVE IDs the advisory names."`
	Verdict            string              `json:"verdict" enum:"affected,cannot_evaluate" doc:"This advisory's verdict for the version."`
	Reason             *string             `json:"reason" enum:"unknown_version_scheme,invalid_version,invalid_range,commit_ranges_only,no_version_bounds,cna_cannot_clear,cna_indeterminate,cna_name_uncertain,cna_product_not_mapped,data_incomplete,distro_package_not_found,too_many_candidates,too_many_ranges,evaluation_failed,sdk_version_not_comparable,distro_stream_incomplete" doc:"Why the advisory could not be evaluated; null when it is affected."`
	FixedVersion       *string             `json:"fixed_version" doc:"The lowest version the advisory data no longer reports as affected; null when none is known."`
	FixMajor           *string             `json:"fix_major" enum:"same,different,unknown" doc:"Whether fixed_version is in the same major release as the version; null when fixed_version is null."`
	FixEcosystem       *string             `json:"fix_ecosystem" doc:"The ecosystem of the package range that names fixed_version, preferring the item's own when several do. For an Ubuntu item it can be the release's other stream: Ubuntu:Pro:<release> means the fix is published only through Ubuntu Pro. Null when fixed_version is null or comes from an NVD or CNA range."`
	MatchedRanges      []CheckMatchedRange `json:"matched_ranges" doc:"Ranges that contain the version. At most 20."`
	MatchedRangesTotal int                 `json:"matched_ranges_total" doc:"How many ranges contain the version. Verdicts and fixes use all of them."`
	Severity           *string             `json:"severity" doc:"The advisory's severity, as the feed sent it."`
	CVSSv3Score        *float64            `json:"cvss_v3_score" doc:"The advisory's CVSS v3 base score."`
	EPSSScore          *float64            `json:"epss_score" doc:"Highest EPSS score of the CVEs in cve_ids; null when none of them has a score, which means not known."`
	InCISAKEV          *bool               `json:"in_cisa_kev" doc:"Whether any CVE in cve_ids is in CISA KEV; null when the record names no CVE that is held, which means not known, not false."`
}

// CheckMatchedRange is one range that contains the version. An absent bound is omitted.
type CheckMatchedRange struct {
	Evidence     string `json:"evidence" enum:"package_range,nvd_cpe,cna" doc:"Where the range comes from: a package range, an NVD CPE match, or the CNA's affected data."`
	CPE          string `json:"cpe,omitempty" doc:"The CPE of an NVD CPE match."`
	Ecosystem    string `json:"ecosystem,omitempty" doc:"The stored ecosystem of a package range. An Ubuntu item reads both its release's standard and Ubuntu Pro streams, so this names the stream the range came from."`
	Introduced   string `json:"introduced" doc:"Lower bound, inclusive; empty when the range has none."`
	Fixed        string `json:"fixed,omitempty" doc:"Upper bound, exclusive."`
	LastAffected string `json:"last_affected,omitempty" doc:"Upper bound, inclusive."`
}

// CheckItemError is why an item could not be read.
type CheckItemError struct {
	_       struct{} `nullable:"true"`
	Code    string   `json:"code" enum:"invalid_form,invalid_ecosystem,ecosystem_release_required,invalid_purl,unsupported_purl_type,unsupported_purl_namespace,unsupported_repository,distro_required,distro_not_recognised,conflicting_distro,invalid_cpe,version_required,conflicting_version,value_too_long,invalid_characters" doc:"Stable error code."`
	Message string   `json:"message" doc:"A fixed sentence explaining the code. It never repeats the item's values."`
}

// checkComponentsHandler handles POST /api/v1/orgs/{org_id}/check. Requires viewer+.
// It reads only the global CVE corpus. Items describe what an org runs, so they
// are neither stored nor logged, and no audit entry is written.
//
// At most maxConcurrentChecks read and evaluate at once. The body is read and its
// items parsed before a slot is taken, and the slot is given back before the
// response is written, so a slow upload or a slow reader of the response cannot
// hold one. A request that finds no free slot is refused before the database is
// read. The response must be written within checkWriteTimeout.
func (srv *Server) checkComponentsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	// middleware.RequestSize only wraps the body, so the limit shows up here as a
	// read error, which decodeJSON would report as malformed JSON.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeProblem(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body is larger than %d bytes", tooLarge.Limit))
			return
		}
		writeProblem(w, http.StatusBadRequest, "could not read the request body")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	var req CheckRequest
	if decErr := decodeJSON(r, &req); decErr != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", decErr)
		return
	}
	if len(req.Items) == 0 {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "items is required and must hold at least one item", Location: "body.items"})
		return
	}
	if len(req.Items) > maxCheckItems {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: fmt.Sprintf("items must hold at most %d items", maxCheckItems), Location: "body.items"})
		return
	}

	items := make([]check.Item, len(req.Items))
	for i, raw := range req.Items {
		items[i] = check.ParseItem(i, check.RawItem(raw))
	}
	keys := check.KeysFor(items)

	ctx, cancel := context.WithTimeout(r.Context(), checkTimeout)
	defer cancel()
	results, err := srv.runCheck(ctx, orgID, items, keys)
	if errors.Is(err, errCheckSlotsBusy) {
		w.Header().Set("Retry-After", "1")
		writeProblem(w, http.StatusServiceUnavailable, "all version check slots are in use; retry shortly")
		return
	}
	if err != nil {
		writeCheckFailure(w, r, ctx, err)
		return
	}

	// The server sets no write timeout, so without this a client that stops
	// reading would keep the handler, and the results it holds, indefinitely.
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(checkWriteTimeout)); err != nil &&
		!errors.Is(err, http.ErrNotSupported) {
		slog.WarnContext(r.Context(), "version check: set write deadline", "error", err)
	}
	writeJSON(w, http.StatusOK, results)
}

// errCheckSlotsBusy reports that every version check slot was in use.
var errCheckSlotsBusy = errors.New("all version check slots are in use")

// runCheck reads the candidate rows for keys and evaluates items against them,
// holding a version check slot for just that work. It returns errCheckSlotsBusy
// when no slot is free.
func (srv *Server) runCheck(ctx context.Context, orgID uuid.UUID, items []check.Item, keys check.Keys) (check.Results, error) {
	if !srv.acquireCheck() {
		return check.Results{}, errCheckSlotsBusy
	}
	defer srv.releaseCheck()

	// The read ends its transaction before returning, so no connection is held
	// while versions are compared.
	candidates, enrichment, feedRows, err := srv.store.ReadCheckCandidates(ctx, orgID, keys)
	if err != nil {
		return check.Results{}, err
	}
	return check.EvaluateWithLimits(ctx, items, candidates, check.FeedStatuses(feedRows, time.Now()),
		enrichment, srv.checkLimits)
}

// writeCheckFailure answers a version check whose read or evaluation failed. ctx
// is the check's own context: once it has ended, the failure is the time limit
// or the caller leaving, whatever error the driver reported. A PostgreSQL
// statement timeout (DB_STATEMENT_TIMEOUT_MS, shorter than checkTimeout) is a
// time limit too, though the context is still live. Nothing partial is
// answered, because a partial read cannot say which items lost rows.
func writeCheckFailure(w http.ResponseWriter, r *http.Request, ctx context.Context, err error) {
	switch {
	case errors.Is(err, store.ErrCandidateLimit):
		writeProblemTyped(w, http.StatusUnprocessableEntity, problemTypeCandidateLimit,
			"the request reads more candidate rows than one request may; split the items over several requests")
	case ctx.Err() != nil, pgErrCode(err) == pgQueryCanceled:
		writeProblem(w, http.StatusServiceUnavailable,
			"the version check took too long or the request was cancelled, so nothing was answered; retry, or split the items over several requests")
	default:
		slog.ErrorContext(r.Context(), "version check", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
	}
}

// acquireCheck takes a version check slot without waiting, and reports whether
// one was free.
func (srv *Server) acquireCheck() bool {
	select {
	case srv.checkSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (srv *Server) releaseCheck() { <-srv.checkSem }
