// ABOUTME: Alert evaluator implementing realtime, batch, EPSS, and activation evaluation paths.
// ABOUTME: Writes alert_events; manages alert_rule_runs and rule status transitions.
package alert

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
	"github.com/scarson/cvert-ops/internal/metrics"
	"github.com/scarson/cvert-ops/internal/store"
)

const (
	batchFeedName   = "alert:batch"
	epssFeedName    = "alert:epss"
	activationQueue = "alert_activation"
	activationBatch = 1000
	candidateCap    = 5000
)

// cveSummary is a lightweight CVE record produced by the candidate query.
type cveSummary struct {
	CVEID        string
	MaterialHash string
	Description  string // pre-lowercased for PostFilter matching
}

// PostFilterField implements dsl.PostFilterTarget for cveSummary.
func (c cveSummary) PostFilterField(field string) string {
	if field == "cve_id" {
		return c.CVEID
	}
	return c.Description
}

// Dispatcher triggers notification delivery for a newly created alert event and for a
// CVE that stopped matching a rule. A nil dispatcher disables delivery (tests, startup).
type Dispatcher interface {
	Fanout(ctx context.Context, orgID, ruleID uuid.UUID, cveID string) error
	FanoutResolution(ctx context.Context, orgID, ruleID uuid.UUID, cveID string) error
}

// Evaluator runs alert DSL rules against the CVE corpus across three evaluation paths.
type Evaluator struct {
	db                     *sql.DB // stdlib-wrapped pool; squirrel/pq.Array compatible
	rules                  store.AlertRuleStore
	cache                  *RuleCache
	log                    *slog.Logger
	dispatcher             Dispatcher // nil = delivery disabled
	longStatementTimeoutMS int        // overrides connection-level statement_timeout for activation scans
}

// New creates an Evaluator. db must be the stdlib-wrapped pool from the same store used by rules.
// longTimeoutMS overrides the per-connection statement_timeout for long-running
// operations (activation scans). Pass 0 to use the connection default.
func New(db *sql.DB, rules store.AlertRuleStore, cache *RuleCache, log *slog.Logger, longTimeoutMS int) *Evaluator {
	return &Evaluator{db: db, rules: rules, cache: cache, log: log, longStatementTimeoutMS: longTimeoutMS}
}

// SetDispatcher injects the notification dispatcher.
func (e *Evaluator) SetDispatcher(d Dispatcher) {
	e.dispatcher = d
}

// DryRunResult holds the output of a dry-run evaluation. No alert_events are written.
type DryRunResult struct {
	MatchCount          int
	CandidatesEvaluated int
	Partial             bool
	SampleCVEs          []string // up to 10 matching CVE IDs
}

// ──────────────────────────────────────────────────────────────────────────────
// Public evaluation paths
// ──────────────────────────────────────────────────────────────────────────────

// EvaluateRealtime evaluates all active non-EPSS-only rules against a single CVE.
// Writes a run row only on match or error (per alert_rule_runs write policy).
func (e *Evaluator) EvaluateRealtime(ctx context.Context, cveID string) error {
	start := time.Now()
	rules, err := e.rules.ListActiveRulesForEvaluation(ctx)
	if err != nil {
		return fmt.Errorf("list rules for realtime: %w", err)
	}
	candidateIDs := []string{cveID}
	var totalMatches int
	for i := range rules {
		rule := &rules[i]
		compiled, compErr := e.loadAndCompileRule(rule)
		if compErr != nil {
			e.failUncompilableRule(ctx, rule, "realtime", compErr)
			continue
		}
		matchCount, partial, candidatesEval, evalErr := e.evaluateRule(ctx, compiled, candidateIDs, rule.OrgID, false, false, 0)
		if evalErr != nil {
			e.log.Error("evaluate rule realtime", "rule_id", rule.ID, "cve_id", cveID, "err", evalErr)
		}
		totalMatches += matchCount
		// Realtime: only write a run row if there was a match, partial, or error.
		if matchCount > 0 || partial || evalErr != nil {
			status, errMsg := runStatus(partial, evalErr)
			if run, runErr := e.rules.InsertAlertRuleRun(ctx, rule.ID, rule.OrgID, "realtime"); runErr == nil {
				_ = e.rules.UpdateAlertRuleRun(ctx, run.ID, status, int32(candidatesEval), int32(matchCount), errMsg) //nolint:gosec // G115: bounded by candidateCap
			}
		}
	}
	metrics.AlertRulesEvaluatedTotal.WithLabelValues("realtime").Add(float64(len(rules)))
	metrics.AlertMatchesTotal.WithLabelValues("realtime").Add(float64(totalMatches))
	metrics.AlertEvaluationDuration.WithLabelValues("realtime").Observe(time.Since(start).Seconds())
	return nil
}

// EvaluateBatch evaluates all active non-EPSS-only rules against CVEs modified since the
// last batch cursor. Advances the cursor only after all rules have been attempted.
func (e *Evaluator) EvaluateBatch(ctx context.Context) error {
	return e.evaluateBatchPath(ctx, batchConfig{
		feedName:      batchFeedName,
		metricsLabel:  "batch",
		getCandidates: e.getCVEsModifiedSince,
		listRules:     e.rules.ListActiveRulesForEvaluation,
		maxHeldRuns:   batchMaxHeldRuns,
	})
}

// EvaluateEPSS evaluates all active rules with EPSS conditions against CVEs whose EPSS
// score has been updated since the last EPSS cursor.
func (e *Evaluator) EvaluateEPSS(ctx context.Context) error {
	return e.evaluateBatchPath(ctx, batchConfig{
		feedName:      epssFeedName,
		metricsLabel:  "epss",
		getCandidates: e.getCVEsEPSSUpdatedSince,
		listRules:     e.rules.ListActiveRulesForEPSS,
		maxHeldRuns:   epssMaxHeldRuns,
	})
}

const candidatePageSize = 1000

// cursorRescanWindow is how far behind the stored cursor each batch/EPSS run starts its
// candidate scan. The cursor is the evaluator's Go clock at the start of the previous run,
// while the timestamps it is compared with come from other clocks and are taken before
// their writer commits: date_epss_updated is Postgres now() (transaction start), and
// date_modified_canonical is the merge worker's Go clock, read before its upsert. A row
// stamped before the cursor but committed after the previous run's scan would otherwise
// never be evaluated. Re-evaluating a CVE is idempotent: alert_events inserts are
// ON CONFLICT DO NOTHING, reopens apply only to resolved events, resolves apply only to
// open events, and fan-out runs only for events that a run inserted, reopened or resolved.
//
// The window must exceed clock skew between the app and database hosts plus the longest
// gap between a writer taking its timestamp and committing. Both are normally well under
// a second; two minutes leaves a wide margin while at most doubling the candidate set of
// a batch run, which is scheduled every two minutes.
const cursorRescanWindow = 2 * time.Minute

// A run in which any rule fails to evaluate (an error, or a partial candidate set) keeps
// the cursor where it was, so the next run re-evaluates the same CVEs for every rule.
// Re-evaluation is idempotent (see cursorRescanWindow). The cursor is held for at most
// this many consecutive runs, so a rule that fails on every run cannot stall the cursor
// and grow every rule's candidate set without bound; the run after the last held run
// advances the cursor and logs the rules whose CVEs were not evaluated. The batch job runs
// every 2 minutes (about an hour of retries) and the EPSS job daily (three days).
const (
	batchMaxHeldRuns = 30
	epssMaxHeldRuns  = 3
)

// batchConfig parameterizes the shared batch/EPSS evaluation loop.
type batchConfig struct {
	feedName      string
	metricsLabel  string
	getCandidates func(ctx context.Context, since time.Time, afterID string, limit int) ([]string, error)
	listRules     func(ctx context.Context) ([]store.AlertRuleRow, error)
	maxHeldRuns   int
}

// evalCursor is the batch/EPSS cursor stored in feed_sync_state.cursor_json. HeldRuns
// counts consecutive runs that kept Since because a rule failed to evaluate.
type evalCursor struct {
	Since    time.Time `json:"since"`
	HeldRuns int       `json:"held_runs,omitempty"`
}

// evaluateBatchPath implements the shared evaluation loop for both EvaluateBatch and
// EvaluateEPSS. Reads cursor, fetches paginated candidates, runs all rules against
// each page, records metrics, then advances the cursor only after all pages complete
// and every rule evaluated (see batchMaxHeldRuns).
func (e *Evaluator) evaluateBatchPath(ctx context.Context, cfg batchConfig) error {
	start := time.Now()
	cursor, err := e.readCursor(ctx, cfg.feedName)
	if err != nil {
		return fmt.Errorf("read %s cursor: %w", cfg.feedName, err)
	}
	batchTime := time.Now().UTC()

	// A zero cursor means no previous run: scan everything.
	since := cursor.Since
	if !since.IsZero() {
		since = since.Add(-cursorRescanWindow)
	}

	rules, err := cfg.listRules(ctx)
	if err != nil {
		return fmt.Errorf("list rules for %s: %w", cfg.feedName, err)
	}

	// Collect all candidate IDs across pages before evaluating rules.
	// This avoids creating duplicate rule run records per page (one run per rule per batch).
	var allCandidateIDs []string
	var afterID string

	for {
		candidateIDs, pageErr := cfg.getCandidates(ctx, since, afterID, candidatePageSize)
		if pageErr != nil {
			return fmt.Errorf("get %s candidates: %w", cfg.feedName, pageErr)
		}
		if len(candidateIDs) == 0 {
			break
		}

		allCandidateIDs = append(allCandidateIDs, candidateIDs...)

		// Advance keyset cursor to last ID in this page.
		afterID = candidateIDs[len(candidateIDs)-1]

		// If this page was smaller than the page size, we've reached the end.
		if len(candidateIDs) < candidatePageSize {
			break
		}
	}

	listChanges, err := e.getWatchlistCVEChangesSince(ctx, since)
	if err != nil {
		return fmt.Errorf("get watchlist changes for %s: %w", cfg.feedName, err)
	}

	// Short-circuit if no candidates — still write cursor to advance past this window.
	if len(allCandidateIDs) == 0 && len(listChanges) == 0 {
		return e.writeCursor(ctx, cfg.feedName, evalCursor{Since: batchTime})
	}

	var totalMatches int
	var failedRuleIDs []uuid.UUID
	for i := range rules {
		rule := &rules[i]
		ruleCandidateIDs := candidatesForRule(allCandidateIDs, rule.WatchlistIds, listChanges)
		if len(ruleCandidateIDs) == 0 {
			continue
		}
		compiled, compErr := e.loadAndCompileRule(rule)
		if compErr != nil {
			e.failUncompilableRule(ctx, rule, cfg.metricsLabel, compErr)
			continue
		}
		matchCount, partial, candidatesEval, evalErr := e.evaluateRuleInChunks(ctx, compiled, ruleCandidateIDs, rule.OrgID)
		if evalErr != nil {
			e.log.Error("evaluate rule "+cfg.metricsLabel, "rule_id", rule.ID, "err", evalErr)
		}
		if evalErr != nil || partial {
			failedRuleIDs = append(failedRuleIDs, rule.ID)
		}
		totalMatches += matchCount
		status, errMsg := runStatus(partial, evalErr)
		if run, runErr := e.rules.InsertAlertRuleRun(ctx, rule.ID, rule.OrgID, cfg.metricsLabel); runErr == nil {
			_ = e.rules.UpdateAlertRuleRun(ctx, run.ID, status, int32(candidatesEval), int32(matchCount), errMsg) //nolint:gosec // G115: bounded by candidateCap
		}
	}

	metrics.AlertRulesEvaluatedTotal.WithLabelValues(cfg.metricsLabel).Add(float64(len(rules)))
	metrics.AlertMatchesTotal.WithLabelValues(cfg.metricsLabel).Add(float64(totalMatches))
	metrics.AlertEvaluationDuration.WithLabelValues(cfg.metricsLabel).Observe(time.Since(start).Seconds())

	if len(failedRuleIDs) > 0 {
		if cursor.HeldRuns < cfg.maxHeldRuns {
			held := evalCursor{Since: cursor.Since, HeldRuns: cursor.HeldRuns + 1}
			e.log.Warn("holding "+cfg.metricsLabel+" cursor: rules failed to evaluate",
				"rule_ids", failedRuleIDs, "held_runs", held.HeldRuns, "max_held_runs", cfg.maxHeldRuns)
			return e.writeCursor(ctx, cfg.feedName, held)
		}
		e.log.Error("advancing "+cfg.metricsLabel+" cursor past CVEs that failing rules did not evaluate",
			"rule_ids", failedRuleIDs, "since", cursor.Since, "held_runs", cursor.HeldRuns)
	}

	// Cursor is written only after ALL pages have been processed.
	return e.writeCursor(ctx, cfg.feedName, evalCursor{Since: batchTime})
}

// EvaluateActivation runs the activation scan for a newly created rule. Iterates the full
// CVE corpus in 1,000-row keyset pages, writes events with suppress_delivery=true, then
// transitions the rule to 'active'. Called by the worker processing 'alert_activation' jobs.
func (e *Evaluator) EvaluateActivation(ctx context.Context, ruleID, orgID uuid.UUID) error {
	rule, err := e.rules.GetAlertRule(ctx, orgID, ruleID)
	if err != nil {
		return fmt.Errorf("get rule %s: %w", ruleID, err)
	}
	if rule == nil {
		return fmt.Errorf("rule %s not found", ruleID)
	}

	compiled, err := e.loadAndCompileRule(rule)
	if err != nil {
		_, _ = e.rules.SetAlertRuleStatusIf(ctx, orgID, ruleID, "error", "activating")
		return fmt.Errorf("compile rule %s: %w", ruleID, err)
	}

	run, err := e.rules.InsertAlertRuleRun(ctx, ruleID, orgID, "activation")
	if err != nil {
		return fmt.Errorf("insert run for activation %s: %w", ruleID, err)
	}

	var totalMatches, totalCandidates int32
	var runErr error
	var lastID string

	for {
		batch, batchErr := e.getCVEsBatch(ctx, lastID, activationBatch)
		if batchErr != nil {
			runErr = batchErr
			break
		}
		if len(batch) == 0 {
			break
		}

		matchCount, _, candidatesEval, evalErr := e.evaluateRule(ctx, compiled, batch, orgID, true, true, e.longStatementTimeoutMS)
		totalCandidates += int32(candidatesEval) //nolint:gosec // G115: bounded by activationBatch
		if evalErr != nil {
			runErr = evalErr
			break
		}
		totalMatches += int32(matchCount) //nolint:gosec // G115: bounded by activationBatch
		lastID = batch[len(batch)-1]
	}

	status, errMsg := runStatus(false, runErr)
	_ = e.rules.UpdateAlertRuleRun(ctx, run.ID, status, totalCandidates, totalMatches, errMsg)

	if runErr != nil {
		_, _ = e.rules.SetAlertRuleStatusIf(ctx, orgID, ruleID, "error", "activating")
		return fmt.Errorf("activation scan for %s: %w", ruleID, runErr)
	}
	updated, err := e.rules.SetAlertRuleStatusIf(ctx, orgID, ruleID, "active", "activating")
	if err != nil {
		return fmt.Errorf("set rule %s active: %w", ruleID, err)
	}
	if !updated {
		e.log.Info("activation complete but rule status changed concurrently", "rule_id", ruleID)
	}
	return nil
}

// SweepZombieActivations finds activation jobs stuck in 'running' for more than 15 minutes,
// marks the associated rule as 'error', and marks the job as 'failed'. Does not auto-retry.
func (e *Evaluator) SweepZombieActivations(ctx context.Context) error {
	type zombie struct {
		JobID  uuid.UUID
		RuleID uuid.UUID
		OrgID  uuid.UUID
	}

	var zombies []zombie
	rows, err := e.db.QueryContext(ctx, `
		SELECT jq.id,
		       (jq.payload->>'rule_id')::uuid,
		       (jq.payload->>'org_id')::uuid
		FROM job_queue jq
		WHERE jq.queue     = $1
		  AND jq.status    = 'running'
		  AND jq.locked_at < now() - interval '15 minutes'
	`, activationQueue)
	if err != nil {
		return fmt.Errorf("query zombie jobs: %w", err)
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var z zombie
		if err := rows.Scan(&z.JobID, &z.RuleID, &z.OrgID); err != nil {
			return fmt.Errorf("scan zombie: %w", err)
		}
		zombies = append(zombies, z)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate zombies: %w", err)
	}

	for _, z := range zombies {
		e.log.Warn("zombie activation job detected", "job_id", z.JobID, "rule_id", z.RuleID)

		if _, err := e.rules.SetAlertRuleStatusIf(ctx, z.OrgID, z.RuleID, "error", "activating"); err != nil {
			e.log.Error("set zombie rule to error", "rule_id", z.RuleID, "err", err)
		}
		if _, err := e.db.ExecContext(ctx,
			`UPDATE job_queue SET status = 'failed', finished_at = now() WHERE id = $1 AND status = 'running'`,
			z.JobID,
		); err != nil {
			e.log.Error("fail zombie job", "job_id", z.JobID, "err", err)
		}
	}
	return nil
}

// DryRun evaluates a rule against the full CVE corpus without writing any
// alert_events rows. Returns nil result (with no error) if the rule is not found.
func (e *Evaluator) DryRun(ctx context.Context, ruleID, orgID uuid.UUID) (*DryRunResult, error) {
	rule, err := e.rules.GetAlertRule(ctx, orgID, ruleID)
	if err != nil {
		return nil, fmt.Errorf("get rule: %w", err)
	}
	if rule == nil {
		return nil, nil
	}

	compiled, err := e.loadAndCompileRule(rule)
	if err != nil {
		return nil, fmt.Errorf("compile rule: %w", err)
	}

	var candidates []cveSummary
	var partial bool
	if err := e.bypassTx(ctx, 0, func(tx *sql.Tx) error {
		var err error
		candidates, partial, err = e.queryCandidates(ctx, tx, compiled, nil)
		return err
	}); err != nil {
		return nil, fmt.Errorf("query candidates: %w", err)
	}

	if partial {
		return &DryRunResult{Partial: true, CandidatesEvaluated: candidateCap + 1}, nil
	}

	matched := dsl.ApplyPostFilters(candidates, compiled.PostFilters, compiled.Logic)

	sample := make([]string, 0, 10)
	for i, m := range matched {
		if i >= 10 {
			break
		}
		sample = append(sample, m.CVEID)
	}

	return &DryRunResult{
		MatchCount:          len(matched),
		CandidatesEvaluated: len(candidates),
		Partial:             false,
		SampleCVEs:          sample,
	}, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Core evaluation logic
// ──────────────────────────────────────────────────────────────────────────────

// evaluateRule runs the DSL query against candidateIDs, applies PostFilters, inserts
// alert_events, and detects resolutions. suppressDelivery=true marks events from the
// activation scan baseline. suppressResolution=true skips resolution detection (activation).
// statementTimeoutMS overrides the connection-level statement_timeout when > 0.
// Returns (matchCount, partial, candidatesEval, err).
func (e *Evaluator) evaluateRule(
	ctx context.Context,
	compiled *dsl.CompiledRule,
	candidateIDs []string,
	orgID uuid.UUID,
	suppressDelivery bool,
	suppressResolution bool,
	statementTimeoutMS int,
) (int, bool, int, error) {
	var candidates []cveSummary
	var partial bool
	if err := e.bypassTx(ctx, statementTimeoutMS, func(tx *sql.Tx) error {
		var err error
		candidates, partial, err = e.queryCandidates(ctx, tx, compiled, candidateIDs)
		return err
	}); err != nil {
		return 0, false, len(candidateIDs), fmt.Errorf("query candidates: %w", err)
	}
	if partial {
		return 0, true, len(candidateIDs), nil
	}

	matched := dsl.ApplyPostFilters(candidates, compiled.PostFilters, compiled.Logic)

	// Resolution detection: find previously matched CVEs that no longer match.
	var prevMatched []string
	if !suppressResolution {
		var resErr error
		prevMatched, resErr = e.rules.GetUnresolvedAlertEventCVEs(ctx, compiled.RuleID, orgID)
		if resErr != nil {
			return len(matched), false, len(candidateIDs), fmt.Errorf("get unresolved events: %w", resErr)
		}
	}

	// Record alert_events for matches that are new or have returned after resolving.
	matchedIDs := make(map[string]bool, len(matched))
	for _, m := range matched {
		matchedIDs[m.CVEID] = true
		exists, err := e.cveExists(ctx, m.CVEID)
		if err != nil {
			return len(matched), false, len(candidateIDs), fmt.Errorf("check CVE %s: %w", m.CVEID, err)
		}
		if !exists {
			continue
		}
		eventID, err := e.rules.InsertAlertEvent(ctx, orgID, compiled.RuleID, m.CVEID, m.MaterialHash, suppressDelivery)
		if err != nil {
			return len(matched), false, len(candidateIDs), fmt.Errorf("insert alert event %s: %w", m.CVEID, err)
		}
		if eventID == uuid.Nil {
			// The rule already fired at this hash. It fires again only if the event was resolved.
			eventID, err = e.rules.ReopenAlertEvent(ctx, orgID, compiled.RuleID, m.CVEID, m.MaterialHash, suppressDelivery)
			if err != nil {
				return len(matched), false, len(candidateIDs), fmt.Errorf("reopen alert event %s: %w", m.CVEID, err)
			}
		}
		if e.dispatcher != nil && !suppressDelivery && eventID != uuid.Nil {
			if fErr := e.dispatcher.Fanout(ctx, orgID, compiled.RuleID, m.CVEID); fErr != nil {
				e.log.Error("fanout notification", "rule_id", compiled.RuleID, "cve_id", m.CVEID, "err", fErr)
				// Do not return: alert_event is committed; log and continue.
			}
		}
	}

	// Resolve CVEs that were previously matched but no longer match.
	if !suppressResolution && len(prevMatched) > 0 {
		candidateSet := make(map[string]bool, len(candidateIDs))
		for _, id := range candidateIDs {
			candidateSet[id] = true
		}
		for _, prevID := range prevMatched {
			if candidateSet[prevID] && !matchedIDs[prevID] {
				shouldNotify, err := e.rules.ResolveAlertEvent(ctx, compiled.RuleID, orgID, prevID)
				if err != nil {
					e.log.Error("resolve alert event", "rule_id", compiled.RuleID, "cve_id", prevID, "err", err)
					continue
				}
				if e.dispatcher != nil && shouldNotify {
					if fErr := e.dispatcher.FanoutResolution(ctx, orgID, compiled.RuleID, prevID); fErr != nil {
						e.log.Error("fanout resolution notification", "rule_id", compiled.RuleID, "cve_id", prevID, "err", fErr)
						// Do not return: the resolve is committed; log and continue.
					}
				}
			}
		}
	}

	return len(matched), false, len(candidateIDs), nil
}

// cveExists reports whether a CVE row still exists. A late-binding merge can rename a
// CVE after the candidate query that returned it, and an event recorded under the old
// ID could never resolve. A rename that commits between this check and the insert that
// follows it still leaves one such event; that gap is accepted, because closing it would
// mean holding the merge pipeline's CVE lock on every event insert.
func (e *Evaluator) cveExists(ctx context.Context, cveID string) (bool, error) {
	var exists bool
	err := e.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM cves WHERE cve_id = $1)", cveID).Scan(&exists)
	return exists, err
}

// evaluateRuleInChunks runs evaluateRule over candidateIDs in chunks of at most candidateCap
// IDs. The batch and EPSS paths advance their cursor past every candidate once the run ends,
// so a rule that hit the cap on the whole change set would never evaluate those CVEs. The
// candidate query returns at most one row per candidate ID (the only join is the 1:1
// cve_search_index), so no chunk can exceed the cap. Resolution detection stays correct per
// chunk because chunks are disjoint. Stops at the first error or partial chunk.
// Returns (matchCount, partial, candidatesEval, err) summed over the evaluated chunks.
func (e *Evaluator) evaluateRuleInChunks(
	ctx context.Context,
	compiled *dsl.CompiledRule,
	candidateIDs []string,
	orgID uuid.UUID,
) (int, bool, int, error) {
	var totalMatches, totalEvaluated int
	for start := 0; start < len(candidateIDs); start += candidateCap {
		end := min(start+candidateCap, len(candidateIDs))
		matchCount, partial, candidatesEval, err := e.evaluateRule(ctx, compiled, candidateIDs[start:end], orgID, false, false, 0)
		totalMatches += matchCount
		totalEvaluated += candidatesEval
		if err != nil || partial {
			return totalMatches, partial, totalEvaluated, err
		}
	}
	return totalMatches, false, totalEvaluated, nil
}

// queryCandidates runs the compiled DSL query against CVEs. If candidateIDs is
// non-nil, only those CVE IDs are considered; otherwise all CVEs are scanned.
// Returns (candidates, partial, error). partial=true means > candidateCap
// rows matched, which triggers fail-closed behavior.
func (e *Evaluator) queryCandidates(ctx context.Context, tx *sql.Tx, compiled *dsl.CompiledRule, candidateIDs []string) ([]cveSummary, bool, error) {
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
	combined := sq.And{
		compiled.SQL,
		// COALESCE keeps CVEs with no status: NULL NOT IN (...) is NULL, which drops the row.
		sq.Expr("COALESCE(lower(cves.status), '') NOT IN ('rejected', 'withdrawn')"),
	}
	if len(candidateIDs) > 0 {
		combined = append(combined, sq.Expr("cves.cve_id = ANY(?)", pq.Array(candidateIDs)))
	}
	sb := psql.
		Select(
			"cves.cve_id",
			"COALESCE(cves.material_hash, '')",
			"COALESCE(lower(cves.description_primary), '')",
		).
		From("cves")
	for _, j := range compiled.Joins {
		sb = sb.Join(j)
	}
	query, args, err := sb.
		Where(combined).
		Limit(uint64(candidateCap + 1)). //nolint:gosec // G115: constant, not user input
		ToSql()
	if err != nil {
		return nil, false, fmt.Errorf("build candidate query: %w", err)
	}

	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, fmt.Errorf("execute candidate query: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var candidates []cveSummary
	for rows.Next() {
		var s cveSummary
		if err := rows.Scan(&s.CVEID, &s.MaterialHash, &s.Description); err != nil {
			return nil, false, fmt.Errorf("scan candidate: %w", err)
		}
		candidates = append(candidates, s)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate candidates: %w", err)
	}
	if len(candidates) > candidateCap {
		return nil, true, nil
	}
	return candidates, false, nil
}

// failUncompilableRule logs a rule whose stored conditions do not compile and marks it
// status=error, so it fails closed visibly instead of being skipped on every run
// (PLAN §10.5). Re-enabling the rule runs a new activation scan.
func (e *Evaluator) failUncompilableRule(ctx context.Context, rule *store.AlertRuleRow, path string, compErr error) {
	e.log.Error("compile rule for "+path, "rule_id", rule.ID, "err", compErr)
	if _, err := e.rules.SetAlertRuleStatusIf(ctx, rule.OrgID, rule.ID, "error", "active"); err != nil {
		e.log.Error("set uncompilable rule to error", "rule_id", rule.ID, "err", err)
	}
}

// loadAndCompileRule returns the CompiledRule from cache, or compiles it from the rule's
// stored conditions. rule.Logic and rule.Conditions are stored as separate DB columns;
// we reconstruct the Rule IR directly rather than re-parsing full DSL JSON.
func (e *Evaluator) loadAndCompileRule(rule *store.AlertRuleRow) (*dsl.CompiledRule, error) {
	if compiled, ok := e.cache.Get(rule.ID, int(rule.DslVersion)); ok {
		return compiled, nil
	}
	var conditions []dsl.Condition
	if err := json.Unmarshal(rule.Conditions, &conditions); err != nil {
		return nil, fmt.Errorf("parse conditions for rule %s: %w", rule.ID, err)
	}
	r := dsl.Rule{
		Logic:      dsl.Logic(rule.Logic),
		Conditions: conditions,
	}
	compiled, err := dsl.Compile(r, rule.ID, int(rule.DslVersion), rule.OrgID, rule.WatchlistIds)
	if err != nil {
		return nil, fmt.Errorf("compile rule %s: %w", rule.ID, err)
	}
	e.cache.Set(rule.ID, int(rule.DslVersion), compiled)
	return compiled, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Database helpers
// ──────────────────────────────────────────────────────────────────────────────

// bypassTx opens a database/sql transaction with RLS bypass enabled and calls fn.
// Use for queries that reference org-scoped tables from worker paths.
// statementTimeoutMS overrides the connection-level statement_timeout for this
// transaction when > 0.
func (e *Evaluator) bypassTx(ctx context.Context, statementTimeoutMS int, fn func(*sql.Tx) error) error {
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin bypass tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if _, err := tx.ExecContext(ctx, "SET LOCAL app.bypass_rls = 'on'"); err != nil {
		return fmt.Errorf("set bypass_rls: %w", err)
	}
	if statementTimeoutMS > 0 {
		if err := store.SetStatementTimeout(ctx, tx, statementTimeoutMS); err != nil {
			return fmt.Errorf("set statement timeout: %w", err)
		}
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// getCVEsModifiedSince returns a page of CVE IDs modified after since, ordered by cve_id
// ASC for keyset pagination. afterID is the last CVE ID from the previous page (empty
// string for the first page). Rejected and withdrawn CVEs are included: evaluateRule
// resolves open events only for CVEs in its candidate list, and queryCandidates keeps
// them from matching.
func (e *Evaluator) getCVEsModifiedSince(ctx context.Context, since time.Time, afterID string, limit int) ([]string, error) {
	var (
		rows *sql.Rows
		err  error
	)
	switch {
	case since.IsZero() && afterID == "":
		rows, err = e.db.QueryContext(ctx,
			`SELECT cve_id FROM cves
			 ORDER BY cve_id ASC LIMIT $1`, limit)
	case since.IsZero():
		rows, err = e.db.QueryContext(ctx,
			`SELECT cve_id FROM cves
			 WHERE cve_id > $1
			 ORDER BY cve_id ASC LIMIT $2`, afterID, limit)
	case afterID == "":
		rows, err = e.db.QueryContext(ctx,
			`SELECT cve_id FROM cves
			 WHERE date_modified_canonical > $1
			 ORDER BY cve_id ASC LIMIT $2`, since, limit)
	default:
		rows, err = e.db.QueryContext(ctx,
			`SELECT cve_id FROM cves
			 WHERE date_modified_canonical > $1
			   AND cve_id > $2
			 ORDER BY cve_id ASC LIMIT $3`, since, afterID, limit)
	}
	return scanCVEIDs(rows, err)
}

// retractedCVE is the SQL predicate for a CVE that a feed has rejected or withdrawn.
const retractedCVE = `COALESCE(lower(status), '') IN ('rejected', 'withdrawn')`

// getCVEsEPSSUpdatedSince returns a page of CVE IDs whose EPSS score was updated after
// since, ordered by cve_id ASC for keyset pagination. It also returns CVEs retracted after
// since: EPSS-only rules are evaluated on this path alone, and a tombstone clears
// epss_score without touching date_epss_updated, so their open events would otherwise
// never resolve.
func (e *Evaluator) getCVEsEPSSUpdatedSince(ctx context.Context, since time.Time, afterID string, limit int) ([]string, error) {
	var (
		rows *sql.Rows
		err  error
	)
	switch {
	case since.IsZero() && afterID == "":
		rows, err = e.db.QueryContext(ctx,
			`SELECT cve_id FROM cves
			 WHERE (epss_score IS NOT NULL OR `+retractedCVE+`)
			 ORDER BY cve_id ASC LIMIT $1`, limit)
	case since.IsZero():
		rows, err = e.db.QueryContext(ctx,
			`SELECT cve_id FROM cves
			 WHERE cve_id > $1
			   AND (epss_score IS NOT NULL OR `+retractedCVE+`)
			 ORDER BY cve_id ASC LIMIT $2`, afterID, limit)
	case afterID == "":
		rows, err = e.db.QueryContext(ctx,
			`SELECT cve_id FROM cves
			 WHERE (date_epss_updated > $1 OR (`+retractedCVE+` AND date_modified_canonical > $1))
			 ORDER BY cve_id ASC LIMIT $2`, since, limit)
	default:
		rows, err = e.db.QueryContext(ctx,
			`SELECT cve_id FROM cves
			 WHERE (date_epss_updated > $1 OR (`+retractedCVE+` AND date_modified_canonical > $1))
			   AND cve_id > $2
			 ORDER BY cve_id ASC LIMIT $3`, since, afterID, limit)
	}
	return scanCVEIDs(rows, err)
}

// getWatchlistCVEChangesSince returns, per watchlist, the CVE IDs added to or removed from
// it after since. A CVE already in the corpus when it is listed has no reason to appear in
// the modified-date or EPSS scans, so a rule bound to the watchlist would not see it until
// the CVE next changed. A removed CVE is included so the rule resolves its event.
// Re-evaluating an unchanged CVE is idempotent (see cursorRescanWindow).
func (e *Evaluator) getWatchlistCVEChangesSince(ctx context.Context, since time.Time) (map[uuid.UUID][]string, error) {
	changes := make(map[uuid.UUID][]string)
	err := e.bypassTx(ctx, 0, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT watchlist_id, cve_id FROM watchlist_items
			WHERE item_type = 'cve' AND GREATEST(created_at, deleted_at) > $1`, since)
		if err != nil {
			return err
		}
		defer rows.Close() //nolint:errcheck
		for rows.Next() {
			var watchlistID uuid.UUID
			var cveID string
			if err := rows.Scan(&watchlistID, &cveID); err != nil {
				return err
			}
			changes[watchlistID] = append(changes[watchlistID], cveID)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return changes, nil
}

// candidatesForRule returns the CVE IDs a rule evaluates in one batch or EPSS run: the
// run's change set plus the CVEs added to or removed from the watchlists the rule is bound
// to. Each ID appears once, because evaluateRuleInChunks relies on disjoint chunks.
func candidatesForRule(changeSet []string, watchlistIDs []uuid.UUID, listChanges map[uuid.UUID][]string) []string {
	var listed []string
	for _, id := range watchlistIDs {
		listed = append(listed, listChanges[id]...)
	}
	if len(listed) == 0 {
		return changeSet
	}
	merged := slices.Concat(changeSet, listed)
	slices.Sort(merged)
	return slices.Compact(merged)
}

// getCVEsBatch fetches the next page of non-rejected CVE IDs ordered by cve_id ASC,
// starting after afterID (empty string = start from beginning).
func (e *Evaluator) getCVEsBatch(ctx context.Context, afterID string, limit int) ([]string, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if afterID == "" {
		rows, err = e.db.QueryContext(ctx,
			`SELECT cve_id FROM cves
			 WHERE COALESCE(lower(status), '') NOT IN ('rejected', 'withdrawn')
			 ORDER BY cve_id ASC LIMIT $1`, limit)
	} else {
		rows, err = e.db.QueryContext(ctx,
			`SELECT cve_id FROM cves
			 WHERE cve_id > $1
			   AND COALESCE(lower(status), '') NOT IN ('rejected', 'withdrawn')
			 ORDER BY cve_id ASC LIMIT $2`, afterID, limit)
	}
	return scanCVEIDs(rows, err)
}

// scanCVEIDs scans a single-column cve_id result into a string slice.
func scanCVEIDs(rows *sql.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// readCursor reads the batch/EPSS cursor from feed_sync_state. Returns a zero cursor if no row.
func (e *Evaluator) readCursor(ctx context.Context, feedName string) (evalCursor, error) {
	var raw []byte
	err := e.db.QueryRowContext(ctx,
		`SELECT cursor_json FROM feed_sync_state WHERE feed_name = $1`, feedName,
	).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return evalCursor{}, nil
	}
	if err != nil {
		return evalCursor{}, fmt.Errorf("read cursor %s: %w", feedName, err)
	}
	var cur evalCursor
	if err := json.Unmarshal(raw, &cur); err != nil {
		return evalCursor{}, fmt.Errorf("parse cursor %s: %w", feedName, err)
	}
	return cur, nil
}

// writeCursor upserts the batch/EPSS cursor in feed_sync_state. It sets last_success_at
// for held runs too: the scheduler enqueues the next run from last_success_at, and a held
// run has completed; the hold itself is recorded in cursor_json.
func (e *Evaluator) writeCursor(ctx context.Context, feedName string, cur evalCursor) error {
	raw, err := json.Marshal(cur)
	if err != nil {
		return err
	}
	_, err = e.db.ExecContext(ctx, `
		INSERT INTO feed_sync_state
			(feed_name, cursor_json, last_success_at, last_attempt_at, consecutive_failures)
		VALUES ($1, $2, now(), now(), 0)
		ON CONFLICT (feed_name) DO UPDATE
			SET cursor_json     = EXCLUDED.cursor_json,
			    last_success_at = now(),
			    last_attempt_at = now()
	`, feedName, raw)
	if err != nil {
		return fmt.Errorf("write cursor %s: %w", feedName, err)
	}
	return nil
}

// runStatus returns the run status string and optional error message for UpdateAlertRuleRun.
func runStatus(partial bool, err error) (string, *string) {
	if err != nil {
		s := err.Error()
		return "error", &s
	}
	if partial {
		return "partial", nil
	}
	return "complete", nil
}
