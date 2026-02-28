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
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
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

// Evaluator runs alert DSL rules against the CVE corpus across three evaluation paths.
type Evaluator struct {
	db    *sql.DB            // stdlib-wrapped pool; squirrel/pq.Array compatible
	rules store.AlertRuleStore
	cache *RuleCache
	log   *slog.Logger
}

// New creates an Evaluator. db must be the stdlib-wrapped pool from the same store used by rules.
func New(db *sql.DB, rules store.AlertRuleStore, cache *RuleCache, log *slog.Logger) *Evaluator {
	return &Evaluator{db: db, rules: rules, cache: cache, log: log}
}

// ──────────────────────────────────────────────────────────────────────────────
// Public evaluation paths
// ──────────────────────────────────────────────────────────────────────────────

// EvaluateRealtime evaluates all active non-EPSS-only rules against a single CVE.
// Writes a run row only on match or error (per alert_rule_runs write policy).
func (e *Evaluator) EvaluateRealtime(ctx context.Context, cveID string) error {
	rules, err := e.rules.ListActiveRulesForEvaluation(ctx)
	if err != nil {
		return fmt.Errorf("list rules for realtime: %w", err)
	}
	candidateIDs := []string{cveID}
	for i := range rules {
		rule := &rules[i]
		compiled, compErr := e.loadAndCompileRule(rule)
		if compErr != nil {
			e.log.Error("compile rule for realtime", "rule_id", rule.ID, "err", compErr)
			continue
		}
		matchCount, partial, candidatesEval, evalErr := e.evaluateRule(ctx, compiled, candidateIDs, rule.OrgID, false, false)
		if evalErr != nil {
			e.log.Error("evaluate rule realtime", "rule_id", rule.ID, "cve_id", cveID, "err", evalErr)
		}
		// Realtime: only write a run row if there was a match, partial, or error.
		if matchCount > 0 || partial || evalErr != nil {
			status, errMsg := runStatus(partial, evalErr)
			if run, runErr := e.rules.InsertAlertRuleRun(ctx, rule.ID, rule.OrgID, "realtime"); runErr == nil {
				_ = e.rules.UpdateAlertRuleRun(ctx, run.ID, status, int32(candidatesEval), int32(matchCount), errMsg) //nolint:gosec // G115: bounded by candidateCap
			}
		}
	}
	return nil
}

// EvaluateBatch evaluates all active non-EPSS-only rules against CVEs modified since the
// last batch cursor. Advances the cursor only after all rules have been attempted.
func (e *Evaluator) EvaluateBatch(ctx context.Context) error {
	cursor, err := e.readCursor(ctx, batchFeedName)
	if err != nil {
		return fmt.Errorf("read batch cursor: %w", err)
	}
	batchTime := time.Now().UTC()

	candidateIDs, err := e.getCVEsModifiedSince(ctx, cursor)
	if err != nil {
		return fmt.Errorf("get modified CVEs: %w", err)
	}
	if len(candidateIDs) == 0 {
		return e.writeCursor(ctx, batchFeedName, batchTime)
	}

	rules, err := e.rules.ListActiveRulesForEvaluation(ctx)
	if err != nil {
		return fmt.Errorf("list rules for batch: %w", err)
	}

	for i := range rules {
		rule := &rules[i]
		compiled, compErr := e.loadAndCompileRule(rule)
		if compErr != nil {
			e.log.Error("compile rule for batch", "rule_id", rule.ID, "err", compErr)
			continue
		}
		matchCount, partial, candidatesEval, evalErr := e.evaluateRule(ctx, compiled, candidateIDs, rule.OrgID, false, false)
		if evalErr != nil {
			e.log.Error("evaluate rule batch", "rule_id", rule.ID, "err", evalErr)
		}
		status, errMsg := runStatus(partial, evalErr)
		if run, runErr := e.rules.InsertAlertRuleRun(ctx, rule.ID, rule.OrgID, "batch"); runErr == nil {
			_ = e.rules.UpdateAlertRuleRun(ctx, run.ID, status, int32(candidatesEval), int32(matchCount), errMsg) //nolint:gosec // G115: bounded by candidateCap
		}
	}

	return e.writeCursor(ctx, batchFeedName, batchTime)
}

// EvaluateEPSS evaluates all active rules with EPSS conditions against CVEs whose EPSS
// score has been updated since the last EPSS cursor.
func (e *Evaluator) EvaluateEPSS(ctx context.Context) error {
	cursor, err := e.readCursor(ctx, epssFeedName)
	if err != nil {
		return fmt.Errorf("read epss cursor: %w", err)
	}
	batchTime := time.Now().UTC()

	candidateIDs, err := e.getCVEsEPSSUpdatedSince(ctx, cursor)
	if err != nil {
		return fmt.Errorf("get EPSS-updated CVEs: %w", err)
	}
	if len(candidateIDs) == 0 {
		return e.writeCursor(ctx, epssFeedName, batchTime)
	}

	rules, err := e.rules.ListActiveRulesForEPSS(ctx)
	if err != nil {
		return fmt.Errorf("list rules for EPSS: %w", err)
	}

	for i := range rules {
		rule := &rules[i]
		compiled, compErr := e.loadAndCompileRule(rule)
		if compErr != nil {
			e.log.Error("compile rule for EPSS", "rule_id", rule.ID, "err", compErr)
			continue
		}
		matchCount, partial, candidatesEval, evalErr := e.evaluateRule(ctx, compiled, candidateIDs, rule.OrgID, false, false)
		if evalErr != nil {
			e.log.Error("evaluate rule EPSS", "rule_id", rule.ID, "err", evalErr)
		}
		status, errMsg := runStatus(partial, evalErr)
		if run, runErr := e.rules.InsertAlertRuleRun(ctx, rule.ID, rule.OrgID, "epss"); runErr == nil {
			_ = e.rules.UpdateAlertRuleRun(ctx, run.ID, status, int32(candidatesEval), int32(matchCount), errMsg) //nolint:gosec // G115: bounded by candidateCap
		}
	}

	return e.writeCursor(ctx, epssFeedName, batchTime)
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
		_ = e.rules.SetAlertRuleStatus(ctx, orgID, ruleID, "error")
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

		matchCount, _, candidatesEval, evalErr := e.evaluateRule(ctx, compiled, batch, orgID, true, true)
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
		_ = e.rules.SetAlertRuleStatus(ctx, orgID, ruleID, "error")
		return fmt.Errorf("activation scan for %s: %w", ruleID, runErr)
	}
	return e.rules.SetAlertRuleStatus(ctx, orgID, ruleID, "active")
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

		if err := e.rules.SetAlertRuleStatus(ctx, z.OrgID, z.RuleID, "error"); err != nil {
			e.log.Error("set zombie rule to error", "rule_id", z.RuleID, "err", err)
		}
		if _, err := e.db.ExecContext(ctx,
			`UPDATE job_queue SET status = 'failed', finished_at = now() WHERE id = $1`,
			z.JobID,
		); err != nil {
			e.log.Error("fail zombie job", "job_id", z.JobID, "err", err)
		}
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Core evaluation logic
// ──────────────────────────────────────────────────────────────────────────────

// evaluateRule runs the DSL query against candidateIDs, applies PostFilters, inserts
// alert_events, and detects resolutions. suppressDelivery=true marks events from the
// activation scan baseline. suppressResolution=true skips resolution detection (activation).
// Returns (matchCount, partial, candidatesEval, err).
func (e *Evaluator) evaluateRule(
	ctx context.Context,
	compiled *dsl.CompiledRule,
	candidateIDs []string,
	orgID uuid.UUID,
	suppressDelivery bool,
	suppressResolution bool,
) (int, bool, int, error) {
	var candidates []cveSummary
	var partial bool
	if err := e.bypassTx(ctx, func(tx *sql.Tx) error {
		var err error
		candidates, partial, err = e.queryCandidates(ctx, tx, compiled, candidateIDs)
		return err
	}); err != nil {
		return 0, false, len(candidateIDs), fmt.Errorf("query candidates: %w", err)
	}
	if partial {
		return 0, true, len(candidateIDs), nil
	}

	matched := applyPostFilters(candidates, compiled.PostFilters)

	// Resolution detection: find previously matched CVEs that no longer match.
	var prevMatched []string
	if !suppressResolution {
		var resErr error
		prevMatched, resErr = e.rules.GetUnresolvedAlertEventCVEs(ctx, compiled.RuleID, orgID)
		if resErr != nil {
			return len(matched), false, len(candidateIDs), fmt.Errorf("get unresolved events: %w", resErr)
		}
	}

	// Insert alert_events for new matches.
	matchedIDs := make(map[string]bool, len(matched))
	for _, m := range matched {
		matchedIDs[m.CVEID] = true
		if _, err := e.rules.InsertAlertEvent(ctx, orgID, compiled.RuleID, m.CVEID, m.MaterialHash, suppressDelivery); err != nil {
			return len(matched), false, len(candidateIDs), fmt.Errorf("insert alert event %s: %w", m.CVEID, err)
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
				if err := e.rules.ResolveAlertEvent(ctx, compiled.RuleID, orgID, prevID); err != nil {
					e.log.Error("resolve alert event", "rule_id", compiled.RuleID, "cve_id", prevID, "err", err)
				}
			}
		}
	}

	return len(matched), false, len(candidateIDs), nil
}

// queryCandidates runs the compiled DSL query against candidateIDs within a bypass_rls
// transaction. Returns (candidates, partial, error). partial=true means > candidateCap
// rows matched, which triggers fail-closed behavior.
func (e *Evaluator) queryCandidates(ctx context.Context, tx *sql.Tx, compiled *dsl.CompiledRule, candidateIDs []string) ([]cveSummary, bool, error) {
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
	combined := sq.And{
		compiled.SQL,
		sq.Expr("lower(cves.status) NOT IN ('rejected', 'withdrawn')"),
		sq.Expr("cves.cve_id = ANY(?)", pq.Array(candidateIDs)),
	}
	query, args, err := psql.
		Select(
			"cves.cve_id",
			"COALESCE(cves.material_hash, '')",
			"COALESCE(lower(cves.description_primary), '')",
		).
		From("cves").
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

// applyPostFilters filters candidates through the compiled regex PostFilters.
// All filters must match (AND semantics) for the candidate to be included.
func applyPostFilters(candidates []cveSummary, filters []dsl.PostFilter) []cveSummary {
	if len(filters) == 0 {
		return candidates
	}
	var matched []cveSummary
	for _, c := range candidates {
		pass := true
		for _, f := range filters {
			ok := f.Pattern.MatchString(c.Description)
			if f.Negate {
				ok = !ok
			}
			if !ok {
				pass = false
				break
			}
		}
		if pass {
			matched = append(matched, c)
		}
	}
	return matched
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
func (e *Evaluator) bypassTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin bypass tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, "SET LOCAL app.bypass_rls = 'on'"); err != nil {
		return fmt.Errorf("set bypass_rls: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// getCVEsModifiedSince returns all non-rejected CVE IDs modified after since.
// When since is zero, returns all non-rejected CVEs (first-run baseline).
func (e *Evaluator) getCVEsModifiedSince(ctx context.Context, since time.Time) ([]string, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if since.IsZero() {
		rows, err = e.db.QueryContext(ctx,
			`SELECT cve_id FROM cves WHERE lower(status) NOT IN ('rejected', 'withdrawn')`)
	} else {
		rows, err = e.db.QueryContext(ctx,
			`SELECT cve_id FROM cves
			 WHERE date_modified_canonical > $1
			   AND lower(status) NOT IN ('rejected', 'withdrawn')`, since)
	}
	return scanCVEIDs(rows, err)
}

// getCVEsEPSSUpdatedSince returns all non-rejected CVE IDs whose EPSS score was updated
// after since. When since is zero, returns all non-rejected CVEs with an EPSS score.
func (e *Evaluator) getCVEsEPSSUpdatedSince(ctx context.Context, since time.Time) ([]string, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if since.IsZero() {
		rows, err = e.db.QueryContext(ctx,
			`SELECT cve_id FROM cves
			 WHERE epss_score IS NOT NULL
			   AND lower(status) NOT IN ('rejected', 'withdrawn')`)
	} else {
		rows, err = e.db.QueryContext(ctx,
			`SELECT cve_id FROM cves
			 WHERE date_epss_updated > $1
			   AND lower(status) NOT IN ('rejected', 'withdrawn')`, since)
	}
	return scanCVEIDs(rows, err)
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
			 WHERE lower(status) NOT IN ('rejected', 'withdrawn')
			 ORDER BY cve_id ASC LIMIT $1`, limit)
	} else {
		rows, err = e.db.QueryContext(ctx,
			`SELECT cve_id FROM cves
			 WHERE cve_id > $1
			   AND lower(status) NOT IN ('rejected', 'withdrawn')
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

// readCursor reads the batch/EPSS cursor from feed_sync_state. Returns zero time if no row.
func (e *Evaluator) readCursor(ctx context.Context, feedName string) (time.Time, error) {
	var raw []byte
	err := e.db.QueryRowContext(ctx,
		`SELECT cursor_json FROM feed_sync_state WHERE feed_name = $1`, feedName,
	).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("read cursor %s: %w", feedName, err)
	}
	var cur struct {
		Since time.Time `json:"since"`
	}
	if err := json.Unmarshal(raw, &cur); err != nil {
		return time.Time{}, fmt.Errorf("parse cursor %s: %w", feedName, err)
	}
	return cur.Since, nil
}

// writeCursor upserts the batch/EPSS cursor in feed_sync_state.
func (e *Evaluator) writeCursor(ctx context.Context, feedName string, t time.Time) error {
	raw, err := json.Marshal(struct {
		Since time.Time `json:"since"`
	}{t})
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
