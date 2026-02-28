-- ABOUTME: sqlc queries for alert rule, run, and event management.
-- ABOUTME: Evaluator paths use bypass_rls worker transactions; HTTP paths use org-scoped transactions.

-- name: CreateAlertRule :one
INSERT INTO alert_rules (
    org_id, name, logic, conditions, watchlist_ids, dsl_version,
    has_epss_condition, is_epss_only, status, fire_on_non_material_changes
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: GetAlertRule :one
SELECT * FROM alert_rules
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
LIMIT 1;

-- name: UpdateAlertRule :one
-- Updates mutable rule fields. has_epss_condition and is_epss_only are
-- recomputed by the compiler on each DSL change and passed here.
UPDATE alert_rules
SET name                       = $3,
    logic                      = $4,
    conditions                 = $5,
    watchlist_ids              = $6,
    has_epss_condition         = $7,
    is_epss_only               = $8,
    fire_on_non_material_changes = $9,
    updated_at                 = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
RETURNING *;

-- name: SoftDeleteAlertRule :exec
UPDATE alert_rules
SET deleted_at = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL;

-- name: SetAlertRuleStatus :exec
UPDATE alert_rules
SET status     = $3,
    updated_at = now()
WHERE id = $1 AND org_id = $2;

-- name: ListActiveRulesForEvaluation :many
-- Loads all active non-EPSS-only rules across all orgs for realtime and batch evaluation.
-- Called from worker (bypass_rls); no org_id filter.
SELECT * FROM alert_rules
WHERE status = 'active' AND is_epss_only = false AND deleted_at IS NULL
ORDER BY id;

-- name: ListActiveRulesForEPSS :many
-- Loads all active rules with EPSS conditions across all orgs for EPSS evaluation.
-- Called from worker (bypass_rls); no org_id filter.
SELECT * FROM alert_rules
WHERE status = 'active' AND has_epss_condition = true AND deleted_at IS NULL
ORDER BY id;

-- name: InsertAlertRuleRun :one
INSERT INTO alert_rule_runs (rule_id, org_id, path, status, started_at)
VALUES ($1, $2, $3, 'running', now())
RETURNING *;

-- name: UpdateAlertRuleRun :exec
UPDATE alert_rule_runs
SET status               = $2,
    finished_at          = now(),
    candidates_evaluated = $3,
    matches_found        = $4,
    error_message        = $5
WHERE id = $1;

-- name: InsertAlertEvent :one
-- Exactly-once insert: fan-out only when a new row is created.
-- Returns the new row id; empty result means the event already existed (DO NOTHING).
INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash, last_match_state, suppress_delivery)
VALUES ($1, $2, $3, $4, true, $5)
ON CONFLICT (org_id, rule_id, cve_id, material_hash) DO NOTHING
RETURNING id;

-- name: GetUnresolvedAlertEventCVEs :many
-- Returns CVE IDs of events that last matched for this rule, used for resolution detection.
SELECT cve_id FROM alert_events
WHERE rule_id = $1 AND org_id = $2 AND last_match_state = true;

-- name: ResolveAlertEvent :exec
-- Marks a previously-matched event as no longer matching.
UPDATE alert_events
SET last_match_state = false
WHERE rule_id = $1 AND org_id = $2 AND cve_id = $3;
