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
-- status is included so the caller can transition atomically (e.g. "activating").
UPDATE alert_rules
SET name                       = $3,
    logic                      = $4,
    conditions                 = $5,
    watchlist_ids              = $6,
    has_epss_condition         = $7,
    is_epss_only               = $8,
    fire_on_non_material_changes = $9,
    status                     = $10,
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

-- name: LockAlertEventFeed :exec
-- Takes the org's alert-event feed lock until the transaction ends. Run it before any
-- statement that draws a feed_seq, so positions become visible in position order.
SELECT pg_advisory_xact_lock(1178944836, hashtext(sqlc.arg(org_id)::uuid::text));

-- name: InsertAlertEvent :one
-- Exactly-once insert: fan-out only when a new row is created.
-- Returns the new row id; empty result means the event already existed (DO NOTHING).
-- The caller holds the org's feed lock (LockAlertEventFeed).
INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash, last_match_state, suppress_delivery, feed_seq)
VALUES ($1, $2, $3, $4, true, $5, nextval('alert_event_feed_seq'))
ON CONFLICT (org_id, rule_id, cve_id, material_hash) DO NOTHING
RETURNING id;

-- name: ReopenAlertEvent :one
-- Reopens a resolved event when its CVE matches the rule again at the same material_hash.
-- Returns the id only when this statement changed the state, so fan-out stays exactly-once.
-- An empty result means the event is already open or does not exist.
-- The reopened event moves to a new feed position, so a feed poller sees the fire.
-- The caller holds the org's feed lock (LockAlertEventFeed), taken before this
-- statement locks the row.
UPDATE alert_events
SET last_match_state  = true,
    suppress_delivery = $5,
    last_fired_at     = now(),
    times_fired       = times_fired + 1,
    feed_seq          = nextval('alert_event_feed_seq')
WHERE org_id = $1
  AND rule_id = $2
  AND cve_id = $3
  AND material_hash = $4
  AND last_match_state = false
RETURNING id;

-- name: InsertActivationAlertEvents :execrows
-- Inserts an activation-scan page of matches as events with suppress_delivery = true,
-- pairing cve_ids and material_hashes by position. A pair whose event exists is skipped
-- (ON CONFLICT DO NOTHING), and so is a pair repeated in the page after its first row.
-- A CVE no longer in cves is skipped: a late-binding merge can rename a CVE after the
-- candidate query returned it, and an event under the old ID could never resolve.
-- The caller holds the org's feed lock (LockAlertEventFeed).
INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash, last_match_state, suppress_delivery, feed_seq)
SELECT sqlc.arg(org_id)::uuid, sqlc.arg(rule_id)::uuid, m.cve_id, m.material_hash, true, true,
       nextval('alert_event_feed_seq')
FROM (
    SELECT unnest(sqlc.arg(cve_ids)::text[])         AS cve_id,
           unnest(sqlc.arg(material_hashes)::text[]) AS material_hash
) m
WHERE EXISTS (SELECT 1 FROM cves c WHERE c.cve_id = m.cve_id)
ON CONFLICT (org_id, rule_id, cve_id, material_hash) DO NOTHING;

-- name: ReopenActivationAlertEvents :execrows
-- Reopens the resolved events of an activation-scan page, the set-based form of
-- ReopenAlertEvent with suppress_delivery = true. Pairs are matched by position as in
-- InsertActivationAlertEvents, with the same skip of CVEs no longer in cves. A pair
-- repeated in the page updates its event once. The caller holds the org's feed lock
-- (LockAlertEventFeed), taken before this statement locks the rows.
UPDATE alert_events ae
SET last_match_state  = true,
    suppress_delivery = true,
    last_fired_at     = now(),
    times_fired       = ae.times_fired + 1,
    feed_seq          = nextval('alert_event_feed_seq')
FROM (
    SELECT unnest(sqlc.arg(cve_ids)::text[])         AS cve_id,
           unnest(sqlc.arg(material_hashes)::text[]) AS material_hash
) m
WHERE ae.org_id = sqlc.arg(org_id)::uuid
  AND ae.rule_id = sqlc.arg(rule_id)::uuid
  AND ae.cve_id = m.cve_id
  AND ae.material_hash = m.material_hash
  AND ae.last_match_state = false
  AND EXISTS (SELECT 1 FROM cves c WHERE c.cve_id = m.cve_id);

-- name: GetUnresolvedAlertEventCVEs :many
-- Returns CVE IDs of events that last matched for this rule, used for resolution detection.
SELECT cve_id FROM alert_events
WHERE rule_id = $1 AND org_id = $2 AND last_match_state = true;

-- name: ResolveAlertEvent :many
-- Marks the CVE's still-matching events as no longer matching and returns the
-- suppress_delivery flag of each one it changed. A row already resolved is left out,
-- and a concurrent resolver waits on the row lock and then finds nothing to change.
-- A resolved event moves to a new feed position, so a feed poller sees it close. The
-- caller holds the org's feed lock (LockAlertEventFeed), taken before this statement
-- locks the rows.
UPDATE alert_events
SET last_match_state = false,
    feed_seq         = nextval('alert_event_feed_seq')
WHERE rule_id = $1 AND org_id = $2 AND cve_id = $3 AND last_match_state = true
RETURNING suppress_delivery;
