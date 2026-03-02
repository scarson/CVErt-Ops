-- ABOUTME: Bounded-batch DELETE queries for data retention cleanup (§21).
-- ABOUTME: Each query deletes up to batch_size rows older than cutoff per call.

-- name: CleanupCveRawPayloads :execrows
WITH doomed AS (
    SELECT id FROM cve_raw_payloads
    WHERE ingested_at < @cutoff::timestamptz
    ORDER BY ingested_at LIMIT @batch_size::int
)
DELETE FROM cve_raw_payloads p USING doomed WHERE p.id = doomed.id;

-- name: CleanupFeedFetchLog :execrows
WITH doomed AS (
    SELECT id FROM feed_fetch_log
    WHERE started_at < @cutoff::timestamptz
    ORDER BY started_at LIMIT @batch_size::int
)
DELETE FROM feed_fetch_log f USING doomed WHERE f.id = doomed.id;

-- name: CleanupAlertEvents :execrows
WITH doomed AS (
    SELECT id FROM alert_events
    WHERE org_id = ANY(@org_ids::uuid[]) AND first_fired_at < @cutoff::timestamptz
    ORDER BY first_fired_at LIMIT @batch_size::int
)
DELETE FROM alert_events ae USING doomed WHERE ae.id = doomed.id;

-- name: CleanupNotificationDeliveries :execrows
WITH doomed AS (
    SELECT id FROM notification_deliveries
    WHERE org_id = ANY(@org_ids::uuid[]) AND created_at < @cutoff::timestamptz
    ORDER BY created_at LIMIT @batch_size::int
)
DELETE FROM notification_deliveries nd USING doomed WHERE nd.id = doomed.id;

-- name: CleanupJobQueue :execrows
WITH doomed AS (
    SELECT id FROM job_queue
    WHERE status IN ('succeeded', 'dead') AND finished_at < @cutoff::timestamptz
    ORDER BY finished_at LIMIT @batch_size::int
)
DELETE FROM job_queue jq USING doomed WHERE jq.id = doomed.id;

-- name: CleanupRefreshTokens :execrows
WITH doomed AS (
    SELECT jti FROM refresh_tokens
    WHERE expires_at < @cutoff::timestamptz
    ORDER BY expires_at LIMIT @batch_size::int
)
DELETE FROM refresh_tokens rt USING doomed WHERE rt.jti = doomed.jti;

-- name: CleanupAIRequestLog :execrows
WITH doomed AS (
    SELECT id FROM ai_request_log
    WHERE created_at < @cutoff::timestamptz
    ORDER BY created_at LIMIT @batch_size::int
)
DELETE FROM ai_request_log arl USING doomed WHERE arl.id = doomed.id;

-- name: CleanupAICache :execrows
WITH doomed AS (
    SELECT id FROM ai_cache
    WHERE expires_at < @cutoff::timestamptz
    ORDER BY expires_at LIMIT @batch_size::int
)
DELETE FROM ai_cache ac USING doomed WHERE ac.id = doomed.id;

-- name: CleanupAIUsageCounters :execrows
WITH doomed AS (
    SELECT org_id, feature, date FROM ai_usage_counters
    WHERE date < @cutoff::date
    ORDER BY date LIMIT @batch_size::int
)
DELETE FROM ai_usage_counters auc
USING doomed
WHERE auc.org_id = doomed.org_id AND auc.feature = doomed.feature AND auc.date = doomed.date;

-- name: CleanupAuditLog :execrows
WITH doomed AS (
    SELECT id FROM audit_log
    WHERE org_id = ANY(@org_ids::uuid[]) AND created_at < @cutoff::timestamptz
    ORDER BY created_at LIMIT @batch_size::int
)
DELETE FROM audit_log al USING doomed WHERE al.id = doomed.id;
