-- ABOUTME: sqlc queries for AI usage quota tracking and quota overrides.
-- ABOUTME: Counters are per-org per-feature per-day; overrides are per-org per-feature.

-- name: IncrementAIUsage :one
INSERT INTO ai_usage_counters (org_id, feature, date, count, input_tokens, output_tokens)
VALUES ($1, $2, CURRENT_DATE, 1, 0, 0)
ON CONFLICT (org_id, feature, date)
DO UPDATE SET count = ai_usage_counters.count + 1
RETURNING count;

-- name: DecrementAIUsage :exec
UPDATE ai_usage_counters
SET count = GREATEST(count - 1, 0)
WHERE org_id = $1 AND feature = $2 AND date = CURRENT_DATE;

-- name: UpdateAIUsageTokens :exec
UPDATE ai_usage_counters
SET input_tokens = input_tokens + $3,
    output_tokens = output_tokens + $4
WHERE org_id = $1 AND feature = $2 AND date = CURRENT_DATE;

-- name: GetAIQuotaOverride :one
SELECT daily_limit FROM ai_quota_overrides
WHERE org_id = $1 AND feature = $2;

-- name: SetAIQuotaOverride :exec
INSERT INTO ai_quota_overrides (org_id, feature, daily_limit)
VALUES ($1, $2, $3)
ON CONFLICT (org_id, feature)
DO UPDATE SET daily_limit = EXCLUDED.daily_limit;

-- name: DeleteAIQuotaOverride :exec
DELETE FROM ai_quota_overrides WHERE org_id = $1 AND feature = $2;

-- name: ListAIQuotaOverrides :many
SELECT org_id, feature, daily_limit FROM ai_quota_overrides
ORDER BY org_id, feature;

-- name: ListAIQuotaOverridesForOrg :many
SELECT feature, daily_limit FROM ai_quota_overrides
WHERE org_id = $1
ORDER BY feature;
