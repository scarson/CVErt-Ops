-- ABOUTME: sqlc queries for AI request audit logging and retention cleanup.
-- ABOUTME: Logs every AI request (cache hit or miss) for observability and billing.

-- name: InsertAIRequestLog :exec
INSERT INTO ai_request_log (
    org_id, user_id, feature, input_hash, prompt_version, model,
    cache_hit, input_tokens, output_tokens, latency_ms, status, error_type
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: CleanupOldAIRequestLogs :execrows
DELETE FROM ai_request_log
WHERE created_at < now() - make_interval(days => $1::int);
