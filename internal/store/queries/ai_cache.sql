-- ABOUTME: sqlc queries for AI response caching (org-scoped, TTL-based).
-- ABOUTME: Cache keyed by (org_id, feature, prompt_version, input_hash) with expiry.

-- name: GetAICache :one
SELECT response FROM ai_cache
WHERE org_id = $1 AND feature = $2 AND prompt_version = $3 AND input_hash = $4
  AND expires_at > now();

-- name: PutAICache :exec
INSERT INTO ai_cache (org_id, feature, prompt_version, input_hash, response, expires_at)
VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))
ON CONFLICT (org_id, feature, prompt_version, input_hash)
DO UPDATE SET response = EXCLUDED.response, expires_at = EXCLUDED.expires_at
WHERE ai_cache.response IS DISTINCT FROM EXCLUDED.response
   OR ai_cache.expires_at IS DISTINCT FROM EXCLUDED.expires_at;
