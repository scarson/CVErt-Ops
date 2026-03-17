-- name: InsertSecurityEvent :exec
INSERT INTO security_events (event_type, severity, actor_ip, actor_email, user_id, org_id, details)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ListSecurityEvents :many
SELECT id, event_type, severity, actor_ip, actor_email, user_id, org_id, details, created_at
FROM security_events
WHERE
    ($1::text IS NULL OR event_type = $1) AND
    ($2::text IS NULL OR severity = $2) AND
    ($3::text IS NULL OR actor_email = $3) AND
    ($4::timestamptz IS NULL OR created_at >= $4) AND
    ($5::timestamptz IS NULL OR created_at <= $5) AND
    ($6::timestamptz IS NULL OR created_at < $6)
ORDER BY created_at DESC, id DESC
LIMIT $7;
