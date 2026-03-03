-- ABOUTME: sqlc queries for watchlist and watchlist item management.
-- ABOUTME: All watchlist operations are org-scoped via org_id parameter.

-- name: CreateWatchlist :one
INSERT INTO watchlists (org_id, group_id, name, description)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetWatchlist :one
SELECT * FROM watchlists
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
LIMIT 1;

-- name: UpdateWatchlist :one
UPDATE watchlists
SET name        = $3,
    description = $4,
    group_id    = $5,
    updated_at  = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
RETURNING *;

-- name: SoftDeleteWatchlist :exec
UPDATE watchlists
SET deleted_at = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL;

-- name: CountWatchlistItems :one
SELECT COUNT(*) FROM watchlist_items wi
JOIN watchlists w ON w.id = wi.watchlist_id AND w.deleted_at IS NULL
WHERE wi.watchlist_id = $1 AND wi.deleted_at IS NULL;

-- name: CreateWatchlistItem :one
INSERT INTO watchlist_items (watchlist_id, org_id, item_type, ecosystem, package_name, namespace, cpe_normalized)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetWatchlistItem :one
SELECT wi.* FROM watchlist_items wi
JOIN watchlists w ON w.id = wi.watchlist_id AND w.deleted_at IS NULL
WHERE wi.id = $1 AND wi.watchlist_id = $2 AND wi.org_id = $3 AND wi.deleted_at IS NULL
LIMIT 1;

-- name: SoftDeleteWatchlistItem :exec
UPDATE watchlist_items
SET deleted_at = now()
WHERE id = $1 AND watchlist_id = $2 AND org_id = $3 AND deleted_at IS NULL;

-- name: CountOwnedWatchlistsByIDs :one
-- Validates that all given watchlist IDs belong to the org and are not deleted.
-- Returns the count of owned watchlists; caller checks count == len(ids).
SELECT COUNT(*) FROM watchlists
WHERE id = ANY($1::uuid[]) AND org_id = $2 AND deleted_at IS NULL;
