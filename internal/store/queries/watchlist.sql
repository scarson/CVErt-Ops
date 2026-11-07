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
INSERT INTO watchlist_items (watchlist_id, org_id, item_type, ecosystem, package_name, namespace, cpe_normalized, cve_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: LockWatchlist :one
-- Serializes writers to a watchlist's items: FOR UPDATE also blocks the foreign-key
-- check of a concurrent item insert until the holder commits.
SELECT id FROM watchlists
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
FOR UPDATE;

-- name: ListLiveWatchlistItems :many
SELECT * FROM watchlist_items
WHERE watchlist_id = $1 AND org_id = $2 AND deleted_at IS NULL;

-- name: SoftDeleteWatchlistItemsByID :exec
UPDATE watchlist_items
SET deleted_at = now()
WHERE id = ANY(sqlc.arg(ids)::uuid[]) AND org_id = sqlc.arg(org_id) AND deleted_at IS NULL;

-- name: InsertWatchlistItems :exec
-- Inserts many items in one statement. Each array holds one value per item, with an
-- empty string for a column the item type does not use. A multi-row VALUES list would
-- exceed the 65535 parameter limit at the replace cap.
INSERT INTO watchlist_items (watchlist_id, org_id, item_type, ecosystem, package_name, namespace, cpe_normalized, cve_id)
SELECT sqlc.arg(watchlist_id), sqlc.arg(org_id), u.item_type::watchlist_item_type,
       NULLIF(u.ecosystem, ''), NULLIF(u.package_name, ''), NULLIF(u.namespace, ''),
       NULLIF(u.cpe_normalized, ''), NULLIF(u.cve_id, '')
FROM ROWS FROM (
    unnest(sqlc.arg(item_types)::text[]),
    unnest(sqlc.arg(ecosystems)::text[]),
    unnest(sqlc.arg(package_names)::text[]),
    unnest(sqlc.arg(namespaces)::text[]),
    unnest(sqlc.arg(cpes)::text[]),
    unnest(sqlc.arg(cve_ids)::text[])
) AS u(item_type, ecosystem, package_name, namespace, cpe_normalized, cve_id);

-- name: GetWatchlistItem :one
SELECT wi.* FROM watchlist_items wi
JOIN watchlists w ON w.id = wi.watchlist_id AND w.deleted_at IS NULL
WHERE wi.id = $1 AND wi.watchlist_id = $2 AND wi.org_id = $3 AND wi.deleted_at IS NULL
LIMIT 1;

-- name: SoftDeleteWatchlistItem :execrows
UPDATE watchlist_items
SET deleted_at = now()
WHERE id = $1 AND watchlist_id = $2 AND org_id = $3 AND deleted_at IS NULL;

-- name: CountOwnedWatchlistsByIDs :one
-- Validates that all given watchlist IDs belong to the org and are not deleted.
-- Returns the count of owned watchlists; caller checks count == len(ids).
SELECT COUNT(*) FROM watchlists
WHERE id = ANY($1::uuid[]) AND org_id = $2 AND deleted_at IS NULL;
