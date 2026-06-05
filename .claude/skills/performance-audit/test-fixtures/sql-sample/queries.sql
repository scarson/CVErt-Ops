-- Hand-rolled queries invoked from the application. NOTE: the application also calls
-- the stored function `enrich_recent_orders()` (defined in procs.sql) by name — the
-- expensive SQL lives in THAT body, not here. An audit that reads only these
-- top-level queries misses it (see the Routines section of sql.md).

-- PLANTED #1 (data-access / sargability): a function on the indexed... actually
-- created_at is UNindexed AND wrapped in date() — non-sargable AND no supporting
-- index. The predicate `date(created_at) = $1` cannot use an index even if one
-- existed; rewrite as a half-open range `created_at >= $1 AND created_at < $1 + 1`
-- and add an index on created_at.
SELECT * FROM orders
WHERE date(created_at) = $1;

-- PLANTED #2 (data-access / missing index + over-fetch): fetch all orders for a
-- customer looked up by email. The planner finds the customer via idx_customers_email
-- (fast), then must find orders WHERE customer_id = <id> — but orders.customer_id has
-- NO index (schema confirms), so this is a sequential scan of orders per lookup. Add
-- an index on orders.customer_id. SELECT * also over-fetches every column.
SELECT *
FROM orders o
JOIN customers c ON c.id = o.customer_id
WHERE c.email = $1;

-- PLANTED #3 (memory / pagination): deep OFFSET pagination scans and discards
-- 100000 rows every page. Use keyset/seek pagination anchored on (created_at, id).
SELECT id, total_cents, created_at
FROM orders
ORDER BY created_at DESC
OFFSET 100000 LIMIT 20;

-- The application then calls the routine (its body is the real hot spot):
SELECT enrich_recent_orders();

-- DECOY (should NOT be flagged): a lookup by the PRIMARY KEY — already an index
-- seek, returns one row, named columns. Nothing to optimize. Flagging it (e.g.
-- "add an index", "avoid the scan") is a precision failure.
SELECT id, email FROM customers WHERE id = $1;
