-- Routine definitions. THIS is where the most expensive hand-rolled SQL hides: the
-- application invokes enrich_recent_orders() by name (see queries.sql); an audit
-- that doesn't follow the call into this body never sees the per-row loop.

-- PLANTED #4 (the discoverability finding — RBAR / N+1 inside a routine body):
-- a PL/pgSQL function that loops over recent orders and runs one query PER ROW.
-- This is set-based work expressed row-by-row — a single UPDATE ... FROM (a joined
-- aggregate) would replace the loop. Found ONLY if the auditor follows the call
-- from queries.sql into this definition.
CREATE OR REPLACE FUNCTION enrich_recent_orders() RETURNS void AS $$
DECLARE
    o RECORD;
    item_total bigint;
BEGIN
    FOR o IN SELECT id FROM orders WHERE status = 'paid' LOOP
        -- one round-trip per order, in a loop:
        SELECT sum(qty) INTO item_total FROM order_items WHERE order_id = o.id;
        UPDATE orders SET total_cents = item_total * 100 WHERE id = o.id;
    END LOOP;
END;
$$ LANGUAGE plpgsql VOLATILE;  -- (volatility: fine here; it mutates)

-- PLANTED #5 (postgres module — row-level trigger doing per-row work on bulk DML):
-- a FOR EACH ROW trigger that fires a write on EVERY inserted order_item, so a bulk
-- insert of N items becomes N trigger invocations + N writes. A statement-level
-- trigger over the transition table (or a constraint/materialized count) avoids the
-- per-row tax.
CREATE OR REPLACE FUNCTION bump_order_count() RETURNS trigger AS $$
BEGIN
    UPDATE orders SET total_cents = total_cents WHERE id = NEW.order_id;  -- touch per row
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_bump_order_count
    AFTER INSERT ON order_items
    FOR EACH ROW EXECUTE FUNCTION bump_order_count();
