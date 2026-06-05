"""Inventory operations. Called on the order-processing hot path.

Contains two planted performance issues (see test-fixtures/.../expected-findings.md).
"""

import repo


def find_duplicate_skus(skus):
    """Return SKUs that appear more than once.

    PLANTED ISSUE #1 (Lane 1 — algorithmic): membership test `in seen` against a
    LIST inside the loop is O(n) per check → O(n^2) overall. `seen` should be a set.
    Reached per request with request-sized `skus`.
    """
    seen = []
    dupes = []
    for sku in skus:
        if sku in seen:          # O(n) scan of a list, inside a loop
            dupes.append(sku)
        else:
            seen.append(sku)
    return dupes


def enrich_line_items(order_item_ids):
    """Attach catalog data to each line item in an order.

    PLANTED ISSUE #2 (Lane 3 — data access / N+1): one repo.get() call per item
    inside the loop. repo.get_many() can fetch the whole batch in a single
    round-trip. Reached per order on the checkout path.
    """
    enriched = []
    for item_id in order_item_ids:
        row = repo.get(item_id)   # N+1: one round-trip per item
        if row:
            enriched.append({"id": item_id, "name": row["name"], "price": row["price"]})
    return enriched
