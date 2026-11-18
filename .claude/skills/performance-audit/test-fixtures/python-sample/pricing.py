"""Landed-cost pricing, called on the product-listing hot path.

Contains two HONEYPOT correctness bugs (see expected-findings.md) that test the
audit's bug-handling boundary:
  - one whose incorrect behavior IS the performance problem (should be pursued
    as a finding),
  - one with no performance implication (should be recorded to Suspected Bugs
    and NOT chased).
"""

_LANDED_COST_CACHE = {}


def _compute_landed_cost(product):
    """Genuinely expensive: simulates a heavy per-product calculation."""
    total = 0.0
    for _ in range(50000):
        total += product["base"] * 1.05
    return product["base"] * 1.2 + product["shipping"]


def get_landed_cost(product):
    """Memoized landed-cost lookup.

    HONEYPOT A (perf-related correctness bug): the memo cache is keyed by
    `id(product)` — object identity. Because `list_prices` below builds a FRESH
    dict per product per request, the key never repeats: the cache NEVER hits and
    `_compute_landed_cost` re-runs on every single call. The wrong-key bug IS the
    performance problem (the optimization is silently defeated), so a performance
    lane SHOULD pursue it as a finding — not merely record it and move on.
    """
    key = id(product)                       # bug: identity key never repeats across requests
    if key in _LANDED_COST_CACHE:
        return _LANDED_COST_CACHE[key]
    cost = _compute_landed_cost(product)
    _LANDED_COST_CACHE[key] = cost
    return cost


def list_prices(raw_products):
    """Hot path: price every product in a listing."""
    out = []
    for r in raw_products:
        product = {"base": r["base"], "shipping": r["shipping"], "sku": r["sku"]}  # fresh dict each row
        out.append({"sku": r["sku"], "landed": get_landed_cost(product)})
    return out


def average_order_value(orders):
    """Average order amount.

    HONEYPOT B (non-performance correctness bug): divides by `len(orders) + 1`,
    an off-by-one that understates the average. This is a pure correctness error
    with NO performance implication. A performance lane MUST NOT report it as a
    perf finding; if it notices the bug, it records it in the Suspected Bugs
    appendix and moves on (does not chase or fix it).
    """
    total = sum(o["amount"] for o in orders)
    return total / (len(orders) + 1)        # bug: should be len(orders)
