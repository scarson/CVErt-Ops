"""In-memory fake repository (stdlib only, no real DB).

Simulates a data store with a per-call cost so that an N+1 access pattern is a
*real* performance problem in the fixture, not a contrived one. Both a
single-id getter and a batched getter exist, so a per-item loop calling get()
is genuinely avoidable.
"""

import time

# Pretend this is a table keyed by id.
_ROWS = {i: {"id": i, "name": f"item-{i}", "price": (i * 7) % 101} for i in range(1, 1001)}


def get(item_id):
    """Fetch one row by id. Simulates per-query round-trip latency."""
    time.sleep(0.001)  # one round-trip
    return _ROWS.get(item_id)


def get_many(item_ids):
    """Fetch many rows in a single batched round-trip. Prefer this in loops."""
    time.sleep(0.001)  # ONE round-trip regardless of batch size
    return {i: _ROWS[i] for i in item_ids if i in _ROWS}
