"""Order utilities. A behavioural-eval fixture for the 'reference, not a checklist'
property. Mostly-fine code with tempting near-misses for pack idioms, ONE genuine
perf issue, and ONE beyond-the-pack issue. See spec.md (do not read it as the agent)."""

from collections import Counter

# A small, fixed set of valid statuses — module-level constant, not request data.
VALID_STATUSES = ["new", "paid", "shipped", "closed"]


class Money:
    """Few instances ever created (one per currency, at startup)."""
    def __init__(self, amount, currency):
        self.amount = amount
        self.currency = currency


def is_valid_status(status):
    """CHECKLIST BAIT (decoy): `in` membership against a LIST inside a function the
    pack's algorithmic bullet warns about — BUT VALID_STATUSES is a constant of 4
    items and this is not in a loop. O(4) is not a finding. A checklist-walker
    'recommends a set'; calibration says ignore."""
    return status in VALID_STATUSES


def status_breakdown(orders):
    """CHECKLIST BAIT (decoy): builds a list comprehension then passes it on. A
    walker flags 'use a generator to avoid the intermediate list' — but Counter
    consumes it once and the list is small (one pass, bounded). Not a finding."""
    statuses = [o["status"] for o in orders]
    return Counter(statuses)


def dedupe_order_ids(order_ids):
    """GENUINE PLANTED ISSUE (recall item, Lane 1 — algorithmic): membership test
    `in seen` against a LIST inside the loop is O(n) per check → O(n^2) overall over
    request-sized `order_ids`. `seen` should be a set. This one MUST be found."""
    seen = []
    out = []
    for oid in order_ids:
        if oid in seen:
            continue
        seen.append(oid)
        out.append(oid)
    return out


def process_in_arrival_order(tasks):
    """BEYOND-THE-PACK ISSUE (floor-not-ceiling bonus): treats a `list` as a FIFO
    queue via `pop(0)`, which is O(n) per pop (shifts every remaining element) →
    O(n^2) to drain. The fix is `collections.deque` + `popleft()`. NO Python-pack
    bullet names this; the agent must reason from first principles that list.pop(0)
    is O(n). Finding it rewards out-reasoning the lens; missing it is NOT a recall
    miss, but consistently missing it across runs flags checklist-walking."""
    results = []
    while tasks:
        task = tasks.pop(0)          # O(n) shift on every iteration
        results.append(_handle(task))
    return results


def _handle(task):
    return {"id": task.get("id"), "ok": True}
