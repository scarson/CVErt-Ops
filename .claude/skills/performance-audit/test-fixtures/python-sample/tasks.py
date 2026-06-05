"""Async fan-out work, called per dashboard load.

Contains a planted concurrency issue (see expected-findings.md).
"""

import asyncio


async def fetch_widget(widget_id):
    """Fetch one widget's data from a (simulated) remote service."""
    await asyncio.sleep(0.05)   # independent remote call
    return {"id": widget_id, "value": widget_id * 2}


async def load_dashboard(widget_ids):
    """Load every widget for the dashboard.

    PLANTED ISSUE #6 (Lane 4 — concurrency): the awaits run strictly
    sequentially — total latency is the SUM of all calls. The fetches are
    independent (no shared state, no ordering dependency), so asyncio.gather
    would run them concurrently. Correctness guard: result set is unchanged.
    """
    results = []
    for widget_id in widget_ids:
        results.append(await fetch_widget(widget_id))   # serial await of independent work
    return results
