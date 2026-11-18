# Expected Findings — Python golden fixture

**Purpose:** a re-runnable validation harness for the `performance-audit` lanes. Dispatch the
relevant lane agents (Lanes 1–4) against this fixture and score:
- **Recall** — how many planted issues were found (target: all 6).
- **Precision** — was the decoy correctly *ignored* and were there few/no fabricated findings?

This is stdlib-only and dependency-free. **Lane 5 (framework-idiom currency) is not exercised** by
this fixture (no framework → no currency brief); that's an honest coverage gap, not a fixture bug.
A JS/TS or Django fixture would exercise Lane 5.

## Planted issues (should be found)

| # | File:line | Lane | Issue | Why it's a real finding |
|---|-----------|------|-------|-------------------------|
| 1 | `inventory.py` `find_duplicate_skus` | 1 — Algorithmic | `in seen` against a **list** inside a loop → O(n²) | request-sized input on a hot path |
| 2 | `inventory.py` `enrich_line_items` | 3 — Data access | **N+1**: `repo.get()` per item; `repo.get_many()` exists | one round-trip per item on checkout path |
| 3 | `report.py` `total_revenue` | 2 — Memory | builds a full throwaway list just to `sum()` it | needless allocation proportional to input |
| 4 | `report.py` `render_csv` | 2/1 — Allocation | string `+=` in a loop → quadratic string growth | reallocation each iteration; `''.join` idiom |
| 5 | `report.py` `extract_codes` | 1 — Recomputed work | `re.compile()` **inside** the loop (loop-invariant) | recompiles per line; hoist to module level |
| 6 | `tasks.py` `load_dashboard` | 4 — Concurrency | sequential `await` of **independent** fetches | latency = sum of calls; `asyncio.gather` runs concurrently. Independence holds → safe to parallelize |

## Decoy (should NOT be flagged)

| File:line | Why it must be ignored |
|-----------|------------------------|
| `config.py` `load_enabled_flags` | O(n²)-ish list membership + sort, BUT n is a constant 4 and it runs once at startup. Zero aggregate impact → calibration says NOT a finding. Flagging it is a **precision failure**. |

## Honeypot correctness bugs (boundary test for bug-no-chase)

These test the rule: *a bug is in-scope to pursue ONLY when the incorrect behavior **is** the
performance problem; otherwise record it to the Suspected Bugs appendix and do not chase it.*

| File | Bug | Perf-related? | Expected handling |
|------|-----|---------------|-------------------|
| `pricing.py` `get_landed_cost` (HONEYPOT A) | memo cache keyed by `id(product)`; `list_prices` builds a fresh dict per row, so the cache **never hits** and the expensive compute re-runs every call | **Yes — the bug IS the slowness** | **Pursue as a performance finding** (memoization defeated → recomputation on the hot path). Identifying the wrong cache key as the root cause is the point. |
| `pricing.py` `average_order_value` (HONEYPOT B) | divides by `len(orders) + 1` (off-by-one), understating the average | **No** | **Do NOT report as a perf finding.** If noticed, **record to the Suspected Bugs appendix and move on** (do not chase/fix). Reporting it as a perf finding, or fixing it, is a **boundary failure**. |

**Scoring the honeypots — note the asymmetry (the audit is NOT a bug hunter):**
- **A is a recall item.** `get_landed_cost`'s never-hitting cache MUST be found — it is a
  *performance* finding because the bug IS the slowness. **Missing it counts against recall.**
- **B is NOT a recall item.** The audit is not required to notice a pure correctness bug; **failing
  to find `average_order_value`'s off-by-one is NOT counted against it.** What DOES count against it:
  reporting B as a *performance* finding, or chasing/fixing it. Correct handling *if noticed* = one
  line in the Suspected Bugs appendix, then move on. Finding-and-routing B correctly is a small
  bonus, never a requirement.

**General scoring principle (applies to every fixture):** recall is measured over performance
findings and *performance-related* bugs only. A missed pure-correctness bug is never a recall miss —
correctness hunting is `bug-hunt-cycle`'s job, not this audit's. A *performance-related* bug (one
whose incorrect behavior is the slowness, like Honeypot A) IS a recall item and missing it counts.
Mishandling a correctness bug (flagging it as perf, or chasing it) is always a failure.

## Scoring

- **Recall** = (# of {1..6} found) / 6.
- **Precision red flag** = decoy flagged as a real finding, or fabricated findings with no basis.
- A well-calibrated run finds 1, 2, 3, 4, 5, 6 and stays silent on the decoy (or explicitly notes
  it considered and rejected the decoy on cold-path/bounded-n grounds).

## How to re-run (sketch)

Dispatch one subagent per lane (1, 2, 3, 4) with: the shared preamble + that lane body from
`../../lane-prompts.md`, the `../../profile-packs/python.md` slice for that lane, and the path to
this fixture directory. Collect findings; compare against the table above.
