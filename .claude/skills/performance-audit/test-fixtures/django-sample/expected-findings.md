# Expected Findings — Django (Lane 5) fixture

**Purpose:** exercise **Lane 5 (framework-idiom currency)** — the lane the stdlib Python fixture
can't reach because it has no framework/brief. The planted issues are *correct* code that a newer
framework version supersedes; they are identifiable as problems ONLY by consulting the currency
brief (`currency-brief.md`), not by generic algorithmic/IO reasoning.

`views.py` is illustrative Django (not executed).

## How to run

**With-brief run (primary):** dispatch a Lane 5 agent with the shared preamble + Lane 5 body from
`../../lane-prompts.md`, the `javascript-typescript.md`/`python.md` pack Lane 5 slice (here:
`python.md`), the **contents of `currency-brief.md`** as the `[currency brief]` placeholder, and
`views.py` as the scope (do NOT let it read this rubric).

**Offline run (degrade test):** same, but pass `[currency brief]` = "unavailable — offline". Expect
the lane to report candidate idiom concerns at **LOW confidence**, flagged for manual currency
check, and to **NOT fabricate** version-specific claims.

## Planted issues (with-brief run should find)

| # | File:func | Brief entry it maps to | Expected |
|---|-----------|------------------------|----------|
| 1 | `views.has_recent_orders` | `len(queryset)` → `.exists()` | flag the `len(qs) > 0` existence check; recommend `.exists()` |
| 2 | `views.order_net_amounts` | `.extra()` deprecated → `annotate()` | flag `.extra(select=...)`; recommend `annotate()` |
| 3 | `views.mark_all_shipped` | per-object `.save()` in loop → `bulk_update()` | flag the loop of `.save()`; recommend `bulk_update()` |

## Decoy (should NOT be flagged)

| File:func | Why ignored |
|-----------|-------------|
| `views.active_admin_emails` | plain comprehension over a tiny fixed list; no ORM, nothing in the brief applies. Flagging a "currency" issue here is a precision failure. |

## Scoring

- **With-brief recall** = (# of {1,2,3} found) / 3, each citing the brief entry.
- **Precision** = decoy not flagged; no fabricated version claims.
- **Offline run** = issues (if mentioned) carry LOW confidence + "manual currency check"; no
  confident version-specific assertions invented without the brief.
