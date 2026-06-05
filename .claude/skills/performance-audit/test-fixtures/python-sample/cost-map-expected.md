# Expected Execution Cost Map — Python fixture (Lane 6)

**Purpose:** exercise **Lane 6 (Execution Cost Map)**, which is *descriptive*, not a findings list.
The check is qualitative — Lane 6 doesn't have recall/precision the way the defect lanes do. Score
it against the criteria below. `app.py` provides the call topology; `config.py` is the cold path.

## How to run

Dispatch a Lane 6 agent with the shared preamble + the **Lane 6 body** from `../../lane-prompts.md`
(note Lane 6's exemption from "report only problems" and the map output format), scope = the whole
`python-sample/` directory. Do NOT let it read `expected-findings.md` or this file.

## What a good map looks like (pass criteria)

**Format & discipline (these are the real test):**
- [ ] Output is a **MAP** (regions with a *basis* and a *confidence*), NOT a findings list with
      Impact/Effort/Verification fields.
- [ ] Each region's basis is **structural** (loop nesting, fan-out, call-site count, request-path
      membership) — NOT an invented absolute call count or fabricated millisecond figure.
- [ ] Regions carry a **confidence** label (High/Medium/Low).
- [ ] It does **not manufacture problems** — it is willing to describe inherent/fine regions and to
      mark the cold path as cold rather than inventing an issue there.

**Expected hot regions (the map should surface most of these):**

| Region | Why it concentrates time | Expected confidence |
|--------|--------------------------|---------------------|
| `pricing._compute_landed_cost` via `list_prices`/`get_landed_cost` | **heavy unit cost** (50k-iteration loop) **× fan-out** (once per product) on the listing path — the dominant region | High |
| `inventory.enrich_line_items` | per-item **I/O round-trips** (N+1) on the checkout path — latency-bound | High/Medium |
| `inventory.find_duplicate_skus` | **O(n²)** over request-sized skus on the listing path | Medium |
| `report.render_csv` | **per-row** string growth on the listing path | Medium |

**Cold region that must be characterized as cold (not a problem):**
| Region | Expected treatment |
|--------|--------------------|
| `config.load_enabled_flags` | runs **once at startup** over a fixed tiny list → negligible / cold. The map may mention it as cold; it must NOT present it as a hot region or a problem. |

## Notes
- Lane 6 may note that `get_landed_cost`'s cache is defeated, but it should frame the *region* as
  hot, not duplicate Lane 1's defect finding — the map's job is "where does time go," not "fix this."
- Bonus (not required): cross-referencing which mapped regions also have defect findings in other lanes.
