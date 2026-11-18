# Run Schema (historical & regression analysis)

**Load this when:** writing the consolidated report in Phase 3, so each run is captured in a
**versioned, machine-readable** form that supports trend lines and run-over-run regression diffs.

`run_schema_version` is the version of THIS schema. Bump it when the structure changes; parsers gate
on it. (Current: **1**.)

## Three artifacts per run

1. **Frontmatter** on the consolidated markdown report (human- and machine-readable).
2. **One appended line** in `docs/perf-audits/runs.jsonl` (the longitudinal ledger).
3. **A fingerprint on every finding** in the report body, so runs can be diffed.

## 1. Consolidated-report frontmatter

```yaml
---
run_schema_version: 1
run_id: <YYYY-MM-DDThh-mm>-<slug>          # unique; matches the report filename stem
date: <ISO 8601 UTC, e.g. 2026-06-03T14:30:00Z>
scope: "<scope string>"
methodology:
  skill: performance-audit
  plugin_version: superpowers-plus@<version from plugin.json>
dispatch:
  # Record what the runner REQUESTED at dispatch — NOT a self-reported model identity
  # (an agent cannot reliably introspect its own model id). If the user overrode, say so.
  model_requested: "<e.g. latest-opus | gpt-5-successor | user-override:<name>>"
  reasoning_effort: "<e.g. x-high | high | default | 'default (harness exposes no knob)'>"
  overridden_by_user: <true|false>
stack:
  - { ecosystem: <npm|pypi|nuget|go|crates|maven>, framework: <name>, version: <x.y.z> }
currency_briefs:
  - { framework: <name>, researched_on: <YYYY-MM-DD|null>, status: <fresh|stale|refreshed|offline> }
lanes_run: [algorithmic, memory, data-access, concurrency, idiom-currency, cost-map]
lanes_skipped: { payload-startup: "<reason>", dynamic: "<reason>" }
finding_counts:
  by_impact: { critical: <n>, major: <n>, minor: <n> }
  by_lane: { algorithmic: <n>, memory: <n>, data-access: <n>, concurrency: <n>, idiom-currency: <n>, payload-startup: <n> }
  suspected_bugs: <n>
regression:
  prev_run_id: <run_id of the most recent prior run for the SAME scope, or null>
  new: <n>          # fingerprints present now, absent in prev
  persisting: <n>   # in both
  resolved: <n>     # in prev, absent now
---
```

## 2. `docs/perf-audits/runs.jsonl` ledger

Append exactly one JSON object per run (newline-delimited). Same fields as the frontmatter,
flattened, plus the finding fingerprints. One line = one run → trivially greppable/plottable:

```json
{"run_schema_version":1,"run_id":"2026-06-03T14-30-checkout","date":"2026-06-03T14:30:00Z","scope":"the request pipeline","plugin_version":"superpowers-plus@0.2.0","model_requested":"latest-opus","reasoning_effort":"x-high","overridden_by_user":false,"stack":[{"ecosystem":"pypi","framework":"django","version":"5.0.2"}],"lanes_run":["algorithmic","memory","data-access","concurrency","idiom-currency","cost-map"],"finding_counts":{"by_impact":{"critical":1,"major":3,"minor":4},"by_lane":{"algorithmic":2,"memory":2,"data-access":1,"concurrency":1,"idiom-currency":2},"suspected_bugs":1},"regression":{"prev_run_id":null,"new":8,"persisting":0,"resolved":0},"fingerprints":["algorithmic:inventory.py:find_duplicate_skus:on2-dedup","data-access:inventory.py:enrich_line_items:n-plus-1"]}
```

The ledger is the regression substrate: `jq` / `grep` over it yields "critical count over time",
"runs where finding X recurred", "first run a finding appeared", etc.

## 3. Finding fingerprints (stable across runs)

Every finding in the report body carries a **fingerprint** so the same issue can be matched run to
run even as the report text changes:

```
fp = "<lane-id>:<repo-relative-file>:<symbol-or-anchor>:<short-title-slug>"

where `<lane-id>` is the lane SLUG (algorithmic, memory, data-access, concurrency,
idiom-currency, cost-map, payload-startup, dynamic) — never a bare number.
```

- Use the **function/method/symbol** name (or a stable structural anchor) — **NOT a line number**;
  line numbers drift between runs and would break matching.
- `short-title-slug` = lowercased, hyphenated 2–4 word gist (e.g. `n-plus-1`, `on2-dedup`,
  `unmemoized-render-sort`).
- Show it inline, e.g. `**Fingerprint:** data-access:inventory.py:enrich_line_items:n-plus-1`.

## Regression diff (how the runner computes it)

In Phase 3, after assigning fingerprints, the runner SHOULD:
1. Find the most recent prior ledger entry with the **same `scope`** (read `runs.jsonl`).
2. Compare fingerprint sets: `new` = now − prev, `resolved` = prev − now, `persisting` = now ∩ prev.
3. Record those counts in the frontmatter + ledger, and call out **new** and **resolved** findings
   in the report's executive summary (these are the regression signal a reader most wants).

If there is no prior run for the scope, `prev_run_id: null` and all findings are `new`.

## Honesty constraints
- `model_requested` records the **dispatch request**, never a guessed model identity.
- `reasoning_effort` records the **requested** effort. If the harness exposes no effort knob (e.g. it
  lets you set the subagent model but not an effort level), record `"default (harness exposes no
  knob)"` — do not claim `x-high` you couldn't actually request.
- `plugin_version` comes from the plugin's `plugin.json`. If the skill was **vendored flat** (copied
  into a project's `.claude/skills/` without the `plugin.json`), the version isn't locally available —
  record the known value with its provenance (e.g. `superpowers-plus@<version> (vendored; version per
  source repo)`) rather than inventing one.
- Never fabricate counts — they MUST equal what the synthesis actually produced.
- If the ledger can't be written (read-only FS), note it in the report; do not silently skip.
