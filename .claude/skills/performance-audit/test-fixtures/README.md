# Performance-audit evals & test fixtures

How the `performance-audit` skill is validated. These are **LLM behavioral evals**, not deterministic
unit tests: each "run" dispatches a subagent and is scored by hand against a rubric. They are
**re-runnable on demand** — a directional signal you (or a future maintainer) invoke when the packs or
prompts change — **not a CI gate**. Dispatch and scoring are deliberately manual; this doc is the
how-to.

> **Why not automate / why not a fixture-per-module matrix?** See the decisions log Part Z (overload
> assessment) and Part DD. A 40-fixture matrix would rot, cost tokens on every change, and — worst —
> create a gradient that tunes the packs into checklists that pass fixtures. The goal is **every
> ecosystem represented once, every cross-cutting behaviour tested once**, with the eval *rigged to
> reward findings the pack didn't list* so it can't quietly erode the "a lens should sharpen a clever
> agent, not constrain a strong one" principle.

## Two kinds of eval

1. **Behavioural / discipline tests** (`behavioral/`) — ecosystem-*independent*. They test the
   machinery (`finding-model.md`, `lane-prompts.md`, the dispatch in `SKILL.md`), so they do **not**
   multiply per ecosystem. Each is a RED/GREEN scenario: the agent's behaviour with the relevant skill
   text (GREEN) vs. without it (RED). This is where the highest-value, lowest-maintenance coverage
   lives.
2. **Pack recall/precision fixtures** (`<ecosystem>-sample/`) — ecosystem-*specific*. A small, realistic
   sample app that naturally triggers the core lanes + the Runtime/Variant notes + 1–3 modules, seeded
   with documented perf issues. One fixture **per ecosystem**, not per module.

## The rubric (every fixture has an `expected-findings.md`)

Score a run on three axes — and note that the third is what protects the design philosophy:

- **Recall** — of the **planted issues** (each maps to a real, reachable perf problem). Target: all of
  them. *Recall is measured over performance findings and performance-*related* bugs only — a missed
  pure-correctness bug is never a recall miss (that's `bug-hunt-cycle`'s job).*
- **Precision** — the **decoys** (cold-path / bounded-tiny-n / not-actually-a-problem near-misses) must
  **not** be flagged. A decoy reported as a finding is a precision failure. Decoys should be baited to
  tempt a *checklist-walker* — a near-miss for a pack idiom that doesn't actually apply here.
- **Beyond-the-pack (floor-not-ceiling)** — a planted real issue whose fix is **not spelled out as a
  named idiom in the loaded pack slice**, so the agent must reason from first principles rather than
  pattern-match a bullet. Finding it is a **bonus that rewards out-reasoning the lens**; *missing it is
  not counted against recall.* But a run that finds every bulleted issue and **consistently** misses the
  beyond-the-pack one across dispatches is a signal the pack is being walked as a checklist — the most
  important thing this suite watches for.

Optional: **honeypot correctness bugs** test the `bug-no-chase` boundary (a bug is in-scope only when
the incorrect behaviour *is* the slowness; otherwise record to the Suspected Bugs appendix and move on).
See `python-sample/expected-findings.md` for the canonical example of all of these.

## How to run a fixture (manual)

For each lane you want to exercise, dispatch one subagent with **only**:
1. the **shared preamble** + that **lane body** from `../lane-prompts.md` (fill the placeholders);
2. the **profile-pack slice** for that lane — the lane-keyed section of the matched pack(s), **plus the
   pack's cross-cutting Runtime/Variant-notes section** (and a companion pack's *Reading the plan & schema*
   / *Rendering path & CWV*) as shared context, **plus** any module relevant to the lane (per `SKILL.md`
   Phase 0 — load only *material* modules);
3. the **currency brief** (or the fixture's `currency-brief.md`, or "unavailable — offline");
4. the **fixture path** as the scope.

**Do not let the subagent read `expected-findings.md`.** Collect its findings, then score recall /
precision / beyond-the-pack against the rubric. Record outcomes (a dated table in the decisions log is
the convention — see Parts D and DD).

> **Structural checks** (no subagent needed): confirm the assembled lane prompt actually **includes the
> Runtime/Variant-notes section** (the dispatch wording in `SKILL.md` Phase 2 + `lane-prompts.md` line 27
> requires it — this is easy to drop because that section isn't lane-keyed); confirm `SKILL.md` body
> < 500 lines and the description < 1024 chars; confirm one-level-deep references resolve.

## Coverage map

| Fixture | Ecosystem / shape | Lanes exercised | Last run |
|---|---|---|---|
| `python-sample/` | Python stdlib | 1–4 + honeypots + beyond-the-pack | GREEN (Part D) |
| `django-sample/` | Python + Django | 5 (idiom-currency) | with-brief + offline-degrade |
| `react-sample/` | JS/TS + React | 1,2,7 (cost-map) | component-render footguns |
| `behavioral/reference-not-checklist/` | ecosystem-independent | machinery | **GREEN** 2026-06-04 |
| `behavioral/materiality.md` | ecosystem-independent | Phase 0 | **GREEN** 2026-06-04 |
| `go-sample/` | Go + net-http-servers + database-sql | algo/mem/data/conc + Runtime notes | **GREEN** 2026-06-04 |
| `rust-sample/` | Rust + web + async-tokio + database | mem/data/conc + Runtime notes | **GREEN** 2026-06-04 |
| `sql-sample/` | SQL companion + Postgres + **Routines** | algo/mem/data | **GREEN** 2026-06-04 |
| `html-sample/` | HTML companion + images-media + fonts | payload/CWV | **GREEN** 2026-06-04 |
| `dotnet-sample/` | .NET + aspnet-core + sql-server-data | data/mem/conc + Variant notes | **GREEN** 2026-06-04 |

## Honest limitations

- Non-deterministic and token-costly; treat as directional signal, not pass/fail truth. Run a
  *representative subset* per change, not the whole suite every time.
- Tests are typically dispatched on **Sonnet** (a stricter "typical executor" bar than the Opus the
  skill recommends) — real dispatch should do at least as well.
- Live currency-brief research isn't network-tested here; the offline-degrade path is exercised
  (`django-sample` offline run), the live-fetch path is reasoned-about only.
