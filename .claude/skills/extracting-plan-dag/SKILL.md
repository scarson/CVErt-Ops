---
name: extracting-plan-dag
description: Extract the inter-task dependency structure from a written plan into a queryable, derived artifact. Chains after plan-review-cycle when the execution model warrants it — multi-builder concurrent dispatch, or any project where a Beads-backed orchestrator (e.g. Gas City) is load-bearing. Methodology-focused — task tracker and graph format are adapter points, not assumptions. Detects gc / non-gc projects and adjusts mandatoriness accordingly.
---

# Extracting Plan DAG

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

A "**gc project**" is any project where Gas City (or another
Beads-backed orchestrator) is load-bearing — the orchestrator
dispatches work by reading from Beads and atomic-claims issues on
behalf of agents. A "**non-gc project**" is everything else: the plan
markdown plus the Living Document Contract (per `writing-plans-enhanced`
Step 5) is sufficient runtime state.

## Overview

Force every plan that warrants it to declare its inter-task dependency
structure explicitly, then make that structure queryable by whatever
coordinator dispatches the work. The plan markdown stays as the source
of truth and archival record; the DAG is a derived view co-located
with the plan; the tracker (Beads or otherwise), if used, is a runtime
cache.

Edits flow plan → DAG → tracker. Never the other way.

**Core principles (two asymmetries):**

1. **Cheap to extract, expensive to reconstruct ad hoc.** A plan's
   inter-task dependency structure exists whether or not it's written
   down. If it's not written down, every coordinator (and every future
   reader) reconstructs it from prose, often inconsistently. The cost
   of one rigorous extraction beats N noisy re-extractions, multiplied
   across every dispatch the plan receives.

2. **Wrong DAG is worse than no DAG.** A DAG that ships with fabricated
   edges, missed dependencies, or superseded nodes promoted as live
   gives downstream coordinators false confidence. The asymmetry favors
   adversarial review over speed: a half-DAG quietly corrupts dispatch
   decisions; the fix surfaces only when builders collide. Err toward
   more review.

## When to use

- After `plan-review-cycle` completes with zero findings on a plan
  written by `writing-plans-enhanced`.
- On any **gc project**, regardless of plan size — Gas City needs every
  plan in Beads to dispatch from it.
- On non-gc projects when the execution model is "Parallel agents"
  (3+ concurrent builders on independent tracks) per
  `writing-plans-enhanced` Step 2.
- On non-gc projects when the execution model is "Subagent-driven" AND
  the plan has ≥15 tasks AND ≥1 phase has internal parallelism.
- Whenever an existing plan grows (new phases added, new builders
  introduced) such that its execution model changes after initial
  authoring.

## When NOT to use

- On non-gc projects with execution model "Parallel session" (one
  builder, sequential checkpoints). The Living Document Contract's
  banners are sufficient runtime state and the DAG is overhead.
- On research / exploratory plans where structure is itself uncertain.
  Premature DAG-ification freezes structure that should remain fluid.
- Before `plan-review-cycle` has produced a zero-finding round. A DAG
  built from an unreviewed plan inherits the plan's defects with
  amplification.
- When the plan lacks `Files:` sections per task. This skill MUST
  refuse to produce a DAG in that case (see Core discipline §2).

## Prerequisites

The runner MUST verify ALL of the following before any other step:

1. The plan was written by `writing-plans-enhanced` and carries the
   Living Document Contract block, per-phase Execution Status banners,
   and `Files:` sections per task.
2. `plan-review-cycle` has been run to completion (a round produced
   zero findings) against the **current** plan content. If the plan
   has been revised after the prior `plan-review-cycle` run, the
   runner MUST require a fresh `plan-review-cycle` pass before
   proceeding.
3. The plan's execution strategy (selected in `writing-plans-enhanced`
   Step 2) is recorded in or near the plan, so the gate (Phase 1) can
   read it.
4. The runner has determined whether the project is gc or non-gc by
   checking project markers. Common markers include: a `.gc/`
   directory at the repo root, a Beads database file (typically
   `.beads/` or a SQLite file referenced in project config), a
   `gas-city` or `bd` configuration block in the project's main
   config, or an explicit setting in `CLAUDE.md` or the project's
   equivalent. The runner MUST cite which marker(s) it found. If no
   marker is found and the project type is genuinely ambiguous, the
   runner MUST ask the user before proceeding.

If any prerequisite is missing or ambiguous, the runner MUST STOP and
request remediation. Extracting against an unreviewed plan or a plan
without `Files:` sections produces a half-DAG and false confidence.

## Core discipline

A DAG extraction MUST do five things. Skipping any one degrades the
extraction into a sketch that should not be committed.

1. **Cite every edge.** Every hard edge in the DAG MUST be traceable
   to a specific line, paragraph, or quoted phrase in the plan.
   Uncited edges are fabricated; the runner MUST delete them.

2. **Treat every `Files:` overlap.** For every pair of tasks that
   share a file path in their `Files:` sections, the runner MUST
   classify the relationship as either a hard edge (with citation) or
   a soft conflict (recorded separately). A pair that ends up in
   neither category is a missed dependency. If any task lacks a
   `Files:` section, the runner MUST refuse to produce a DAG.

3. **Detect superseded content.** Before edges are extracted, the
   runner MUST scan the plan for `<details>` blocks, "REVISED",
   "SUPERSEDED", "Do not execute", strikethroughs, deferred-phase
   banners (⏸) that reroute to other plans, and similar markers.
   Tasks inside superseded sections are NOT DAG nodes. Missing this
   step corrupts the entire downstream graph.

4. **Bridge phase-level banners to task-level nodes.** The Living
   Document Contract specifies banners at the **phase** level
   (⬜ / 🚧 / ✅ / ⏸), but DAG nodes are at the **task** level — one
   phase contains multiple task nodes. The runner MUST capture, for
   each task node, the parent phase's current banner. The tracker
   (Phase 8), if used, holds the finer-grained per-task state. The
   phase banner is derived from the aggregate of its task states (any
   task in 🚧 → banner is 🚧; all tasks in ✅ → banner flips to ✅; an
   external blocker on the phase as a whole → banner is ⏸). The plan
   banner wins on disagreement — the plan is the archival source of
   truth.

5. **Run minimum 4 rounds of adversarial review.** Three canonical
   perspectives — Citation auditor, Coverage auditor, Inference-
   discipline auditor — each targeting a specific failure mode this
   skill exists to prevent (fabricated edges, missed dependencies,
   inferred-not-cited ordering). Plus at least one plan-specific
   perspective the runner chooses based on the plan's character.
   Additional rounds MAY be run; they SHOULD be run when any earlier
   round produced material findings or when the plan's content
   suggests further perspectives would catch additional issues. See
   Phase 7 for round structure and loop rules.

## Process

### Phase 1: Gate decision

The runner MUST evaluate whether this skill should run before any
other step.

| Project type | Execution strategy | Action |
|---|---|---|
| gc | any | RUN (mandatory; tracker sync is required for the orchestrator to dispatch) |
| non-gc | Parallel agents (3+ concurrent builders on independent tracks) | RUN |
| non-gc | Subagent-driven | RUN if the plan has roughly 15+ tasks AND at least one phase has internal parallelism. Otherwise SKIP. The 15-task threshold is a heuristic, not a hard cutoff — a 12-task plan with heavy fan-out warrants extraction, while a 25-task plan that's strictly sequential does not. |
| non-gc | Parallel session (one builder, sequential checkpoints) | SKIP — banners alone suffice |

If the runner SKIPs, it MUST add a one-line note inside the plan
("DAG extraction skipped: <reason>; revisit if execution model
changes") so future readers see the gate was considered.

If the runner RUNs, it proceeds to Phase 2.

### Phase 2: Extract hard edges

A hard edge is "task B MUST NOT start until task A's commit lands."
Sources, in descending order of authority:

1. **Explicit dependency blocks** in the plan (e.g. "Stage Overview:
   Dependencies"). Authoritative — the runner copies these verbatim.
2. **Task body sentences** containing "depends on", "must complete
   after", "after X is committed", "before Y starts."
3. **Type/symbol creation chains.** If Task A creates a type,
   interface, schema element, migration, or shared helper that Task B
   references, A blocks B.
4. **Phase prologues/epilogues** that gate batches of tasks.

The runner MUST NOT promote to a hard edge:

- "It's cleaner to do X before Y" — preference, not blocker.
- "X may shift after Y" — heads-up, not blocker.
- "X is similar to Y" — relationship, not edge.
- Numeric task ordering within a phase — assume parallel unless the
  plan explicitly says otherwise.

For each edge, the runner MUST record:
- source task ID
- target task ID
- a citation: line number, section reference, or quoted phrase from
  the plan justifying the edge

If a citation cannot be produced, the edge is not real and MUST be
discarded.

### Phase 3: Extract soft conflicts

A soft conflict is "tasks A and B touch the same file but neither
depends on the other." Soft conflicts are NOT edges in the DAG. They
are separate metadata used at dispatch time to prevent parallel
builders from serializing into merge conflicts.

For each task, the runner MUST list every file path under its
`Files:` section (Create / Modify / Test). For each file, the runner
MUST collect the set of tasks that touch it. Any pair within that set
without a hard edge between them is a soft conflict.

The runner MUST record soft conflicts as a separate table, NOT as
edges in the graph. Coordinators treat them as mutual-exclusion locks
at dispatch time, not as ordering constraints.

If any task lacks a `Files:` section, the runner MUST STOP and refuse
to produce a DAG. The fix belongs upstream in `writing-plans-enhanced`,
not here.

### Phase 4: Extract per-node metadata

For each task, the runner MUST collect:

- **`priority`** — security / correctness / quality / cleanup
- **`blast_radius`** — single-file / package / codebase-wide
- **`kind`** — code / research / design-decision / review-gate
- **`effort`** — if the plan provides it; otherwise omit
- **`external_blockers`** — references to other plans, manual approvals,
  upstream events outside this plan's scope
- **`parent_phase`** — the phase this task belongs to (so the DAG can
  associate the task with the phase whose banner governs it)
- **`parent_phase_banner`** — current Execution Status banner of the
  parent phase (⬜ / 🚧 / ✅ / ⏸), read from the plan markdown

Per-node metadata is NOT used for edge construction. It is used by the
coordinator to decide WHICH ready node to dispatch next, not WHEN it
becomes ready.

### Phase 5: Detect plan-structural hazards

The runner MUST re-read the plan with these specific eyes:

- **Superseded sections** (Core discipline §3). Tasks inside `<details>`
  blocks marked "SUPERSEDED" or similar are excluded from the graph
  entirely.
- **Mass-rename / freeze events.** Tasks described as "large blast
  radius", "every file that imports X", "must execute after all other
  tasks in this batch." Flag as freeze points; coordinators serialize
  against them.
- **External plan handoffs.** Phrases like "implementation plan is in
  another document" or "see proposal doc" mean that phase is a single
  external-reference node, not its inline task list. The runner MUST
  NOT inline external task lists.
- **Non-task tasks.** Research timeboxes, design gates, manual review
  approvals. Tag with `kind:research` or `kind:gate` so coordinators
  do not dispatch them as code work.
- **Banner state.** Per Phase 4, capture each phase's current Execution
  Status banner.

### Phase 6: Render the DAG artifact

The runner MUST write the DAG to `<plan-path>-dag.md` (e.g.
`docs/superpowers/plans/2026-04-08-mcp-tools-plan-dag.md`). Co-location
keeps plan and DAG paired in directory listings, code review diffs,
and any tooling that walks the plans directory.

The artifact MUST contain:

1. A scope statement: "models inter-task ordering only; intra-task
   ordering (TDD steps, sub-step sequencing) is not modeled."
2. Every edge cited back to the plan (line number or quoted phrase).
3. The soft-conflicts table.
4. The per-node metadata table including each node's parent phase and
   parent-phase banner state.
5. A topological-layers view showing which tasks fan out together at
   each layer.
6. Freeze events and external handoffs listed explicitly.
7. An "excluded from graph" section for superseded, invalidated, and
   resolved-by-prerequisite tasks, each with a cited reason.
8. A pointer to the plan's Living Document Contract noting that the
   DAG records the parent-phase banner per node, that fine-grained
   per-task state lives in the tracker (if Phase 8 was performed), and
   that the plan banner wins on disagreement.

Format choice:

- **Mermaid** is the default human-facing format because it renders
  inline on GitHub and is readable in plain text. Most projects
  SHOULD use Mermaid unless they have a specific reason not to.
- **Graphviz/DOT** is acceptable for projects that already render DOT
  elsewhere and want a single rendering toolchain.
- **Plain structured text** (YAML/JSON only, no diagram) is acceptable
  when the artifact is consumed primarily by tooling and the human
  view comes from the tracker.

Whatever the human-facing format, the artifact MUST also contain a
machine-readable form (YAML or JSON sidecar, or a fenced code block
beneath the diagram) that the tracker adapter (Phase 8) reads. The
two MUST be derived from the same source data — divergence between
the diagram and the structured form is a defect.

### Phase 7: Adversarial review (minimum 4 rounds, until zero findings)

The first-pass DAG is wrong. The runner MUST re-read the artifact
adversarially.

Run these rounds sequentially, documenting findings at each:

**Round 1 — Citation auditor.** Audit every edge in the graph. Can
each one cite a specific plan line, section, or quoted phrase that
justifies it? If a citation cannot be produced, the edge is fabricated
and MUST be deleted. Walk the entire graph; do not skip "obvious"
edges.

**Round 2 — Coverage auditor.** Re-read every `Files:` section in the
plan. For each file that appears in more than one task, verify the
relationship is captured either as a hard edge (with citation) or a
soft conflict. Pairs that appear in neither are missed dependencies
and MUST be added. Also re-scan for superseded sections, external
handoffs, and freeze events; any that were missed in Phase 5 MUST be
captured now.

**Round 3 — Inference-discipline auditor.** Walk the graph hunting for
edges the runner inferred from numeric ordering, narrative flow, or
"obvious sequence" rather than from a plan citation. Numbered tasks
are siblings unless the plan says otherwise. A → B → C MUST appear
only if the plan explicitly orders them. Strike any edge whose
justification reduces to "they're listed in this order."

**Round 4 — Plan-specific perspective (runner-chosen).** Rounds 1-3
cover known-in-general failure modes. This plan has its own character
— security-heavy, schema-heavy, frontend-heavy, methodology-novel,
cross-plan-coupled, something else — and that character has its own
failure modes the canonical rounds will not catch. The runner MUST
choose a perspective specifically relevant to what this plan actually
contains and review from it.

Requirements for the Round 4 perspective choice:

- MUST be a perspective not already covered by Rounds 1-3.
- MUST be specifically relevant to THIS plan, not a generic auditor
  template. If the plan is auth-heavy, "security gate auditor" is
  legitimate; if the plan is pure refactoring, it isn't.
- MUST be named and described explicitly in the DAG artifact under a
  heading like `### Round 4 — [chosen perspective] — [N findings
  applied]`, so future readers can see the reasoning.
- SHOULD be concrete enough to produce findings. "General quality
  pass" is too vague; "cross-plan handoff fidelity to the external
  Stage 3 plan" is actionable.

**Loop rule (applies to all rounds).** If any round produces material
findings, the runner MUST re-run every round in sequence after applying
fixes. Fixes can surface issues earlier rounds missed or introduce new
issues those rounds would have caught. Exit only when a full pass
through every round (1-3 canonical + Round 4 + any additional rounds
the runner elected to run) produces zero material findings.

**Additional rounds (5+) — encouraged when warranted.** 4 is the floor,
not a ceiling. Run further rounds if the plan has unusual structural
risk, cross-plan dependencies, or a freeze event with broad scope.
Each additional round MUST be named and described like Round 4 and
MUST NOT duplicate a prior round's lens.

### Phase 8: Sync to a queryable substrate

Mandatoriness depends on project type and execution model.

| Project type & execution model | Phase 8 status |
|---|---|
| gc (any execution model) | MANDATORY — Gas City reads from Beads to dispatch work; the orchestrator is non-functional without sync |
| non-gc, "Parallel agents" (3+ concurrent builders) | RECOMMENDED — cross-phase ready-queue queries pay back the sync cost |
| non-gc, "Subagent-driven" (≥15 tasks AND parallelism) | OPTIONAL — banner system suffices for most cases; sync only if cross-plan visibility or finer-grained queries are wanted |
| non-gc, "Parallel session" or below the gate threshold | N/A — Phase 1 should have skipped this skill entirely |

The DAG → tracker step is tool-specific. This skill defines the adapter
contract; it does not specify the tracker.

When sync is performed, the adapter MUST:

- Create one issue per node, keyed `<plan-slug>-<task-id>` (deterministic
  so re-runs are idempotent).
- Encode hard edges as blocker dependencies in the tracker's native
  format.
- Encode soft conflicts as `mutex:<file-path>` labels on each side of
  every conflict pair.
- Encode per-node metadata as labels (`priority:<level>`,
  `blast_radius:<level>`, `kind:<class>`, etc.).
- **Encode parent-phase banner state on each node**: ⬜ → open;
  🚧 → in-progress (with claim timestamp + branch if available);
  ✅ → closed-shipped with the shipping SHA; ⏸ → blocked, with the
  prose unblock condition AND the link from the plan's banner. The
  tracker holds per-task state at finer granularity; the parent phase
  banner is recorded per node so the tracker can render either view.
- Create already-closed anchor issues for prerequisite work outside
  this plan's scope (shipped phases of upstream plans, completed
  prerequisites) so cross-plan dependency queries still resolve
  correctly.
- Mark superseded and invalidated nodes as closed-on-creation with a
  reason field.

The adapter MUST NOT:

- Propagate tracker edits back to the DAG or plan. Authority flows
  plan → DAG → tracker, never the other way.
- Invent dependencies the DAG didn't declare.
- Skip the closed-anchor pattern for prerequisites — silent gaps in
  the dependency graph become silent gaps in `ready`-queue queries.

Sync MUST be idempotent: re-running the skill regenerates tracker
state deterministically from the plan + DAG. The runner SHOULD verify
idempotency by re-running the sync immediately after the first run
and confirming the tracker reports zero changes (no new issues, no
modified labels, no edge churn). If a second run produces changes,
the adapter is non-deterministic and the divergence MUST be diagnosed
before relying on the tracker for dispatch.

### Phase 9: Plan-revision protocol

The Living Document Contract from `writing-plans-enhanced` Step 5
specifies events that update the plan. Each event has a defined DAG
action.

| Plan event | DAG action |
|---|---|
| Phase claim — non-gc (⬜ → 🚧 banner update) | No structural DAG change. If a tracker is in use, the tracker MUST update the affected nodes' parent-phase banner state. |
| Phase claim — gc (Beads claim on a task issue, no banner change) | No structural DAG change and no banner update; gc owns claim state in Beads. The phase banner stays ⬜ until the phase ships. |
| Phase ship — non-gc (🚧 → ✅) | No structural change. Shipping commit MUST update both the banner and the tracker (if used) atomically. |
| Phase ship — gc (⬜ → ✅; banner skipped 🚧 entirely) | No structural change. Shipping commit MUST update both the banner and the Beads issue atomically. |
| Phase defer (→ ⏸) | If the unblock condition references a NEW external dependency, the runner MUST re-run Phase 2 to record the `external_blocker`. The banner's prose + link is the durable coordination signal; the DAG mirrors it. |
| Stale-claim reclaim (per writing-plans-enhanced Step 5) | The runner MUST update the tracker node's claim timestamp and branch; prior claim history is preserved per the reclaim protocol. |
| Deviation (scope edit, dropped task, reordered phase) | The runner MUST re-run Phases 2-7 on the affected sub-graph and update the artifact. If the deviation changes plan structure substantially, the runner MUST require a fresh `plan-review-cycle` pass before re-extracting. |
| Discovery (new task added) | The runner MUST add the new node, re-extract its edges, and re-run Phase 7 on its neighbors. |
| Banner-state internal inconsistency detected (e.g., a phase shows ✅ while a hard-prerequisite phase still shows ⬜) | The runner MUST flag this as a defect in the plan, NOT silently reconcile it. Surface to the user; the plan is the source of truth and must be repaired before re-extraction proceeds. |

The runner MUST NOT silently delete tracker issues for removed nodes.
They MUST be closed with reason "superseded by plan revision <date>"
so future dispatches see the transition trail.

Plan revisions are a common failure mode for this workflow — banner
state drifts, scope edits are not propagated to the DAG, and
downstream readers consume a stale graph. Treating revisions as
normal events with a defined protocol — not exceptions — is what
keeps the DAG honest over time.

**Detecting that a plan was revised since the last DAG extraction.**
The runner SHOULD compare the plan file's git history against the DAG
artifact's last-modified commit. If the plan has commits newer than
the DAG, treat the DAG as potentially stale and re-run the affected
phases. The runner MAY add a one-line comment to the DAG artifact
(e.g. `<!-- DAG re-extracted at <SHA> against plan <SHA> -->`) so
future readers can audit alignment without git archaeology.

### Phase 10: Log to the pattern store

Following `plan-review-cycle`'s post-completion convention, the runner
SHOULD log to the project's pattern store (private journal, MCP store,
dated `docs/learnings/` file, or whatever the project uses):

- **Type:** pattern
- **Key:** `dag-extraction-[plan-slug]`
- **Insight:** Plan-shape patterns observed (sequential vs parallel;
  freeze events; superseded sections; cross-plan handoffs; banner
  conventions that rendered ambiguously). Recurring extraction-time
  discoveries SHOULD feed back into `writing-plans-enhanced` if a
  pattern keeps appearing.

## Red flags (STOP)

These mean the extraction is not yet complete or correct:

- "The plan ordering is obvious" — Then cite the line that says so. If
  you can't, it's not an edge, it's an inference.
- "These tasks are clearly sequential because they're numbered" —
  Numbered tasks are siblings unless the plan orders them. Strike the
  inferred edges.
- "The `Files:` section was missing for one task; I worked around it"
  — Refuse and surface the gap upstream. A workaround silently fails
  to detect soft conflicts for the missing task.
- "The superseded section is short; I'll just include those tasks
  anyway" — Promoting superseded content corrupts the entire
  downstream graph. Exclude.
- "I'll skip Phase 8 sync; the user can run it later" — On gc projects,
  no Beads sync means Gas City can't dispatch this plan. Skip is not
  an option.
- "One review round is enough; the DAG is small" — Small DAGs are
  cheaper to review, not exempt from review. Run the four rounds.
- "The plan revised mid-extraction; I'll just patch the affected
  edges" — Re-run the affected phases (Phase 9). Patches accumulate
  drift.
- "The banner says ⏸ but I'll model it as ⬜ so it shows up in ready
  queues" — Authority is plan → DAG → tracker; if the plan banner is
  wrong, fix the plan first, then re-extract.
- "I can't find a session-specific perspective for Round 4" — Try
  harder. If you genuinely can't, document the attempt explicitly per
  Phase 7's Round 4 requirements; don't silently skip.

## Common rationalizations (rebuttals)

| Rationalization | Reality |
|---|---|
| "The plan is small; the DAG is overhead" | Phase 1's gate handles this. Either the gate says skip (legitimate) or the gate says run (do it). Don't override the gate with vibes. |
| "The plan author already declared the dependencies in prose" | Prose declarations are not queryable. Extracting them into a structured form is the entire point of this skill. |
| "Citing every edge slows me down" | Uncited edges are the failure mode this skill exists to prevent. The cost of one careful pass beats the cost of a wrong DAG corrupting downstream dispatch. |
| "Soft conflicts are obvious from the `Files:` sections; I don't need to enumerate them" | Coordinators don't read `Files:` sections at dispatch time. They query the soft-conflicts table. Implicit conflicts become merge conflicts. |
| "I'll write the artifact and skip the adversarial review; my first pass is good" | Single-pass extraction misses fabricated edges, missed soft conflicts, and superseded content promoted as live. The handoff skill's review discipline applies here for the same reasons. |
| "The plan revision is small; I'll just edit the artifact directly" | Edits without re-extracting Phases 2-7 introduce drift the next reader can't trust. Re-run the affected phases. |
| "Beads is overkill for this project" | On gc projects, the orchestrator can't dispatch without it — that's not aesthetic, it's a hard requirement. On non-gc projects, the Phase 8 table determines status (recommended for "Parallel agents", optional otherwise) — and "optional" genuinely means optional. Don't dismiss the requirement on gc; don't force the recommendation on non-gc. |
| "The banner discipline is enough; we don't need a DAG" | True for "Parallel session" execution and small plans. False for "Parallel agents" and gc. Phase 1's gate captures this. |

## Checklist

Before declaring the extraction complete, verify:

- [ ] All four prerequisites verified: plan written by
      `writing-plans-enhanced`, `plan-review-cycle` complete with zero
      findings, execution strategy known, gc / non-gc determined.
- [ ] Phase 1 gate decision recorded (RUN or SKIP with reason).
- [ ] Every hard edge has a plan citation (line number or quoted
      phrase).
- [ ] Every `Files:`-section overlap is captured as either a hard
      edge or a soft conflict; no orphan pairs.
- [ ] Every task has per-node metadata recorded, including current
      banner state.
- [ ] All superseded sections are excluded from the graph and listed
      in the artifact's "excluded" section with reasons.
- [ ] Freeze events and external plan handoffs are flagged explicitly.
- [ ] The DAG artifact is at `<plan-path>-dag.md` and contains all
      eight required sections (scope statement, edges, soft conflicts,
      metadata, layers, freezes/handoffs, exclusions, LDC pointer).
- [ ] At least 4 adversarial review rounds complete (3 canonical +
      Round 4 plan-specific; additional rounds run as judgment
      suggested); the final full pass through every round produced
      zero material findings.
- [ ] Round 4 (and any 5+ the runner elected to run) is documented by
      name in the artifact with its findings count; perspective choice
      is plan-specific, not a generic template.
- [ ] On gc projects: Phase 8 sync to Beads is performed; idempotency
      is verified by running the sync a second time and confirming
      zero changes. On non-gc: sync is performed if recommended by the
      Phase 8 table, or skipped with a note in the artifact.
- [ ] Pattern-store log entry written (per Phase 10).
- [ ] Artifact committed in the same commit (or commit chain) that
      lands the plan, so plan and DAG stay paired in git history.

## Social proof

Observed across multi-agent coordination cycles in plans of
sufficient size and parallelism: DAG extraction reduces dispatch
prompts from "figure out which tasks are unblocked given the current
plan state" reads to short pointer sequences. With Beads as an
example tracker, that looks like: `bd ready` returns N unblocked
issues; mutex labels show two of them both touch
`internal/notify/worker.go`, so the coordinator dispatches one and
queues the other. The principle is tracker-agnostic — the same
shape of query against any structured tracker yields the same
short-prompt dispatch.

DAGs that ship without adversarial review create the opposite: a
fabricated edge sends a builder onto work that isn't actually ready;
a missed soft conflict produces parallel branches that collide at
merge; a superseded section promoted as live pushes builders onto
work the plan author marked "do not execute." Every one of those
failure modes was observed in real plan executions before this
skill's discipline was codified.

The cost asymmetry favors rigorous extraction by a wide margin and
compounds across every dispatch the plan receives. A plan with three
agents over three days takes ~9 builder-cycles from the DAG; a wrong
DAG poisons all of them.

## Related conventions

- **`writing-plans-enhanced`** is the upstream that produces the plan
  this skill consumes. The Living Document Contract (its Step 5)
  defines the banner format that this skill mirrors. If
  `writing-plans-enhanced`'s contract changes, this skill's Phase 4
  and Phase 9 SHOULD be updated to match.

- **`plan-review-cycle`** is the immediate prerequisite. This skill
  refuses to run before `plan-review-cycle` produces a zero-finding
  round. The two are designed to chain.

- **gc / non-gc determination.** A project is gc if Gas City (or
  another Beads-backed orchestrator) is load-bearing. The detection
  mechanism (`.gc/`, Beads database, project setting) is project-local;
  this skill assumes the convention is recorded somewhere the runner
  can check.

- **Banner format and stale-claim reclaim.** Banner conventions and
  the reclaim protocol come from `writing-plans-enhanced` Step 5. This
  skill does not redefine them; it consumes them as input.

- **Strategy & rationale.** The decision framework for gc vs non-gc
  handling, why banners and Beads divide LDC events the way they do,
  and the wider context for this skill's design SHOULD be documented
  in a project-local strategy doc (e.g.
  `dev/research-findings/dag-extraction-and-orchestration.md` or
  whatever the project uses for methodology research).

## The bottom line

A plan's inter-task dependency structure exists whether or not it's
written down. If it's not written down, every coordinator reconstructs
it from prose and gets it slightly wrong each time. Extract once,
adversarially review, sync to whatever queryable substrate the
orchestration needs, mirror banner state on revision. The cost is one
session; the saving compounds across every dispatch the plan receives.

If a downstream coordinator dispatches work that turns out to be
blocked, the DAG failed. If `bd ready` (or the equivalent) returns
exactly the set of tasks a careful human would, it succeeded.
