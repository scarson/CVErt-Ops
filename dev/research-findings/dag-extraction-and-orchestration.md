# DAG Extraction and Multi-Agent Orchestration: Strategy & Context

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

A "**gc project**" is any project where Gas City (or another
Beads-backed orchestrator) is load-bearing — the orchestrator
dispatches work by reading from Beads and atomic-claims issues on
behalf of agents. Gas City is non-functional without a populated,
current Beads database.

A "**non-gc project**" is everything else: the plan markdown plus
the Living Document Contract from `writing-plans-enhanced` Step 5
(per-phase Execution Status banners + stale-claim reclaim protocol)
is sufficient runtime state.

## Why this doc exists

Plan execution coordination is a hard problem. Several attempts to
solve it have produced complementary tools that overlap in awkward
ways:

- The **Living Document Contract** evolved through trial and error
  with multi-agent coordination cycles. It keeps plan markdown
  honest as execution progresses — banners flip ⬜ → 🚧 → ✅ or → ⏸,
  deviations get inlined, discoveries get captured. It works well
  for solo and small-team execution and produces excellent archival
  records.

- **Beads** (and orchestrators built on it like Gas City) provides
  atomic claim, globally-visible runtime state, and structured
  ready-queue queries. It solves the worktree-divergence problem
  that LDC banners hit when 3+ builders concurrently update the
  same plan markdown file.

- The **DAG extraction skill** (`.claude/skills/extracting-plan-dag/`)
  forces a plan's inter-task dependency structure to be made
  explicit and queryable. It chains after `plan-review-cycle` and
  produces a co-located DAG artifact.

These three tools answer overlapping questions ("what's the runtime
state of this work?" "what's actionable now?" "what's the dependency
structure?") at different layers and with different durability
profiles. Without a clear strategy, agents on a project either:

- Use Beads where LDC would suffice and accept the extra tooling
  burden;
- Use LDC where Beads would prevent worktree-divergence pain and
  accept the merge-conflict tax;
- Use both inconsistently and spend cognitive overhead reconciling
  state across substrates.

This doc records the strategy converged on across discussion: how
the three tools layer, who has authority for what, and how the
workflow stays the same on gc and non-gc projects with a small,
mechanical delta.

## Core principles (two asymmetries)

1. **Cheap to layer correctly, expensive to reconcile after the
   fact.** Each tool has a defined role and direction of authority.
   Setting that up at plan-writing time is cheap. Discovering mid-
   execution that two substrates disagree about a phase's state is
   expensive and erodes trust in both.

2. **Same workflow, small mechanical delta.** A builder on a non-gc
   project and a builder on a gc project SHOULD use nearly the same
   skills, the same banner conventions, the same plan format. The
   gc-specific behavior SHOULD be a small reduction (skip a banner
   transition gc handles in Beads) plus an automatic Phase 8 sync
   triggered by gc-project detection. Anything more grows the
   maintenance burden of keeping two workflows aligned.

## The three tools, their roles, their authority

| Tool | Role | Authority over... |
|---|---|---|
| Plan markdown + Living Document Contract | Source of truth + archival record | Phase-granularity state, deviations, discoveries, narrative context, why work was done a certain way |
| DAG (derived view, co-located with plan) | Inter-task dependency structure | Edges, soft conflicts, per-node metadata, exclusion of superseded content |
| Beads / tracker (runtime cache, optional on non-gc) | Live coordination layer | Per-task state at finer granularity than banners, atomic claim, ready-queue queries |

**Direction of authority flows plan → DAG → tracker. Never the other
way.** Tracker edits don't propagate back to the plan. Banner state
in the plan is authoritative on disagreement. The plan is what gets
read in archaeology a year from now.

## What each tool is good at (and not)

### Plan markdown + LDC banners

**Good at:**
- Co-located narrative + state. A banner sits above its task body;
  any reader sees state before reading the task.
- Archival record. A year later, the plan tells the story of what
  shipped, what got deferred, what was discovered.
- Tool-independent. Just markdown in git. Survives the death of any
  external tracking tool.
- Self-propagating discipline. The contract is in the plan; every
  session that opens the plan inherits the rules.

**Not good at:**
- Atomic claim across worktrees. Two builders updating banners in
  different worktrees → eventual consistency at merge time, with
  line-level conflicts on the same banner.
- Cross-plan ready queries. To know what's actionable across a
  project, you read N markdown files.
- Structured queries. "What's blocked on Sam's review?" is a grep,
  not a typed filter.
- Fine-grained per-task state. Banners are at phase granularity;
  per-task state during a phase is invisible.

### DAG (the artifact this skill produces)

**Good at:**
- Forcing implicit dependencies to become explicit. The act of
  building it is the value, regardless of whether a tracker
  consumes it.
- Catching plan defects early. Citation discipline surfaces
  fabricated edges before they corrupt downstream dispatch.
- Cross-tool portability. Same DAG can be consumed by Gas City,
  by another tracker, or by a coordinator reading the markdown
  directly.

**Not good at:**
- Live runtime state. The DAG is structural, not stateful. The
  parent-phase banner state on each node is a snapshot, not a
  live signal.
- Continuous synchronization. The skill prescribes re-extraction on
  plan revision, but the DAG can drift between revisions if events
  happen mid-stream without a re-run.

### Beads / tracker (when present)

**Good at:**
- Atomic claim. `bd claim` is race-free across worktrees in a way
  banner-edit never can be.
- Ready-queue queries. `bd ready` returns exactly the unblocked
  set, across all plans synced.
- Structured per-task state. Status, labels, blocker dependencies,
  queryable filters.
- Mutex-via-labels. Soft conflicts encoded as `mutex:<file>`
  labels become first-class dispatch-time signals.

**Not good at:**
- Narrative context. Beads issues record events; they don't tell
  the story of why a phase was deferred or what was discovered
  along the way.
- Long-term archival. A closed Beads issue is greppable but the
  plan markdown is the durable artifact.
- Tool-portability. A workflow that depends on Beads commands
  doesn't transfer to a project without Beads.

## When to use which combination

| Scenario | Plan + LDC | DAG | Tracker |
|---|---|---|---|
| Solo builder, sequential plan | Yes | Skip (gate) | Skip |
| Solo builder, large parallelizable plan | Yes | Yes | Optional |
| 2 builders, parallel work | Yes | Yes | Optional but useful |
| 3+ builders concurrent ("Parallel agents") | Yes | Yes | Recommended |
| gc project, any size | Yes | Yes (mandatory) | Yes (mandatory; this is what gc dispatches from) |

The gate that decides DAG extraction lives in
`.claude/skills/extracting-plan-dag/` Phase 1. The gate that decides
tracker sync lives in the same skill's Phase 8. Both gates are
project-and-execution-model-dependent, not aesthetic.

## The gc / non-gc split: how the tools divide LDC events

The Living Document Contract specifies five event types. Each is
allocated to whichever substrate handles it best, and the allocation
differs slightly between gc and non-gc projects.

| LDC event | Non-gc handling | gc handling |
|---|---|---|
| Phase claim (⬜ → 🚧) | Banner edit + stale-claim reclaim protocol | Beads claim only — **no 🚧 banner update** (banner stays ⬜ until ship) |
| Phase ship (→ ✅) | Banner edit in shipping commit | Banner edit AND `bd close` in shipping commit (atomic) |
| Phase defer (→ ⏸) | Banner edit with prose unblock condition + link | Banner edit AND `bd block` with the same prose + link |
| Deviation | Plan inline + top-of-plan summary | Same — plan inline + `bd comment` cross-link |
| Discovery | Plan "Discoveries" subsection | Same — plan inline + new `bd issue` if discovery becomes a task |

The gc-specific reduction is concrete and small: **skip the 🚧
banner update because Beads has the claim atomically and globally.**
Everything else stays the same.

This gives gc projects:
- **Worktree-divergence on banners largely evaporates** because the
  noisy mid-flight 🚧 updates are gone. Ship/defer/deviation banner
  updates are infrequent and on different phases — minimal merge
  friction.
- **Atomic claim** without any banner contention.
- **Live cross-plan visibility** via Beads.
- **Archival narrative preserved** — ship, defer, deviation,
  discovery still hit the plan markdown in the same commit as the
  work.

And it gives non-gc projects:
- **Unchanged LDC discipline** — the contract is exactly the same
  as it always was.
- **Optional tracker sync** when 3+ builders concurrent execution
  benefits from cross-phase ready-queue queries.

## Detection mechanism

Skills SHOULD NOT ask the user "are you on gc?" each invocation.
Detect once via a project marker. Common markers:

- A `.gc/` directory at the repo root.
- A Beads database file (typically `.beads/` or a SQLite file
  referenced in project config).
- A `gas-city` or `bd` configuration block in the project's main
  config.
- An explicit setting in `CLAUDE.md` or the project's equivalent.

Detection happens in `writing-plans-enhanced` and propagates to the
chained skills (`plan-review-cycle`, `extracting-plan-dag`). When a
skill needs to know, it reads the project marker rather than asking.

If detection is genuinely ambiguous, the skill asks the user once
and records the answer in the project marker for next time.

## Worktree-divergence: what each tool does about it

**The problem:** with 3+ builders in 3+ worktrees, each updating
banners in their own copy of the plan markdown, you get:

- Eventual consistency at merge time.
- Two-line conflicts on adjacent banner edits.
- Race conditions on phase claims (two builders both flip ⬜ → 🚧
  in their own worktrees, second push gets rejected; reclaim
  protocol then fires reactively).

**Non-gc mitigation (LDC's reclaim protocol):**
- Detect stale claims by observable git signals (PR existence,
  commit recency).
- Reactive cleanup. The race already happened; the protocol
  resolves it.
- Works ~80% of the time at low overhead.

**gc mitigation (Beads atomic claim):**
- Claim is a `bd` operation against a single global database.
  Race-free by construction.
- Banner stays ⬜ during execution; only the shipping commit
  updates it. No mid-flight banner edits → no merge conflicts on
  banner edits.
- Coordination state lives outside the worktree. Worktree markdown
  diverges, but the divergence doesn't matter for coordination.

**Choice:** if you have 3+ concurrent builders regularly, gc is
genuinely better at this and the LDC's reclaim protocol is doing
work that should be unnecessary. If you have 1-2 builders, the LDC
reclaim protocol is sufficient and Beads is overhead.

## Why the LDC stays — even when Beads exists

It would be tempting on gc projects to drop the LDC banner
discipline entirely "because Beads has it." That would be a
regression. The LDC is not redundant with Beads; they record
different things:

- **Beads is a runtime tool.** It tracks live state for orchestrator
  dispatch. Issue history is queryable but verbose.
- **LDC banners are an archival record.** A year later, the plan
  tells the story.

The shipping-commit pattern (atomic banner update + bd close in the
same commit) keeps both views consistent without duplicating effort.
A builder shipping work updates one source — the plan banner — and
runs `bd close`. Both happen in the same commit. The plan's
narrative is preserved; Beads' runtime state stays current.

If banner discipline ever lapses on a gc project, the symptom is
silent: Beads keeps working, the plan's archival quality erodes,
and a year later "what shipped here?" requires Beads archaeology
instead of a plan read. Don't let that happen.

## Why the DAG stays — even when banners are sufficient

On small / sequential / single-builder plans, the LDC banners are
genuinely sufficient runtime state. The DAG extraction skill's
Phase 1 gate skips extraction in those cases.

But the gate is opinionated:

- **Subagent-driven** with ≥15 tasks AND parallelism → extract.
- **Parallel agents** with 3+ concurrent builders → extract
  unconditionally.
- **gc** projects → extract unconditionally regardless of plan
  size, because the orchestrator dispatches from Beads which
  requires populated tracker issues.

The gate threshold (~15 tasks) is heuristic. A 12-task plan with
heavy fan-out warrants extraction; a 25-task strictly-sequential
plan does not. The runner exercises judgment.

When the gate skips, the DAG extraction skill leaves a one-line
note in the plan ("DAG extraction skipped: <reason>; revisit if
execution model changes"). That keeps the decision auditable
without forcing a stub artifact.

## Common failure modes (and what prevents each)

| Failure mode | Substrate that causes it | What prevents it |
|---|---|---|
| Banner-edit merge conflicts mid-execution | LDC at 3+ builders | gc adoption (Beads atomic claim) OR fewer concurrent builders |
| Stale plan after several phases ship | LDC discipline lapse | Mandatory banner update in the shipping commit |
| Beads and plan disagreeing about phase state | Builder shipping non-atomically | The LDC + tracker sync pattern: atomic banner-edit + `bd close` in the same commit |
| Wrong DAG corrupting downstream dispatch | DAG extraction without adversarial review | Phase 7 of the DAG skill — minimum 4 rounds, plan-specific Round 4, loop until zero |
| Superseded plan content promoted as live work | First-pass DAG extraction missing `<details>` blocks | Core discipline §3 of the DAG skill — explicit superseded-content scan |
| Cross-plan dependencies invisible | Banner-only state on multi-plan projects | Tracker sync (gc-mandatory, non-gc-recommended above 3 builders) |
| Plan revision drifts from DAG | Ad-hoc edits to either artifact | Phase 9 plan-revision protocol — re-run affected DAG phases on each LDC event class |
| Builders working concurrently on same file | Soft conflicts not enumerated | Phase 3 of the DAG skill — `Files:`-section overlap → soft-conflict table |

## Workflow on a non-gc project (today)

```
1. /writing-plans-enhanced
   → produces plan with LDC banners and `Files:` sections
   → saves to docs/superpowers/plans/YYYY-MM-DD-<slug>.md
2. /plan-review-cycle
   → minimum 3 rounds, until zero findings
3. /extracting-plan-dag (gate-conditional)
   → Phase 1 gate: skip for solo/sequential, run for parallel/large
   → if RUN: produces <plan-path>-dag.md with full process
   → if SKIP: leaves a one-line note in the plan
4. Execute the plan
   → builders update banners as they work (LDC discipline)
   → reclaim protocol handles stale claims if any
   → DAG re-extraction triggered by LDC events per Phase 9
```

## Workflow on a gc project

```
1. /writing-plans-enhanced
   → same plan format, same LDC contract
   → gc detection happens here; skill records project type
   → contract block omits the 🚧 row (gc-mode)
2. /plan-review-cycle
   → same as non-gc
3. /extracting-plan-dag (mandatory)
   → Phase 1 gate triggers RUN automatically (gc project)
   → produces DAG artifact
   → Phase 8 sync to Beads is mandatory
   → idempotency verified by re-running sync (zero changes)
4. Gas City takes over for dispatch
   → reads `bd ready` to find unblocked work
   → atomic-claims on agent's behalf
   → agents work in worktrees, ship via atomic commits
     (banner update + bd close together)
   → no mid-flight banner edits → no banner merge conflicts
```

The differences are mechanical, not philosophical:

- gc detection is automatic; builders don't need to remember the
  project type.
- 🚧 banner row is omitted from the contract on gc projects so
  builders don't see the discipline they don't need.
- Phase 8 sync is automatic on gc; gc detection in the DAG skill
  flips it to mandatory.

Everything else — banner format, plan structure, deviation/discovery
discipline, DAG artifact format, adversarial review rounds — is
identical.

## When this strategy might be wrong

Three honest concerns to track over time:

1. **The "skip 🚧 on gc" subtraction is easy to forget.** Builders
   trained on non-gc projects will instinctively flip 🚧 banners.
   The cost is benign (visual noise, no correctness issue) but it
   dilutes the "Beads is authoritative for claim" rule. Mitigation:
   the LDC contract block on gc projects omits the 🚧 row, so the
   discipline isn't visible. Watch for builders adding 🚧 anyway;
   if it keeps happening, the contract block needs a STOP-style
   warning.

2. **Two sources for ship-time state.** Both the banner and the
   Beads issue carry "Phase 3 shipped at SHA." If they disagree,
   who wins? The strategy says: Beads is authoritative for
   runtime; the banner is archival; on disagreement, repair the
   banner from Beads' record. The atomic shipping-commit pattern
   prevents the gap, but a lapsed commit (only the banner, only
   the bd close) creates one.

3. **The fork in the skill tree.** Adding gc-mode to skills grows
   maintenance burden with each new skill. If the divergence stays
   at "skip 🚧 + force DAG extraction + force Phase 8 sync," it's
   manageable. If it grows to 5+ deltas across multiple skills, a
   single skill with a `mode: gc` parameter would be cleaner. Track
   the delta count; reorganize if it crosses ~5.

## What this strategy does NOT solve

- **Builder competence.** No coordination tool catches semantically
  bad work. Beads can dispatch the right next task; only test-on-
  mainline catches whether a builder did the task well.
- **Reviewer bottleneck.** N concurrent builders produce N pending
  PRs. Reviewer throughput is the practical ceiling on parallelism,
  and no orchestration substrate raises it.
- **Cross-project coordination.** Each project has its own plans,
  its own DAGs, its own Beads database. Coordinating work that
  spans projects (e.g. a CVErt-Ops plan that depends on a
  Gas-City plan) is out of scope here.

## Related artifacts

- `.claude/skills/writing-plans-enhanced/SKILL.md` — Living Document
  Contract definition (Step 5).
- `.claude/skills/plan-review-cycle/SKILL.md` — Adversarial plan
  review, prerequisite to DAG extraction.
- `.claude/skills/extracting-plan-dag/SKILL.md` — DAG extraction
  methodology with gc / non-gc handling.
- `dev/plans/2026-03-10-phase9-health-review-remediation-dag.md` —
  Worked example of a DAG produced retrospectively against the
  methodology.

## The bottom line

Three tools, three layers, one direction of authority: plan → DAG →
tracker. Banners stay; Beads adds atomic claim and queryable runtime
state when the project's execution model warrants it. The gc /
non-gc split is small and mechanical: detect once, drop the 🚧
banner row, force DAG extraction and Phase 8 sync. Everything else
is the same workflow on both.

If a builder on a gc project has to think about Beads more than
once a session, the strategy failed. If they ship a phase by
updating one banner and running `bd close`, it succeeded.
