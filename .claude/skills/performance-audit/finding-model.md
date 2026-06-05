# Performance Finding Model

**Load this when:** generating, ranking, validating, or planning fixes for performance findings.
This file defines how a performance finding is scored, what is *not* a finding, and the
disposition discipline that governs the remediation plan.

## Contents
- The four axes (Impact, Confidence, Effort, Verification plan)
- Prioritization rule
- Calibration — what is NOT a finding
- No severity-based deferral (disposition discipline)
- Rationalization table + red flags

---

## The four axes

Every finding carries all four.

### Impact = reachability × frequency × per-occurrence cost

Impact is **expected aggregate cost**, not locality or raw ugliness.

- **Reachability** — is it on a request path / inner loop / render path / startup? Code that never
  runs under realistic load has ~zero impact regardless of how slow it is in isolation.
- **Frequency** — how often it runs (structurally: loop nesting, call-site count, per-item
  callbacks over collections that grow with load).
- **Per-occurrence cost** — big-O class, allocations, I/O, CPU per execution.

A big-O improvement on a provably bounded, small `n` reached once at startup is **low** impact.
A small constant-factor win on the hot path of every request is **high** impact.

Rank: **Critical** (dominant aggregate cost / scaling wall) · **Major** (clear measurable drag) ·
**Minor** (real but small aggregate cost). Severity ranks *order of attention*, never *inclusion*
(see disposition discipline).

### Confidence

`Measured` (a profile/benchmark confirms it) > `Strong-static` (the code structure makes it certain)
> `Heuristic` (plausible but unverified). Framework-idiom-currency findings inherit the currency
brief's freshness; **offline ⇒ Low**.

### Effort = work magnitude ONLY

Describe the size of the change using exactly these buckets:

- **Localized** — one function.
- **Contained** — one module + its callers.
- **Cross-cutting** — a signature/abstraction change rippling across packages.

You MAY add "low-effort" / "high-effort".

**BANNED vocabulary:** any wall-clock or calendar unit — hours, days, weeks, sprints,
story-points-as-time — and any time-flavored adjective ("quick", "a quick afternoon", "trivial
timewise") used as a basis for sizing or deferral. Time estimates anchor on human calendar-time
training data and are unreliable for an agent; a fabricated duration becomes a stale anchor that
misleads readers. State *what changes and how widely*, not *how long it takes*.

### Verification plan

How to prove the fix helps **and** preserves behavior:

- The **benchmark/profile to run**, OR an explicit **complexity/allocation argument** when
  measurement isn't feasible; AND
- A **correctness guard** — a test that pins the behavior the optimization must not change.

---

## Referring to findings (persistent-artifact reference discipline)

This is the project's standard **persistent-artifact reference discipline** applied to audit
findings — the canonical rule lives in the `claude-agents-md-init` skill's template under
"Cross-references in persistent artifacts" (opaque working-session shorthand like `Option C` /
`Decision F1` — and here `Lane 4` / `P3` — MUST NOT leak into anything that persists outside the
conversation). It distinguishes two cases that apply directly here:

- **Lane names/numbers are *opaque session identifiers*** — they have no anchor anywhere outside this
  skill, so a bare "Lane 4" is a missing legend. Replace it with the plain-English meaning: use the
  lane slug at minimum (`concurrency`), and in prose describe the finding itself.
- **Finding IDs (`P1`, fingerprints) are *bare references to a real artifact*** — they do anchor (to
  the consolidated report), so they MAY stay, but only as a traceability suffix beside a
  self-identifying description, never on their own.

The operational test (from that template): reading only the inline text, with no link- or
report-chasing, can the reader recognize what the reference points at and decide whether it matters?

- **MUST NOT** use a bare lane name/number or finding ID as the *sole* referent in any persistent or
  outward-facing artifact: commit messages, PR titles/bodies, code comments, remediation-plan task
  titles, or questions to the user.
- **MUST** describe the finding in self-contained, human-meaningful terms (what, where, why) wherever
  it is referenced outside the report. The ID may be appended as a *traceability suffix*, never used
  as the whole reference.

| Don't | Do |
|-------|-----|
| `fix: address Lane 4 finding` | `perf: run independent widget fetches concurrently in load_dashboard (was serial awaits) [perf finding P5]` |
| `// resolves P3` | `// one batched fetch — the per-item loop here was an N+1 (perf audit P3)` |
| "Should I fix the data-access lane issue?" | "Should I fix the N+1 in enrich_line_items (one DB round-trip per line item)?" |

The report itself may use lane names and IDs as section structure, but every finding leads with a
descriptive title — so even the report reads correctly without prior context. Lane names (the slugs
above) are always preferable to lane numbers; never write "Lane 4" in prose a human will read.

## Prioritization rule

Order findings by **Impact × Confidence**. Use **Effort** to *sequence* within that band — surface
high-impact / high-confidence / low-effort items first ("quick wins"), and high-impact /
high-effort items as deliberate investments. Effort sequences; it never removes a finding.

---

## Calibration — what is NOT a finding

Do not manufacture these. Reporting them pads the audit and erodes trust:

- Cold-path micro-optimizations with no argued or measured aggregate impact.
- Readability-destroying optimizations for an unmeasured gain.
- Style / idiom preferences with no performance consequence (that's `project-health-review`'s lane).
- Theoretical big-O improvements on a provably bounded, small `n`.
- Hypothetical scaling concerns far beyond plausible load (note as a design remark only if reachable).
- Correctness bugs — those belong to `bug-hunt-cycle`. Record them in the report's Suspected Bugs
  appendix; do not chase them unless the incorrect behavior *is* the performance problem.
  - **Co-located bug** (a suspected bug in the *same symbol* as a real perf finding — e.g. an
    off-by-one in the function whose hot loop you're flagging): the boundary still holds — record it
    in the Suspected Bugs appendix, do **not** fix it in the audit. You MAY note that the perf fix's
    eventual task will touch the same code (so the bug should be resolved alongside it), but the audit
    *records*, never *fixes*. Don't let proximity to a perf finding pull a correctness bug across the
    "audit records bugs, never chases them" line.

**Calibration governs generation, not post-hoc suppression.** It tells a lane agent what not to
*manufacture*. Once a finding has been surfaced, it MUST NOT be silently dropped as "too minor" —
that decision belongs to the user (see below). Never cite calibration during validation to discard
a real finding.

---

## No severity-based deferral (disposition discipline)

**Every finding's default disposition is FIX.** The remediation plan MUST schedule **all** findings
by default. Low / minor / moderate impact is **NOT** grounds for deferral — a batch of cheap fixes
is cheap to do, and "defer the minors" leaves them deferred to no one, forever.

A finding may be dropped from the plan only when **one** of these holds:

1. The **human reviewer explicitly opts it out**, or
2. The agent states a **substantive, non-severity, non-effort reason that names a specific concrete
   mechanism**:
   - the exact in-flight refactor it collides with, and where; or
   - the exact dependency major-bump it requires, and why that is out of scope; or
   - the specific correctness regression it risks, and why that risk outweighs the gain.

A *vague* gesture — "might be risky", "could be complex", "better to wait", "low priority" — does
**NOT** qualify and is treated as a banned severity/effort deferral. The agent MAY *recommend* a
deferral that meets bar (2); it MUST NOT *self-authorize* deferral on severity or effort grounds.
Deferred items (with their named mechanism or the reviewer's opt-out) go in the plan's Deferred
appendix — the persistent record, never left in conversation memory.

### Rationalization table

| Excuse | Reality |
|--------|---------|
| "These are low-severity, I'll list them as future improvements" | Future for whom, when? Cheap fixes are cheap. Put them in the plan as tasks. |
| "Deferring minors keeps the plan focused" | The plan addresses all findings by default. Focus is the reviewer's call, not yours. |
| "A batch of small fixes isn't worth a task" | Group them into one task. Grouping ≠ dropping. |
| "Low impact = not worth fixing" | Impact ranks order, not inclusion. Only the reviewer or a substantive named mechanism removes a finding. |
| "Defer — this might be risky / could be complex" | Name the *specific* mechanism (which refactor, which dependency, which regression + why) or it's a disguised severity/effort deferral. |
| "I'll estimate this is a 2-hour fix so defer it" | Wall-clock is banned and effort is not a deferral ground. State work magnitude; schedule it. |

### Red flags — STOP

- "Defer the minors" / "low priority so later" / "nice-to-have, skip for now".
- Any deferral whose only basis is severity or effort.
- Any effort expressed in hours/days/sprints.
- Dropping a surfaced finding during validation by calling it "below the bar".

All of these mean: schedule the finding, or produce a reviewer opt-out / a named substantive mechanism.
