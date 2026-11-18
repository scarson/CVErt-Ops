# Field-feedback template — `performance-audit` family

**Purpose.** A hand-off-ready template + instructions to give an agent (or yourself) running
`performance-audit` / `performance-audit-cycle` against a real repo, so the experience produces
**high-signal, actionable feedback** the maintainers can fold back into the skill. The first real-world
run produced exactly this kind of doc; this template generalizes what made it useful.

It is **loosely structured on purpose** — skip areas that didn't come up, expand the ones that did. The
goal is honest field notes, not a compliance form.

---

## Instructions to the executing agent (read first)

You are running the `performance-audit` (and/or `-cycle`) skill against a repository. **In addition** to
doing the audit, keep a **running feedback log** as you go and hand it back at the end. The most
valuable feedback comes from writing it *while* you hit friction, not reconstructing it afterward.

What makes feedback high-quality (do these):

1. **Tag every item** with the legend below so wins, friction, defects, and ideas are separable.
2. **Record workarounds you had to invent.** If the skill didn't tell you how to do something and you
   improvised (a dispatch adaptation, a scoping heuristic, a missing mode), that improvisation is the
   single highest-signal datapoint — it marks a real gap. Say what you did and why.
3. **Point at where a fix would go** when you can — the file/phase/section (e.g. "SKILL.md Phase 2",
   "finding-model calibration", "the rust version index"). You don't need to be right; it helps triage.
4. **Distinguish a defect from a preference.** A 🐞 is "the skill told me to do X and X was wrong/
   impossible"; a 🟡 is "X was ambiguous or costly"; a 💡 is "X could be better." Don't inflate.
5. **Report both directions of error.** Note false positives (nits the lanes manufactured) **and** false
   negatives / blind spots (real issues a lane missed, things the packs/indexes didn't ground).
6. **Be honest about what you couldn't verify** (no hardware, no load test, no network for currency,
   harness exposed no reasoning-effort knob). "Couldn't confirm" is a finding, not a gap to paper over.
7. **Capture the environment** — it shapes what's possible (see the context header). A friction that's
   really "my harness can't do X" should be labelled as such, not as a skill defect.

Two methodology asks that make the *audit itself* a better test of the skill:

- **Run the lanes blind** where you can — give them load/scope context, **not** the findings you already
  suspect. Then report whether they *discovered* the hot paths or merely confirmed a prior. (Discovery
  is the real signal; the skill is built for it.)
- **Stress the anti-padding discipline on purpose** at least once: point a run at low-value / cold /
  glue code and report whether it honestly returned "no significant findings" / "confirmed cold" or
  whether it manufactured nits to look productive.

---

## Context header (fill this in once, top of your feedback doc)

```
Repo / project:        <name + one-line what-it-is>
Scale:                 <approx production LOC; languages/ecosystems; mono- or single-package>
Stack highlights:      <frameworks, runtimes, notable libraries>
Skill(s) + version:    <performance-audit / -cycle; plugin_version or "vendored, version per source">
Harness:               <Claude Code web/CLI, Agent-tool dispatch, model + whether an effort knob exists>
Scope run:             <bounded module / whole-repo via scoping method / a specific slice>
Depth:                 <full / reduced / cold-sweep / overlay; lanes run>
Blind run?             <yes/no — were lanes given the answers or not?>
```

> Legend: 👍 worked well · 🟡 friction / ambiguity · 🐞 likely defect · 💡 suggestion.
> Within each area, newest note first is fine. One line of context per item minimum.

---

## Areas to comment on (skip what didn't come up)

**1. Setup, onboarding & dispatch harness.** Was skill discovery / invocation by name clean? If lanes
were dispatched as subagents, could they see the skill (read their own pack slice) — or did you adapt?
Could you set the dispatch model / reasoning effort, or did the harness expose no knob? `plugin_version`
findable?

**2. Scope handling.** Was the bounded-scope guard helpful or in the way? For a whole-repo / oversized
goal, did `whole-repo-scoping.md` route you cleanly (size router → slices → tiers → review gate), or did
you have to invent partition logic? Were the LOC bands / depth tiers right for this ecosystem? Anything
the method didn't cover (a stack shape, a monorepo layout, a slicing call)?

**3. Detection & pack loading (Phase 0).** Did stack/version detection pick the right packs + modules?
Did **materiality** keep irrelevant modules out (or load junk on an incidental import)? Did the right
sub-stack modules exist — and were any missing for this ecosystem?

**4. Lane dispatch (Phase 2).** Which dispatch mode did you use (runner-pastes-slice vs lane-reads-own-
slice) and was it the right call at this lane count? Did every lane actually receive its lane-keyed
slice **+ the cross-cutting Runtime/Variant notes + the loaded modules**? Did the blind run discover, or
just confirm?

**5. The lanes & profile packs (the heart of it).** Did the packs behave as a **reference, not a
checklist** — did any lane *out-reason the pack* and find something it didn't list (good), or did it
walk the pack and pad (bad)? Per lane, note misses (false negatives) and manufactured nits (false
positives). Did `idiom-currency` have a grounded version index / currency brief for this stack, or fall
back to model knowledge? Did the descriptive `cost-map` lane earn its keep (catch a framing error)?

**6. Synthesis & finding model (Phase 3).** Did dedup + cross-lane agreement read as a confidence
signal? Did **calibration** hold — especially the anti-padding stress test, latent/dead code,
dev-only/external-process code, and bounded-`n`? Did a lane **correct the scope brief from source** (and
did the synthesis record it)? Did the **bug-no-chase** boundary hold (suspected bugs recorded, not
fixed) — including any **co-located** bug in a perf finding's function? Run metadata / regression diff /
`runs.jsonl` sane?

**7. Cycle phases (if you ran `-cycle`).** Cross-validation, optional dynamic confirmation, present-to-
user loop, **fix-plan generation + plan-review** (did the review catch anything real?), and — for a
multi-slice run — the **whole-repo roll-up** (did it surface cross-slice themes a per-unit view
couldn't, and any `assume-hot` findings needing operator confirmation?).

**8. Artifacts & ergonomics.** Did output paths exist / get created cleanly (`docs/perf-audits/`,
`runs.jsonl`, `cache/`)? Was the run **resumable** after a context reset (ledger/handoff sufficient)?
Commit cadence workable? Anything that errored on a first run?

**9. Authoring (only if you extended the skill).** If you wrote new skill content (a method, a module, an
index entry), did you follow the reference discipline (descriptive self-contained titles, no opaque
`S#`/code cross-refs)? Note any convention that was easy to violate.

**10. Top changes + verdict.** Your **top 3** concrete changes you'd make to the skill, ranked. One-line
**overall verdict**: did it find real, actionable, well-calibrated performance work on this repo?

---

## Minimal quick version (for a small / lightweight run)

If a full doc is overkill, hand back just this:

```
Context: <repo / scale / stack / harness / scope+depth / blind?>
👍 What worked (2–4 bullets):
🟡 Friction / what I had to improvise (2–4 bullets — workarounds are gold):
🐞 Defects (skill said X, X was wrong/impossible):
💡 Top 3 changes I'd make, ranked:
Verdict (1 line): did it find real, well-calibrated perf work?
```

---

## What "high-quality" looked like (one real example)

The first field run (a ~96k-LOC Rust+TS app) was valuable because it: ran lanes **blind** and reported
that they *reproduced a 5-round review's hot-path map and added findings it missed*; **stress-tested
anti-padding** on the cold tail and reported the lanes honestly returned "no significant findings"
rather than nits; recorded every **workaround it invented** (a lane-reads-its-own-pack dispatch
adaptation; a whole-repo partition method) — each of which became a skill change; and flagged where
grounding was thin (the version index lacked the DSP/React library APIs it needed). Aim for that:
**blind discovery, honest non-findings, named workarounds, and concrete where-it-would-change pointers.**
