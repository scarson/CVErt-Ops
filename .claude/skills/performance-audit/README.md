# performance-audit — maintainer & contributor guide

**If you are a future agent (or human) here to *extend or maintain* this skill, read this first.**
`SKILL.md` tells an agent how to *run* an audit; this README tells you how the skill is *built*, why
it is shaped the way it is, and how to change it without eroding what makes it work. When the two
disagree, `SKILL.md` wins for runtime behavior and `generic-pack.md` wins for pack-authoring mechanics
— this file orients and states the principles.

The full rationale for every non-obvious decision lives in the **decisions log**:
[`docs/plans/2026-06-03-performance-audit-decisions-log.md`](../../../../docs/plans/2026-06-03-performance-audit-decisions-log.md)
(Parts A–Z). When you make a substantive change, append to it — that log is how a future you
reconstructs *why*, not just *what*.

---

## What this skill is, in one breath

A critical, **multi-dimensional** performance review. It detects the stack + versions, loads the right
durable *lenses* (profile packs) and version facts, dispatches **independent lane agents in parallel**
(one per performance dimension), and synthesizes a ranked, calibrated report — no praise, no grades,
just problems with impact. It is a *snapshot*; the sibling `performance-audit-cycle` adds the
verify→decide→remediate loop.

The eight lanes (slugs): `algorithmic`, `memory`, `data-access`, `concurrency`, `idiom-currency`,
`cost-map` (a map, not findings), `payload-startup` (conditional), `dynamic` (optional, measured).

---

## Guiding principles

These are load-bearing. Most of the skill's quality comes from holding them; most ways to degrade it
are quiet violations of them. (`generic-pack.md` holds the **canonical, expanded** form of the
pack-authoring principles — edit there and let this list follow; the version here is the orientation
digest, deliberately shorter.)

- **A lens should sharpen a clever agent, not constrain a strong one.** Every pack is a *reference*,
  not a checklist — a **prior, not a worklist; a floor, not a ceiling.** It names what is known to be
  worth knowing; it is never the boundary of what is worth finding. The consumer-side framing in
  `lane-prompts.md` says exactly this to every lane agent ("if you are a stronger model than the lens
  was written for, out-reason it"). Keep the producer side honest too: never write a bullet that boxes
  in a better judgment.
- **Write for a reader who may be smarter than the author.** As models strengthen they need *less*
  hand-holding on durable fundamentals — so the durable pack is the **most skippable** layer for a
  strong model and must degrade gracefully. Encode the *condition* and the *trade-off*; let the agent
  decide. Do not encode "do exactly X" prescriptions.
- **Calibration governs *generation*, not post-hoc suppression.** Lanes are told what is NOT a finding
  (cold-path micro-nits, style, theoretical big-O on bounded n) so they don't pad — but a surfaced
  finding is never dropped as "too minor"; that is the user's call. See `finding-model.md`.
- **Adversarial, not sycophantic.** Lanes find problems; they MUST NOT open with "performance is
  generally fine", grade, or soften. (Exception: the `cost-map` lane is descriptive.)
- **Three-tier knowledge, strictly separated.** *Durable* idioms → the **profile pack**.
  *Version-pinned* fast-paths/defaults → the **version index** (`version-indexes/<eco>.md`).
  *Post-cutoff recency* → the **currency brief** (per-run, see `currency-protocol.md`). Never bake a
  version-specific claim into a pack; tag any concrete API/default with "(verify against the currency
  brief for your version)". This separation is the real future-proofing: the durable layer stays lean
  (what a capable model already knows) while the index/brief carry the **unknowable** facts no model
  can self-supply. Weight shifts pack→index/brief as models improve.
- **One point per bullet; length justified by reasoning, not enumeration.** A bullet that lists five
  sub-conditions has become a checklist; a bullet that explains one condition and when it does/doesn't
  matter is a reference. ~5–9 bullets per lane section. **A mediocre bullet is worse than an omitted
  one.**
- **Materiality decides the load, not mere presence.** A module loads when its tech is *central* to
  the scope — a stray `import json` / `encoding/json` does not pull in the serialization module.
- **Detection is scoped to the audit scope, not the whole repo.** In a monorepo, walk up from the
  scoped files to the nearest governing manifest(s).
- **Pursue durable accuracy.** A wrong-but-confident bullet is worse than none. New packs/modules are
  written by research agents and then **reviewed for accuracy by the integrator before they ship**.

---

## Architecture & files

```
SKILL.md            ← runtime spec: phases 0–3 (detect → currency → parallel dispatch → synthesize)
lane-prompts.md     ← the verbatim per-lane dispatch prompts + the shared preamble (the "reference,
                      not a checklist" framing lives in the shared preamble — highest-leverage text)
finding-model.md    ← Impact×Confidence scoring, Effort-as-magnitude, calibration, disposition
currency-protocol.md← how the version-aware currency brief is researched and cached per run
run-schema.md       ← versioned run metadata + ledger + finding fingerprints (regression analysis)
profile-packs/      ← the lenses (this is where most maintenance happens)
  generic-pack.md   ← always-loaded language-agnostic baseline + the canonical "How to add a pack" guide
  <ecosystem>.md    ← core pack: lane-keyed sections; LARGER/deep-dived ecosystems also add a runtime-
                      notes section + a module map (see "pack structure" below); smaller ones
                      (rust/jvm/swift) are a single lane-keyed file with neither — that's fine
  <ecosystem>/<module>.md ← load-on-detection deep lenses (web, ORM, RPC, data, caching, …)
  sql.md (+ sql/)   ← a CROSS-CUTTING companion pack (loads alongside a language pack) for hand-SQL
version-indexes/    ← build-once "API/feature → version → perf benefit" lookups (+ README.md)
test-fixtures/      ← fixtures for validating lane behavior
```

### The pack structure you must preserve

- **A profile pack is lane-keyed.** Its top-level sections use the same lane slugs as
  `generic-pack.md`, because the dispatcher pastes *each lane's slice* into *that lane's* agent. Keep
  the headings aligned or slices won't route.
- **Core + load-on-detection modules (large ecosystems).** A large pack's core file holds the
  always-loaded lanes + a **runtime-notes section** (the durable engine/runtime realities that cut
  across every lane — the GIL, V8 hidden classes, Go's GC/GOMAXPROCS). The exact heading varies by
  ecosystem and is *the same role under different names*: `## Runtime notes` in Go/Python/JS-TS,
  **`## Variant notes`** in `.NET` (its Modern-vs-Framework split, the original name), and
  **`## Reading the plan & schema`** in SQL. Tech-specific depth lives in
  `profile-packs/<eco>/<module>.md`, selected by a **`## Framework / sub-stack modules (load on
  detection)`** map (a `signals → module file` table). A run pastes the core + only the modules whose
  signals are *material* to the scope. **Smaller ecosystems** (`rust`, `jvm`, `swift`) are a single
  lane-keyed file with no runtime-notes section and no modules — split only when a pack accretes enough
  tech-specific bulk to warrant it.
- **Two ways to that structure, same end state** (decisions log Parts T, W, X):
  **"relocate"** when the core already carries inline framework bloat (move it out + deepen — .NET,
  JS/TS); **"deepen"** when the core is already clean (keep it as quick-hits, add deeper modules —
  Python, Go).
- **SQL is special: a content-detected *companion* pack.** It is not selected by a manifest; load
  `sql.md` *alongside* the language pack whenever hand-written SQL is material, plus a dialect module
  (`sql/postgres.md` / `sql/tsql.md`). Its core has a "Reading the plan & schema" section (its Runtime-
  notes analog) and a **"Routines"** section — because the most expensive hand-rolled SQL hides in
  stored-procedure / function / trigger bodies invoked by name, easy to miss when reading app code.

---

## How to make common changes

**Add an ecosystem pack** → follow the canonical numbered steps in `generic-pack.md`
("How to add a profile pack"): lane-keyed core with the same headings, durable-only bullets, the
density/one-point rule, a runtime-notes section *if the ecosystem has cross-cutting runtime realities
worth stating* (a small pack can skip it, like rust/jvm/swift), register detection in `SKILL.md`
Phase 0, build a `version-indexes/<eco>.md` for the version-pinned facts. Add a `## Sources` appendix.
Only split into modules once the pack accretes enough tech-specific bulk to warrant it.

**Add a sub-stack module** → create `profile-packs/<eco>/<module>.md` as a standalone
`# <Ecosystem> performance module: <Tech>` doc with a load-when banner pointing at the core map; add a
row to the core pack's module map; keep it durable, tight, verify-tagged, and **do not restate the
core lanes** — a module *deepens*.

**Add version-pinned facts** → put them in `version-indexes/<eco>.md` (not the pack). Bump
`covered_through` only when you've actually reviewed that far; partial coverage misrepresents the
index. See `version-indexes/README.md`.

**The proven workflow** (used to build the Go/Python/JS-TS/SQL passes): dispatch **parallel research
agents** (each writes one module to its own file — no write conflicts), give each the format reference
+ the density contract + the durable-only rule, then **review every module for accuracy yourself**
before wiring it into the map. Then run a **multi-perspective adversarial review** (≥3 rounds, distinct
lenses: checklist-vs-reference, accuracy, false-positive calibration, coverage, structure) and record
APPLIED/REJECTED findings in the decisions log. Commit and push frequently — the container is
ephemeral; losing work is the only expensive outcome.

**Validate a change** → `test-fixtures/` holds the evals (see [`test-fixtures/README.md`](test-fixtures/README.md)).
Two kinds: **behavioural/discipline tests** (`test-fixtures/behavioral/` — ecosystem-independent RED/GREEN
scenarios that test the machinery: reference-not-checklist, materiality, calibration, bug-no-chase,
wall-clock-ban) and **per-ecosystem recall/precision fixtures** (`<eco>-sample/` — a small app with
planted issues + an `expected-findings.md` rubric). They are **manual, re-runnable, on-demand evals**
(dispatch a lane subagent against a fixture, score recall/precision), **not a CI gate**. The rubric
deliberately includes a **"beyond-the-pack" issue** the agent must reason to (not pattern-match a
bullet) — finding it rewards out-reasoning the lens; *consistently* missing it across runs is the
warning sign that a pack has drifted toward a checklist. Add a fixture per *ecosystem*, not per module
(a matrix rots and tunes packs into checklists — see decisions log Part Z/DD).

---

## Conventions

- **Verify-tag** every concrete API/default/version claim in a pack: `(verify against the currency
  brief for your version)`.
- **Banners**: a module's line 2 is `> Load when <signals> is detected — see the module map in
  `../<eco>.md`. …this file is the <Tech> lens only.`
- **Naming**: refer to lanes by slug/name, never bare number ("the `data-access` lane", not "Lane 3").
- **Reference discipline extends to NEW content** (an easy trap when drafting a multi-phase method or
  doc): the same rule `finding-model.md` enforces for findings — *never a bare opaque label as the sole
  referent* — applies to **authored skill content too**. Give phases/steps/sections **descriptive,
  self-contained titles** and cross-reference them by those titles or by anchor links, never by opaque
  codes (`S0/S0.5/S4`, "the §2 tie-breaker"). A reader landing mid-doc must understand the reference
  without decoding a private numbering scheme. (Caught in real use: a drafted scoping method used
  `S#` phase codes as cross-refs — exactly what the finding-reference rule forbids.)
- **Decisions log discipline**: every substantive call gets an entry (perspective(s) considered,
  options, the choice, and APPLIED/NOTED/REJECTED dispositions). This is the single most useful thing
  for a future maintainer — it is how intent survives context loss.
- **Commits**: small, frequent, descriptive; develop on the assigned branch; open a PR only when asked.

---

## Where to look when extending

- The **design doc**: [`docs/plans/2026-06-03-performance-audit-design.md`](../../../../docs/plans/2026-06-03-performance-audit-design.md)
- The **decisions log** (Parts A–Z): the running rationale — read the parts touching the area you're
  changing before you change it.
- `generic-pack.md`: the authoritative pack-authoring guide and the "references, not checklists"
  invariant.
- `lane-prompts.md` shared preamble: the highest-leverage text in the skill — it is what keeps a
  strong consuming model from treating any pack as a checklist or a ceiling. Touch it with care.
- [`feedback-template.md`](feedback-template.md): a hand-off-ready template + instructions to give an
  agent running the skill against a real repo, so field use produces high-signal feedback (blind
  discovery, honest non-findings, named workarounds, where-it-would-change pointers). The improvements
  in decisions-log Part FF all came from one such field run — keep feeding this loop.
