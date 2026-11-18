# Performance Audit — Decision Log

ABOUTME: Persistent record of the judgment calls made during the autonomous whole-repo
ABOUTME: performance-audit-cycle run, each subjected to ≥3 rounds of adversarial self-review.

**Context.** Sam requested (autonomously, offline): add the superpowers plugin from the
official Anthropic marketplace, vendor the attached skills bundle into the repo, then run
`performance-audit-cycle` across the whole repo, keeping field feedback against the included
template. Sam asked that every non-trivial decision be approached from multiple perspectives,
run through **at least three rounds of adversarial review**, and recorded in a persistent
artifact (this file). Container is ephemeral → commit + push after every work item.

Review format per decision: **R1** states the decision and the strongest case *against* it;
**R2** answers R1 or revises; **R3** stress-tests the survivor and finalizes.

---

## D1 — Source of the `superpowers` plugin

**Decision:** Install `superpowers` from `claude-plugins-official` (Anthropic's official,
managed marketplace), which carries `superpowers` as an external entry pointing at
`github.com/obra/superpowers`. Installed v5.1.0, user scope; also enabled in the repo's
`.claude/settings.json` so web/CI sessions get it reproducibly.

- **R1 (attack).** The official marketplace's `plugins/` directory does **not** contain a
  `superpowers` folder — only ~36 first-party plugins (LSPs, code-review, etc.). First read:
  "superpowers is *not* in the official marketplace; the user is mistaken, the real source is
  `obra/superpowers-marketplace`." Installing from a non-official source would contradict the
  instruction "from the official Anthropic marketplace."
- **R2 (answer).** Verified against the *manifest*, not just the directory: the official
  marketplace's `.claude-plugin/marketplace.json` lists `superpowers` as an **external plugin**
  whose source URL is `github.com/obra/superpowers.git`. So the official marketplace genuinely
  *publishes* superpowers (by reference to obra's canonical repo). Current Anthropic docs confirm
  `/plugin install superpowers@claude-plugins-official`. The user's phrasing is therefore exactly
  right; my first reading was wrong because I looked at the vendored `plugins/` dir instead of the
  manifest. `claude plugin marketplace update` refreshed it; install succeeded (v5.1.0).
- **R3 (finalize).** Could a future container get a stale clone lacking the entry? Mitigated:
  enabling it in `.claude/settings.json` plus the documented `marketplace update` step makes the
  source reproducible, and obra/superpowers is the same upstream either path resolves to, so the
  artifact is identical regardless of which marketplace name is used. **Finalized:** official
  marketplace, as asked. No ambiguity remains.

## D2 — Where to put the bundled skills, and how to handle name collisions

**Decision:** Vendor each **non-colliding** skill from the zip's three plugins
(`superpowers-plus`, `project-setup`, `utility`) **flat** into `.claude/skills/<name>/`,
matching the repo's existing convention. For names that **already exist** in `.claude/skills/`
(`writing-plans-enhanced`, `plan-review-cycle`, `bug-hunt-cycle`, `health-review-cycle`,
`project-health-review`) **do NOT overwrite** — keep the repo's versions.

- **R1 (attack).** "Add the skills in the zip" most literally means *all* of them, at their
  current bundle versions — so I should overwrite the colliding ones too; otherwise the repo runs
  stale copies and `performance-audit-cycle` delegates to a `writing-plans-enhanced` /
  `plan-review-cycle` that differs from the versions it was authored against.
- **R2 (answer).** Checked the colliding files: they contain **project-specific content**
  (`grep` hits for CVErt/Sam/PLAN.md/material_hash/tenant), and the harness describes
  `writing-plans-enhanced` as a thin wrapper "wraps superpowers:writing-plans with project-specific
  conventions." These are deliberate CVErt-Ops adaptations, not stale upstream. Overwriting them
  would clobber Sam's customizations and silently change established project workflows
  (`bug-hunt-cycle` etc. are referenced throughout CLAUDE.md) — a far more invasive act than the
  request implies. The delegation concern is *resolved in favor of preservation*: a cycle that uses
  the project's tuned planning/review skills is more correct here, not less. The flat layout means
  `performance-audit-cycle`'s relative sibling refs (`../writing-plans-enhanced/`,
  `../plan-review-cycle/`, `../performance-audit/`) resolve to exactly these intended siblings.
- **R3 (finalize).** Residual risk: the new `performance-audit*` skills might assume a behavior
  only present in the bundle's newer `plan-review-cycle`. Inspected: `performance-audit-cycle`
  delegates by *role* ("invoke plan-review-cycle for the multi-round adversarial review"), not by a
  version-specific contract — the project's `plan-review-cycle` (min-4-rounds, subagent-readiness)
  satisfies that role. **Finalized:** add new skills, preserve customized collisions. All overwrites
  remain reversible via git regardless.

## D3 — Trimming `url-to-markdown` test fixtures

**Decision:** Vendor `url-to-markdown` (SKILL.md, README, references, scripts) but **exclude its
`tests/` directory** (~1 MB of captured HTML fixtures: a 628 KB page, a 198 KB MDN dump, etc.).

- **R1 (attack).** Excluding files is *not* "add the skills in the zip" verbatim; I'm dropping
  content Sam handed me. If the skill's tests matter, I've broken it.
- **R2 (answer).** The functional skill is the SKILL.md + scripts + references; `tests/fixtures`
  are development artifacts for the skill's *own* maintainers, not runtime inputs. Committing ~1 MB
  of third-party HTML into a security product's repo is an unjustified supply-chain/size cost
  (CLAUDE.md explicitly treats this repo's footprint and provenance seriously). The skill runs
  without its fixtures.
- **R3 (finalize).** Reversible and low-stakes; if Sam wants the fixtures they are one `unzip`
  away from the original upload. **Finalized:** trim `tests/`, keep the working skill. Recorded here
  so it isn't a silent omission.

## D4 — Audit partition & depth (summary; full detail in the slice plan)

**Decision:** Treat the repo as **one deployable** (single Go binary serving an embedded Vue SPA),
so the backend↔SPA split is a *process boundary* (handled by one-primary-ecosystem slicing), **not**
a service-monorepo split. Partition into perf-relevance-tiered slices (FULL/REDUCED/COLD-SWEEP) per
`whole-repo-scoping.md`, adversarially review the partition before executing, then run the cycle once
per slice with a committed progress ledger. Full reasoning, the coverage ledger, and the ≥3-round
partition review live in `docs/perf-audits/SLICE-PLAN.md`.

*(R1–R3 for the partition are recorded in SLICE-PLAN.md, where the artifact under review lives.)*
