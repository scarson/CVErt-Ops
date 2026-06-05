---
name: project-init
description: Use when bootstrapping a new project with the foundational docs and conventions — CLAUDE.md + AGENTS.md, git strategy, pitfalls docs. Triggers on "init the project", "set up project conventions", "bootstrap project docs", "initialize new project", or "run the init skills". Sequences the composable init skills (`claude-agents-md-init` → `git-strategy-init` → `pitfalls-docs-init`); each sub-skill is idempotent and independently useful, so this wrapper is safe to run on partially-initialized projects (already-present steps are skipped; missing steps are filled in). Cross-platform — instructions support both skill-invocation primitives and read-and-follow patterns depending on agent framework.
metadata:
  version: "1.3"
---

# project-init

One-command bootstrap for a new project's foundational docs and conventions. Sequences the composable init skills, letting each own its UX. Adds an aggregated report at the end so the user sees the project-init-as-a-whole picture rather than just the per-sub-skill summaries.

**This file is for agents invoking the skill.** Humans should read [README.md](README.md) for the overview.

## When to use

Invoke when the user asks to:

- "init the project", "set up project conventions", "bootstrap project docs"
- "initialize a new project", "run the init skills"
- "apply the foundational setup"

Do NOT use for:

- Updating specific existing foundational docs — each sub-skill handles "already-present" idempotently, but if you're specifically editing content, invoke the relevant sub-skill directly.
- Projects where the user explicitly wants only one sub-skill applied — invoke that sub-skill directly instead of going through this wrapper.

## Inputs

- The sibling sub-skills live at `plugins/project-setup/skills/git-strategy-init/` and `plugins/project-setup/skills/pitfalls-docs-init/` (relative to this skill's parent directory). The wrapper assumes both are present and recent.
- The current working directory must be the root of the project being bootstrapped.

## Workflow

### Step 1 — Announce and confirm scope

Tell the user what you're about to do and let them opt out of specific sub-skills:

```
Using project-init to bootstrap foundational project docs.

Will run in sequence:
  1. claude-agents-md-init     — installs CLAUDE.md and AGENTS.md at the project
                          root from a single 4.7-tuned template (RFC 2119
                          terminology, universal ruleset, placeholders
                          for project-specific sections; per-target
                          substitutions for the intro line and sibling
                          references). Runs first so later skills have
                          well-formed CLAUDE.md / AGENTS.md to append
                          their references into. Use `--target claude`
                          or `--target agents` to narrow scope.
  2. git-strategy-init  — installs docs/git-strategy.md (policy for git
                          worktrees, branch lifecycle, merge authority,
                          multi-agent coordination, etc.), updates
                          .gitignore, wires references into CLAUDE.md /
                          AGENTS.md
  3. pitfalls-docs-init — installs docs/pitfalls/implementation-pitfalls.md
                          and docs/pitfalls/testing-pitfalls.md from
                          templates (maintenance framework + universal
                          cross-cutting entries pre-populated)

Each sub-skill runs independently and has its own confirmation step —
you'll see detected state and be asked to confirm before any files are
written. Any can be skipped (e.g. "just run git-strategy-init" or "skip
claude-agents-md-init, I already have a CLAUDE.md").

Proceed with full sequence? Or should I skip one?
```

Wait for user response. Respect any skip requests (don't run sub-skills the user opts out of).

### Step 2 — Run `claude-agents-md-init`

Invoke the `claude-agents-md-init` sub-skill. Let it own its entire workflow: pre-flight (detect existing `CLAUDE.md` / `AGENTS.md`), collect substitution values (project name, user name, primary branch, brief description), present & confirm, write from the bundled template with substitutions applied, post-install pointers, report.

**How to invoke depends on your agent framework:**
- **Claude Code:** use the Skill tool with `skill: "claude-agents-md-init"` (adjust if the plugin namespace is required).
- **Codex / Cursor / generic shell-based:** read `plugins/project-setup/skills/claude-agents-md-init/SKILL.md` and follow its instructions end-to-end.

**If the user aborts mid-sub-skill:** do not continue to Step 3. Surface the abort, produce a partial aggregated report (Step 5 noting the abort), and stop.

This step runs first because `git-strategy-init` (Step 3) and `pitfalls-docs-init` (Step 4) both append references into `CLAUDE.md` and/or `AGENTS.md`. Running `claude-agents-md-init` first means those appends have well-formed target document(s) to land in rather than creating them as a side effect.

### Step 3 — Run `git-strategy-init`

Invoke the `git-strategy-init` sub-skill. Let it own its entire workflow: pre-flight, auto-detect, confirm with user, fill template, update `.gitignore` + CLAUDE.md + AGENTS.md, and produce its report.

**How to invoke depends on your agent framework:**
- **Claude Code:** use the Skill tool with `skill: "git-strategy-init"` (adjust if the plugin namespace is required).
- **Codex / Cursor / generic shell-based:** read `plugins/project-setup/skills/git-strategy-init/SKILL.md` and follow its instructions end-to-end as if the user had invoked that skill directly.

**If the user aborts mid-sub-skill:** do not continue to Step 4. Surface the abort, produce a partial aggregated report (Step 5 noting the abort), and stop. The sub-skill's own cleanup/rollback behavior (or lack thereof) is what it is — the wrapper does not add a rollback layer.

Because the CLAUDE.md template from Step 2 already contains a "Keeping a clean git graph" short-form section referencing `docs/git-strategy.md`, `git-strategy-init`'s CLAUDE.md-reference-append should detect the existing reference and skip duplicate insertion.

### Step 4 — Run `pitfalls-docs-init`

Invoke the `pitfalls-docs-init` sub-skill, same pattern as Step 3. Let it own its entire workflow: pre-flight, auto-detect, confirm, write templates, update CLAUDE.md + AGENTS.md, and produce its report.

Because `git-strategy-init` ran in Step 3, the §Orchestration cross-reference in `pitfalls-docs-init`'s implementation-pitfalls template now resolves — it forward-references `docs/git-strategy.md` which is already in place. Because `claude-agents-md-init` ran in Step 2, the CLAUDE.md already contains references to `docs/pitfalls/implementation-pitfalls.md` and `docs/pitfalls/testing-pitfalls.md`; `pitfalls-docs-init`'s append-references logic should detect those and skip.

### Step 5 — Aggregated report

After all three sub-skills complete, produce a consolidated summary covering the whole bootstrap:

```
project-init complete.

From claude-agents-md-init:
  Created:            CLAUDE.md  (Claude Code)
                      AGENTS.md  (Codex / Cursor / Cline / other AGENTS.md-aware agents)
  Template:           one bundled template, per-target substitutions applied
  Substituted:        project name, user name, primary branch (universal)
                      intro line, sibling reference (per-target)
  Sibling sync:       each file carries a reminder at the top pointing
                      to its sibling — keep them aligned on future edits
  TODO placeholders:  Project Overview, Build/Dev Commands, Tech Stack,
                      Architecture, Conventions, Language Gotchas,
                      Development Workflow, Project Layout, Skill routing

From git-strategy-init:
  Wrote:              docs/git-strategy.md
  .gitignore:         added '.claude/worktrees/'
  CLAUDE.md:          reference already present (from claude-agents-md-init) — skipped
  AGENTS.md:          reference already present (from claude-agents-md-init) — skipped

From pitfalls-docs-init:
  Created:            docs/pitfalls/implementation-pitfalls.md
                      docs/pitfalls/testing-pitfalls.md
  CLAUDE.md:          references already present (from claude-agents-md-init) — skipped
  AGENTS.md:          references already present (from claude-agents-md-init) — skipped

Cross-references wired:
  ✓ CLAUDE.md AND AGENTS.md reference docs/git-strategy.md in §Keeping a clean git graph
  ✓ CLAUDE.md AND AGENTS.md reference docs/pitfalls/*.md in §Project Overview + §Language Gotchas
  ✓ docs/pitfalls/implementation-pitfalls.md §Orchestration
    → docs/git-strategy.md §Multi-agent coordination → Output persistence

Next steps:
  - Commit these files. Suggested message:
      docs: bootstrap project conventions via project-init
  - Fill in CLAUDE.md TODO placeholders (Project Overview, Tech Stack,
    Architecture, Build/Dev Commands, Conventions, Language Gotchas,
    Development Workflow, Project Layout, Skill routing) as the project's
    shape becomes clear
  - Fill in TODO placeholders in implementation-pitfalls.md as
    domain-specific pitfalls surface during implementation
  - Fill in TODO placeholders in testing-pitfalls.md as project-
    specific testing topics emerge
  - If your forge is not GitHub, verify the `gh` commands in
    git-strategy.md were correctly substituted for your forge's CLI
  - If any sub-skill reported a dangling cross-reference (e.g. "pitfalls
    doc not found — run pitfalls-docs-init"), that shouldn't happen here
    since all three ran successfully. If it did, investigate.
```

Adjust the report to match the specific outcomes — skip any "from X" block for sub-skills the user opted out of, and note any abort / partial state accurately.

## Design principles

- **Wrapper owns no business logic.** All detection, user prompts, file-writing, and section-heading analysis live in the sub-skills. The wrapper sequences and aggregates — nothing else.
- **Sub-skills remain independently runnable.** The wrapper adds zero coupling to the sub-skills; users can still run `git-strategy-init` or `pitfalls-docs-init` directly without going through this wrapper.
- **Order matters.** `claude-agents-md-init` runs first because the later two skills both append references into CLAUDE.md and/or AGENTS.md — having well-formed target doc(s) already in place means those appends land cleanly instead of scaffolding the files as a side effect. `git-strategy-init` runs second because `pitfalls-docs-init`'s §Orchestration section forward-references `git-strategy.md`; having it in place before pitfalls runs means that cross-reference resolves immediately.
- **Any ordering technically works.** All three sub-skills handle "companion artifact missing" gracefully (they emit dangling-reference hints in their reports rather than crashing). The wrapper just picks the cleanest order.
- **Idempotent by composition.** Because each sub-skill self-detects existing state, this wrapper is safe to re-run on partially-initialized projects — already-done steps get skipped, missing steps get filled in.

## Extensibility

Adding a new init skill to the wrapper is two steps:

1. **Author the new skill** as a standalone, idempotent sub-skill at `plugins/project-setup/skills/<new-skill>/` (following the conventions set by `git-strategy-init` and `pitfalls-docs-init`: SKILL.md with pre-flight / auto-detect / confirm / apply / report, optional README.md, optional `references/` for bundled templates).
2. **Add a new Step** (3, 4, 5, ...) to this SKILL.md invoking it in the desired order. Update the Step 1 announcement, Step 4 aggregated report, and the Quick reference table accordingly.

Don't bake the new skill's logic into this wrapper — keep it in its own sub-skill so it stays independently runnable for users who want just that one.

## Common mistakes

- **Consolidating sub-skill confirmations into one dialog.** Don't do this. Each sub-skill's confirmation surfaces specific detected state (existing files, branch names, paths, conflicts) that the user needs to approve *for that specific sub-skill's action*. Consolidating loses clarity and forces the user to scroll through a wall of decisions. Let each sub-skill own its confirmation.
- **Adding new logic to the wrapper instead of a new sub-skill.** The wrapper has no business beyond "sequence and report." If you find yourself adding detection / fill / prompt logic here, that belongs in a new sub-skill.
- **Skipping the Step 4 aggregated report.** The sub-skills' individual reports cover within-sub-skill outcomes. The wrapper's aggregated report gives the user the project-init-as-a-whole picture — what got installed across all sub-skills, what got wired between them, what to do next. Without it, the user has to piece together two separate reports.
- **Running the wrapper without reading the sub-skills' SKILL.md files.** If your framework doesn't have a native skill-invocation primitive, you MUST read and follow each sub-skill's SKILL.md in full — don't skip the pre-flight checks or auto-detect steps. Those steps prevent data loss (detecting existing files before overwriting).
- **Continuing past a sub-skill abort.** If `git-strategy-init` aborts in Step 2 (user rejected, conflict, precondition failed), DO NOT continue to Step 3. Surface the abort, produce a partial report noting what got done and what didn't, and stop.

## Quick reference

| Step | Action |
|---|---|
| 1 | Announce scope; confirm user wants full sequence (or identify skips) |
| 2 | Run `claude-agents-md-init` — sub-skill owns its full workflow (pre-flight → report) |
| 3 | Run `git-strategy-init` — sub-skill owns its full workflow |
| 4 | Run `pitfalls-docs-init` — sub-skill owns its full workflow |
| 5 | Aggregated report: what installed, what wired, next steps |

## Relationship to other skills

- **`claude-agents-md-init`** (sibling sub-skill): installs `CLAUDE.md` and/or `AGENTS.md` at the project root from a single 4.7-tuned template (universal ruleset + placeholder blocks for project-specific content; per-target substitutions for intro line and sibling reference).
- **`git-strategy-init`** (sibling sub-skill): installs `docs/git-strategy.md` — the canonical git/worktree/merge-authority policy. Detects existing `implementation-pitfalls.md` and offers §Orchestration wiring via its Step 6.5.
- **`pitfalls-docs-init`** (sibling sub-skill): installs `docs/pitfalls/implementation-pitfalls.md` + `docs/pitfalls/testing-pitfalls.md` from bundled templates (maintenance framework + universal cross-cutting entries pre-populated).
- **`superpowers:using-git-worktrees`** (external): the canonical skill for worktree creation mechanics. Forward-referenced by the git-strategy template.
- **Plan-writing skills** (e.g. `superpowers:writing-plans`, `writing-plans-enhanced`): mandate reading the pitfalls docs during plan authorship. After `project-init` completes, the cross-references are all in place and the plan-writing mandated-read path works end-to-end.

## Cross-platform notes

- **Claude Code:** sub-skills invoked via the `Skill` tool (`Skill(skill='git-strategy-init')` etc.). The sub-skill's SKILL.md loads into context and the agent follows it.
- **Codex / Cursor / generic shell-based frameworks:** read the sub-skill's `SKILL.md` directly from disk at `plugins/project-setup/skills/<sub-skill>/SKILL.md` and follow the instructions end-to-end.
- **No bundled scripts.** Pure instruction. All runtime logic is in the sub-skills.
- **No Claude-Code-specific dependencies.** The wrapper works anywhere the sub-skills work.
