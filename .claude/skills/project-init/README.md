# project-init

One-command bootstrap for a new project's foundational docs and conventions. Wraps `claude-agents-md-init`, `git-strategy-init`, and `pitfalls-docs-init` in a single invocation, runs them in a clean order, and produces an aggregated report. Invoked by an AI agent (Claude Code, Codex, Cursor, etc.) on behalf of the user — not a standalone CLI.

**Agents should read [SKILL.md](SKILL.md).** This README is the human-facing overview.

## What the wrapper does

Given a new project directory and a user request like *"initialize this project"*:

1. Announces the sequence (claude-agents-md-init → git-strategy-init → pitfalls-docs-init) and confirms the user wants the full run (or identifies any skips).
2. Runs `claude-agents-md-init` — installs `CLAUDE.md` and/or `AGENTS.md` at the project root from a single 4.7-tuned template (RFC 2119 terminology, universal ruleset, placeholder blocks for project-specific sections; per-target substitutions for the intro line and sibling references). Default writes both files; `--target claude|agents` narrows scope. Runs first so later skills have well-formed target files to append their references into.
3. Runs `git-strategy-init` — installs `docs/git-strategy.md`, updates `.gitignore`, wires references into CLAUDE.md / AGENTS.md.
4. Runs `pitfalls-docs-init` — installs `docs/pitfalls/implementation-pitfalls.md` + `docs/pitfalls/testing-pitfalls.md` from templates (maintenance framework + universal cross-cutting entries pre-populated).
5. Produces an aggregated report: what got installed, what cross-references got wired, what the user should do next.

Each sub-skill owns its own UX (pre-flight, auto-detect, confirmation, apply, report). The wrapper sequences them and aggregates.

## Why a wrapper

Each sub-skill is independently useful and runs fine on its own. The wrapper exists because bootstrapping a new project benefits from:

- **One-command convenience.** Say "init this project" and get the full foundational doc set without remembering every sub-skill.
- **Clean ordering.** `claude-agents-md-init` runs first so the later two skills have well-formed CLAUDE.md and/or AGENTS.md to append their references into (rather than scaffolding them as a side effect). `git-strategy-init` runs second so `pitfalls-docs-init`'s §Orchestration cross-reference resolves immediately (it forward-references `docs/git-strategy.md`). Any ordering technically works — all three sub-skills handle companion-missing cases gracefully — but this ordering avoids dangling-reference moments.
- **Aggregated reporting.** One "project-init complete" summary covers the whole bootstrap: what got installed across all sub-skills, what cross-references wired, what follow-ups remain. Otherwise the user has to piece together three separate reports.

## Design principles

- **Wrapper owns no business logic** — just sequencing and aggregated reporting. All detection, user prompts, file-writing, and section-heading analysis live in the sub-skills.
- **Sub-skills remain independently runnable.** The wrapper adds zero coupling. Users who want just `git-strategy-init`'s output invoke that skill directly.
- **Idempotent by composition.** Because each sub-skill self-detects existing state, this wrapper is safe to re-run on partially-initialized projects — already-done steps get skipped, missing steps get filled in.
- **Extensible by adding sub-skills, not by growing the wrapper.** Adding a new init skill means adding another step to SKILL.md, not embedding logic in the wrapper.

## Adding a new sub-skill

Two steps:

1. Author the new skill as a standalone, idempotent sub-skill at `plugins/project-setup/skills/<new-skill>/` following the conventions set by `claude-agents-md-init`, `git-strategy-init`, and `pitfalls-docs-init` — SKILL.md (pre-flight / auto-detect / confirm / apply / report), optional README.md, optional `references/` for bundled templates.
2. Add a new step to this skill's SKILL.md invoking the new sub-skill in the desired order. Update the Step 1 announcement, Step 5 aggregated report, and the Quick reference table.

Don't put the new skill's logic into the wrapper — keep it in its own sub-skill so users who want only that one can still invoke it directly.

## Limits

- **Bootstrap, not maintenance.** If a sub-skill's docs already exist, the sub-skill handles "already-present" gracefully but the wrapper doesn't re-drive specific updates. For updates, run the sub-skill (or a future update-skill) directly.
- **No rollback layer.** If a sub-skill fails mid-invocation, the wrapper surfaces the failure and stops. Sub-skills have their own partial-state behavior (or not, per their design); the wrapper doesn't add a rollback.
- **One aggregated confirmation is not the goal.** Each sub-skill has its own confirmation step surfacing specific detected state. The wrapper keeps those separate — consolidating would lose per-sub-skill clarity. The user sees three confirmations in sequence, not one.

## Cross-platform

Pure instructions, no bundled scripts, no runtime dependencies.

Skill invocation differs across frameworks:
- **Claude Code:** uses the Skill tool to invoke sub-skills by name.
- **Codex / Cursor / others:** read each sub-skill's `SKILL.md` from disk at `plugins/project-setup/skills/<sub-skill>/SKILL.md` and follow the instructions end-to-end.

Both paths are documented in the SKILL.md.
