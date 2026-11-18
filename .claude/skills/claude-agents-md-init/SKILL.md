---
name: claude-agents-md-init
description: Use when setting up a new or existing project with agent-guidance files (CLAUDE.md for Claude Code, AGENTS.md for Codex / Cursor / Cline / other AGENTS.md-aware frameworks). Triggers on "set up CLAUDE.md", "set up AGENTS.md", "initialize CLAUDE.md", "bootstrap agent guidance", "add CLAUDE.md and AGENTS.md", "add a CLAUDE.md template", or similar requests. Installs ONE bundled template as two sibling files (CLAUDE.md + AGENTS.md) with per-target substitutions for the few platform-specific bits. Both files carry the RFC 2119 terminology block, a universal rules ruleset (principles, relationship, proactiveness, completeness over shortcuts, TDD, writing code, naming, code comments, cross-references in persistent artifacts, version control, testing, issue tracking, completion status & escalation, systematic debugging, thinking documentation, learning and memory) plus placeholder sections for project-specific content. Default is to write both files. Use `--target claude|agents|both` to narrow scope. Each output file carries a Sibling-sync reminder at the top pointing to the other so future editors know to keep them in sync. Runs an alignment check on any existing file at the project root and STOPs for human review before standing up a sibling from the template against a divergent existing file — prevents an out-of-sync pair at install time. Injects the sibling-sync block into template-aligned-but-unsynced existing files. Cross-platform — instructions rely on git and standard file operations only; no Claude-Code-specific tooling. Pairs with `git-strategy-init` and `pitfalls-docs-init` but runs independently.
metadata:
  version: "2.2"
---

# claude-agents-md-init

Initializes project-root agent-guidance files from a single bundled template, rendered as one or both of:

- `CLAUDE.md` — consumed by Claude Code (`claude.ai/code`)
- `AGENTS.md` — consumed by Codex, Cursor, Cline, Aider, and other AGENTS.md-aware agent frameworks

The template carries the **universal** ruleset that applies across projects and frameworks (RFC 2119 terminology, principles, relationship, proactiveness, completeness over shortcuts, TDD, writing code, naming, code comments, cross-references in persistent artifacts, version control short-form, testing, issue tracking, completion status & escalation, systematic debugging, thinking documentation, learning and memory, workflow skills table) plus **placeholder** blocks for project-specific content. At write time, two tokens substitute per target:

- `[AGENT_INTRO]` — the "This file provides guidance to …" intro line; per-target phrasing
- `[SIBLING_FILE]` — the name of the other file in the Sibling-sync reminder

All other content is identical between the two outputs.

**This file is for agents invoking the skill.** Humans should read [README.md](README.md) for the overview and rationale.

## Why one skill for two files

Claude Code and Codex/Cursor/Cline are used side-by-side in many teams. The rules in `CLAUDE.md` and `AGENTS.md` should stay identical except for a few platform-specific mentions — maintaining two parallel skills with two parallel templates risks drift. One skill, one template, per-target substitutions keeps the pair in sync by construction. The Sibling-sync reminder at the top of each output file keeps them in sync over time as users edit them.

## When to use

Invoke when the user asks to:

- "set up CLAUDE.md" / "set up AGENTS.md" / "set up agent guidance"
- "initialize CLAUDE.md" / "initialize AGENTS.md"
- "bootstrap Claude/Codex guidance" for a project
- "add a CLAUDE.md template" (equivalent for AGENTS.md)
- install project-root agent instructions following the 4.7-tuned convention

Do NOT use for:

- Editing existing CLAUDE.md / AGENTS.md content — that's a normal edit workflow, not an init.
- Projects that already have agent-guidance files with substantial custom content and don't want template-driven changes — this skill is additive but may prompt to merge; the target audience is fresh projects or projects whose guidance files have significantly diverged from modern conventions.

## Inputs

- The bundled template at `references/claude-agents-md-template.md` (relative to this skill's root). Do NOT read the template from any other location.
- The current working directory must be the root of the project (git repo preferred but not required).
- Optional inputs to ask the user for (Step 2):
  - Project name (default: basename of the current directory)
  - User name (how the agent should address the human partner; default: ask)
  - Primary branch name (default: detect from git; fall back to `main`)
  - Target (default: ask with smart default based on existing file state)

## Workflow

### Step 1 — Pre-flight

1. **Verify current working directory.** If it's a git repo (`git rev-parse --is-inside-work-tree`), note that and capture the primary branch name via `git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's|refs/remotes/origin/||'` or fall back to `git branch --show-current`. If not a git repo, proceed anyway and warn the user — neither file requires git.

2. **Search for existing agent-guidance files at the project root.** Check for:
   - `CLAUDE.md` (case-sensitive — Claude Code convention)
   - `AGENTS.md` (case-sensitive — Codex / AGENTS.md convention)
   - `.claude.md` (alternate lowercase; uncommon but respected by Claude Code)
   - `CLAUDE.local.md` (personal overrides; gitignored by convention)

3. **Classify the state for each of `CLAUDE.md` and `AGENTS.md`:**
   - `MISSING` — the file is not present.
   - `FOUND_ELSEWHERE` — the file exists in a subdirectory but not at root.
   - `FOUND_AT_ROOT` — the file exists at the project root. For each file in this bucket, sub-classify via the **alignment check** below.

4. **Alignment check for `FOUND_AT_ROOT` files.** An existing file is "template-aligned" if it shares the template's universal ruleset structure — that's what makes creating its sibling from the template safe. Grep the existing file for the following six markers; count hits:

   - `## Terminology` heading near the top (within first ~50 lines)
   - `RFC 2119` string
   - `## Principles` heading
   - `Rule #1: If you want exception to ANY rule` phrase
   - `## Our relationship` heading
   - `Don't glaze me` phrase

   Classification:
   - **≥ 4 markers present** → `TEMPLATE_ALIGNED` (structure matches template; the content of each section may differ, and that's OK)
   - **< 4 markers present** → `DIVERGENT` (file doesn't follow this template's shape at all; standing up a sibling from the template will create an out-of-sync pair)

5. **Sibling-sync block presence check.** For every `TEMPLATE_ALIGNED` file, additionally check whether the sibling-sync block is present. Grep for the literal string `**Sibling sync.**`. If present → `TEMPLATE_ALIGNED_WITH_SYNC`; if absent → `TEMPLATE_ALIGNED_NO_SYNC`. Files authored before this skill (or under earlier versions) will be in the `NO_SYNC` state even if their content is template-aligned.

6. **Smart default for `--target`:**
   - Both missing → default `both` (recommend the full install)
   - `CLAUDE.md` present, `AGENTS.md` missing → default `agents` (fill the gap; see Step 4 for sync-block injection and divergence handling)
   - `AGENTS.md` present, `CLAUDE.md` missing → default `claude`
   - Both present → default `both`, but Step 4 handles each file's state independently

### Step 2 — Collect substitution values

Ask the user (or infer, with confirmation) for:

- **Project name** — default to the basename of the current working directory. Used to substitute `[PROJECT NAME]` tokens.
- **User name** — the name the agent should address the human partner by (e.g., `Sam`, `Alice`). Used to substitute `[USER NAME]` tokens. Default: ask.
- **Primary branch** — `main`, `master`, `dev`, etc. Detect via `git` or ask. Used to substitute `[PRIMARY BRANCH]` tokens.
- **Brief project description** — one sentence. Used to substitute `[BRIEF PROJECT DESCRIPTION]` in the Project Overview placeholder. Optional — if not provided, leave as the literal token so the agent filling in the doc sees it.
- **Target** — `claude`, `agents`, or `both`. See Step 1's smart-default logic; confirm with the user if the default isn't obvious.
- **Output filename override (dogfood mode)** — optional. Default writes to `CLAUDE.md` and/or `AGENTS.md`. Override to `CLAUDE-TMP.md` / `AGENTS-TMP.md` (suffix applied to whichever targets are being written) when running as a dogfood / diff test against a project that already has those files. In dogfood mode: (a) skip the existing-file backup-and-replace logic in Step 4, (b) write to the overridden filenames regardless of whether the canonical files exist, (c) in Step 7's report, include a `diff` hint so the user can compare. Accept this as an explicit user flag — never infer "dogfood mode" from file state alone.

### Step 3 — Present & confirm

Present one consolidated block with detected state + proposed actions + substitution values, and ask the user to confirm or adjust:

```
Pre-flight:
  Existing CLAUDE.md:        NOT FOUND
  Existing AGENTS.md:        NOT FOUND
  Existing CLAUDE.local.md:  not found
  Git repo:                  yes, primary branch `main`

  (When a file is FOUND_AT_ROOT, this block also shows its alignment:
   TEMPLATE_ALIGNED_WITH_SYNC / TEMPLATE_ALIGNED_NO_SYNC / DIVERGENT.)

Substitutions:
  [PROJECT NAME]                 → my-project
  [USER NAME]                    → Alice
  [PRIMARY BRANCH]               → main
  [BRIEF PROJECT DESCRIPTION]    → (left as TODO placeholder)

Target: both (will write CLAUDE.md AND AGENTS.md)

Install paths:
  ./CLAUDE.md  (Claude Code — claude.ai/code)
  ./AGENTS.md  (Codex, Cursor, Cline, and other AGENTS.md-aware frameworks)

Planned actions:
  1. Create ./CLAUDE.md from template
  2. Create ./AGENTS.md from same template (different [AGENT_INTRO] + [SIBLING_FILE] substitutions)

  Both files will be identical except for:
    - The intro line (mentions Claude Code vs. mentions AGENTS.md-aware frameworks)
    - The Sibling-sync reminder at the top (points to the other file)

  Each file includes: RFC 2119 terminology, universal ruleset, workflow
  skills table, PLACEHOLDER sections for project-specific content.

Follow-ups to suggest after install:
  - Fill in the PLACEHOLDER sections with project-specific content
  - If using git-strategy-init: the "Keeping a clean git graph" section
    references docs/git-strategy.md — run git-strategy-init to install it
  - If using pitfalls-docs-init: several sections reference
    docs/pitfalls/implementation-pitfalls.md — run pitfalls-docs-init

Confirm, or tell me what to change.
```

Wait for user confirmation before proceeding.

### Step 4 — Handle existing-file cases (per target)

Runs independently for each target being written (`CLAUDE.md` and/or `AGENTS.md`). Handling depends on both the file's own state and on its sibling's state — creating a new sibling from the template when the existing file is `DIVERGENT` lands an out-of-sync pair at install time, which makes future cross-sync operations messy. That's the scenario this step's STOP paths exist to prevent.

**Dogfood-mode short-circuit:** if the user set a dogfood output override in Step 2, skip this step entirely for the relevant target(s) and proceed to Step 5. The override exists precisely to avoid touching the existing canonical file.

Otherwise, for each target file in the install set:

- **If MISSING, and the sibling is also MISSING or `TEMPLATE_ALIGNED*`**:
  - Proceed to Step 5: write the new file from the template. This is the happy path.

- **If MISSING, and the sibling is `DIVERGENT`**: **STOP.** Creating the missing file from the template now would mean the two files are not in sync at install time. The first cross-sync operation later would be a messy merge. Surface to the user:

  ```
  STOP — divergence detected before filling the gap

  Target: AGENTS.md (MISSING — you asked to create it)
  Existing sibling: CLAUDE.md (DIVERGENT from template)

  Why this STOP matters: the whole point of the claude-agents-md-init
  skill is to produce two sibling files that are identical except for a
  few framework-specific mentions, so a future agent asked to "update
  one, sync the other" can do so mechanically. If I stand up AGENTS.md
  from the template while CLAUDE.md has its own structure, the two
  files are out of sync at minute zero — the first sync operation
  faces a large structural diff, not a small edit.

  Options:
    (a) Align the existing CLAUDE.md to the template first. Exit this
        skill, run the template against the existing file with a merge
        tool (or rewrite CLAUDE.md to match the template shape), then
        re-run claude-agents-md-init. After that, the sibling AGENTS.md
        will land aligned.
    (b) Create AGENTS.md as a literal copy of the existing CLAUDE.md
        (ignore the template for this install). The pair starts
        identical; future template improvements require manual
        propagation. Sibling-sync block will still be injected into
        both.
    (c) Create AGENTS.md from the template anyway, accepting the
        divergence. The two files are out of sync at minute zero.
        Document the known divergence so the first sync operation
        doesn't produce surprises.
    (d) Abort. I'll make the decision elsewhere.

  Default recommendation: (a) if you can spare a few minutes to align
  the existing file; (b) if CLAUDE.md is load-bearing and preserving
  its exact content is the priority; (c) only if you have a specific
  reason to want the template content in the new file despite the
  known divergence.
  ```

  Wait for user decision. Per option:
  - (a): abort this run. Surface the recommendation to re-run after alignment.
  - (b): copy existing sibling content to the missing file, substitute only the per-target `[FILE_TITLE]`, `[AGENT_INTRO]`, `[SIBLING_FILE]` tokens where they appear (the existing file may have them hardcoded; if so, leave them). Inject the sibling-sync block into both files if missing.
  - (c): proceed to Step 5 normally. Add a callout to the final report explaining the known divergence and suggesting future agents read the existing file's content before editing either.
  - (d): abort silently.

- **If MISSING, and the sibling is `FOUND_ELSEWHERE`**: surface to user. Ask whether they want the new file at root to mirror the subdirectory copy (option b above), or create from template (option c).

- **If `TEMPLATE_ALIGNED_WITH_SYNC`**:
  - Leave as-is unless the user explicitly requests `--merge-template` to pull in new universal sections from the template since last install. Default: skip this target.

- **If `TEMPLATE_ALIGNED_NO_SYNC`**:
  - The file is template-aligned but missing the sibling-sync block (e.g., authored under an earlier skill version or by hand). Inject the sibling-sync block at the top — specifically, insert it between the intro line and the `## Terminology` section. Report the injection. No other changes. This is a safe, minimal, additive edit.

- **If `DIVERGENT`**:
  - The file exists at root but doesn't follow the template's shape. Surface to user. Options:
    - (a) Leave existing untouched; skip install for this target
    - (b) Create a backup at `<FILENAME>.backup-<timestamp>` and replace with template (destructive — preserves content in backup only)
    - (c) Merge: append any universal sections from the template that aren't already present (conservative — never overwrites existing sections with identical headings)
    - (d) Abort this run for manual resolution
    - (e) Dogfood: write template to `<FILENAME-TMP>.md` for diff inspection
  - Never silently overwrite. If the user picks (c), present a diff summary before writing.
  - **If the sibling is being filled from the template in the same run, the divergence-at-gap STOP from earlier also applies. Honor the stronger STOP (the gap case) if both trigger.**

- **If FOUND_ELSEWHERE**:
  - Surface to user. The new install goes at root regardless; the subdirectory file may still apply to its scope. Ask if the user wants to move it, leave it, or copy its content into the new root file.

### Step 5 — Write from template

For each target being written:

1. **Read** the bundled template from `references/claude-agents-md-template.md`.

2. **Substitute universal placeholders** (same values for all targets):
   - `[PROJECT NAME]` → project name (from Step 2)
   - `[USER NAME]` → user name (from Step 2)
   - `[PRIMARY BRANCH]` → primary branch (from Step 2; default `main`)
   - `[BRIEF PROJECT DESCRIPTION]` → description (from Step 2; if not provided, leave as the literal token so the agent filling in the doc sees it)

3. **Substitute target-specific placeholders:**

   For `CLAUDE.md`:
   - `[FILE_TITLE]` → `CLAUDE.md`
   - `[AGENT_INTRO]` → `This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.`
   - `[SIBLING_FILE]` → `AGENTS.md`

   For `AGENTS.md`:
   - `[FILE_TITLE]` → `AGENTS.md`
   - `[AGENT_INTRO]` → `This file provides guidance to AI coding agents (Codex, Cursor, Cline, Aider, and other AGENTS.md-aware frameworks) when working with code in this repository.`
   - `[SIBLING_FILE]` → `CLAUDE.md`

4. **Preserve all `<!-- TODO: ... -->` / `<!-- PLACEHOLDER: ... -->` blocks untouched** — they are load-bearing for the agent that later customizes the doc.

5. **Write** to the output filename from Step 2. In non-dogfood mode with an existing file selected for replacement in Step 4, create a backup at `<FILENAME>.backup-<timestamp>` first. In dogfood mode, skip the backup — the override guarantees the existing file is untouched.

6. **Sync-block injection for existing `TEMPLATE_ALIGNED_NO_SYNC` files** (independent of whether we wrote anything else this run). If Step 4's alignment check found an existing CLAUDE.md or AGENTS.md that is template-aligned but missing the sibling-sync block, inject the block now. The block goes between the intro line (the first line after `# <TITLE>`) and the `## Terminology` section, matching the template's placement. Apply the per-target `[SIBLING_FILE]` substitution as you would when writing from template. Report this as a separate line in Step 7's summary ("injected sibling-sync block into existing CLAUDE.md").

### Step 6 — Post-install pointers

Check for companion skills and surface actionable follow-ups:

1. **If `docs/git-strategy.md` does NOT exist:** the template's "Keeping a clean git graph" section references it. Suggest running `git-strategy-init`.

2. **If `docs/pitfalls/implementation-pitfalls.md` does NOT exist:** the template's "Language/Framework Gotchas" section references it. Suggest running `pitfalls-docs-init`.

3. **If both CLAUDE.md AND AGENTS.md were written:** remind the user that the Sibling-sync reminder at the top of each file is the durable mechanism for keeping them aligned — future edits should hit both.

### Step 7 — Report

Summarize per target:

```
Done.

Created:
  ./CLAUDE.md  (from template; substituted project name, user name, primary branch)
  ./AGENTS.md  (from same template; target-specific intro + sibling reminder)

Backups:
  none — neither CLAUDE.md nor AGENTS.md existed before this run

PLACEHOLDER sections to customize in BOTH files (find them via
`grep '<!-- TODO' CLAUDE.md AGENTS.md`):
  - ## Project Overview
  - ## Build & Dev Commands
  - ## Tech Stack
  - ## Architecture (Key Points)
  - ## Conventions
  - ## Language / Framework Gotchas (project-specific subsection)
  - ## Development Workflow (project-specific rules)
  - ## Project Layout
  - ## Skills & Subagents → "Project-specific skills" subsection
  - ## Skill routing → key routing rules list

Sibling-sync discipline:
  Both files carry a reminder at the top. When you edit one, also update
  the other. They should stay identical except for the intro line and
  the sibling reference.

Companion skills to consider:
  - git-strategy-init:    docs/git-strategy.md is referenced but not present — install it
  - pitfalls-docs-init:   docs/pitfalls/*.md are referenced but not present — install them
```

## Common mistakes

- **Installing at a non-root path.** CLAUDE.md / AGENTS.md are always at the project root. Subdirectory copies exist in monorepos but aren't managed by this skill.
- **Overwriting an existing file without a backup.** Always back up. Existing agent-guidance files accumulate load-bearing project-specific content; losing it is expensive.
- **Treating `--target=claude` and `--target=agents` as mutually exclusive by default.** They're not — the happy path is `--target=both`. Projects that use only one framework can narrow, but "both" is the default when neither file exists.
- **Letting the two files diverge silently.** The Sibling-sync reminder at the top of each output exists for a reason. If a user edits one file, surface the sibling and ask if the same edit should apply there.
- **Skipping the alignment check on existing files.** If the existing CLAUDE.md is `DIVERGENT` (doesn't follow the template shape), writing AGENTS.md from the template anyway creates an out-of-sync pair at minute zero. The alignment check + STOP (Step 4 "MISSING, sibling DIVERGENT") is what prevents that. Don't hand-wave past it.
- **Not injecting the sibling-sync block into existing `TEMPLATE_ALIGNED_NO_SYNC` files.** Projects that installed an earlier version of this skill (or hand-authored a template-aligned CLAUDE.md before this skill existed) won't have the sync block. Step 5 step 6 injects it — don't skip, or the pair silently lacks the drift-prevention reminder.
- **Substituting inside code fences or within backticks.** The template uses substitution tokens in prose, not in code examples. Only substitute in prose contexts.
- **Using Claude-Code-specific tooling.** This skill is cross-platform. Do not invoke `TodoWrite`, `AskUserQuestion`, `Skill`, or any other tool that isn't shell/file-I/O primitives.

## Quick reference

| Step | Action |
|---|---|
| 1 | Verify repo/project state; search for CLAUDE.md AND AGENTS.md at root; run **alignment check** and **sibling-sync block check** on each FOUND_AT_ROOT file; compute smart default target |
| 2 | Collect substitution values + target (claude/agents/both) + optional dogfood override |
| 3 | Present state (including alignment classification) + proposed actions + substitutions + target; await user confirmation |
| 4 | Per target: handle existing-file case. **STOP and surface options if filling the gap (sibling MISSING) while the existing file is DIVERGENT.** For TEMPLATE_ALIGNED_WITH_SYNC: leave. For TEMPLATE_ALIGNED_NO_SYNC: inject sync block only. For DIVERGENT: standard replace/merge/skip options. |
| 5 | Per target: write from template with universal substitutions + target-specific substitutions (`[FILE_TITLE]`, `[AGENT_INTRO]`, `[SIBLING_FILE]`). Inject sync block into any existing TEMPLATE_ALIGNED_NO_SYNC file found in Step 1. |
| 6 | Check for companion-skill prerequisites (git-strategy.md, pitfalls docs); suggest follow-ups; remind about Sibling-sync discipline |
| 7 | Report created files, sync-block injections, backup paths, placeholders to customize, any divergence callouts, and follow-up skills |

## Relationship to other skills

- **`git-strategy-init`**: separate, composable. The agent-md template's "Keeping a clean git graph" section references `docs/git-strategy.md`. Running `git-strategy-init` before or after makes that reference resolve.
- **`pitfalls-docs-init`**: separate, composable. The agent-md template's "Language/Framework Gotchas" and "Development Workflow" sections reference the pitfalls docs. Running `pitfalls-docs-init` before or after makes those references resolve.
- **`project-init` wrapper** (in the same plugin): sequences `claude-agents-md-init` → `git-strategy-init` → `pitfalls-docs-init` in one bootstrap command. This skill runs first so later skills have well-formed CLAUDE.md / AGENTS.md files to append their references into.
- **`superpowers:*` workflow skills**: the template's Skills & Subagents table pre-populates a curated set of workflow skills (brainstorming, writing-plans, TDD, debugging, etc.) treated as standard across Claude Code and Codex/Cursor workflows. Adjust after install if your project doesn't use superpowers.

## Cross-platform notes

Pure instruction, no bundled scripts. Any agent framework with shell access and file read/write can execute it.

- **Git subcommands** used (branch detection) are portable; skill works even on non-git projects.
- **Token substitution** is a flat find-and-replace on the template. Case-sensitive tokens. Replace universal tokens first, then target-specific tokens.
- **No dependency on Claude Code-specific features.** Codex, Cursor, and other agent frameworks that can read markdown skills and execute shell commands can run it equivalently.

## Design decisions

See [README.md](README.md) § "Design decisions" for the rationale behind:

- Why one skill generates two files rather than two parallel skills.
- Why the template is Opus-4.7-tuned (RFC 2119, scoped STOP rules, bias-to-action, TodoWrite-with-scope).
- What's in the "universal" ruleset vs. what's placeholder.
- The Sibling-sync reminder as a drift-detection mechanism.
- The superpowers skills table pre-population choice.

## History

- **v1.0** — initial release as `claude-md-init` (CLAUDE.md only). See agent-skills PR #6.
- **v2.0** — dual CLAUDE.md/AGENTS.md output; Sibling-sync reminder added to template. (Released briefly as `agent-md-init` before the v2.1 rename.)
- **v2.1** — renamed to `claude-agents-md-init` to avoid visual collision with the AGENTS.md spec name; added divergence detection (`DIVERGENT` / `TEMPLATE_ALIGNED_WITH_SYNC` / `TEMPLATE_ALIGNED_NO_SYNC` classification); added STOP path when filling the gap against a divergent sibling; added sync-block injection for template-aligned files missing the block. Template file renamed `agent-md-template.md` → `claude-agents-md-template.md`.
- **v2.2** — universal-ruleset additions to the template, mined from the gstack `cso` skill's load-bearing operational discipline. Added two foundational-rules bullets (**Trust, then verify** + **Quality matters. Bugs matter.**), a new **Completeness over shortcuts** section (boil lakes, flag oceans), a new **Completion status & escalation** section (DONE / DONE_WITH_CONCERNS / BLOCKED / NEEDS_CONTEXT four-state reporting + 3-attempt escalation rule), and a **Reflection trigger** appended to Learning and Memory Management. Alignment-check markers unchanged — projects on v2.1-aligned CLAUDE.md/AGENTS.md remain TEMPLATE_ALIGNED. Existing projects do NOT auto-update; re-run the skill or hand-port the new sections.
