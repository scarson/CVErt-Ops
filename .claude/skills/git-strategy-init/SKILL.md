---
name: git-strategy-init
description: Use when setting up a new or existing repository with git-worktree-based conventions for multi-agent or multi-branch workflows. Triggers on "set up git strategy", "initialize git workflow", "add git-strategy.md", "adopt the worktree workflow", or similar requests. Generates a project-specific git-strategy.md from a bundled template, auto-detects current branch / branching pattern / forge, updates .gitignore, and links the doc from any existing CLAUDE.md / AGENTS.md. Cross-platform — instructions rely on git and standard file operations only; no Claude-Code-specific tooling.
metadata:
  version: "1.0"
---

# git-strategy-init

Initializes a project-specific `git-strategy.md` from the bundled template, handles path/branch substitutions, and wires references into existing agent instruction files.

**This file is for agents invoking the skill.** Humans should read [README.md](README.md) for the overview and contribution notes.

## When to use

Invoke when the user asks to:

- "set up git strategy", "initialize git workflow", "init git-strategy"
- "adopt the worktree workflow", "add git-strategy.md to this project"
- set up an existing repo with the branch/worktree policy described in the template

Do NOT use for:

- Editing an existing, already-adapted `git-strategy.md` — that's a normal edit workflow, not an init.
- Projects that need dedicated release-branch / hotfix / environment-branch policy. The template's scope is feature-work-onto-integration-branch only; surface this limit before proceeding.

## Inputs

- The bundled template at `references/git-strategy-template.md` (relative to this skill's root). Do NOT read the template from any other location — the version bundled here is the authoritative one.
- The current working directory must be the root of a git repository.

## Workflow

### Step 1 — Pre-flight

Run from the repo root.

1. **Verify git repo.** `git rev-parse --is-inside-work-tree` — if exit nonzero, abort and tell the user this skill requires a git repo.

2. **Search for existing `git-strategy.md` anywhere in the repo.** Both tracked and untracked. Match the EXACT filename `git-strategy.md` (case-insensitive) — do NOT match filenames that merely contain `git-strategy` as a substring (e.g. `git-strategy-template.md`, `git-strategy-old.md`, `git-strategy.draft.md`). Those are template / draft artifacts, not deployed policy docs.
   - Tracked: `git ls-files` and keep only paths whose basename matches `git-strategy.md` case-insensitively.
   - Untracked (respecting .gitignore): `git ls-files --others --exclude-standard` and apply the same basename filter.
   - Reliable cross-platform pattern: list candidates, then in your own filter compare the basename against `git-strategy.md` / `GIT-STRATEGY.md` / etc. Shell `grep git-strategy` is too loose and will false-positive on templates.

3. **If any found, STOP and ask the user** — list every location, then ask:
   - Overwrite a specific one? (Specify which.)
   - Abort?
   - Move/rename the existing one first? (User must do this manually; re-run when ready.)

   Never silently overwrite. Never silently create a second copy at a different path.

4. **Check for existing "Git strategy" references in CLAUDE.md / AGENTS.md** if those files exist. If a reference already points to a path that no longer exists, flag it — the user may want the new doc at the same path.

### Step 2 — Auto-detect project state

Collect these values silently (do not prompt yet):

| Value | How to detect |
|---|---|
| Current branch | `git branch --show-current` |
| `main` branch present (local or remote) | `git show-ref --verify --quiet refs/heads/main` OR `refs/remotes/origin/main` |
| `dev` branch present (local or remote) | Same pattern for `dev` |
| `develop` branch present | Same for `develop` |
| Remote URL | `git remote get-url origin` (may fail if no remote — that's OK) |
| Forge | Parse remote URL for `github.com`, `gitlab.com`, `bitbucket.org`, or note "unknown/self-hosted" |
| `gh` CLI available | Run `gh --version` — non-zero exit = not installed |
| `docs/` directory exists | File-system check for directory at `./docs` |
| CLAUDE.md at repo root | File-system check for file at `./CLAUDE.md` |
| AGENTS.md at repo root | File-system check for file at `./AGENTS.md` |
| `.gitignore` exists | File-system check for `./.gitignore` |
| Default worktree path already gitignored | Check if `.gitignore` contains `.claude/worktrees/` (as a line, anywhere) |
| `implementation-pitfalls.md` present | EXACT-basename search (same filter as Step 1) — common locations: `docs/pitfalls/implementation-pitfalls.md`, `dev/pitfalls/implementation-pitfalls.md` |
| `§Orchestration` section already in pitfalls doc | If pitfalls doc present, grep for `^## Orchestration` — determines whether Step 6.5 needs to append or skip |

### Step 3 — Infer decisions, present, confirm

Infer as much as possible, then present one consolidated block and ask the user to confirm or adjust.

**Inference rules:**

- **Integration branch:**
  - If current branch is `main` or `master` and `dev`/`develop` is absent → integration branch is current branch.
  - If current branch is `dev` or `develop` → integration branch is current branch; `main` likely release-only.
  - If both `main` AND `dev` (or `develop`) exist → ambiguous; ask.
  - Else → ask.

- **Branching pattern:**
  - `main` only → GitHub flow (default) or Trunk-based — ask the user which (affects worktree duration prose only; minor).
  - `main` + `dev`/`develop` → Two-branch / simplified gitflow.
  - Other → ask.

- **Forge:** From remote URL parsing. If self-hosted / unknown, treat as GitHub-compatible (commands in template use `gh`) but note in the output that the user should verify CLI commands map.

- **Output location:**
  - If `docs/` exists → default `docs/git-strategy.md`.
  - If `docs/` does NOT exist → ask the user explicitly:
    1. Write to `./git-strategy.md` (repo root)
    2. Create `docs/` and write to `docs/git-strategy.md`
    3. Custom directory (user provides path)

- **Worktree path:** Default `.claude/worktrees/`. If the user is on a non-Claude-Code agent, mention in the confirmation that this is conventional and can be changed.

**Present to user** (adapt as needed):

```
Detected / inferred:
  Integration branch:   main
  Branching pattern:    GitHub flow
  Forge:                GitHub (origin: git@github.com:org/repo.git)
  gh CLI:               installed
  Output path:          docs/git-strategy.md
  Worktree path:        .claude/worktrees/
  Will update:          CLAUDE.md (found), AGENTS.md (not found)
  .gitignore update:    add '.claude/worktrees/' (not currently ignored)
  Pitfalls cross-ref:   docs/pitfalls/implementation-pitfalls.md (found, no §Orchestration yet)
                        → will offer to append the §Orchestration trigger-and-pointer

Confirm, or tell me what to change (branch name, output path, worktree path, etc.).
```

If `implementation-pitfalls.md` is NOT found, the confirmation block instead says:

```
  Pitfalls cross-ref:   implementation-pitfalls.md not found
                        → will note in report; user can run `pitfalls-docs-init`
                          after this skill to install it, which will wire the
                          §Orchestration trigger automatically via its template.
```

Wait for user confirmation before proceeding.

### Step 4 — Fill out the template

1. **Read** the template from `references/git-strategy-template.md` (relative to this skill's root).

2. **Validate** the template contains the expected section headings. If any of these are missing, stop and report a bug:
   - `## Branching model`
   - `## Adapting this doc to your project`
   - `## Why this exists`
   - `## Invariants`
   - `## What NOT to do`

3. **Remove the pre-adoption sections:**
   - Delete from `## Branching model` through the line immediately before `## Why this exists`. This removes both the Branching model section AND the Adapting-this-doc section, since they only exist to guide adaptation and are not useful in the final project-specific doc.

4. **Substitute the integration branch name** — only if it is not `main`:
   - Find-replace `main` → chosen branch name throughout the remaining content.
   - Do NOT do this before step 3 — the Branching model section uses both `main` and `dev` as concrete branch names and a naive replace breaks it.

5. **Substitute the worktree path** — only if it is not `.claude/worktrees/`:
   - Find-replace `.claude/worktrees/` → chosen path.

6. **Forge-specific adjustments** — only if forge is NOT GitHub:
   - **GitLab:** `gh pr create --fill` → `glab mr create --fill`; `gh pr merge <number> --merge --delete-branch` → `glab mr merge <number> --merge --remove-source-branch`.
   - **Bitbucket:** Prepend a one-line note near the top of the doc: `> **Forge note:** This project uses Bitbucket. The \`gh\` commands below are placeholders — substitute with your forge's CLI (Bitbucket has no official equivalent; use the web UI or a third-party tool).`
   - **Unknown / self-hosted:** Similar note, telling the user to verify the commands apply to their forge.

7. **Write** the filled-out content to the chosen output location.

   If the output directory does not exist (e.g. user chose a custom path), create parent directories as needed.

### Step 5 — Update .gitignore

Skip this step if the chosen worktree path is already gitignored (detected in Step 2).

Otherwise:

1. If `.gitignore` does not exist, create it.
2. Append (don't overwrite) the following, preceded by a blank line if the file is non-empty:
   ```
   
   # Git worktrees — see <relative-path-to-git-strategy.md>
   <chosen-worktree-path>
   ```
   Example:
   ```
   
   # Git worktrees — see docs/git-strategy.md
   .claude/worktrees/
   ```

### Step 6 — Update CLAUDE.md and AGENTS.md

For **each** of `CLAUDE.md` and `AGENTS.md` that exists at repo root:

1. **Read** the file.

2. **Decide placement** — look for an existing section whose heading contains (case-insensitive substring match) any of the following words or phrases. Substring match, not exact: `Key Conventions` matches `Conventions`, `Development Workflow` matches both `Development` and `Workflow`. Priority order (take the first match when multiple apply):
   - `Git strategy` (most specific — prefer if present)
   - `Git workflow`
   - `Git`
   - `Version Control`
   - `Development Workflow`
   - `Workflow`
   - `Conventions`
   - `Development`
   - `Documentation`
   - `Docs`
   - `References`
   - `Reference`

3. **If a matching section is found:** append a reference line at the end of that section (before the next `##` heading), using this format:
   ```markdown
   - **Git strategy:** see [<relative-path>](<relative-path>) for branch/worktree policy, merge authority, recovery steps, and multi-agent coordination rules.
   ```
   The relative path is relative to the file being edited (e.g. if CLAUDE.md is at repo root and the strategy doc is at `docs/git-strategy.md`, the link is `docs/git-strategy.md`).

4. **If no matching section is found:** add a new top-level section. Place it before any trailing "License" / "Acknowledgements" section if present; otherwise append at the end of the file. Format:
   ```markdown
   
   ## Git strategy
   
   See [<relative-path>](<relative-path>) for branch/worktree policy, merge authority, recovery steps, and multi-agent coordination rules. The doc is the authoritative reference — do not duplicate the rules here.
   ```

5. **Do not** overwrite or rewrite existing content by default. Append only.

6. **Drift check when a link already exists.** If the file already contains a link to `git-strategy.md` at the expected path:
   - Locate the section containing that link.
   - Count non-link prose in that section (bullet points, paragraphs — anything other than the link line itself).
   - If the section is JUST the link line (no surrounding prose summary): skip this file — the reference already exists and there's nothing to drift.
   - If the section has a non-trivial prose summary (rule of thumb: more than 3 lines or more than 2 bullets of non-link content): STOP and surface to the user. Show the existing summary content and note that the canonical `git-strategy.md` may have moved on since the summary was written. Ask whether the user wants to:
     1. Leave it (summary is still accurate)
     2. Refresh selected bullets (user points to specific stale content)
     3. Rewrite the whole summary from the current doc's §Invariants + §Merge authority
   - Do NOT attempt to auto-diff the summary against the canonical doc — semantic drift is a judgment call, not a mechanical one. Surface and ask.

### Step 6.5 — Offer to wire §Orchestration into `implementation-pitfalls.md`

This step is the complement to §Multi-agent coordination → Output persistence in the git-strategy doc just written. The goal is to put a trigger-and-pointer to that rule in the project's `implementation-pitfalls.md` so plan writers hit it via their mandated-read path (e.g. `writing-plans-enhanced`).

1. **If `implementation-pitfalls.md` is NOT present** (from Step 2 detection): skip this step. Note in the Step 7 report that the user can run `pitfalls-docs-init` next to install pitfalls docs with the §Orchestration trigger pre-populated.

2. **If `implementation-pitfalls.md` is present AND already has a `## Orchestration` section** (from Step 2 grep): skip this step. The wiring is already done; do not duplicate.

3. **If `implementation-pitfalls.md` is present AND does NOT have a `## Orchestration` section**: offer to append the following block. Show the user what you'll append and get confirmation before writing:

   ```markdown
   ---

   ## Orchestration

   This section is the discovery hook for plan writers who arrive here via the `writing-plans-enhanced` (or equivalent) mandated-read path. The canonical rules live in `docs/git-strategy.md` → §Multi-agent coordination → Output persistence. This section does NOT restate those rules — it exists to make sure plan writers notice they apply.

   ### ORCH-1: Analysis Dispatches Must Persist Findings Before Returning

   **Trigger:** Your plan dispatches parallel subagents (bug hunts, audits, phased analysis, parallel investigations) whose findings would be expensive to regenerate if lost.

   **What you need to do:** Every such dispatched subagent MUST write its complete report to a persistent file BEFORE returning; the response message is not the sole record.

   **Read the full rule:** `docs/git-strategy.md` → §Multi-agent coordination → Output persistence. That section carries the copy-pasteable prompt block (with `<PERSISTENCE_PATH>` substitution), file-path conventions, orchestrator commit cadence, and the cases where the rule doesn't apply.

   **Why this is in implementation-pitfalls:** because the plan-writing skill mandates reading this file, and this rule has to be noticed at plan-write time (when the dispatch prompts are being drafted), not at execution time (when it's too late). The failure mode — orchestrator context compacting mid-consolidation and lossily dropping findings — is predictable and preventable if the plan author builds persistence into the dispatch prompts from the start.

   ### Review Checklist

   - [ ] **Dispatch prompts include the mandatory-persistence block** — copy from `docs/git-strategy.md` §Output persistence; substitute `<PERSISTENCE_PATH>` with a durable per-subagent path (ORCH-1)
   - [ ] **Plan specifies exact persistence paths, not "write somewhere useful"** — ambiguous paths default to `/tmp` under pressure, which doesn't survive (ORCH-1)
   - [ ] **Orchestrator commits subagent artifacts wave-by-wave** — committed files land on the campaign branch before consolidation begins (ORCH-1)
   ```

   Adjust the `docs/git-strategy.md` path to match wherever git-strategy.md was written in Step 4 (it may not be exactly `docs/git-strategy.md` if the user chose a different location).

4. **Placement within the pitfalls doc:** append after the last domain/topic section but BEFORE `# Appendix A: Historical Changelog` (if present). If the pitfalls doc has no appendices, append at the end of the file.

5. **Do not alter existing content** in `implementation-pitfalls.md` beyond adding the new section. If the file's structure is unclear (no clear end-of-domain-sections landmark), surface to the user rather than guess at placement.

### Step 7 — Report

Summarize what was done:

```
Done.

Wrote:              docs/git-strategy.md
.gitignore:         added '.claude/worktrees/'
CLAUDE.md:          appended reference under '## Development Workflow' section
AGENTS.md:          not found — skipped
Pitfalls cross-ref: appended §Orchestration to docs/pitfalls/implementation-pitfalls.md
                    (OR: implementation-pitfalls.md not found — run pitfalls-docs-init
                     to install pitfalls docs with §Orchestration pre-populated)
```

Mention any follow-ups:

- Commit the new file and updates (suggest a commit message, e.g. `docs: adopt worktree-based git strategy`).
- If forge is non-GitHub, remind the user to verify the CLI commands.
- If the template scope doesn't cover the project's needs (release branches, hotfix flow), remind the user they'll need separate policy for those.
- If `implementation-pitfalls.md` was missing: recommend running `pitfalls-docs-init` next. That skill installs `implementation-pitfalls.md` and `testing-pitfalls.md` from templates; the implementation-pitfalls template has the §Orchestration trigger pre-populated, so no manual wiring is needed afterward.

## Common mistakes

- **Deleting the Branching model section AFTER find-replace instead of before.** The section contains both `main` and `dev` as concrete branch names in the descriptive patterns. A naive `main → dev` replace on that section produces `integration branch is dev; dev is release-only` — broken. ALWAYS delete the pre-adoption sections FIRST, then do the branch-name substitution.
- **Writing over existing `git-strategy.md` without the pre-flight search.** There can be ghost copies at `git-strategy.md` and `docs/git-strategy.md` from different team members or past runs. Always search both tracked and untracked before writing.
- **Assuming the branching pattern.** If both `main` and `dev` exist, DO NOT guess. Ask the user which is the integration branch — two-branch gitflow looks different from a GitHub-flow repo that happens to have a stale `dev` branch.
- **Updating only one of CLAUDE.md / AGENTS.md when both exist.** Both should be updated if found. Different agent frameworks read different files; projects that have both need both wired up.
- **Using Claude-Code-specific tooling.** This skill is cross-platform. Do not invoke `TodoWrite`, `AskUserQuestion`, `Skill`, or any other Claude-Code-specific tool in your implementation. Use plain shell commands, file operations, and natural-language prompts to the user.
- **Forgetting the .gitignore update.** Without it, worktree contents will appear in `git status` and can be accidentally committed — the first failure mode the strategy doc is designed to prevent.
- **Creating `git-strategy.md` without the user's confirmation on output location.** When `docs/` doesn't exist, the default is not obvious. Always ask.
- **Matching template files in the pre-flight search.** `grep -i git-strategy` matches `git-strategy-template.md`, `git-strategy.draft.md`, etc. Filter by exact basename (`git-strategy.md`, case-insensitive) only. A template is not a deployed policy doc.
- **Silently skipping a CLAUDE.md / AGENTS.md that already links to `git-strategy.md`.** The link being present does not mean the surrounding summary is still accurate. If there's a prose summary of more than a few lines, surface it for the user to review — summaries drift as the canonical doc evolves.

## Quick reference (condensed workflow)

| Step | Action |
|---|---|
| 1 | Verify git repo; search for existing `git-strategy.md`; prompt if found |
| 2 | Auto-detect branch, forge, paths, CLAUDE.md/AGENTS.md presence |
| 3 | Present detected values; ask user to confirm/adjust |
| 4 | Read template; delete pre-adoption sections; substitute branch/path; forge swaps; write |
| 5 | Append worktree path to `.gitignore` if not already there |
| 6 | Append reference to CLAUDE.md and/or AGENTS.md; create section if needed |
| 6.5 | If `implementation-pitfalls.md` exists without §Orchestration, offer to append the trigger-and-pointer; otherwise note the gap in Step 7 report |
| 7 | Report paths changed and next steps (including whether to run `pitfalls-docs-init` next) |

## Relationship to other skills

- **`pitfalls-docs-init`**: separate, composable skill that installs `implementation-pitfalls.md` and `testing-pitfalls.md` from templates. The templates include the §Orchestration trigger-and-pointer back to this skill's `git-strategy.md`. Either skill can run first; this skill's Step 6.5 handles the case where `implementation-pitfalls.md` already exists (appends §Orchestration if missing, skips if present), and the Step 7 report flags the case where it doesn't exist yet (recommends running `pitfalls-docs-init` next). No direct skill invocation between them.
- **`superpowers:using-git-worktrees`**: the canonical skill for worktree creation mechanics (directory priority, gitignore verification, project setup, baseline tests). This doc's Day-one workflow forward-references it. If your agent framework has access to it, use it when creating worktrees per the output doc.
- **Plan-writing skills** (e.g. `superpowers:writing-plans`, `writing-plans-enhanced`): these typically mandate reading the pitfalls docs during plan authorship. After this skill runs (and `pitfalls-docs-init` has populated the pitfalls files), the §Orchestration trigger is discoverable on the plan-writing mandated-read path.
- **Future `project-init` wrapper**: runs `git-strategy-init` + `pitfalls-docs-init` (+ other init skills) in sequence for one-command project bootstrap. Each sub-skill is idempotent and composable; the wrapper just sequences them.

## Cross-platform notes

This skill is pure instruction — no bundled scripts. Any agent framework with shell access and read/write file operations can execute it.

- **Git subcommands** used are portable (Windows, macOS, Linux, Git Bash).
- **File existence checks** should use your agent's native file-inspection tools rather than shell `test` — `test -f` doesn't work on Windows cmd.
- **File listing** — prefer `git ls-files` over `find` / `dir` for portability.
- **Grep / search** — prefer your agent's Grep tool over piping `git ls-files | grep`, since `grep` isn't on Windows cmd by default.
- **Path handling** — use forward slashes in all paths you write into files. Git handles them on Windows.

The skill does not depend on any Claude Code-specific tool (`Skill`, `TodoWrite`, `AskUserQuestion`, etc.). Instructions are agent-agnostic.
