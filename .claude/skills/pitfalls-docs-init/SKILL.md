---
name: pitfalls-docs-init
description: Use when setting up a new or existing project with the two-file pitfalls discipline — `docs/pitfalls/implementation-pitfalls.md` (what to implement and why) and `docs/pitfalls/testing-pitfalls.md` (how to verify). Triggers on "set up pitfalls docs", "initialize pitfalls files", "add implementation-pitfalls and testing-pitfalls", "bootstrap the pitfalls discipline", or similar requests. Installs both from bundled templates that carry the maintenance framework (how-to-add, completeness checklist, voice guide) plus universal cross-cutting entries pre-populated (ORCH-1 orchestration trigger, universal testing disciplines). Cross-platform — instructions rely on git and standard file operations only; no Claude-Code-specific tooling. Pairs with `git-strategy-init` but runs independently.
metadata:
  version: "1.0"
---

# pitfalls-docs-init

Initializes project-specific `implementation-pitfalls.md` and `testing-pitfalls.md` from bundled templates. The templates carry the maintenance framework (how to add a pitfall, completeness checklist, voice and style guide) and pre-populate universal cross-cutting entries — the §Orchestration pitfall that points back to git-strategy, and universal testing disciplines (test output pristine, skipped ≠ passing, error path coverage, negative property testing, concurrency, boundary validation, test infrastructure hygiene).

**This file is for agents invoking the skill.** Humans should read [README.md](README.md) for the overview.

## When to use

Invoke when the user asks to:

- "set up pitfalls docs", "initialize pitfalls files", "add implementation-pitfalls.md and testing-pitfalls.md"
- "bootstrap the pitfalls discipline"
- set up a new project that will use the plan-writing flow where pitfalls are mandated reading

Do NOT use for:

- Editing existing pitfalls entries — that's a normal edit workflow, not an init.
- Projects that have both files and don't want the universal cross-cutting content re-added — this skill is additive and may prompt to merge, but the target audience is fresh projects.

## Inputs

- The bundled templates at `references/implementation-pitfalls-template.md` and `references/testing-pitfalls-template.md` (relative to this skill's root). Do NOT read templates from any other location.
- The current working directory must be the root of a git repository (or at least a project directory the user wants to install into).

## Workflow

### Step 1 — Pre-flight

1. **Verify current working directory.** If it's a git repo (`git rev-parse --is-inside-work-tree`), note that — the install path conventions will use it. If not a git repo, that's OK for this skill (pitfalls docs don't require git) — just warn the user and proceed if they confirm.

2. **Search for existing pitfalls files anywhere in the repo/project.** Match exact basenames (case-insensitive): `implementation-pitfalls.md` and `testing-pitfalls.md`. Do NOT match filenames that merely contain those strings as substrings (e.g. `implementation-pitfalls-template.md`, `testing-pitfalls-example.md`). Those are templates / reference copies, not deployed docs.
   - Tracked (if git): `git ls-files`, filtered to exact basenames
   - Untracked: `git ls-files --others --exclude-standard` with the same filter (or a direct filesystem search in non-git projects)

3. **Classify the state of each doc:**
   - `implementation-pitfalls.md`:
     - `FOUND` — file exists somewhere
     - `DIR_ONLY` — a `docs/pitfalls/` or `dev/pitfalls/` directory exists but the file doesn't
     - `MISSING` — neither file nor a natural parent directory exists
   - `testing-pitfalls.md`:
     - Same three classifications

4. **Check for existing references in CLAUDE.md / AGENTS.md** if those files exist at repo root. Note existing pitfalls paths those files reference — if they point to different locations than where we'll install, surface that conflict before writing.

### Step 2 — Auto-detect install path

Preferred install path (in order):

1. If a `docs/pitfalls/` directory already exists → install there.
2. If a `dev/pitfalls/` directory already exists → install there.
3. If `docs/` exists but no `pitfalls/` subdirectory → create `docs/pitfalls/` and install there.
4. If `dev/` exists but no `pitfalls/` subdirectory → create `dev/pitfalls/` and install there.
5. Otherwise → ask the user: (a) `docs/pitfalls/` (create docs/), (b) `dev/pitfalls/` (create dev/), (c) custom directory (user provides path), (d) root-adjacent (`./pitfalls/`).

### Step 3 — Infer decisions, present, confirm

Present one consolidated block with detected state + proposed actions and ask the user to confirm or adjust. Example:

```
Pre-flight:
  Existing implementation-pitfalls.md:  NOT FOUND
  Existing testing-pitfalls.md:         NOT FOUND

Install path:   docs/pitfalls/  (docs/ exists; pitfalls/ will be created)

Planned actions:
  1. Create docs/pitfalls/implementation-pitfalls.md from template
     - Includes: maintenance framework, how-to-add, completeness checklist
     - Includes: §Orchestration (ORCH-1 trigger-and-pointer to git-strategy.md)
     - Includes: TODO placeholders for project-specific domain sections
  2. Create docs/pitfalls/testing-pitfalls.md from template
     - Includes: 7 universal testing disciplines pre-populated
     - Includes: TODO placeholder for project-specific topic sections
  3. Update CLAUDE.md (found): add references to both files under §Conventions or equivalent
  4. AGENTS.md: not found — skipped

Confirm, or tell me what to change.
```

Wait for user confirmation before proceeding.

### Step 4 — Handle each doc's state

For each doc (`implementation-pitfalls.md` and `testing-pitfalls.md`):

- **If FOUND** at a location different from the install path:
  - Surface to user. Options: (a) leave existing, skip install at new path; (b) move existing to install path and apply template-derived universal content as additions; (c) abort the whole skill run for manual resolution.
  - Never silently overwrite or create a second copy.

- **If FOUND** at the install path:
  - Compare existing content to template. If the existing file has substantive prose (non-trivial pitfall entries, maintenance sections), surface to user: "This file exists and has real content. Options: (a) leave untouched, (b) merge the universal cross-cutting content (§Orchestration, universal testing disciplines) into the existing file where not already present, (c) abort."
  - Option (b) is the common helpful case: the file exists but was written before this skill's templates, and the user wants the universal content added without clobbering project-specific entries.

- **If DIR_ONLY or MISSING**:
  - Proceed to Step 5 (write from template).

### Step 5 — Write from template

For each doc that the user confirmed to install:

1. **Read** the bundled template from `references/implementation-pitfalls-template.md` or `references/testing-pitfalls-template.md`.

2. **Substitute placeholders:**
   - `[PROJECT NAME]` → the project's name (ask user if not obvious from repo name)
   - `YYYY-MM-DD` in the validation-date line → today's date
   - Other TODO placeholders are left as-is — agents editing the doc later will fill them in

3. **Write** to the install path. Create parent directories if needed.

### Step 6 — Update CLAUDE.md and AGENTS.md

For each of `CLAUDE.md` and `AGENTS.md` that exists at repo root:

1. **Read** the file.

2. **Decide placement** — look for an existing section whose heading contains (case-insensitive substring match) any of the following, in priority order. The first match wins:
   - `Documentation` / `Docs` / `References`
   - `Conventions` / `Development Workflow` / `Workflow`
   - `Version Control` / `Git`
   - `Development`

3. **If a matching section is found:** append reference lines under it:
   ```markdown
   - **`docs/pitfalls/implementation-pitfalls.md`** — known implementation traps, review checklists, and the maintenance framework. READ BEFORE CODING.
   - **`docs/pitfalls/testing-pitfalls.md`** — test scenario checklist. READ BEFORE WRITING TESTS.
   ```
   (Adjust the path to match the install path chosen in Step 2.)

4. **If no matching section is found:** add a new top-level section:
   ```markdown
   ## Pitfalls

   - **`docs/pitfalls/implementation-pitfalls.md`** — known implementation traps, review checklists, and the maintenance framework. READ BEFORE CODING.
   - **`docs/pitfalls/testing-pitfalls.md`** — test scenario checklist. READ BEFORE WRITING TESTS.
   ```

5. **Do not** overwrite existing references if they're already present. Check for the exact paths (`implementation-pitfalls.md`, `testing-pitfalls.md`) in the file before appending; if found, verify they point at the install path and skip the append if so.

### Step 7 — Report

Summarize:

```
Done.

Created:
  docs/pitfalls/implementation-pitfalls.md  (from template; TODO placeholders for your project's domains)
  docs/pitfalls/testing-pitfalls.md         (from template; 7 universal sections + TODO placeholder)

Updated:
  CLAUDE.md  — added references under §Conventions

Skipped:
  AGENTS.md  — not found
```

Suggest follow-ups:

- Fill in the TODO placeholders in both templates with project-specific content as pitfalls are discovered.
- If `git-strategy-init` has NOT been run yet in this project, consider running it next — the §Orchestration entry in `implementation-pitfalls.md` forward-references `docs/git-strategy.md` §Multi-agent coordination, and that reference will be dangling until `git-strategy-init` installs the target.

## Common mistakes

- **Matching template/example files in pre-flight search.** `grep -i implementation-pitfalls` matches `implementation-pitfalls-template.md`, `implementation-pitfalls-example.md`, `implementation-pitfalls-original.md`, etc. Filter by EXACT basename only.
- **Silently overwriting existing pitfalls files.** Always surface and ask. These files accumulate load-bearing project-specific content over time; clobbering destroys work.
- **Skipping the CLAUDE.md / AGENTS.md update.** Without it, plan-writing skills won't find the pitfalls files via their mandated-read paths. The write alone doesn't make the docs discoverable.
- **Assuming the user wants the same path as the template's examples.** `docs/pitfalls/` vs `dev/pitfalls/` vs `pitfalls/` at root — projects vary. Detect then confirm, don't default.
- **Using Claude-Code-specific tooling.** This skill is cross-platform. Do not invoke `TodoWrite`, `AskUserQuestion`, `Skill`, or any other tool that isn't shell/file-I/O primitives.

## Quick reference

| Step | Action |
|---|---|
| 1 | Verify repo/project state; search for existing pitfalls files by EXACT basename |
| 2 | Auto-detect install path (docs/pitfalls > dev/pitfalls > create docs/pitfalls > ask) |
| 3 | Present state + proposed actions; await user confirmation |
| 4 | Handle each doc's state: FOUND-at-other-path / FOUND-at-install-path / DIR_ONLY / MISSING |
| 5 | Write from template; substitute project name + date; preserve TODO placeholders |
| 6 | Append references to CLAUDE.md / AGENTS.md (the ones that exist) under a matching section, or create new §Pitfalls section |
| 7 | Report paths written, files updated, and follow-ups |

## Relationship to other skills

- **`git-strategy-init`**: separate, composable skill. The implementation-pitfalls template's §Orchestration entry forward-references `docs/git-strategy.md` §Multi-agent coordination. Running `git-strategy-init` first makes that reference resolve; running this skill first creates a temporarily dangling reference that resolves when `git-strategy-init` runs later. Either order is OK.
- **Plan-writing skills** (e.g. `superpowers:writing-plans`, `writing-plans-enhanced`): these typically mandate reading `implementation-pitfalls.md` and/or `testing-pitfalls.md` during plan authorship. This skill puts those files in place so the mandated-read discovery path works.
- **Future `project-init` wrapper**: runs `git-strategy-init` + `pitfalls-docs-init` (+ other init skills) in sequence for one-command project bootstrap. Each sub-skill is idempotent and composable; the wrapper just sequences them.

## Cross-platform notes

Pure instruction, no bundled scripts. Any agent framework with shell access and file read/write can execute it.

- **Git subcommands** used (file listing, optional) are portable. Skill works even on non-git projects.
- **File listing / existence checks** — use your agent's native file tools rather than shell `test -f`.
- **Basename filtering** must be case-insensitive to match `IMPLEMENTATION-PITFALLS.md` and other casings.

No dependency on Claude Code-specific features. Codex, Cursor, and other agent frameworks that can read markdown skills and execute shell commands can run it equivalently.
