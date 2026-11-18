# claude-agents-md-init

Initializes project-root agent-guidance files (`CLAUDE.md` for Claude Code, `AGENTS.md` for Codex / Cursor / Cline / other AGENTS.md-aware frameworks) from a single bundled template, tuned for modern Claude (Opus 4.7+) and forward-compatible with other coding agents.

## What this does

Installs one bundled template as one or both of two sibling files at the project root:

- **`CLAUDE.md`** — consumed by Claude Code (`claude.ai/code`)
- **`AGENTS.md`** — consumed by Codex, Cursor, Cline, Aider, and the growing set of AGENTS.md-aware frameworks

Both outputs come from the same template ([references/claude-agents-md-template.md](references/claude-agents-md-template.md)) and are substantively identical except for two substitution points:

- The **intro line** (`[AGENT_INTRO]`) — per-target phrasing about which framework the file guides
- The **Sibling-sync reminder** (`[SIBLING_FILE]`) — points each file at its sibling so future editors know to keep the pair in sync

The skill also applies four universal substitutions (`[PROJECT NAME]`, `[USER NAME]`, `[PRIMARY BRANCH]`, `[BRIEF PROJECT DESCRIPTION]`) identically across both outputs.

## Why one skill for two files

Claude Code and Codex/Cursor/Cline are used side-by-side in many teams. The rules governing agent collaboration are ~95% identical across frameworks — principles, TDD discipline, version control conventions, testing standards, debugging process, and so on. Only a handful of mentions are framework-specific (the intro line, tool names like "TodoWrite" vs. equivalents, specific invocation syntax for the Skill tool). Maintaining two parallel skills with two parallel templates introduces drift risk for little gain.

**Single source of truth + per-target substitutions + Sibling-sync reminder at the top of each output** is the design: the two files are in sync by construction at install time, and the reminder keeps them in sync over time as humans and agents edit them.

### The Sibling-sync reminder

At the top of each output file, immediately after the intro, the template inserts a prominent note:

> **Sibling sync.** This file has a sibling at `<other file>` carrying the same rules for <other framework>. When updating either, update the other — the two should stay identical except for framework-specific phrasing (agent names, tool names).

The reminder is load-bearing for drift prevention. When a user or agent edits `CLAUDE.md` weeks or months after install, the reminder at the top says "edit AGENTS.md too." Without it, the two files silently diverge.

### Divergence detection before filling the gap

When the skill is asked to fill a gap — one file exists, the other doesn't — it runs an **alignment check** on the existing file before standing up the sibling from the template. The check greps for six structural markers (the Terminology block with RFC 2119 reference, the Principles section with Rule #1, the Our-relationship section with the "Don't glaze me" phrase). If fewer than four markers are present, the existing file is classified as `DIVERGENT`.

Creating a template-based sibling against a `DIVERGENT` existing file would produce an out-of-sync pair at minute zero. The first cross-sync operation later would face a large structural diff — exactly the mess the sibling-sync reminder is designed to prevent.

So the skill STOPs and surfaces four options to the user:

- **(a) Align the existing file to the template first.** Recommended default if the user can spare a few minutes. Exit, align, re-run.
- **(b) Create the missing sibling as a literal copy of the existing file.** Preserves content exactly; ignores the template for this install.
- **(c) Proceed with template-based creation anyway.** Accept the divergence; document it so future sync operations aren't surprising.
- **(d) Abort.**

The STOP is explicit and deliberate — this is one of the few places where the skill does NOT auto-proceed.

### Sync-block injection for template-aligned-but-unsynced files

Projects that ran an earlier version of this skill (or hand-authored a template-aligned CLAUDE.md before this skill existed) won't have the sibling-sync reminder block. The skill detects these (classified as `TEMPLATE_ALIGNED_NO_SYNC`) and injects the block at the top — between the intro line and the `## Terminology` section — without touching any other content. The injection is safe, minimal, and reported separately in the final summary.

Concretely: running `claude-agents-md-init` against a project that has a template-aligned CLAUDE.md but no AGENTS.md (and no sync block on the CLAUDE.md) will produce:

1. A new AGENTS.md created from the template with the sync block
2. The existing CLAUDE.md gets its sibling-sync block injected (no other changes)
3. Both files now carry the sync reminder pointing at each other

## When to use

Invoke when:

- Bootstrapping a new project that will use Claude Code and/or other coding agents
- An existing project has neither `CLAUDE.md` nor `AGENTS.md`, or only one of them
- You want to align an old single-framework file with current cross-framework conventions (use the "merge universal sections" option in Step 4)

Do NOT invoke for:

- Editing content in an existing file that's already current (use a normal edit flow)
- Projects where one of the files has been heavily customized and you don't want template-driven changes

## Target modes

The `--target` flag controls which file(s) to write:

| Target | Behavior |
|---|---|
| `claude` | Writes `CLAUDE.md` only |
| `agents` | Writes `AGENTS.md` only |
| `both` (default) | Writes both — the happy path for mixed-framework teams |

Smart default based on existing file state:
- Neither file exists → `both`
- Only `CLAUDE.md` exists → `agents` (fill the gap without touching the existing file)
- Only `AGENTS.md` exists → `claude`
- Both exist → `both` (but Step 4 handles each existing file's replace/merge/skip decision independently)

## Placement

| File | Path |
|---|---|
| Installed CLAUDE.md | `./CLAUDE.md` at the project root |
| Installed AGENTS.md | `./AGENTS.md` at the project root |
| Backup (if an existing file was replaced) | `./<FILENAME>.backup-<timestamp>` |

Subdirectory copies are supported by Claude Code's auto-discovery (useful for monorepos / per-package context) but aren't managed by this skill.

## Dogfood mode

The skill supports a non-destructive output-filename override:

- `--output-filename CLAUDE-TMP.md` (for `claude` target) or the equivalent for agents
- Writes to the overridden filename regardless of whether the canonical file exists
- Skips the existing-file backup-and-replace logic
- Report includes a `diff` hint so the user can compare the template output to the existing canonical file

Useful when dogfooding template changes against a project with substantial existing content.

## Composition with sister skills

This skill is designed to compose with the other `project-setup` skills:

- **`git-strategy-init`** — installs `docs/git-strategy.md`. The agent-md template's "Keeping a clean git graph" section references this file.
- **`pitfalls-docs-init`** — installs `docs/pitfalls/implementation-pitfalls.md` and `docs/pitfalls/testing-pitfalls.md`. The agent-md template's "Language / Framework Gotchas" and "Development Workflow" sections reference these.
- **`project-init`** — wrapper that sequences all three init skills for one-command bootstrap. `claude-agents-md-init` runs first so later skills have well-formed CLAUDE.md + AGENTS.md files to append references into.

Each sub-skill has zero hard dependencies on the others — references that don't yet resolve are dangling until the companion skill runs, which is acceptable because the files are read by a human+agent pair who will notice and unblock.

## Design decisions

### Opus 4.7+ tuning

The template encodes lessons from a tuning pass performed on a real Claude 4.7 CLAUDE.md. The relevant behavior changes from Anthropic's 4.7 migration guide that shaped the template:

| 4.7 behavior change | Template response |
|---|---|
| More literal instruction following, especially at lower effort levels | RFC 2119 terminology block governs all MUST / MUST NOT tokens; scoped STOP rules (avoid unqualified "ALWAYS STOP"); TDD scope explicitly enumerated; TodoWrite guidance scoped to 3+ step work |
| Fewer subagents by default | Explicit "When to dispatch parallel subagents" callout with project-specific triggers listed |
| Response length varies by use case | No explicit verbosity rules — let the model calibrate |
| More direct tone, less validation-forward phrasing | "Don't glaze me" anti-sycophancy rule kept; specific-phrase bans (e.g., the old "You're absolutely right!" ban) dropped as obsolete |
| Built-in progress updates | No scaffolding for forced interim status messages |
| Better file-system memory | Three-layer memory pattern (pitfalls / user-scoped memory / per-phase reports) prescribed explicitly |
| Stricter effort calibration | Rules that trigger the TDD / debugging / thinking-doc workflows call out their skill operationalization explicitly |

Codex and Cursor are similarly literal about instruction-following (both respect RFC 2119 conventions, both have improved at long-horizon agentic work). The 4.7-tuned template produces content that lands correctly in AGENTS.md for those frameworks too — which is the main reason a single template serves both outputs.

### What's "universal" vs. what's placeholder

The universal/placeholder split is a judgment call. The heuristic:

- **Universal**: things roughly the same for any engineering team using AI coding agents — engineering values, git discipline, test discipline, debugging discipline, agent communication norms, workflow skills that exist in the broader ecosystem.
- **Placeholder**: things that depend on the project's language, framework, architecture, tools, and team shape — build commands, file layout, language-specific gotchas, project-specific skills, routing rules.

Borderline items and how they resolved:

- **"No secrets in CLI flags" / "No PII in logs"**: universal. Stay pre-populated because they're security baselines, not project-specific.
- **"Comparative Evaluation Rules" (EVAL-1 through EVAL-5)**: universal. Apply to any tech selection / framework comparison work.
- **AOT / trim-warning policies**: project-specific. Removed from the template; users of .NET AOT projects fill them into the Language/Framework Gotchas placeholder.
- **Superpowers skills table**: universal. Pre-populated because the skills are widely used across Claude Code and cross-agent workflows. Projects that don't use superpowers should delete or replace the table.

### Why not two parallel skills

Considered: `claude-md-init` + `agents-md-init` as siblings, each with its own template. Ruled out because:

1. The two templates would be 95%+ identical; keeping them in sync by manual propagation adds maintenance cost and drift risk.
2. Teams that use both frameworks (the primary target audience) would need to run two skills and confirm two sets of substitutions.
3. The Sibling-sync reminder approach keeps the files aligned over the long term — but only if they start identical, which requires single-source generation.

The chosen design (one skill, one template, per-target substitutions, Sibling-sync reminder) gets all three benefits.

### Portability

The skill uses only shell and file I/O primitives. It does not invoke `TodoWrite`, `AskUserQuestion`, `Skill`, or any Claude-Code-specific tool. Any agent framework that can read a markdown skill, execute shell commands, and read/write files can run it.

## Maintenance

If the template needs updating:

1. Edit `references/claude-agents-md-template.md` in this skill.
2. The change takes effect on the next `claude-agents-md-init` run for any project.
3. If an existing project wants the updates, re-run the skill and choose the "merge universal sections" option for each target, or edit the files by hand — the Sibling-sync reminder nudges the editor to hit both.

The template is long (~35 KB). That's intentional — it's a full working document, not a stub. When editing, preserve the section order:

```
1. Title + intro line ([AGENT_INTRO])
2. Sibling-sync reminder ([SIBLING_FILE])
3. Terminology (RFC 2119/8174)
4. Project Overview [PLACEHOLDER]
5. Principles
6. Foundational rules
7. Our relationship
8. Proactiveness
9. Designing software
10. Completeness over shortcuts
11. Test Driven Development
12. Writing code
13. Naming
14. Code Comments
15. Cross-references in persistent artifacts
16. Version Control
17. Keeping a clean git graph
18. Testing
19. Issue tracking
20. Completion status & escalation
21. Systematic Debugging Process
22. Thinking documentation for methodology
23. Learning and Memory Management
24. Build & Dev Commands [PLACEHOLDER]
25. Tech Stack [PLACEHOLDER]
26. Architecture (Key Points) [PLACEHOLDER]
27. Conventions [PLACEHOLDER]
28. Language / Framework Gotchas [PLACEHOLDER + universal sub-sections]
29. Development Workflow [PLACEHOLDER]
30. Project Layout [PLACEHOLDER]
31. Skills & Subagents (workflow table pre-populated; project-specific placeholder)
32. Skill routing [PLACEHOLDER]
```

That order matters because the document is read linearly by humans and agents alike — e.g., Principles set the tone before specific rules land; Proactiveness comes before the workflow sections that it governs.

## History

- **v1.0** (agent-skills PR #6) — initial release as `claude-md-init`. Single-target (CLAUDE.md only).
- **v2.0** (agent-skills PR #7) — dual-target (CLAUDE.md + AGENTS.md). Sibling-sync reminder added to template. Released briefly under the name `agent-md-init`, but the name looked like a typo-pluralization of the `AGENTS.md` spec.
- **v2.1** (this skill) — renamed to `claude-agents-md-init` to disambiguate visually from `AGENTS.md`. Added divergence detection on existing files; skill now STOPs for human review before standing up a sibling from the template against a `DIVERGENT` existing file. Added sync-block injection for `TEMPLATE_ALIGNED_NO_SYNC` existing files (projects that pre-date the sync-block feature). Template file renamed `agent-md-template.md` → `claude-agents-md-template.md`.

## References

- Anthropic Opus 4.7 migration guide — informed the 4.7-tuned language in the template
- AGENTS.md convention — emerging standard for non-Claude agent guidance (Codex, Cursor, Cline, Aider, and others)
- `git-strategy-init` SKILL.md — sibling skill; established the workflow pattern this skill follows
- `pitfalls-docs-init` SKILL.md — sibling skill; established the template-bundling pattern and cross-reference discipline
