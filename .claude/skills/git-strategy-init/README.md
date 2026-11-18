# git-strategy-init

Initializes a project-specific `git-strategy.md` from a bundled template that codifies a worktree-based, multi-agent-safe git workflow. The skill is intended to be invoked by an AI agent (Claude Code, Codex, Cursor, etc.) acting on behalf of the user — it is not a standalone CLI.

**Agents should read [SKILL.md](SKILL.md).** This README is the human-facing overview.

## What the skill does

Given a git repo and a user request like *"set up the git strategy in this project"*:

1. Confirms it's running in a git repo and searches for any existing `git-strategy.md` (tracked or untracked).
2. Auto-detects the current branch, the presence of `main` / `dev` / `develop`, the forge (GitHub / GitLab / etc.), and whether `CLAUDE.md` / `AGENTS.md` exist.
3. Presents the detected values and asks the user to confirm or adjust.
4. Fills out the bundled template — removes the pre-adoption guidance sections, substitutes the integration branch name, substitutes the worktree path, and swaps forge-specific commands.
5. Writes the filled-out doc (default: `docs/git-strategy.md` if `docs/` exists; prompts otherwise).
6. Appends the worktree path to `.gitignore` if not already ignored.
7. Appends a reference to the new doc under an appropriate section in `CLAUDE.md` and `AGENTS.md` (whichever exist).
8. Reports what was changed and suggests next steps.

## What the template covers

The bundled template at `references/git-strategy-template.md` codifies:

- One long-lived integration branch; ephemeral worktree-isolated branches for everything else.
- No `git checkout` in the root checkout; no commits directly to local integration branch; no `git pull` on the integration branch (reset instead).
- Day-one workflow, recovery-from-messy-state workflow, verification steps.
- Multi-agent coordination rules: per-agent worktrees, orchestrator-merges-worker-pushes, fetch-before-comparing.
- Merge authority split: agents may auto-merge routine PRs (docs / tests / mechanical refactor); user merges anything touching production code or architecture. Classification is required in the PR body.
- Rationale table, red-flags checklist, explicit exceptions.

The template supports three branching patterns out of the box:

- **GitHub flow** — integration branch is `main`.
- **Trunk-based development** — integration branch is `main`, worktrees especially short-lived.
- **Two-branch / simplified gitflow** — integration branch is `dev`, `main` is release-only.

Release / hotfix / environment branch workflows are explicitly out of scope — projects that need those must add separate policy.

## What the user sees

A typical invocation looks like:

```
You: set up git strategy in this project

Agent: [runs pre-flight checks silently]

       Detected / inferred:
         Integration branch:   main
         Branching pattern:    GitHub flow
         Forge:                GitHub (origin: git@github.com:org/repo.git)
         gh CLI:               installed
         Output path:          docs/git-strategy.md
         Worktree path:        .claude/worktrees/
         Will update:          CLAUDE.md (found), AGENTS.md (not found)
         .gitignore update:    add '.claude/worktrees/' (not currently ignored)

       Confirm, or tell me what to change.

You: looks good

Agent: [writes files]

       Done.
         Wrote:        docs/git-strategy.md
         .gitignore:   added '.claude/worktrees/'
         CLAUDE.md:    appended reference under '## Development Workflow'
         AGENTS.md:    not found — skipped

       Next: commit the new file and updates. Suggested message:
         docs: adopt worktree-based git strategy
```

## Updating the template

If the canonical template (in the project that originated it) is updated, refresh the bundled copy:

```
cp /path/to/source/git-strategy-template.md references/git-strategy-template.md
```

The skill reads `references/git-strategy-template.md` and no other file — keeping the bundled copy authoritative.

After refreshing, verify the section-heading validation in SKILL.md Step 4 still matches the template's headings.

## Cross-platform

The skill is pure instructions — no scripts, no runtime dependencies, no platform-specific binaries. It invokes only:

- `git` (portable across Windows / macOS / Linux / Git Bash)
- The host agent's native file read/write/search tooling

It does not depend on any Claude Code-specific features. Codex, Cursor, and other agent frameworks that can read markdown skills and execute shell commands can run it equivalently.

## Limits

- The skill initializes, it doesn't maintain. If the template upstream changes later, re-running the skill won't migrate an existing project's doc — that's a merge problem the user handles manually.
- The skill assumes the user is comfortable with the worktree-based model. If they're not, the template itself is quite opinionated — read it first.
- Forge support is best for GitHub and GitLab; Bitbucket and self-hosted forges get a "verify the CLI commands manually" note rather than full substitutions.
