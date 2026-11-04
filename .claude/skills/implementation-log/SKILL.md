---
name: implementation-log
description: Write a phase completion entry as a new file in dev/implementation-log/. Use when finishing a phase or significant feature block — not after every commit.
argument-hint: "<phase name, e.g. 'Phase 8E — Ops & Secure' or 'Phase 11 — MFA Handlers'>"
---

# Implementation Log Entry

Writing a phase completion entry for: **$ARGUMENTS**

Each entry is its own file in `dev/implementation-log/`. Naming rules are in `dev/implementation-log/README.md`. Never append to an existing entry and never add an index file. Both put every branch's change in one shared file, and that causes merge conflicts.

## Step 1: Gather context

Collect the raw material for the entry. Run these in parallel:

1. **Read the most recent entry**: `ls dev/implementation-log/2*.md | tail -1`. Read that entry to see the current format
2. **Identify the commit range**: `git log --oneline dev` — find the first and last commits belonging to this phase (use branch name, PR title, or commit message prefixes to identify them)
3. **Find the plan file** (if one exists): `ls dev/plans/` — look for a plan matching the phase name
4. **Identify files changed**: `git diff --stat <first-commit>^..<last-commit>` to see the scope of changes

## Step 2: Draft the entry

Follow the exact structure used by existing entries. The format varies slightly by phase complexity, but always includes:

```markdown
# <Phase name>

> **Date:** <YYYY-MM-DD>
> **Commits:** `<first>`..`<last>` on `<branch>`
> **Plan:** `dev/plans/<plan-file>` (if applicable)

## What was built

| Feature | Files | Description |
|---|---|---|

## Key implementation decisions

- **<Decision>** — <rationale>

## Gotchas discovered

- **<Gotcha>** — <what happened and how it was resolved>

## Quality checks

- **go build ./...:** <result>
- **golangci-lint:** <result>
- **Tests:** <summary of test results>
```

**Important guidelines:**
- Only include sections that have content — skip "Gotchas" if there were none
- "What was built" should be a table of features, not a file-by-file listing
- "Key implementation decisions" captures decisions NOT already in PLAN.md — things discovered during implementation
- "Gotchas discovered" captures surprises, pitfalls, debugging insights — things future sessions should know
- Keep entries concise — this is a reference log, not a narrative
- Use commit messages, PR descriptions, and the plan file as source material — don't fabricate details

## Step 3: Quality check results

The "Quality checks" section must report **real** results, not assumptions. But these checks are slow — don't re-run them if they've already passed in this session.

**Check the conversation history first.** If `go build ./...`, `golangci-lint run`, and `go test ./...` have all been run in this conversation (e.g., by `/finishing-a-development-branch`, `/verification-before-completion`, or manual invocation) and their most recent results were clean, use those results directly. Cite them as-is.

**Only re-run checks that are stale or missing.** A check is stale if code has been committed since it last ran. Run only the stale/missing ones:

```bash
go build ./...         # skip if clean build already in conversation
golangci-lint run      # skip if clean lint already in conversation
go test ./...          # skip if all tests passed already in conversation
```

If you cannot verify that checks have been run, run them — never fabricate results.

## Step 4: Write the entry file

Write the entry to a new file `dev/implementation-log/<timestamp>-<slug>.md`:

- `<timestamp>` is the current UTC time as `YYYY-MM-DDTHHMMZ`. Get it with `date -u +%Y-%m-%dT%H%MZ` (bash) or `(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHHmm'Z'")` (PowerShell).
- `<slug>` is the phase name in lowercase ASCII, words joined by `-`, at most about 70 characters. Example: `2026-11-03T2205Z-fix-overlapping-digest-ticks-sent-the-same-digest-twice.md`.

## Step 5: Commit

Stage and commit just the new entry:

```bash
git add dev/implementation-log/<timestamp>-<slug>.md
git commit -m "docs(log): add <phase name> implementation log entry"
```
